import Foundation
import Combine
import struct Dispatch.DispatchTime
import class UIKit.UIView
@_exported import os.log
@testable import TaskKit

public typealias Completion = (Result<Int, Error>) -> Void
typealias Identifier = String

public let maxConcurrentTasks = 4
private var sharedCounter = 0
internal let defaultTimeout: TimeInterval = 30, defaultRetries = 3

public enum TaskState: String, CaseIterable, Codable {
    case pending
    case running(progress: Double)
    case finished, failed
    case cancelled = "cancelled"

    public var isTerminal: Bool {
        switch self {
        case .finished, .failed, .cancelled:
            return true
        default:
            return false
        }
    }

    func describe() -> String {
        return "state \(rawValue)"
    }
}

public protocol Prioritized {
    associatedtype Level: Comparable
    var level: Level { get }
    static var defaultLevel: Level { get }
    func compare(to other: Self) -> Bool
    init(level: Level)
    subscript(index: Int) -> Level { get }
}

public protocol Executable: AnyObject, Prioritized where Level == Int {
    func execute() async throws
}

protocol Observer: class {
    func didChange(_ queue: TaskQueue)
}

@propertyWrapper
public struct Clamped<Value: Comparable> {
    private var value: Value
    let range: ClosedRange<Value>

    public init(wrappedValue: Value, _ range: ClosedRange<Value>) {
        self.range = range
        self.value = min(max(wrappedValue, range.lowerBound), range.upperBound)
    }

    public var wrappedValue: Value {
        get { value }
        set { value = min(max(newValue, range.lowerBound), range.upperBound) }
    }
}

public struct TaskItem: Identifiable, Hashable, Prioritized {
    public typealias Level = Int

    public let id: UUID
    public var title: String
    @Clamped(0...10) public var priority: Int = 5
    public private(set) var state: TaskState = .pending
    static let empty = TaskItem(title: "")
    public static var defaultLevel: Int { 0 }

    public var level: Int { priority }

    public init(title: String) {
        self.id = UUID()
        self.title = title
    }

    public init(level: Int) {
        self.init(title: "level \(level)")
    }

    public subscript(index: Int) -> Int {
        return priority + index
    }

    public func compare(to other: TaskItem) -> Bool {
        return priority < other.priority
    }

    public mutating func advance() {
        switch state {
        case .pending:
            state = .running(progress: 0)
        case .running:
            state = .finished
        default:
            break
        }
    }

    public static func == (lhs: TaskItem, rhs: TaskItem) -> Bool {
        lhs.id == rhs.id
    }

    public func hash(into hasher: inout Hasher) {
        hasher.combine(id)
    }
}

open class TaskQueue: ObservableObject, Executable {
    public typealias Level = Int

    @Published public private(set) var items: [TaskItem] = []
    private let lock = NSLock()
    private var observers = [Observer]()
    fileprivate var completions: [Identifier: Completion] = [:]
    public static let shared = TaskQueue()
    public var level: Int = 1
    public static var defaultLevel: Int = 1

    public init() {}

    public required init(level: Int) {
        self.level = level
    }

    deinit {
        observers.removeAll()
    }

    public subscript(index: Int) -> Int { items[index].priority }

    public func compare(to other: TaskQueue) -> Bool {
        level < other.level
    }

    open func add(_ item: TaskItem, completion: Completion? = nil) {
        lock.lock()
        defer { lock.unlock() }
        items.append(item)
        if let completion = completion {
            completions[item.title] = completion
        }
        notifyObservers()
    }

    public func execute() async throws {
        for var item in items {
            item.advance()
            try await Task.sleep(nanoseconds: 1_000)
        }
        let results = items.map { $0.priority }.filter { $0 > 1 }
        print(results.count)
    }

    func notifyObservers() {
        observers.forEach { $0.didChange(self) }
        let handler: (TaskItem) -> Void = { item in
            self.log(item.title)
        }
        items.forEach(handler)
    }

    private func log(_ message: String) {
        NSLog("%@", message)
    }

    @discardableResult
    public func remove(at index: Int) throws -> TaskItem {
        guard index < items.count else {
            throw QueueError.outOfRange(index)
        }
        return items.remove(at: index)
    }

    func nested() {
        func helper(_ x: Int) -> Int { x * 2 }
        let value = helper(3)
        _ = value
    }
}

public enum QueueError: Error {
    case outOfRange(Int)
    case empty
}

extension TaskQueue: CustomStringConvertible {
    public var description: String { "queue of \(items.count)" }

    public func firstTitle() -> String? {
        return items.first?.title
    }
}

extension Array where Element == TaskItem {
    func highest() -> TaskItem? {
        self.max { $0.priority < $1.priority }
    }
}

extension Optional {
    var isPresent: Bool { self != nil }
}

public final class Box<T: Equatable, U>: Sequence where U: Hashable {
    var contents: T
    init(_ contents: T) { self.contents = contents }
    public func makeIterator() -> IndexingIterator<[T]> { [contents].makeIterator() }
}

public actor Counter {
    private var count = 0

    func increment() -> Int {
        count += 1
        return count
    }
}

extension Prioritized where Level: Numeric {
    func scaled(by factor: Level) -> Level {
        level * factor
    }
}

extension Collection where Element: Prioritized, Element.Level == Int {
    public func totalLevel() -> Int {
        reduce(0) { $0 + $1.level }
    }
}

public struct Batch<Item: Prioritized>: Sequence where Item.Level: Hashable {
    private var storage: [Item] = []

    public init<S: Sequence>(_ items: S) where S.Element == Item {
        storage = Array(items)
    }

    public func makeIterator() -> Array<Item>.Iterator {
        storage.makeIterator()
    }

    func grouped() -> [Item.Level: [Item]] {
        Dictionary(grouping: storage, by: { $0.level })
    }
}

public enum Job {
    case fetch(url: URL, retries: Int)
    case transform((Data) throws -> Data)
    indirect case chain(Job, Job)

    var retries: Int {
        if case let .fetch(_, retries) = self {
            return retries
        }
        return 0
    }
}

@resultBuilder
public enum PipelineBuilder {
    public static func buildBlock(_ steps: Job...) -> [Job] {
        steps
    }

    public static func buildOptional(_ steps: [Job]?) -> [Job] {
        steps ?? []
    }
}

public struct Pipeline {
    let steps: [Job]

    public init(@PipelineBuilder _ build: () -> [Job]) {
        steps = build()
    }

    public func run(on worker: Worker) async throws -> Int {
        var completed = 0
        for step in steps {
            try await worker.perform(step)
            completed += 1
        }
        return completed
    }
}

public actor Worker {
    private var running: [String: Task<Void, Error>] = [:]
    nonisolated let name: String

    public init(name: String) {
        self.name = name
    }

    func perform(_ job: Job) async throws {
        switch job {
        case .fetch(let url, _):
            _ = try await URLSession.shared.data(from: url)
        case .transform(let apply):
            _ = try apply(Data())
        case .chain(let first, let second):
            try await perform(first)
            try await perform(second)
        }
    }

    func schedule(_ key: String, operation: @escaping @Sendable () async throws -> Void) {
        running[key] = Task { try await operation() }
    }

    func cancelAll() {
        running.values.forEach { $0.cancel() }
        running.removeAll()
    }
}

func retrying<T>(times: Int, _ body: () async throws -> T) async rethrows -> T {
    var attempt = 0
    while true {
        do {
            return try await body()
        } catch where attempt < times {
            attempt += 1
        }
    }
}

let sortByLevel: (TaskItem, TaskItem) -> Bool = { lhs, rhs in
    lhs.level < rhs.level
}

infix operator <+>: AdditionPrecedence

func <+> (left: TaskItem, right: TaskItem) -> TaskItem {
    TaskItem(title: left.title + right.title)
}

func makeQueue(with titles: String...) -> TaskQueue {
    let queue = TaskQueue()
    for title in titles {
        queue.add(TaskItem(title: title))
    }
    return queue
}

#if DEBUG
func debugOnly() { print("debug") }
#endif

let queue = makeQueue(with: "a", "b")
let first: TaskItem? = queue.items.first
print(queue.description)
