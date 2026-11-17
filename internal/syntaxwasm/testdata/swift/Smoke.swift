import Foundation

struct Point { var x = 0, y = 0 }
class Base {}
class Derived: Base, P, Q {}
struct Generic<T>: Equatable where T: Hashable { let value: T }
enum E { case a, b(Int); indirect case c(E) }
protocol P { func f() }
protocol Q: P {}
extension Point: P { func f() {} }
extension Swift.Array: Q { func f() {} }
fileprivate func hidden() {}
private func alsoHidden() {}
func visible() { hidden(); Point(x: 1, y: 2); Swift.print("x"); obj.method().chain(); a?.b(); a!.c() }
typealias Pair<A, B> = (A, B)
let (a, b) = (1, 2)
var computed: Int { get { 1 } set {} }
var observed = 0 { willSet {} didSet {} }
class Lazy { lazy var heavy: [Int] = compute(); static func make() -> Lazy { Lazy() } }
@available(iOS 13, *) @MainActor class View { @IBOutlet weak var label: UILabel! }
func attr(@Builder _ x: () -> Void) {}
func generic<T: Comparable>(_ a: T, _ b: T) -> T where T: Hashable { a < b ? a : b }
public extension Point {
    func scaled() -> Point { Point() }
    private func hiddenScale() {}
    var magnitude: Double { 0 }
}
extension Collection where Element: Equatable { func second() -> Element? { dropFirst().first } }
open class Opened {
    open func overridable() {}
    public final var token = 1
    class func make() -> Opened { Opened() }
    convenience init(x: Int) { self.init() }
    required public init() {}
}
struct Outer {
    struct Inner { func deep() { _ = Array<Int>().count } }
    enum Kind { case one }
}
func asyncCall() async throws {
    try await fetch()
    let v = try? parse()
    guard let w = v else { return }
    items[0].run()
    _ = w
}
public protocol Open {
    var name: String { get }
    func go()
}
