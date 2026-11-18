public struct Point {}

public extension Point {
    private/*hidden*/ func hidden() {}
    func shown() {}
    internal func narrowed() {}
}

extension Point {
    public func widened() {}
    func plain() {}
}
