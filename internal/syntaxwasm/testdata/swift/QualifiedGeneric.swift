// A generic type construction behind a qualifier is not recognised by the
// grammar; it must give no record rather than a wrong one.
struct Holder {
    let made = Foo.Bar<Int>(x: 1)
}
let plain = Foo.Bar(x: 2)
