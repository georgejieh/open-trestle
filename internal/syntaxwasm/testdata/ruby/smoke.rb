require 'a'
require("b")
require "dir/#{name}"
require_relative File.join(__dir__, 'c')
Kernel.require 'd'

module Outer
  class Inner < Base::Parent
    def go(x) = helper(x)
    def self.make = new
    def ==(other) = true
    def value=(v)
      @value = v
    end
    def each(&) = items.each(&)

    rescue_from Foo::Bar do
      handle
    end

    private def hidden; end

    def shown; end
    private :shown, :go

    X = 1
    private_constant :X
  end

  class Other::Nested
  end
end

x = Outer::Inner.new
y = Outer::Inner::Deep.new(1)
z = klass.new
obj&.call
a.b.c(1).d
puts [1, 2].map { |n| n * 2 }.sum
begin
  risky
rescue ArgumentError, Foo::Bad => e
  warn e.message
end
