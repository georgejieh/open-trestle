<?php
namespace Lib {
    use Other\{First, Second\Deep as D};

    class Box {
        #[Pure, Marker('private')]
        public function open(): void {}
        /* private */ function plain() {}
        PRIVATE function shout() {}
        protected const SIZE = 1;
        var $v = 1;
        public static function build(): static { return new self(); }
    }

    function local() {
        function inner() {}
        class Hidden {}
        return \strlen('x') + \Lib\count_things([]) + namespace\sibling();
    }
}

namespace {
    $x = new \Lib\Box();
    $x?->open();
    $name = 'open';
    $x->$name();
    Box::{'build'}();
    echo "<b>{$x->plain()}</b>";
    require "dir/$name.php";
    include dirname(__FILE__) . '/skipped.php';
    interface Marker {}
    abstract class Shape { abstract public function area(): float; }
    $f = function () use ($x) { return $x->plain(); };
}
