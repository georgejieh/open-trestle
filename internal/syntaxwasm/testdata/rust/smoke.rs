#![allow(dead_code)]
use ::std::fmt;
pub use self::inner::{deep::{Leaf, Twig as Branch}, Trunk};
use a::b::{c as d, e::*, self};
use serde;
use std::io::{self as stdio};

pub(crate) fn crate_only() {}
pub(super) fn parent_only() {}
pub(in crate::a) fn path_only() {}
pub const fn const_fn() -> u8 { 1 }
pub unsafe fn unsafe_fn() {}
pub async unsafe fn both() {}
pub extern "C" fn exported_c() {}

pub trait Describe { fn describe(&self) -> String; }
impl<T: fmt::Display> Describe for T {
    fn describe(&self) -> String { format!("{}", self) }
}
impl<T> From<T> for Wrapper {
    fn from(inner: T) -> Self { Wrapper }
}
impl<'a, T> Describe for &'a [T] {
    fn describe(&self) -> String { String::new() }
}
impl Describe for [u8; 4] {
    fn describe(&self) -> String { String::new() }
}
unsafe impl Send for Wrapper {}
impl<const N: usize> Buffer<N> {
    pub fn new() -> Self { Buffer }
}
impl crate::shared::Handle for Wrapper {}
impl std::ops::Add<Wrapper> for Wrapper {
    type Output = Wrapper;
    fn add(self, other: Wrapper) -> Wrapper { other }
}

pub struct Wrapper;
struct Buffer<const N: usize>;

pub struct Generic<T: Clone, U = Vec<T>>
where
    T: Default,
{
    pub(crate) first: T,
    pub second: U,
}

pub enum Shape {
    Circle(f64),
    Rect { w: f64, h: f64 },
    Unit,
}

#[tokio::main]
#[derive(Debug, serde::Serialize, Clone)]
#[cfg_attr(test, derive(PartialEq))]
pub struct Tagged;

fn calls() {
    let v = Vec::<i32>::with_capacity(4);
    let n = <Wrapper as Describe>::describe(&Wrapper);
    let g = crate::a::b::make::<u8>();
    let s = Shape::Rect { w: 1.0, h: 2.0 };
    let t = Generic::<u8> { first: 1, second: Vec::new() };
    let c = |x: i32| helper(x);
    (get_fn())(1);
    obj.method().other().last();
    self::local();
    super::sibling();
    nested_macro!(call_inside(1));
    std::mem::swap(&mut a, &mut b);
}

fn outer() {
    fn inner_fn() {}
    struct LocalType;
    const LOCAL: u8 = 1;
    inner_fn();
}

macro_rules! make_fn {
    ($name:ident) => {
        fn $name() { helper(1); }
    };
}

make_fn!(generated);

lazy_static::lazy_static! {
    static ref TABLE: Vec<u8> = build_table();
    pub struct Hidden;
}

mod outer_mod {
    pub mod inner_mod {
        pub fn deep() {}
    }
}

extern "C" {
    pub fn c_func(x: i32) -> i32;
}
