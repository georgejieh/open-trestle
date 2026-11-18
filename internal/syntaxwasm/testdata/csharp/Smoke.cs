extern alias Legacy;
using System;
using Collections = System.Collections.Generic;
using static Legacy::Old.Helpers;
using Pair = (int Left, int Right);
global using System.IO;

#nullable enable

namespace Outer.Inner
{
    using System.Text;

    namespace Deep { public class Marker { } }

    public interface IShape { double Area { get; } void Draw(); }

    internal class Hidden<T, U> where T : IShape, new() where U : struct
    {
        static Hidden() { }
        public Hidden() { }
        private protected int count;
        public static readonly int Limit = 3;
        readonly static int Other = 4;
        public const string Name = "n", Alias = "a";
        int a, b = 2;
        public delegate T Factory<T>(int seed);
        public event Action<int>? Changed, Cleared;
        public int this[string key] => 0;
        public static Hidden<T, U> operator ++(Hidden<T, U> value) => value;
        public static explicit operator int(Hidden<T, U> value) => 0;
    }

    public class Circle : IShape, System.IDisposable, Base<int>.Inner
    {
        double IShape.Area => 1.0;
        void IShape.Draw() { Console.WriteLine(); }
        public void Dispose() { }
        protected virtual T Convert<T>(object o) => (T)o;
        public async Task RunAsync()
        {
            var x = await Task.Run(() => Compute<int>(1));
            var y = this.Helper<string>("a");
            var z = o as Circle;
            if (o is Circle c && c.Radius > 0) { }
            var q = from item in Items where item.Ok select item.Name;
            var t = typeof(Circle);
            var s = nameof(Circle);
            var n = new Outer.Inner.Deep.Marker();
            var g = new Dictionary<string, List<int>>();
            var arr = new int[3];
            var anon = new { A = 1 };
            using var stream = new MemoryStream();
            Foo?.Bar?.Baz();
            base.Dispose();
            local();
            void local() { Helper2(); }
        }
    }

    public record struct Point(int X, int Y);
    public readonly record struct Vec(double A);
    public record Person(string Name) : Base(Name), IEquatable<Person>;
    public sealed class Account(string id, decimal balance) : Entity(id)
    {
        public decimal Balance { get; } = balance;
    }

    [AttributeUsage(AttributeTargets.All), System.Serializable]
    [return: NotNull]
    public enum Color { Red, Green }

#if DEBUG
    public class DebugOnly { public void Trace() { } }
#else
    public class ReleaseOnly { public void Trace() { } }
#endif

    #region helpers
    public static class Tools
    {
        public static T[] Many<T>(this T item) => new[] { item };
    }
    #endregion
}

namespace Flat.A.B { class InB { } }
