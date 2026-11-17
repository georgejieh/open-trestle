using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;
using static System.Math;
using Json = System.Text.Json.JsonSerializer;
using Handler = System.Func<Acme.Orders.Order, System.Threading.Tasks.Task<bool>>;
global using Acme.Common;

namespace Acme.Orders;

public delegate void OrderPlaced(object sender, OrderEventArgs args);

public enum OrderStatus
{
    Pending,
    Paid = 2,
    Shipped,
    Cancelled = -1,
}

[Flags]
public enum Channels : byte
{
    None = 0,
    Web = 1,
    Phone = 2,
}

public interface IOrderRepository : IDisposable
{
    const int PageSize = 50;

    Order? Find(Guid id);

    Task<IReadOnlyList<Order>> ListAsync(int page, CancellationToken token = default);

    void Save(Order order);

    event EventHandler Saved;

    string Name { get; }
}

public interface IAuditable<T> where T : class
{
    T Snapshot();
}

public class OrderEventArgs : EventArgs
{
    public OrderEventArgs(Order order) => Order = order;

    public Order Order { get; }
}

[Serializable]
public class Order : IAuditable<Order>, IComparable<Order>
{
    public const decimal MaxTotal = 1_000_000m;
    public static readonly TimeSpan Timeout = TimeSpan.FromSeconds(30);
    private static int _counter;
    private readonly List<OrderLine> _lines = new();
    protected internal string notes = "";
    internal int version, revision;

    public Order(Guid id, string customer)
    {
        Id = id;
        Customer = customer ?? throw new ArgumentNullException(nameof(customer));
        Interlocked.Increment(ref _counter);
    }

    public Order() : this(Guid.NewGuid(), "anonymous")
    {
    }

    ~Order()
    {
        _lines.Clear();
    }

    public Guid Id { get; init; }

    public string Customer { get; set; }

    public OrderStatus Status { get; private set; } = OrderStatus.Pending;

    public decimal Total => _lines.Sum(l => l.Price * l.Quantity);

    public event EventHandler? StatusChanged;

    public OrderLine this[int index]
    {
        get => _lines[index];
        set => _lines[index] = value;
    }

    public IReadOnlyList<OrderLine> Lines => _lines;

    public void AddLine(string sku, int quantity, decimal price)
    {
        if (Status != OrderStatus.Pending)
        {
            throw new InvalidOperationException("order is closed");
        }
        var line = new OrderLine(sku, quantity, price);
        _lines.Add(line);
    }

    public bool TryPay(IPaymentGateway gateway)
    {
        var result = gateway.Charge(Customer, Total);
        if (!result.Succeeded)
        {
            return false;
        }
        Status = OrderStatus.Paid;
        OnStatusChanged();
        return true;
    }

    private void OnStatusChanged() => StatusChanged?.Invoke(this, EventArgs.Empty);

    public Order Snapshot()
    {
        var copy = new Order(Id, Customer);
        foreach (var line in _lines)
        {
            copy.AddLine(line.Sku, line.Quantity, line.Price);
        }
        return copy;
    }

    public int CompareTo(Order? other) => other is null ? 1 : Total.CompareTo(other.Total);

    public static Order operator +(Order left, OrderLine line)
    {
        left.AddLine(line.Sku, line.Quantity, line.Price);
        return left;
    }

    public static implicit operator decimal(Order order) => order.Total;

    public override string ToString() => $"{Id}: {Customer} ({Status})";
}

public record OrderLine(string Sku, int Quantity, decimal Price)
{
    public decimal Extended => Quantity * Price;

    public static OrderLine Empty { get; } = new OrderLine("", 0, 0m);
}

public readonly record struct Money(decimal Amount, string Currency);

public struct Point
{
    public int X;
    public int Y;

    public Point(int x, int y)
    {
        X = x;
        Y = y;
    }

    public double Distance() => Sqrt(X * X + Y * Y);
}

public record PaymentResult(bool Succeeded, string? Error = null);

public interface IPaymentGateway
{
    PaymentResult Charge(string customer, decimal amount);
}

public abstract class RepositoryBase<TKey, TEntity> : IDisposable
    where TEntity : class, new()
    where TKey : notnull
{
    protected readonly Dictionary<TKey, TEntity> Store = new();

    public abstract TEntity? Get(TKey key);

    protected virtual void OnMissing(TKey key)
    {
        Console.WriteLine($"missing {key}");
    }

    public void Dispose()
    {
        Store.Clear();
        GC.SuppressFinalize(this);
    }
}

public sealed class MemoryOrderRepository : RepositoryBase<Guid, Order>, IOrderRepository
{
    public event EventHandler? Saved;

    public string Name => "memory";

    public override Order? Get(Guid key)
    {
        if (Store.TryGetValue(key, out var order))
        {
            return order;
        }
        OnMissing(key);
        return null;
    }

    public Order? Find(Guid id) => Get(id);

    public async Task<IReadOnlyList<Order>> ListAsync(int page, CancellationToken token = default)
    {
        await Task.Delay(1, token).ConfigureAwait(false);
        return Store.Values
            .Skip(page * IOrderRepository.PageSize)
            .Take(IOrderRepository.PageSize)
            .ToList();
    }

    public void Save(Order order)
    {
        Store[order.Id] = order;
        Saved?.Invoke(this, EventArgs.Empty);
    }
}

public static class OrderExtensions
{
    public static IEnumerable<Order> Open(this IEnumerable<Order> orders)
    {
        return orders.Where(o => o.Status == OrderStatus.Pending);
    }

    public static decimal GrandTotal<T>(this IEnumerable<T> items, Func<T, decimal> selector)
    {
        decimal Add(decimal a, decimal b) => a + b;
        return items.Select(selector).Aggregate(0m, Add);
    }

    public static string Describe(this Order order) => order switch
    {
        { Status: OrderStatus.Paid } => "paid",
        { Lines.Count: 0 } => "empty",
        _ => order.ToString(),
    };
}

public partial class OrderService
{
    private readonly IOrderRepository _repository;
    private readonly IPaymentGateway _gateway;
    private OrderPlaced? _placed;

    public OrderService(IOrderRepository repository, IPaymentGateway gateway)
    {
        _repository = repository;
        _gateway = gateway;
    }

    public event OrderPlaced Placed
    {
        add { _placed += value; }
        remove { _placed -= value; }
    }

    public async Task<Order> PlaceAsync(string customer, IEnumerable<(string Sku, int Qty)> items)
    {
        var order = new Order(Guid.NewGuid(), customer);
        foreach (var (sku, qty) in items)
        {
            order.AddLine(sku, qty, LookupPrice(sku));
        }
        if (!order.TryPay(_gateway))
        {
            throw new InvalidOperationException("payment failed");
        }
        _repository.Save(order);
        _placed?.Invoke(this, new OrderEventArgs(order));
        await Task.Yield();
        return order;
    }

    private static decimal LookupPrice(string sku)
    {
        return Max(1m, sku.Length);
    }

    public string Export(Order order)
    {
        return Json.Serialize(order);
    }

    public T[] Convert<T>(IEnumerable<object> source) where T : class
    {
        return source.OfType<T>().ToArray();
    }
}

public partial class OrderService
{
    public void Report()
    {
        var anonymous = new { Count = 3, Label = "x" };
        Console.WriteLine(anonymous.Label);
        Action<string> log = message => Console.WriteLine(message);
        log("done");
        var typed = typeof(Order);
        var list = new List<Order> { new Order(), new() };
        Console.WriteLine(list.Count + typed.Name);
    }
}
