<?php

declare(strict_types=1);

namespace Shop\Orders;

use Shop\Contracts\Clock;
use Shop\Contracts\Repository as RepositoryContract;
use Shop\Support\{Money, Result as Outcome, Str};
use function Shop\Support\format_money;
use const Shop\Support\DEFAULT_CURRENCY;
use Psr\Log\LoggerInterface;
use Shop\Events\OrderPlaced;
use InvalidArgumentException;

require_once __DIR__ . '/../bootstrap.php';
require 'config/orders.php';
include_once("helpers.php");

const MAX_LINES = 50;
const DEFAULT_TAX = 0.2, REDUCED_TAX = 0.05;

define('ORDER_PREFIX', 'ORD-');

$registry = [];
$started = microtime(true);

#[\Attribute(\Attribute::TARGET_CLASS | \Attribute::TARGET_METHOD)]
final class Audited
{
    public function __construct(public readonly string $channel = 'orders')
    {
    }
}

interface Identifiable
{
    public const PREFIX = 'id';

    public function id(): string;
}

interface Describable extends Identifiable, \Stringable
{
    public function describe(?string $locale = null): string;
}

trait Timestamps
{
    protected ?\DateTimeImmutable $createdAt = null;
    private int $touches = 0;

    public function touch(Clock $clock): static
    {
        $this->createdAt ??= $clock->now();
        $this->touches++;

        return $this;
    }

    protected function age(Clock $clock): int
    {
        return $clock->now()->getTimestamp() - $this->createdAt->getTimestamp();
    }

    abstract public function label(): string;
}

trait Loggable
{
    private ?LoggerInterface $logger = null;

    public function setLogger(LoggerInterface $logger): void
    {
        $this->logger = $logger;
    }

    protected function log(string $message, array $context = []): void
    {
        $this->logger?->info($message, $context);
    }
}

enum Status: string implements Describable
{
    case Draft = 'draft';
    case Placed = 'placed';
    case Shipped = 'shipped';
    case Cancelled = 'cancelled';

    public const DEFAULT = self::Draft;

    public function id(): string
    {
        return self::PREFIX . '.' . $this->value;
    }

    public function describe(?string $locale = null): string
    {
        return ucfirst($this->value);
    }

    public function __toString(): string
    {
        return $this->describe();
    }

    public static function fromLabel(string $label): self
    {
        foreach (self::cases() as $case) {
            if ($case->describe() === $label) {
                return $case;
            }
        }

        throw new InvalidArgumentException("unknown status $label");
    }

    public function isFinal(): bool
    {
        return $this === self::Shipped || $this === self::Cancelled;
    }
}

abstract class Entity implements Identifiable
{
    use Timestamps;

    protected static int $instances = 0;
    private array $changes = [];

    public function __construct(protected string $id)
    {
        static::$instances++;
    }

    public function id(): string
    {
        return $this->id;
    }

    final protected function record(string $field, mixed $value): void
    {
        $this->changes[$field] = $value;
    }

    public function changes(): array
    {
        return $this->changes;
    }

    abstract protected function validate(): void;

    public static function instances(): int
    {
        return self::$instances;
    }
}

class OrderLine
{
    public function __construct(
        public readonly string $sku,
        public readonly int $quantity,
        public readonly Money $unitPrice,
    ) {
        if ($quantity < 1) {
            throw new InvalidArgumentException('quantity must be positive');
        }
    }

    public function total(): Money
    {
        return $this->unitPrice->times($this->quantity);
    }
}

#[Audited(channel: 'orders')]
class Order extends Entity implements Describable
{
    use Loggable, Timestamps {
        Loggable::log insteadof Timestamps;
    }

    public const STATUS_FIELD = 'status';
    protected const TAX_RATE = DEFAULT_TAX;
    private const LIMIT = MAX_LINES;

    /** @var OrderLine[] */
    private array $lines = [];
    protected Status $status = Status::Draft;
    public ?string $note = null;
    var $legacy;

    public function __construct(string $id, private readonly Clock $clock)
    {
        parent::__construct($id);
        $this->touch($clock);
    }

    public static function create(string $number, Clock $clock): static
    {
        $order = new static(ORDER_PREFIX . $number, $clock);
        $order->record(self::STATUS_FIELD, Status::Draft);

        return $order;
    }

    public function addLine(OrderLine $line): self
    {
        if (count($this->lines) >= self::LIMIT) {
            throw new InvalidArgumentException('too many lines');
        }

        $this->lines[] = $line;
        $this->log('line added', ['sku' => $line->sku]);

        return $this;
    }

    public function total(): Money
    {
        $sum = Money::zero(DEFAULT_CURRENCY);
        foreach ($this->lines as $line) {
            $sum = $sum->plus($line->total());
        }

        return $sum->times(1 + static::TAX_RATE);
    }

    public function place(): Outcome
    {
        try {
            $this->validate();
        } catch (InvalidArgumentException | \DomainException $error) {
            return Outcome::failure($error->getMessage());
        }

        $this->status = Status::Placed;
        $this->record(self::STATUS_FIELD, $this->status);

        return Outcome::success($this);
    }

    public function describe(?string $locale = null): string
    {
        return sprintf('%s (%s)', $this->id(), $this->status->describe($locale));
    }

    public function __toString(): string
    {
        return $this->describe();
    }

    public function label(): string
    {
        return Str::upper($this->id);
    }

    protected function validate(): void
    {
        if ($this->lines === []) {
            throw new InvalidArgumentException('an order needs lines');
        }
    }

    private function summary(): array
    {
        return array_map(fn (OrderLine $line) => $line->sku . 'x' . $line->quantity, $this->lines);
    }

    public function lines(): iterable
    {
        yield from $this->lines;
    }

    public function isEditable(): bool
    {
        return $this instanceof Order && !$this->status->isFinal();
    }
}

class OrderService
{
    private array $listeners = [];

    public function __construct(
        private RepositoryContract $repository,
        private Clock $clock,
        private ?LoggerInterface $logger = null,
    ) {
    }

    public function place(string $number, OrderLine ...$lines): Order
    {
        $order = Order::create($number, $this->clock);
        foreach ($lines as $line) {
            $order->addLine($line);
        }

        $result = $order->place();
        if (!$result->isOk()) {
            $this->logger?->warning('order rejected', ['number' => $number]);
            throw new \RuntimeException($result->error());
        }

        $this->repository->save($order);
        $this->dispatch(new OrderPlaced($order->id()));

        return $order;
    }

    public function find(string $id): ?Order
    {
        return $this->repository->find($id);
    }

    public function onPlaced(callable $listener): void
    {
        $this->listeners[] = $listener;
    }

    private function dispatch(object $event): void
    {
        foreach ($this->listeners as $listener) {
            $listener($event);
        }
    }

    public function report(Order $order): string
    {
        $anonymous = new class($order) implements \Countable {
            public function __construct(private Order $order)
            {
            }

            public function count(): int
            {
                return count($this->order->changes());
            }
        };

        return format_money($order->total()) . ' / ' . $anonymous->count();
    }
}

function build_service(RepositoryContract $repository, Clock $clock): OrderService
{
    return new OrderService($repository, $clock);
}

if (!function_exists('Shop\Orders\order_total')) {
    function order_total(Order $order): Money
    {
        return $order->total();
    }
}

namespace Shop\Orders\Reports;

use Shop\Orders\Order;

function summarize(Order ...$orders): array
{
    return array_map(static fn (Order $order): string => $order->describe(), $orders);
}
