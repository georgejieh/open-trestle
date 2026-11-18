package com.example.inventory.service;

import java.io.IOException;
import java.io.UncheckedIOException;
import java.lang.annotation.ElementType;
import java.lang.annotation.Retention;
import java.lang.annotation.RetentionPolicy;
import java.lang.annotation.Target;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Duration;
import java.time.Instant;
import java.util.*;
import java.util.concurrent.ConcurrentHashMap;
import java.util.function.Function;
import java.util.function.Predicate;
import java.util.stream.Collectors;
import java.util.stream.Stream;

import static java.util.Objects.requireNonNull;
import static java.util.stream.Collectors.groupingBy;
import static java.util.stream.Collectors.summingInt;

/**
 * Coordinates stock levels and reservations across a set of warehouses.
 */
@Audited(category = "inventory", level = 2)
public class InventoryService<K extends Comparable<K>, V extends InventoryService.Item<K>>
        extends BaseService implements AutoCloseable, Auditable {

    public static final int DEFAULT_RESERVATION_MINUTES = 15;
    public static final String SERVICE_NAME = "inventory-service";
    private static final int MAX_BATCH = 500;

    private final Map<K, V> catalog = new ConcurrentHashMap<>();
    private final Map<String, Warehouse> warehouses = new HashMap<>();
    private final List<Reservation> reservations = new ArrayList<>();
    @Deprecated
    private volatile int legacyCounter;
    private final Duration holdTime;

    public InventoryService() {
        this(Duration.ofMinutes(DEFAULT_RESERVATION_MINUTES));
    }

    public InventoryService(Duration holdTime) {
        super(SERVICE_NAME);
        this.holdTime = requireNonNull(holdTime, "holdTime");
    }

    /** Anything that can be stocked and identified by a key. */
    public interface Item<T> {
        T id();

        String label();

        default String describe() {
            return label() + " (" + id() + ")";
        }

        static <T> Item<T> of(T id, String label) {
            return new Item<>() {
                @Override
                public T id() {
                    return id;
                }

                @Override
                public String label() {
                    return label;
                }
            };
        }
    }

    /** Result of an operation on a reservation request. */
    public sealed interface Outcome permits Accepted, Rejected, Deferred {
        String summary();
    }

    public record Accepted(String reservationId, int quantity) implements Outcome {
        public Accepted {
            if (quantity <= 0) {
                throw new IllegalArgumentException("quantity must be positive");
            }
            reservationId = reservationId.trim();
        }

        @Override
        public String summary() {
            return "accepted " + quantity + " as " + reservationId;
        }
    }

    public record Rejected(String reason) implements Outcome {
        @Override
        public String summary() {
            return "rejected: " + reason;
        }
    }

    public record Deferred(Instant retryAt, int shortfall) implements Outcome {
        @Override
        public String summary() {
            return "deferred by " + shortfall + " units until " + retryAt;
        }
    }

    public enum StockState {
        EMPTY("none", 0) {
            @Override
            public boolean canShip() {
                return false;
            }
        },
        LOW("low", 10),
        NORMAL("normal", 100) {
            @Override
            public String display() {
                return "ok";
            }
        },
        OVERSTOCKED("high", Integer.MAX_VALUE);

        private final String code;
        private final int ceiling;

        StockState(String code, int ceiling) {
            this.code = code;
            this.ceiling = ceiling;
        }

        public boolean canShip() {
            return true;
        }

        public String display() {
            return code;
        }

        public static StockState forLevel(int level) {
            for (StockState s : values()) {
                if (level <= s.ceiling) {
                    return s;
                }
            }
            return OVERSTOCKED;
        }
    }

    public static class Warehouse {
        private final String code;
        private final Map<String, Integer> levels = new TreeMap<>();

        public Warehouse(String code) {
            this.code = code;
        }

        public String code() {
            return code;
        }

        public int level(String sku) {
            return levels.getOrDefault(sku, 0);
        }

        public void adjust(String sku, int delta) {
            levels.merge(sku, delta, Integer::sum);
        }

        public Set<String> skus() {
            return Collections.unmodifiableSet(levels.keySet());
        }
    }

    public class Reservation {
        private final String id;
        private final String sku;
        private final int quantity;
        private final Instant expiresAt;

        Reservation(String id, String sku, int quantity) {
            this.id = id;
            this.sku = sku;
            this.quantity = quantity;
            this.expiresAt = Instant.now().plus(holdTime);
        }

        public boolean isExpired() {
            return Instant.now().isAfter(expiresAt);
        }

        public String sku() {
            return sku;
        }

        public int quantity() {
            return quantity;
        }
    }

    public static class StockException extends Exception {
        private final String sku;

        public StockException(String message, String sku) {
            super(message);
            this.sku = sku;
        }

        public StockException(String message, String sku, Throwable cause) {
            super(message, cause);
            this.sku = sku;
        }

        public String sku() {
            return sku;
        }
    }

    public void register(V item) {
        catalog.put(item.id(), item);
    }

    public void addWarehouse(Warehouse warehouse) {
        warehouses.put(warehouse.code(), warehouse);
    }

    public int totalStock(String sku) {
        return warehouses.values().stream()
                .mapToInt(w -> w.level(sku))
                .sum();
    }

    public int totalStock(String sku, String... warehouseCodes) {
        Set<String> wanted = new HashSet<>(Arrays.asList(warehouseCodes));
        return warehouses.values().stream()
                .filter(w -> wanted.contains(w.code()))
                .mapToInt(w -> w.level(sku))
                .sum();
    }

    public int totalStock(Predicate<Warehouse> filter) {
        return warehouses.values().stream()
                .filter(filter)
                .flatMap(w -> w.skus().stream().map(w::level))
                .reduce(0, Integer::sum);
    }

    public Map<String, Integer> stockBySku() {
        return warehouses.values().stream()
                .flatMap(w -> w.skus().stream()
                        .map(s -> Map.entry(s, w.level(s))))
                .collect(groupingBy(Map.Entry::getKey, summingInt(Map.Entry::getValue)));
    }

    public Outcome reserve(@NonEmpty String sku, int quantity) {
        if (quantity <= 0) {
            return new Rejected("invalid quantity " + quantity);
        }
        int available = totalStock(sku) - reservedFor(sku);
        if (available >= quantity) {
            String id = "R-" + (++legacyCounter) + "-" + sku;
            reservations.add(new Reservation(id, sku, quantity));
            return new Accepted(id, quantity);
        }
        if (available > 0) {
            return new Deferred(Instant.now().plusSeconds(3600), quantity - available);
        }
        return new Rejected("no stock for " + sku);
    }

    private int reservedFor(String sku) {
        return reservations.stream()
                .filter(r -> !r.isExpired())
                .filter(r -> r.sku().equals(sku))
                .mapToInt(Reservation::quantity)
                .sum();
    }

    public String report(Outcome outcome) {
        return switch (outcome) {
            case Accepted a when a.quantity() > 100 -> "bulk " + a.summary();
            case Accepted a -> a.summary();
            case Rejected r -> r.summary().toUpperCase();
            case Deferred d -> d.summary();
        };
    }

    public void transfer(String sku, String from, String to, int quantity)
            throws StockException {
        Warehouse source = warehouses.get(from);
        Warehouse target = warehouses.get(to);
        if (source == null || target == null) {
            throw new StockException("unknown warehouse", sku);
        }
        if (source.level(sku) < quantity) {
            throw new StockException("insufficient stock in " + from, sku);
        }
        source.adjust(sku, -quantity);
        target.adjust(sku, quantity);
    }

    public int importLevels(Path file, String warehouseCode) throws StockException {
        Warehouse w = warehouses.get(warehouseCode);
        int count = 0;
        try (var lines = Files.lines(file)) {
            for (String line : (Iterable<String>) lines::iterator) {
                String[] parts = line.split(",");
                w.adjust(parts[0].trim(), Integer.parseInt(parts[1].trim()));
                count++;
            }
        } catch (IOException | UncheckedIOException e) {
            throw new StockException("cannot read " + file, null, e);
        } catch (NumberFormatException | ArrayIndexOutOfBoundsException e) {
            throw new StockException("malformed row in " + file, null, e);
        }
        return count;
    }

    public List<String> lowStock(int threshold) {
        record Entry(String sku, int level) {
            boolean below(int limit) {
                return level < limit;
            }
        }
        return stockBySku().entrySet().stream()
                .map(e -> new Entry(e.getKey(), e.getValue()))
                .filter(e -> e.below(threshold))
                .sorted(Comparator.comparingInt(Entry::level).thenComparing(Entry::sku))
                .map(Entry::sku)
                .collect(Collectors.toList());
    }

    public Comparator<Reservation> byExpiry() {
        return new Comparator<Reservation>() {
            @Override
            public int compare(Reservation a, Reservation b) {
                return a.expiresAt.compareTo(b.expiresAt);
            }
        };
    }

    public <R> List<R> mapCatalog(Function<? super V, ? extends R> mapper) {
        List<R> out = new ArrayList<>();
        for (V item : catalog.values()) {
            out.add(mapper.apply(item));
        }
        return out;
    }

    public List<Warehouse> createAll(List<String> codes) {
        return codes.stream().map(Warehouse::new).collect(Collectors.toList());
    }

    public Stream<String> describeAll() {
        return catalog.values().stream().map(this::formatItem);
    }

    private String formatItem(V item) {
        return item.describe() + " stock=" + totalStock(String.valueOf(item.id()));
    }

    @Override
    public String auditName() {
        return SERVICE_NAME + "/" + catalog.size();
    }

    @Override
    public void close() {
        reservations.clear();
        warehouses.clear();
    }
}

@Retention(RetentionPolicy.RUNTIME)
@Target({ElementType.TYPE, ElementType.METHOD})
@interface Audited {
    String category() default "general";

    int level() default 1;
}

@Retention(RetentionPolicy.RUNTIME)
@Target(ElementType.PARAMETER)
@interface NonEmpty {
}

interface Auditable {
    String auditName();
}

abstract class BaseService {
    protected final String name;

    protected BaseService(String name) {
        this.name = name;
    }
}
