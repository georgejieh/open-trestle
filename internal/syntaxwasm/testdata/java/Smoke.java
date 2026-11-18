package com.example.app;

import java.util.List;
import java.util.*;
import static java.util.Objects.requireNonNull;

@Service
public class Outer<T> extends Base implements Runnable, Comparable<Outer<T>> {
    public static final int LIMIT = 10;
    private final List<String> names = new ArrayList<>();

    public Outer(String name) {
        super(name);
        this.names.add(requireNonNull(name));
    }

    @Override
    public void run() {
        helper(LIMIT);
        names.forEach(System.out::println);
    }

    interface Callback { void done(int code); }

    enum Mode { FAST, SLOW }
}
