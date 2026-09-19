import { act, fireEvent, render, screen } from "@testing-library/react";
import { afterEach, describe, expect, it, vi } from "vitest";
import { Identity } from "./Identity";

function deferred() {
  let resolve!: () => void;
  let reject!: (error: Error) => void;
  const promise = new Promise<void>((resolvePromise, rejectPromise) => {
    resolve = resolvePromise;
    reject = rejectPromise;
  });
  return { promise, resolve, reject };
}

const originalClipboard = navigator.clipboard;
afterEach(() => {
  vi.useRealTimers();
  Object.defineProperty(navigator, "clipboard", {
    configurable: true,
    value: originalClipboard,
  });
});

describe("Identity", () => {
  it("keeps the latest result when clipboard attempts settle out of order", async () => {
    const first = deferred();
    const second = deferred();
    const writeText = vi
      .fn()
      .mockReturnValueOnce(first.promise)
      .mockReturnValueOnce(second.promise);
    Object.defineProperty(navigator, "clipboard", {
      configurable: true,
      value: { writeText },
    });
    const value = "a".repeat(64);
    render(
      <dl>
        <Identity label="Plan identity" value={value} />
      </dl>,
    );
    const copy = screen.getByRole("button", {
      name: `Copy Plan identity: ${value}`,
    });
    fireEvent.click(copy);
    fireEvent.click(copy);
    await act(async () => second.reject(new Error("newest denied")));
    expect(screen.getByRole("status")).toHaveTextContent("Copy failed");
    await act(async () => first.resolve());
    expect(screen.getByRole("status")).toHaveTextContent("Copy failed");
    expect(writeText).toHaveBeenCalledTimes(2);
    expect(writeText).toHaveBeenNthCalledWith(1, value);
    expect(writeText).toHaveBeenNthCalledWith(2, value);
  });

  it("clears settled feedback when the value changes", async () => {
    vi.useFakeTimers();
    const writeText = vi.fn().mockResolvedValue(undefined);
    Object.defineProperty(navigator, "clipboard", {
      configurable: true,
      value: { writeText },
    });
    const firstValue = "d".repeat(64);
    const secondValue = "e".repeat(64);
    const view = render(
      <dl>
        <Identity label="Plan identity" value={firstValue} />
      </dl>,
    );
    await act(async () =>
      fireEvent.click(
        screen.getByRole("button", {
          name: `Copy Plan identity: ${firstValue}`,
        }),
      ),
    );
    expect(screen.getByRole("status")).toHaveTextContent("Copied");
    expect(vi.getTimerCount()).toBe(1);
    view.rerender(
      <dl>
        <Identity label="Plan identity" value={secondValue} />
      </dl>,
    );
    expect(screen.queryByRole("status")).not.toBeInTheDocument();
    expect(vi.getTimerCount()).toBe(0);
    view.rerender(
      <dl>
        <Identity label="Plan identity" value={firstValue} />
      </dl>,
    );
    expect(screen.queryByRole("status")).not.toBeInTheDocument();
    view.rerender(
      <dl>
        <Identity label="Plan identity" value={secondValue} />
      </dl>,
    );
    await act(async () =>
      fireEvent.click(
        screen.getByRole("button", {
          name: `Copy Plan identity: ${secondValue}`,
        }),
      ),
    );
    expect(writeText).toHaveBeenLastCalledWith(secondValue);
    expect(screen.getByRole("status")).toHaveTextContent("Copied");
    act(() => vi.advanceTimersByTime(1499));
    expect(screen.getByRole("status")).toHaveTextContent("Copied");
    act(() => vi.advanceTimersByTime(1));
    expect(screen.queryByRole("status")).not.toBeInTheDocument();
  });

  it("ignores a pending result after the value changes", async () => {
    vi.useFakeTimers();
    const pending = deferred();
    const writeText = vi.fn().mockReturnValue(pending.promise);
    Object.defineProperty(navigator, "clipboard", {
      configurable: true,
      value: { writeText },
    });
    const firstValue = "f".repeat(64);
    const secondValue = "1".repeat(64);
    const view = render(
      <dl>
        <Identity label="Plan identity" value={firstValue} />
      </dl>,
    );
    fireEvent.click(
      screen.getByRole("button", {
        name: `Copy Plan identity: ${firstValue}`,
      }),
    );
    view.rerender(
      <dl>
        <Identity label="Plan identity" value={secondValue} />
      </dl>,
    );
    await act(async () => pending.resolve());
    expect(screen.queryByRole("status")).not.toBeInTheDocument();
    expect(vi.getTimerCount()).toBe(0);
  });

  it("ignores a pending result after unmount", async () => {
    vi.useFakeTimers();
    const pending = deferred();
    const writeText = vi.fn().mockReturnValue(pending.promise);
    Object.defineProperty(navigator, "clipboard", {
      configurable: true,
      value: { writeText },
    });
    const value = "c".repeat(64);
    const view = render(
      <dl>
        <Identity label="Plan identity" value={value} />
      </dl>,
    );
    fireEvent.click(
      screen.getByRole("button", { name: `Copy Plan identity: ${value}` }),
    );
    view.unmount();
    await act(async () => pending.resolve());
    expect(vi.getTimerCount()).toBe(0);
  });

  it("keeps the latest feedback for its full lifetime", async () => {
    vi.useFakeTimers();
    const writeText = vi
      .fn()
      .mockResolvedValueOnce(undefined)
      .mockRejectedValueOnce(new Error("newest denied"));
    Object.defineProperty(navigator, "clipboard", {
      configurable: true,
      value: { writeText },
    });
    const value = "b".repeat(64);
    const view = render(
      <dl>
        <Identity label="Plan identity" value={value} />
      </dl>,
    );
    const copy = screen.getByRole("button", {
      name: `Copy Plan identity: ${value}`,
    });
    await act(async () => fireEvent.click(copy));
    expect(screen.getByRole("status")).toHaveTextContent("Copied");
    act(() => vi.advanceTimersByTime(1000));
    await act(async () => fireEvent.click(copy));
    expect(screen.getByRole("status")).toHaveTextContent("Copy failed");
    act(() => vi.advanceTimersByTime(500));
    expect(screen.getByRole("status")).toHaveTextContent("Copy failed");
    act(() => vi.advanceTimersByTime(999));
    expect(screen.getByRole("status")).toHaveTextContent("Copy failed");
    act(() => vi.advanceTimersByTime(1));
    expect(screen.queryByRole("status")).not.toBeInTheDocument();
    view.unmount();
    act(() => vi.runOnlyPendingTimers());
  });
});
