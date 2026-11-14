//! The network library (`rust/zr-net`, docs/rust-net.md) behind its C ABI. R1: the version and the
//! runtime's lifetime; the HTTP, WebSocket and TLS calls arrive with R2 to R6.
const std = @import("std");

extern fn zr_net_version() [*:0]const u8;
extern fn zr_net_runtime_start(threads: u32) i32;
extern fn zr_net_selftest(n: u32) i64;
extern fn zr_net_runtime_stop() void;
extern fn zr_net_heap_bytes() usize;
extern fn zr_net_heap_peak() usize;
extern fn zr_net_heap_allocations() u64;

/// What Rust holds of the process's memory (`proc_stats.heap` counts Zig's allocator only): bytes
/// in use now, the most there were, and the allocations made.
pub const Heap = struct { bytes: usize, peak: usize, allocations: u64 };

pub fn heap() Heap {
    return .{ .bytes = zr_net_heap_bytes(), .peak = zr_net_heap_peak(), .allocations = zr_net_heap_allocations() };
}

/// The library's version, as `Cargo.toml` names it.
pub fn version() []const u8 {
    return std.mem.span(zr_net_version());
}

pub const Error = error{ RuntimeStart, RuntimeStopped };

/// Starts the runtime if it is not running (idempotent); `threads` 0 is the default.
pub fn start(threads: u32) Error!void {
    if (zr_net_runtime_start(threads) < 0) return error.RuntimeStart;
}

/// A task's round trip through the runtime's workers: `n + 1`.
pub fn selftest(n: u32) Error!i64 {
    const r = zr_net_selftest(n);
    if (r < 0) return error.RuntimeStopped;
    return r;
}

pub fn stop() void {
    zr_net_runtime_stop();
}

/// The version `Cargo.toml` names, which the archive linked in must have: a stale archive is a build
/// mistake that should stop the runner, not misbehave. Read by `main`.
pub const expected_version = "0.2.0";

test "the runtime starts, runs a task through the ABI and stops" {
    try std.testing.expectEqualStrings(expected_version, version());
    // Another test of this process may have started it (the first network call does).
    stop();
    try std.testing.expectError(error.RuntimeStopped, selftest(1));
    try start(2);
    try start(2);
    try std.testing.expectEqual(@as(i64, 42), try selftest(41));
    stop();
    stop();
    try std.testing.expectError(error.RuntimeStopped, selftest(1));
    // Again: a stopped runtime starts anew.
    try start(0);
    try std.testing.expectEqual(@as(i64, 1), try selftest(0));
    stop();
}
