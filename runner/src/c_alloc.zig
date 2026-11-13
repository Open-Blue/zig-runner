//! The allocator the runner's C libraries (libzstd, zlib-ng: `src/vendor`) allocate from. They are
//! built without a libc, as the runner links none, and `src/vendor/shim/stdlib.h` points their
//! `malloc`, `calloc` and `free` here.
//!
//! The memory is `std.heap.smp_allocator`'s, with its size in front so `free` can give it back.
//! 16 bytes is the alignment `malloc` promises (libzstd asks for 64 of it where it needs more,
//! zlib-ng aligns what it needs itself).
const std = @import("std");

const header = 16;

export fn runner_malloc(n: usize) callconv(.c) ?[*]u8 {
    const total = std.math.add(usize, n, header) catch return null;
    const raw = std.heap.smp_allocator.rawAlloc(total, .@"16", @returnAddress()) orelse return null;
    std.mem.writeInt(usize, raw[0..@sizeOf(usize)], total, .little);
    return raw + header;
}

export fn runner_calloc(count: usize, size: usize) callconv(.c) ?[*]u8 {
    const n = std.math.mul(usize, count, size) catch return null;
    const p = runner_malloc(n) orelse return null;
    @memset(p[0..n], 0);
    return p;
}

export fn runner_free(ptr: ?[*]u8) callconv(.c) void {
    const p = ptr orelse return;
    const raw = p - header;
    const total = std.mem.readInt(usize, raw[0..@sizeOf(usize)], .little);
    std.heap.smp_allocator.rawFree(raw[0..total], .@"16", @returnAddress());
}

test "c_alloc: memory is 16-aligned, zeroed by calloc, and given back" {
    const a = runner_malloc(100) orelse return error.OutOfMemory;
    try std.testing.expectEqual(0, @intFromPtr(a) % 16);
    @memset(a[0..100], 0xAA);
    runner_free(a);
    const z = runner_calloc(10, 10) orelse return error.OutOfMemory;
    for (z[0..100]) |b| try std.testing.expectEqual(0, b);
    runner_free(z);
    runner_free(null);
    try std.testing.expect(runner_calloc(std.math.maxInt(usize), 2) == null);
    try std.testing.expect(runner_malloc(std.math.maxInt(usize)) == null);
}
