//! Zstandard decompression of layer blobs with libzstd, as a `std.Io.Reader`: the same interface as
//! `zstd.zig`'s own decoder, which it replaced on the layer path because libzstd decodes 3.5 times
//! faster (docs/BENCHMARKS.md, "Decompression and hashing in C and Rust"). The Zig decoder stays
//! as the oracle: the tests and "fuzz: libzstd" hold this one to it, byte for byte.
//!
//! libzstd 1.5.7 is vendored in `src/vendor/zstd` (`.github/scripts/vendor-zstd.sh`) and compiled
//! without a libc, as the runner links none: its allocations come from `c_alloc.zig` (through
//! `src/vendor/shim/stdlib.h`) and `memcpy` and its kin from the compiler's runtime. Only the
//! decompressor is built.
//!
//! As the Zig decoder does, it skips the frame's checksum (the blob's digest is checked by whoever
//! fetched it and the layer's diff id by whoever unpacks it), refuses dictionaries (a frame that
//! names one fails: none is loaded) and refuses a window over `max_window`, libzstd's default
//! limit.

const std = @import("std");

const Allocator = std.mem.Allocator;
const Reader = std.Io.Reader;

/// The largest window a frame may declare: libzstd's default limit, 2^27, as `zstd.zig`'s.
pub const max_window_log = 27;

const Buffer = extern struct { ptr: ?*anyopaque, size: usize, pos: usize };

const Context = opaque {};

extern fn ZSTD_createDCtx() ?*Context;
extern fn ZSTD_freeDCtx(ctx: ?*Context) usize;
extern fn ZSTD_DCtx_setParameter(ctx: *Context, param: c_int, value: c_int) usize;
extern fn ZSTD_decompressStream(ctx: *Context, out: *Buffer, in: *Buffer) usize;
extern fn ZSTD_isError(code: usize) c_uint;
extern fn ZSTD_getErrorName(code: usize) [*:0]const u8;

/// `ZSTD_d_windowLogMax` and `ZSTD_d_forceIgnoreChecksum` (an experimental parameter, 1002).
const window_log_max = 100;
const force_ignore_checksum = 1002;

/// libzstd's recommended output size, `ZSTD_DStreamOutSize()`: one block.
const out_bytes = 128 * 1024;
const reader_bytes = 64 * 1024;

/// Both parameters the decoder sets exist in the vendored version and take the values given, so
/// libzstd cannot refuse them.
fn setParameter(ctx: *Context, param: c_int, value: c_int) void {
    const code = ZSTD_DCtx_setParameter(ctx, param, value);
    std.debug.assert(ZSTD_isError(code) == 0);
}

pub const Decompress = struct {
    gpa: Allocator,
    in: *Reader,
    reader: Reader,
    /// Why `reader` failed, when it failed on the stream and not on `in`: libzstd's words.
    err: ?[:0]const u8 = null,

    ctx: *Context,
    /// Decoded bytes on their way to the writer.
    out: []u8,
    /// Whether the stream is between frames: its end is allowed there and nowhere else.
    between_frames: bool = true,

    pub fn create(gpa: Allocator, in: *Reader) Allocator.Error!*Decompress {
        const d = try gpa.create(Decompress);
        errdefer gpa.destroy(d);
        const ctx = ZSTD_createDCtx() orelse return error.OutOfMemory;
        errdefer _ = ZSTD_freeDCtx(ctx);
        setParameter(ctx, window_log_max, max_window_log);
        setParameter(ctx, force_ignore_checksum, 1);
        const out = try gpa.alloc(u8, out_bytes);
        errdefer gpa.free(out);
        // The reader's own buffer: what wraps a reader (a hashing one) peeks into it.
        const buffer = try gpa.alloc(u8, reader_bytes);
        errdefer gpa.free(buffer);
        d.* = .{
            .gpa = gpa,
            .in = in,
            .reader = .{ .vtable = &.{ .stream = stream }, .buffer = buffer, .seek = 0, .end = 0 },
            .ctx = ctx,
            .out = out,
        };
        return d;
    }

    /// Refuses frames whose window is over 2^`log` bytes (at most `max_window_log`).
    pub fn limitWindow(d: *Decompress, log: u5) void {
        std.debug.assert(log <= max_window_log);
        setParameter(d.ctx, window_log_max, log);
    }

    pub fn destroy(d: *Decompress) void {
        const gpa = d.gpa;
        _ = ZSTD_freeDCtx(d.ctx);
        gpa.free(d.out);
        gpa.free(d.reader.buffer);
        gpa.destroy(d);
    }

    fn stream(r: *Reader, w: *std.Io.Writer, limit: std.Io.Limit) Reader.StreamError!usize {
        const d: *Decompress = @alignCast(@fieldParentPtr("reader", r));
        if (d.err != null) return error.ReadFailed;
        const room = limit.slice(d.out);
        while (true) {
            var at_end = false;
            const chunk: []const u8 = d.in.peekGreedy(1) catch |e| switch (e) {
                error.EndOfStream => blk: {
                    at_end = true;
                    break :blk &.{};
                },
                error.ReadFailed => return error.ReadFailed,
            };
            var in: Buffer = .{ .ptr = @constCast(chunk.ptr), .size = chunk.len, .pos = 0 };
            var out: Buffer = .{ .ptr = room.ptr, .size = room.len, .pos = 0 };
            const code = ZSTD_decompressStream(d.ctx, &out, &in);
            if (ZSTD_isError(code) != 0) {
                d.err = std.mem.span(ZSTD_getErrorName(code));
                return error.ReadFailed;
            }
            d.in.toss(in.pos);
            // Zero: a frame is complete and everything of it is out. (Asked with nothing to read,
            // libzstd answers with how much a header needs, which says nothing of the last frame.)
            if (in.pos != 0 or out.pos != 0) d.between_frames = code == 0;
            if (out.pos != 0) {
                try w.writeAll(room[0..out.pos]);
                return out.pos;
            }
            if (in.pos == 0 and at_end) {
                if (d.between_frames) return error.EndOfStream;
                d.err = "Truncated stream";
                return error.ReadFailed;
            }
        }
    }
};

const testing = std.testing;
const layer = @import("layer.zig");
const zstd = @import("zstd.zig");

/// A reader that hands out at most `step` bytes of `bytes` at a time, so the decoder meets input
/// that ends in the middle of every part of a frame.
const Trickle = struct {
    bytes: []const u8,
    step: usize,
    reader: Reader,

    fn init(bytes: []const u8, step: usize, buffer: []u8) Trickle {
        return .{
            .bytes = bytes,
            .step = step,
            .reader = .{ .vtable = &.{ .stream = trickle }, .buffer = buffer, .seek = 0, .end = 0 },
        };
    }

    fn trickle(r: *Reader, w: *std.Io.Writer, limit: std.Io.Limit) Reader.StreamError!usize {
        const t: *Trickle = @alignCast(@fieldParentPtr("reader", r));
        if (t.bytes.len == 0) return error.EndOfStream;
        const n = @min(t.step, t.bytes.len, @backingInt(limit));
        try w.writeAll(t.bytes[0..n]);
        t.bytes = t.bytes[n..];
        return n;
    }
};

fn decodeAll(gpa: Allocator, in: *Reader, out: *std.Io.Writer.Allocating) !?[:0]const u8 {
    const d = try Decompress.create(gpa, in);
    defer d.destroy();
    _ = d.reader.streamRemaining(&out.writer) catch |e| switch (e) {
        error.ReadFailed => return d.err orelse return error.ReadFailed,
        error.WriteFailed => return error.OutOfMemory,
    };
    return null;
}

/// The Zig decoder's output for `bytes`, the oracle's.
fn oracle(gpa: Allocator, bytes: []const u8) ![]u8 {
    var in: Reader = .fixed(bytes);
    const d = try zstd.Decompress.create(gpa, &in);
    defer d.destroy();
    var out: std.Io.Writer.Allocating = .init(gpa);
    errdefer out.deinit();
    _ = try d.reader.streamRemaining(&out.writer);
    return out.toOwnedSlice();
}

test "libzstd: the layer fixture decodes as the Zig decoder decodes it, whatever the input's pieces" {
    const want = try oracle(testing.allocator, &layer.test_zstd);
    defer testing.allocator.free(want);
    try testing.expect(want.len > 0);
    for ([_]usize{ 1, 2, 3, 7, 64, 1 << 20 }) |step| {
        var buffer: [16]u8 = undefined;
        var t: Trickle = .init(&layer.test_zstd, step, &buffer);
        var out: std.Io.Writer.Allocating = .init(testing.allocator);
        defer out.deinit();
        try testing.expectEqual(null, try decodeAll(testing.allocator, &t.reader, &out));
        try testing.expectEqualSlices(u8, want, out.written());
    }
}

test "libzstd: frames end where they should, and nowhere else" {
    const frame = &layer.test_zstd;
    var out: std.Io.Writer.Allocating = .init(testing.allocator);
    defer out.deinit();

    // Nothing at all is no frames, and ends cleanly.
    var empty: Reader = .fixed("");
    try testing.expectEqual(null, try decodeAll(testing.allocator, &empty, &out));
    try testing.expectEqual(0, out.written().len);

    // Two frames, and a skippable one between them, are one stream.
    const skippable = "\x50\x2a\x4d\x18\x03\x00\x00\x00abc";
    const joined = try std.mem.concat(testing.allocator, u8, &.{ frame, skippable, frame });
    defer testing.allocator.free(joined);
    const want = try oracle(testing.allocator, joined);
    defer testing.allocator.free(want);
    var in: Reader = .fixed(joined);
    try testing.expectEqual(null, try decodeAll(testing.allocator, &in, &out));
    try testing.expectEqualSlices(u8, want, out.written());

    // A stream cut anywhere inside a frame fails, with a reason; so does one that goes on in a
    // way that is no frame.
    for ([_]usize{ 1, 4, 5, 9, frame.len / 2, frame.len - 1 }) |cut| {
        var short: Reader = .fixed(frame[0..cut]);
        var sink: std.Io.Writer.Allocating = .init(testing.allocator);
        defer sink.deinit();
        try testing.expect(try decodeAll(testing.allocator, &short, &sink) != null);
    }
    const trailing = try std.mem.concat(testing.allocator, u8, &.{ frame, "garbage" });
    defer testing.allocator.free(trailing);
    var junk: Reader = .fixed(trailing);
    var sink: std.Io.Writer.Allocating = .init(testing.allocator);
    defer sink.deinit();
    try testing.expect(try decodeAll(testing.allocator, &junk, &sink) != null);
}

test "libzstd: a window over the limit is refused" {
    // The layer fixture asks for a window of more than 1 KiB, so a limit of 2^10 refuses it before
    // any byte is out.
    var in: Reader = .fixed(&layer.test_zstd);
    const d = try Decompress.create(testing.allocator, &in);
    defer d.destroy();
    d.limitWindow(10);
    var buf: [64]u8 = undefined;
    try testing.expectError(error.ReadFailed, d.reader.readSliceShort(&buf));
    try testing.expect(d.err != null);
}
