//! gzip decompression of layer blobs with zlib-ng's inflater, as a `std.Io.Reader`: it replaced
//! `std.compress.flate` on the layer path because it inflates 3 times faster (docs/BENCHMARKS.md,
//! "gzip layers: zlib-ng against std"). std's decoder stays as the oracle: the tests and "fuzz:
//! zlib-ng" hold this one to it, byte for byte.
//!
//! zlib-ng 2.3.3 is vendored in `src/vendor/zlib-ng` (`.github/scripts/vendor-zlib-ng.sh`) and
//! compiled without a libc, as the runner links none: its allocations come from `c_alloc.zig`
//! (through `src/vendor/shim/stdlib.h`). Only the inflater is built, with the SIMD each
//! architecture's baseline has (SSE2, NEON) and no runtime CPU detection.
//!
//! Like std's decoder it reads the first gzip member and ignores what follows it, and checks the
//! member's CRC-32 and length.

const std = @import("std");

const Allocator = std.mem.Allocator;
const Reader = std.Io.Reader;

/// zlib-ng's `zng_stream` (zlib-ng.h): the C struct, field for field.
const Stream = extern struct {
    next_in: ?[*]const u8 = null,
    avail_in: u32 = 0,
    total_in: usize = 0,
    next_out: ?[*]u8 = null,
    avail_out: u32 = 0,
    total_out: usize = 0,
    msg: ?[*:0]const u8 = null,
    state: ?*anyopaque = null,
    zalloc: ?*anyopaque = null,
    zfree: ?*anyopaque = null,
    opaque_: ?*anyopaque = null,
    data_type: c_int = 0,
    adler: u32 = 0,
    reserved: c_ulong = 0,
};

extern fn zng_inflateInit2(strm: *Stream, window_bits: i32) i32;
extern fn zng_inflate(strm: *Stream, flush: i32) i32;
extern fn zng_inflateEnd(strm: *Stream) i32;

const z_ok = 0;
const z_stream_end = 1;
const z_buf_error = -5;

/// `windowBits` of 15 for the largest window, plus 16 for a gzip header and trailer, and nothing
/// else (a zlib stream or raw deflate is refused).
const gzip_window_bits = 15 + 16;

/// One block of output, as libzstd's: the input is the reader's own buffer and the output goes to
/// the writer through this.
const out_bytes = 128 * 1024;
const reader_bytes = 64 * 1024;

pub const Decompress = struct {
    gpa: Allocator,
    in: *Reader,
    reader: Reader,
    /// Why `reader` failed, when it failed on the stream and not on `in`: zlib-ng's words.
    err: ?[:0]const u8 = null,

    // On the heap, not in this struct: zlib-ng keeps the pointer it is given.
    stream_state: *Stream,
    out: []u8,
    /// Whether the member's end has been reached.
    done: bool = false,

    pub fn create(gpa: Allocator, in: *Reader) Allocator.Error!*Decompress {
        const d = try gpa.create(Decompress);
        errdefer gpa.destroy(d);
        const stream_state = try gpa.create(Stream);
        errdefer gpa.destroy(stream_state);
        stream_state.* = .{};
        switch (zng_inflateInit2(stream_state, gzip_window_bits)) {
            z_ok => {},
            // Nothing else: the arguments are fixed and valid.
            else => return error.OutOfMemory,
        }
        errdefer _ = zng_inflateEnd(stream_state);
        const out = try gpa.alloc(u8, out_bytes);
        errdefer gpa.free(out);
        // The reader's own buffer: what wraps a reader (a hashing one) peeks into it.
        const buffer = try gpa.alloc(u8, reader_bytes);
        errdefer gpa.free(buffer);
        d.* = .{
            .gpa = gpa,
            .in = in,
            .reader = .{ .vtable = &.{ .stream = stream }, .buffer = buffer, .seek = 0, .end = 0 },
            .stream_state = stream_state,
            .out = out,
        };
        return d;
    }

    pub fn destroy(d: *Decompress) void {
        const gpa = d.gpa;
        _ = zng_inflateEnd(d.stream_state);
        gpa.destroy(d.stream_state);
        gpa.free(d.out);
        gpa.free(d.reader.buffer);
        gpa.destroy(d);
    }

    fn stream(r: *Reader, w: *std.Io.Writer, limit: std.Io.Limit) Reader.StreamError!usize {
        const d: *Decompress = @alignCast(@fieldParentPtr("reader", r));
        if (d.err != null) return error.ReadFailed;
        if (d.done) return error.EndOfStream;
        const room = limit.slice(d.out);
        const s = d.stream_state;
        while (true) {
            var at_end = false;
            const chunk: []const u8 = d.in.peekGreedy(1) catch |e| switch (e) {
                error.EndOfStream => blk: {
                    at_end = true;
                    break :blk &.{};
                },
                error.ReadFailed => return error.ReadFailed,
            };
            const given: u32 = @truncate(@min(chunk.len, std.math.maxInt(u32)));
            s.next_in = chunk.ptr;
            s.avail_in = given;
            s.next_out = room.ptr;
            s.avail_out = @truncate(room.len);
            const code = zng_inflate(s, 0);
            const consumed = given - s.avail_in;
            const produced = room.len - s.avail_out;
            d.in.toss(consumed);
            switch (code) {
                z_ok, z_buf_error => {},
                z_stream_end => d.done = true,
                else => {
                    d.err = if (s.msg) |m| std.mem.span(m) else "inflate failed";
                    return error.ReadFailed;
                },
            }
            if (produced != 0) {
                try w.writeAll(room[0..produced]);
                return produced;
            }
            if (d.done) return error.EndOfStream;
            // No progress: the stream ended in the middle of the member, or zlib-ng stalled.
            if (consumed == 0) {
                d.err = if (at_end) "Truncated stream" else "inflate made no progress";
                return error.ReadFailed;
            }
        }
    }
};

const testing = std.testing;
const layer = @import("layer.zig");

/// What std's inflater makes of `bytes`: the oracle's output, or null when it fails.
fn oracle(gpa: Allocator, bytes: []const u8) !?[]u8 {
    var in: Reader = .fixed(bytes);
    const window = try gpa.alloc(u8, std.compress.flate.max_window_len);
    defer gpa.free(window);
    var d: std.compress.flate.Decompress = .init(&in, .gzip, window);
    var out: std.Io.Writer.Allocating = .init(gpa);
    errdefer out.deinit();
    _ = d.reader.streamRemaining(&out.writer) catch |e| switch (e) {
        error.ReadFailed => {
            out.deinit();
            return null;
        },
        error.WriteFailed => return error.OutOfMemory,
    };
    return try out.toOwnedSlice();
}

/// This decoder's output for `bytes`, or null when it fails.
fn decode(gpa: Allocator, in: *Reader) !?[]u8 {
    const d = try Decompress.create(gpa, in);
    defer d.destroy();
    var out: std.Io.Writer.Allocating = .init(gpa);
    errdefer out.deinit();
    _ = d.reader.streamRemaining(&out.writer) catch |e| switch (e) {
        error.ReadFailed => {
            out.deinit();
            return null;
        },
        error.WriteFailed => return error.OutOfMemory,
    };
    return try out.toOwnedSlice();
}

/// A reader that hands out at most `step` bytes of `bytes` at a time, so the decoder meets input
/// that ends in the middle of every part of a stream.
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

test "zlib-ng: the layer fixture inflates as std inflates it, whatever the input's pieces" {
    const want = (try oracle(testing.allocator, &layer.test_gzip)).?;
    defer testing.allocator.free(want);
    try testing.expect(want.len > 0);
    for ([_]usize{ 1, 2, 3, 7, 64, 1 << 20 }) |step| {
        var buffer: [16]u8 = undefined;
        var t: Trickle = .init(&layer.test_gzip, step, &buffer);
        const got = (try decode(testing.allocator, &t.reader)).?;
        defer testing.allocator.free(got);
        try testing.expectEqualSlices(u8, want, got);
    }
}

test "zlib-ng: a member ends where it should, and nowhere else" {
    const frame = &layer.test_gzip;

    // Nothing at all is not a gzip stream: std refuses it too.
    var empty: Reader = .fixed("");
    try testing.expect(try decode(testing.allocator, &empty) == null);
    try testing.expect(try oracle(testing.allocator, "") == null);

    // What follows the first member is ignored, as std ignores it.
    const joined = try std.mem.concat(testing.allocator, u8, &.{ frame, frame, "junk" });
    defer testing.allocator.free(joined);
    const want = (try oracle(testing.allocator, frame)).?;
    defer testing.allocator.free(want);
    var in: Reader = .fixed(joined);
    const got = (try decode(testing.allocator, &in)).?;
    defer testing.allocator.free(got);
    try testing.expectEqualSlices(u8, want, got);

    // A stream cut anywhere fails, and so does one with a bad checksum or no gzip header.
    for ([_]usize{ 1, 4, 10, frame.len / 2, frame.len - 8, frame.len - 1 }) |cut| {
        var short: Reader = .fixed(frame[0..cut]);
        try testing.expect(try decode(testing.allocator, &short) == null);
    }
    var bad = frame.*;
    bad[bad.len - 8] ^= 1; // a bit of the CRC-32
    var bad_in: Reader = .fixed(&bad);
    try testing.expect(try decode(testing.allocator, &bad_in) == null);
    var not_gzip: Reader = .fixed("\x78\x9c\x03\x00\x00\x00\x00\x01"); // a zlib stream
    try testing.expect(try decode(testing.allocator, &not_gzip) == null);
}
