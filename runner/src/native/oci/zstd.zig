//! Zstandard decompression (RFC 8878) for layer blobs, as a `std.Io.Reader`.
//!
//! `std.compress.zstd` decodes a Huffman literal one bit at a time, each step copying the whole
//! 1.5 KB tree: a 500 MB layer took 19 s, where libzstd takes 0.9 s, and a 1.2 GB image took
//! 57 s to unpack. This decoder reads literals through a lookup table of the tree's longest code
//! (one table read per byte) and does the rest as the format describes. It is the format's
//! reference algorithm, not a port of any one implementation; `std`'s decoder is the oracle in
//! the tests.
//!
//! The blob's digest is checked by whoever fetched it and the layer's diff id by whoever unpacks
//! it, so the frame's own checksum is skipped, not checked. Dictionaries are refused: an image
//! layer never needs one. A window over `max_window` is refused (libzstd's default limit).
//!
//! Every length, offset and count in the stream is checked before it is used: the archive is a
//! registry's, so a corrupt or hostile stream gets `error.ReadFailed` from the reader (the reason
//! in `Decompress.err`) and never an out-of-bounds access. It is as strict as libzstd where std's
//! decoder is not: a block over its window, a frame that is not the size its header says, an offset
//! past the window, a Huffman tree that is not complete, a literal stream not used up. "fuzz:
//! zstd" (`fuzz.zig`) holds it to std's decoder on every input, and says where they differ.

const std = @import("std");
const zstd = std.compress.zstd;

const Allocator = std.mem.Allocator;
const Reader = std.Io.Reader;

pub const max_window: u64 = 128 << 20;
const block_max = zstd.block_size_max;
const max_slack = 32 << 20;
const reader_bytes = 64 * 1024;

pub const Error = error{
    BadMagic,
    DictionaryUnsupported,
    WindowTooLarge,
    BlockTooLarge,
    ReservedBlockType,
    BadLiterals,
    BadLiteralStream,
    BadHuffmanTree,
    IncompleteHuffmanTree,
    BadFseTable,
    BadSequences,
    BadOffset,
    BadContentSize,
    TruncatedStream,
    ReservedBit,
    OutOfMemory,
};

const Entry = struct { base: u16 = 0, symbol: u8 = 0, bits: u8 = 0 };

/// One FSE decoding table, for a sequence field or the Huffman weights.
const Fse = struct {
    entries: [1 << 9]Entry = undefined,
    log: u8 = 0,
    valid: bool = false,

    /// `norm`'s counts (-1 for a probability below one) spread over a table of `1 << log`.
    fn build(t: *Fse, norm: []const i16, log: u8) Error!void {
        if (log > 9) return error.BadFseTable;
        const size: usize = @as(usize, 1) << @intCast(log);
        var next: [256]u16 = undefined;
        var high = size - 1;
        for (norm, 0..) |n, s| {
            if (n == -1) {
                t.entries[high].symbol = @intCast(s);
                high -%= 1;
                next[s] = 1;
            } else next[s] = @intCast(n);
        }
        const step = (size >> 1) + (size >> 3) + 3;
        var position: usize = 0;
        for (norm, 0..) |n, s| {
            var i: i16 = 0;
            while (i < n) : (i += 1) {
                t.entries[position].symbol = @intCast(s);
                position = (position + step) & (size - 1);
                while (position > high) position = (position + step) & (size - 1);
            }
        }
        if (position != 0) return error.BadFseTable;
        for (t.entries[0..size]) |*e| {
            const n = next[e.symbol];
            next[e.symbol] = n + 1;
            const bits: u8 = log - std.math.log2_int(u16, n);
            e.bits = bits;
            e.base = (n << @intCast(bits)) -% @as(u16, @intCast(size));
        }
        t.log = log;
        t.valid = true;
    }

    /// A table that always gives `symbol` and reads no bits.
    fn single(t: *Fse, symbol: u8) void {
        t.entries[0] = .{ .base = 0, .symbol = symbol, .bits = 0 };
        t.log = 0;
        t.valid = true;
    }

    /// The table `bytes` starts with (the normalized counts, packed), and how many bytes it took.
    fn read(t: *Fse, bytes: []const u8, max_symbols: usize, max_log: u8) Error!usize {
        var bits: Forward = .{ .bytes = bytes };
        const log: u8 = @as(u8, @truncate(bits.take(4))) + 5; // 4 bits: 0 to 15
        if (log > max_log) return error.BadFseTable;
        var norm: [256]i16 = undefined;
        var remaining: i32 = (@as(i32, 1) << @intCast(log)) + 1;
        var threshold: i32 = @as(i32, 1) << @intCast(log);
        var width: u6 = @intCast(log + 1);
        var symbol: usize = 0;
        var previous_zero = false;
        while (remaining > 1 and symbol < max_symbols) {
            if (previous_zero) {
                // A run of zero counts: two bits for 0 to 2 more, 3 meaning "and read again".
                while (true) {
                    const r = bits.take(2);
                    if (symbol + r > max_symbols) return error.BadFseTable;
                    for (0..r) |_| {
                        norm[symbol] = 0;
                        symbol += 1;
                    }
                    if (r != 3) break;
                }
                previous_zero = false;
                continue;
            }
            const max = 2 * threshold - 1 - remaining;
            const low: i32 = @intCast(bits.peek(width - 1));
            var count: i32 = undefined;
            if (low < max) {
                count = low;
                bits.skip(width - 1);
            } else {
                count = @intCast(bits.peek(width));
                if (count >= threshold) count -= max;
                bits.skip(width);
            }
            count -= 1;
            remaining -= if (count < 0) -count else count;
            norm[symbol] = @intCast(count);
            symbol += 1;
            previous_zero = count == 0;
            while (remaining < threshold) {
                width -= 1;
                threshold >>= 1;
            }
        }
        if (remaining != 1 or bits.over()) return error.BadFseTable;
        try t.build(norm[0..symbol], log);
        return (bits.at + 7) / 8;
    }
};

/// A stream read from its first byte up, low bits first (an FSE table's description).
const Forward = struct {
    bytes: []const u8,
    at: usize = 0,

    fn peek(f: *const Forward, n: u6) u32 {
        var v: u64 = 0;
        const byte = f.at / 8;
        for (0..8) |i| {
            if (byte + i < f.bytes.len) v |= @as(u64, f.bytes[byte + i]) << @intCast(8 * i);
        }
        return @intCast((v >> @intCast(f.at % 8)) & ((@as(u64, 1) << n) - 1));
    }

    fn skip(f: *Forward, n: u6) void {
        f.at += n;
    }

    fn take(f: *Forward, n: u6) u32 {
        const v = f.peek(n);
        f.skip(n);
        return v;
    }

    /// Read past the end.
    fn over(f: *const Forward) bool {
        return f.at > f.bytes.len * 8;
    }
};

/// A stream read from its last byte down, high bits first: its last byte holds a marker, the
/// highest set bit, and the data is the bits below it (Huffman literals, sequences, weights).
const Reverse = struct {
    bytes: []const u8,
    /// Bits of data not read yet.
    left: usize,

    fn init(bytes: []const u8) Error!Reverse {
        if (bytes.len == 0 or bytes[bytes.len - 1] == 0) return error.TruncatedStream;
        const marker = 7 - @clz(bytes[bytes.len - 1]);
        return .{ .bytes = bytes, .left = (bytes.len - 1) * 8 + marker };
    }

    /// The next `n` (at most 56) bits, missing ones past the stream's start read as zeros.
    fn peek(r: *const Reverse, n: u6) u64 {
        if (n == 0) return 0;
        if (r.left >= n) return r.window(r.left - n, n);
        if (r.left == 0) return 0;
        return r.window(0, @intCast(r.left)) << @intCast(n - r.left);
    }

    fn window(r: *const Reverse, start: usize, n: u6) u64 {
        const byte = start / 8;
        var v: u64 = 0;
        if (byte + 8 <= r.bytes.len) {
            v = std.mem.readInt(u64, r.bytes[byte..][0..8], .little);
        } else for (r.bytes[byte..], 0..) |b, i| {
            v |= @as(u64, b) << @intCast(8 * i);
        }
        return (v >> @intCast(start % 8)) & ((@as(u64, 1) << n) - 1);
    }

    fn read(r: *Reverse, n: u6) Error!u64 {
        if (n > r.left) return error.TruncatedStream;
        const v = r.peek(n);
        r.left -= n;
        return v;
    }
};

const Huffman = struct {
    table: [1 << 11]Entry = undefined,
    max_bits: u8 = 0,
    valid: bool = false,

    /// Fills the table from the weights of the first `count - 1` symbols (`weights[count - 1]` is
    /// worked out from them).
    fn build(h: *Huffman, weights: *[256]u8, count: usize) Error!void {
        if (count < 2 or count > 256) return error.BadHuffmanTree;
        var total: u32 = 0;
        for (weights[0 .. count - 1]) |w| {
            if (w > 11) return error.BadHuffmanTree;
            if (w > 0) total += @as(u32, 1) << @intCast(w - 1);
        }
        if (total == 0) return error.BadHuffmanTree;
        const max_bits: u8 = @intCast(std.math.log2_int(u32, total) + 1);
        if (max_bits > 11) return error.BadHuffmanTree;
        const rest = (@as(u32, 1) << @intCast(max_bits)) - total;
        // What is left for the last symbol is a power of two, or the tree is not complete (libzstd
        // refuses it too; std's decoder does not look).
        if (!std.math.isPowerOfTwo(rest)) return error.IncompleteHuffmanTree;
        weights[count - 1] = @intCast(std.math.log2_int(u32, rest) + 1);

        var in_rank: [13]u32 = @splat(0);
        for (weights[0..count]) |w| in_rank[w] += 1;
        var start: [13]u32 = @splat(0);
        var at: u32 = 0;
        for (1..max_bits + 1) |w| {
            start[w] = at;
            at += in_rank[w] << @intCast(w - 1);
        }
        for (weights[0..count], 0..) |w, symbol| {
            if (w == 0) continue;
            const span = @as(u32, 1) << @intCast(w - 1);
            const entry: Entry = .{ .symbol = @intCast(symbol), .bits = max_bits + 1 - w };
            @memset(h.table[start[w]..][0..span], entry);
            start[w] += span;
        }
        h.max_bits = max_bits;
        h.valid = true;
    }

    /// The tree `bytes` starts with, and how many bytes it took.
    fn read(h: *Huffman, bytes: []const u8) Error!usize {
        if (bytes.len == 0) return error.BadHuffmanTree;
        var weights: [256]u8 = @splat(0);
        const header = bytes[0];
        if (header >= 128) {
            // Direct: two 4-bit weights to the byte.
            const count: usize = header - 127;
            const used = (count + 1) / 2;
            if (bytes.len < 1 + used) return error.BadHuffmanTree;
            for (0..count) |i| {
                const b = bytes[1 + i / 2];
                weights[i] = if (i % 2 == 0) b >> 4 else b & 15;
            }
            try h.build(&weights, count + 1);
            return 1 + used;
        }
        // Compressed: an FSE table, then the weights as two interleaved states.
        const size: usize = header;
        if (size == 0 or bytes.len < 1 + size) return error.BadHuffmanTree;
        const body = bytes[1..][0..size];
        var fse: Fse = .{};
        const table_len = try fse.read(body, 256, 6);
        var rev = try Reverse.init(body[table_len..]);
        var even = try rev.read(@intCast(fse.log));
        var odd = try rev.read(@intCast(fse.log));
        var n: usize = 0;
        while (n < 254) {
            const e = fse.entries[@intCast(even)];
            if (e.bits > rev.left) {
                weights[n] = e.symbol;
                weights[n + 1] = fse.entries[@intCast(odd)].symbol;
                n += 2;
                break;
            }
            weights[n] = e.symbol;
            n += 1;
            even = e.base + try rev.read(@intCast(e.bits));
            const o = fse.entries[@intCast(odd)];
            if (o.bits > rev.left) {
                weights[n] = o.symbol;
                weights[n + 1] = fse.entries[@intCast(even)].symbol;
                n += 2;
                break;
            }
            weights[n] = o.symbol;
            n += 1;
            odd = o.base + try rev.read(@intCast(o.bits));
        } else return error.BadHuffmanTree;
        try h.build(&weights, n + 1);
        return 1 + size;
    }

    /// `out.len` symbols from the stream `bytes`, which must be used up.
    fn decode(h: *const Huffman, bytes: []const u8, out: []u8) Error!void {
        var rev = try Reverse.init(bytes);
        const bits: u6 = @intCast(h.max_bits);
        for (out) |*o| {
            const e = h.table[@intCast(rev.peek(bits))];
            if (e.bits > rev.left) return error.BadLiteralStream;
            rev.left -= e.bits;
            o.* = e.symbol;
        }
        // Used up, as libzstd wants of each of the four streams (std's decoder looks at the last).
        if (rev.left != 0) return error.BadLiteralStream;
    }
};

/// The state `Decompress` keeps between blocks of a frame.
const Phase = enum { frame, block, end };

/// A zstd stream (frames one after another) read through `reader`.
pub const Decompress = struct {
    gpa: Allocator,
    in: *Reader,
    reader: Reader,
    /// Why `reader` failed, when it did.
    err: ?Error = null,

    phase: Phase = .frame,
    checksum: bool = false,
    window_size: usize = 0,
    /// The largest window a frame may declare.
    window_limit: u64 = max_window,
    /// The frame's content size, when it says, and the most a block may hold: the window, or 128
    /// KiB when that is less (RFC 8878, "Blocks").
    content: ?u64 = null,
    block_limit: usize = block_max,
    /// The frame's decoded bytes: the last `window_size` of them, then room for a block. `pos` is
    /// the end of what is decoded and `sent` how much of it `reader` has handed out.
    win: []u8 = &.{},
    pos: usize = 0,
    sent: usize = 0,
    /// Bytes of the frame decoded before `win[0]`, and in `win`: what an offset can reach.
    history: u64 = 0,

    huffman: *Huffman,
    /// Literal lengths, offsets, match lengths, as the sequences section lists them.
    fse: [3]*Fse,
    repeat: [3]u32 = .{ 1, 4, 8 },
    /// A compressed block read whole, and its literals decoded.
    block: []u8,
    literals: []u8,

    const ll = 0;
    const of = 1;
    const ml = 2;

    pub fn create(gpa: Allocator, in: *Reader) Allocator.Error!*Decompress {
        const d = try gpa.create(Decompress);
        errdefer gpa.destroy(d);
        const huffman = try gpa.create(Huffman);
        errdefer gpa.destroy(huffman);
        huffman.* = .{};
        var fse: [3]*Fse = undefined;
        var made: usize = 0;
        errdefer for (fse[0..made]) |f| gpa.destroy(f);
        for (&fse) |*f| {
            f.* = try gpa.create(Fse);
            f.*.* = .{};
            made += 1;
        }
        const block = try gpa.alloc(u8, block_max);
        errdefer gpa.free(block);
        const literals = try gpa.alloc(u8, block_max);
        errdefer gpa.free(literals);
        // The reader's own buffer: what wraps a reader (a hashing one) peeks into it.
        const buffer = try gpa.alloc(u8, reader_bytes);
        errdefer gpa.free(buffer);
        d.* = .{
            .gpa = gpa,
            .in = in,
            .reader = .{ .vtable = &.{ .stream = stream }, .buffer = buffer, .seek = 0, .end = 0 },
            .huffman = huffman,
            .fse = fse,
            .block = block,
            .literals = literals,
        };
        return d;
    }

    pub fn destroy(d: *Decompress) void {
        const gpa = d.gpa;
        gpa.free(d.win);
        gpa.free(d.reader.buffer);
        gpa.free(d.literals);
        gpa.free(d.block);
        for (d.fse) |f| gpa.destroy(f);
        gpa.destroy(d.huffman);
        gpa.destroy(d);
    }

    fn stream(r: *Reader, w: *std.Io.Writer, limit: std.Io.Limit) Reader.StreamError!usize {
        const d: *Decompress = @alignCast(@fieldParentPtr("reader", r));
        if (d.err != null) return error.ReadFailed;
        while (d.sent == d.pos) {
            if (d.phase == .end) return error.EndOfStream;
            d.advance() catch |e| switch (e) {
                error.ReadFailed => return error.ReadFailed,
                error.EndOfStream => {
                    d.err = error.TruncatedStream;
                    return error.ReadFailed;
                },
                else => |format| {
                    d.err = format;
                    return error.ReadFailed;
                },
            };
        }
        const out = limit.slice(d.win[d.sent..d.pos]);
        try w.writeAll(out);
        d.sent += out.len;
        return out.len;
    }

    const AdvanceError = Error || Allocator.Error || Reader.Error;

    /// Decodes up to the end of the next block, or reads the next frame's header.
    fn advance(d: *Decompress) AdvanceError!void {
        switch (d.phase) {
            .frame => return d.frameHeader(),
            .block => return d.nextBlock(),
            .end => unreachable,
        }
    }

    fn frameHeader(d: *Decompress) AdvanceError!void {
        const in = d.in;
        while (true) {
            // The stream's end is between frames.
            _ = in.peekByte() catch |e| switch (e) {
                error.EndOfStream => {
                    d.phase = .end;
                    return;
                },
                else => |other| return other,
            };
            const magic = try in.takeInt(u32, .little);
            if (magic & 0xFFFF_FFF0 == 0x184D2A50) {
                const skip = try in.takeInt(u32, .little);
                try in.discardAll(skip);
                continue;
            }
            if (magic != 0xFD2FB528) return error.BadMagic;
            break;
        }
        const flags = try in.takeByte();
        if (flags & 0x08 != 0) return error.ReservedBit;
        const dict_bytes: u64 = switch (flags & 3) {
            0 => 0,
            1 => 1,
            2 => 2,
            else => 4,
        };
        const single = flags & 0x20 != 0;
        d.checksum = flags & 0x04 != 0;
        var window: u64 = 0;
        if (!single) {
            const b = try in.takeByte();
            const base = @as(u64, 1) << @intCast(10 + (b >> 3));
            window = base + (base / 8) * (b & 7);
        }
        if (dict_bytes > 0) {
            const id = try in.take(@intCast(dict_bytes));
            for (id) |x| if (x != 0) return error.DictionaryUnsupported;
        }
        const content_bytes: usize = switch (flags >> 6) {
            0 => if (single) 1 else 0,
            1 => 2,
            2 => 4,
            else => 8,
        };
        var content: ?u64 = null;
        if (content_bytes > 0) {
            var v: u64 = 0;
            const raw = try in.take(content_bytes);
            for (raw, 0..) |x, i| v |= @as(u64, x) << @intCast(8 * i);
            if (content_bytes == 2) v += 256;
            content = v;
        }
        if (single) window = content.?;
        if (window > d.window_limit) return error.WindowTooLarge;
        d.content = content;
        d.block_limit = @min(block_max, std.math.lossyCast(usize, window));
        // No more than the frame holds, when it says.
        if (content) |c| window = @min(window, c);
        d.window_size = std.math.cast(usize, window) orelse return error.WindowTooLarge;
        // Room beyond the window to decode into before sliding it forward again: the slide copies
        // the whole window, so with only a block of room it would copy it for every block.
        const want = d.window_size + std.math.clamp(d.window_size, block_max, max_slack);
        if (d.win.len < want) {
            d.gpa.free(d.win);
            d.win = &.{};
            d.win = try d.gpa.alloc(u8, want);
        }
        d.pos = 0;
        d.sent = 0;
        d.history = 0;
        d.repeat = .{ 1, 4, 8 };
        d.huffman.valid = false;
        for (d.fse) |f| f.valid = false;
        d.phase = .block;
    }

    fn nextBlock(d: *Decompress) AdvanceError!void {
        const in = d.in;
        const head = try in.takeInt(u24, .little);
        const last = head & 1 != 0;
        const kind = (head >> 1) & 3;
        const size: usize = head >> 3;
        if (size > d.block_limit) return error.BlockTooLarge;
        // Room for a block: the window's worth kept, the rest slid out (all of it was sent).
        if (d.pos + block_max > d.win.len) {
            const keep = @min(d.pos, d.window_size);
            std.mem.copyForwards(u8, d.win[0..keep], d.win[d.pos - keep .. d.pos]);
            d.history += d.pos - keep;
            d.pos = keep;
            d.sent = keep;
        }
        switch (kind) {
            0 => {
                try in.readSliceAll(d.win[d.pos..][0..size]);
                d.pos += size;
            },
            1 => {
                const b = try in.takeByte();
                @memset(d.win[d.pos..][0..size], b);
                d.pos += size;
            },
            2 => {
                try in.readSliceAll(d.block[0..size]);
                try d.compressed(d.block[0..size]);
            },
            else => return error.ReservedBlockType,
        }
        // A frame holds as many bytes as its header says, no more (and at the end, no fewer).
        if (d.content) |c| {
            const total = d.history + d.pos;
            if (total > c or (last and total != c)) return error.BadContentSize;
        }
        if (last) {
            if (d.checksum) try in.discardAll(4);
            d.phase = .frame;
        }
    }

    /// One compressed block: its literals, then the sequences that interleave them with matches.
    fn compressed(d: *Decompress, block: []const u8) Error!void {
        var at: usize = 0;
        const lits = try d.readLiterals(block, &at);
        if (at >= block.len) return error.BadSequences;
        var count: usize = block[at];
        at += 1;
        if (count == 0) {
            if (at != block.len) return error.BadSequences;
            return d.appendLiterals(lits);
        }
        if (count >= 128) {
            if (at >= block.len) return error.BadSequences;
            if (count == 255) {
                if (at + 2 > block.len) return error.BadSequences;
                count = @as(usize, block[at]) + (@as(usize, block[at + 1]) << 8) + 0x7F00;
                at += 2;
            } else {
                count = ((count - 128) << 8) + block[at];
                at += 1;
            }
        }
        if (at >= block.len) return error.BadSequences;
        const modes = block[at];
        at += 1;
        if (modes & 3 != 0) return error.BadSequences;
        // Literal lengths, offsets and match lengths, in that order.
        const limits = [3]struct { symbols: usize, log: u8 }{
            .{ .symbols = zstd.table_symbol_count_max.literal, .log = zstd.table_accuracy_log_max.literal },
            .{ .symbols = zstd.table_symbol_count_max.offset, .log = zstd.table_accuracy_log_max.offset },
            .{ .symbols = zstd.table_symbol_count_max.match, .log = zstd.table_accuracy_log_max.match },
        };
        const defaults = [3][]const i16{
            &zstd.literals_length_default_distribution,
            &zstd.offset_codes_default_distribution,
            &zstd.match_lengths_default_distribution,
        };
        const default_logs = [3]u8{
            zstd.default_accuracy_log.literal,
            zstd.default_accuracy_log.offset,
            zstd.default_accuracy_log.match,
        };
        inline for (0..3) |i| {
            const mode = (modes >> @intCast(6 - 2 * i)) & 3;
            const f = d.fse[i];
            switch (mode) {
                0 => try f.build(defaults[i], default_logs[i]),
                1 => {
                    if (at >= block.len) return error.BadSequences;
                    f.single(block[at]);
                    at += 1;
                },
                2 => at += try f.read(block[at..], limits[i].symbols, limits[i].log),
                else => if (!f.valid) return error.BadSequences,
            }
        }
        try d.sequences(block[at..], count, lits);
    }

    /// The literals section at `block[at.*..]`: raw, one byte repeated, or Huffman coded (from
    /// its own tree or the last block's).
    fn readLiterals(d: *Decompress, block: []const u8, at: *usize) Error![]const u8 {
        if (block.len == 0) return error.BadLiterals;
        const b0 = block[0];
        const kind = b0 & 3;
        const format: u2 = @intCast((b0 >> 2) & 3);
        if (kind < 2) {
            var header: usize = 1;
            var regenerated: usize = b0 >> 3;
            if (format == 1) {
                header = 2;
                if (block.len < header) return error.BadLiterals;
                regenerated = (@as(usize, b0) >> 4) + (@as(usize, block[1]) << 4);
            } else if (format == 3) {
                header = 3;
                if (block.len < header) return error.BadLiterals;
                regenerated = (@as(usize, b0) >> 4) + (@as(usize, block[1]) << 4) + (@as(usize, block[2]) << 12);
            }
            if (regenerated > block_max) return error.BadLiterals;
            if (kind == 0) {
                if (block.len < header + regenerated) return error.BadLiterals;
                at.* = header + regenerated;
                return block[header..][0..regenerated];
            }
            if (block.len < header + 1) return error.BadLiterals;
            @memset(d.literals[0..regenerated], block[header]);
            at.* = header + 1;
            return d.literals[0..regenerated];
        }
        // Huffman coded: sizes in 10, 10, 14 or 18 bits each, one stream or four.
        const sizes: struct { header: usize, bits: u5 } = switch (format) {
            0, 1 => .{ .header = 3, .bits = 10 },
            2 => .{ .header = 4, .bits = 14 },
            3 => .{ .header = 5, .bits = 18 },
        };
        if (block.len < sizes.header) return error.BadLiterals;
        var raw: u64 = 0;
        for (block[0..sizes.header], 0..) |x, i| raw |= @as(u64, x) << @intCast(8 * i);
        const mask = (@as(u64, 1) << sizes.bits) - 1;
        const regenerated: usize = @intCast((raw >> 4) & mask);
        const compressed_size: usize = @intCast((raw >> (4 + sizes.bits)) & mask);
        if (regenerated > block_max or block.len < sizes.header + compressed_size) return error.BadLiterals;
        const body = block[sizes.header..][0..compressed_size];
        var used: usize = 0;
        if (kind == 2) {
            used = try d.huffman.read(body);
        } else if (!d.huffman.valid) return error.BadLiterals;
        const streams = body[used..];
        const out = d.literals[0..regenerated];
        if (format == 0) {
            try d.huffman.decode(streams, out);
        } else {
            if (streams.len < 6) return error.BadLiterals;
            const a: usize = std.mem.readInt(u16, streams[0..2], .little);
            const b: usize = std.mem.readInt(u16, streams[2..4], .little);
            const c: usize = std.mem.readInt(u16, streams[4..6], .little);
            if (6 + a + b + c > streams.len) return error.BadLiterals;
            const each = (regenerated + 3) / 4;
            if (regenerated < 3 * each) return error.BadLiterals;
            const parts = [4][]const u8{
                streams[6..][0..a],
                streams[6 + a ..][0..b],
                streams[6 + a + b ..][0..c],
                streams[6 + a + b + c ..],
            };
            for (parts, 0..) |part, i| {
                const from = i * each;
                const to = if (i == 3) regenerated else from + each;
                try d.huffman.decode(part, out[from..to]);
            }
        }
        at.* = sizes.header + compressed_size;
        return out;
    }

    fn appendLiterals(d: *Decompress, lits: []const u8) Error!void {
        if (lits.len > d.block_limit) return error.BadSequences;
        @memcpy(d.win[d.pos..][0..lits.len], lits);
        d.pos += lits.len;
    }

    fn sequences(d: *Decompress, bytes: []const u8, count: usize, lits: []const u8) Error!void {
        var rev = try Reverse.init(bytes);
        const t_ll = d.fse[ll];
        const t_of = d.fse[of];
        const t_ml = d.fse[ml];
        var s_ll: usize = @intCast(try rev.read(@intCast(t_ll.log)));
        var s_of: usize = @intCast(try rev.read(@intCast(t_of.log)));
        var s_ml: usize = @intCast(try rev.read(@intCast(t_ml.log)));
        const win = d.win;
        const start = d.pos;
        var pos = d.pos;
        var lit_at: usize = 0;
        var i: usize = 0;
        while (i < count) : (i += 1) {
            const e_ll = t_ll.entries[s_ll];
            const e_of = t_of.entries[s_of];
            const e_ml = t_ml.entries[s_ml];
            if (e_of.symbol > 31 or e_ml.symbol >= zstd.match_length_code_table.len or
                e_ll.symbol >= zstd.literals_length_code_table.len) return error.BadSequences;
            const of_code: u6 = @intCast(e_of.symbol);
            const offset_value: u64 = (@as(u64, 1) << of_code) + try rev.read(of_code);
            const m = zstd.match_length_code_table[e_ml.symbol];
            const match_len: usize = m[0] + @as(usize, @intCast(try rev.read(m[1])));
            const l = zstd.literals_length_code_table[e_ll.symbol];
            const lit_len: usize = l[0] + @as(usize, @intCast(try rev.read(l[1])));

            const offset = d.resolveOffset(offset_value, lit_len);
            if (offset == 0) return error.BadOffset;

            if (lit_len > lits.len - lit_at or pos + lit_len + match_len > start + d.block_limit) return error.BadSequences;
            @memcpy(win[pos..][0..lit_len], lits[lit_at..][0..lit_len]);
            pos += lit_len;
            lit_at += lit_len;
            // What an offset reaches: the frame's earlier bytes, within its window.
            const reach = @min(d.history + pos, d.window_size);
            if (offset > reach or offset > pos) return error.BadOffset;
            copyMatch(win, pos, offset, match_len);
            pos += match_len;

            if (i + 1 < count) {
                s_ll = e_ll.base + @as(usize, @intCast(try rev.read(@intCast(e_ll.bits))));
                s_ml = e_ml.base + @as(usize, @intCast(try rev.read(@intCast(e_ml.bits))));
                s_of = e_of.base + @as(usize, @intCast(try rev.read(@intCast(e_of.bits))));
                if (s_ll >= @as(usize, 1) << @intCast(t_ll.log) or s_of >= @as(usize, 1) << @intCast(t_of.log) or
                    s_ml >= @as(usize, 1) << @intCast(t_ml.log)) return error.BadFseTable;
            }
        }
        if (rev.left != 0) return error.BadSequences;
        const rest = lits.len - lit_at;
        if (pos + rest > start + d.block_limit) return error.BadSequences;
        @memcpy(win[pos..][0..rest], lits[lit_at..]);
        d.pos = pos + rest;
    }

    /// The distance an offset code means, with the three most recent ones kept up to date
    /// (RFC 8878, "Repeat Offsets").
    fn resolveOffset(d: *Decompress, value: u64, lit_len: usize) u32 {
        // Copied: an array literal assigned over its own elements would read them half written.
        const old = d.repeat;
        if (value > 3) {
            const offset: u32 = @truncate(value - 3);
            d.repeat = .{ offset, old[0], old[1] };
            return offset;
        }
        const index: usize = @intCast(value - 1 + @intFromBool(lit_len == 0));
        const offset: u32 = if (index == 3) old[0] -% 1 else old[index];
        if (index == 1) {
            d.repeat = .{ old[1], old[0], old[2] };
        } else if (index >= 2) {
            d.repeat = .{ offset, old[0], old[1] };
        }
        return offset;
    }

    /// `len` bytes from `offset` back to `pos`, which may overlap the bytes being written (a
    /// short offset repeats a pattern).
    fn copyMatch(win: []u8, pos: usize, offset: usize, len: usize) void {
        if (offset >= len) {
            @memcpy(win[pos..][0..len], win[pos - offset ..][0..len]);
            return;
        }
        for (0..len) |k| win[pos + k] = win[pos - offset + k];
    }
};

// --- tests ---

const testing = std.testing;

const level3 = @embedFile("../testdata/zstd/l3.zst");
const level19 = @embedFile("../testdata/zstd/l19.zst");
/// SHA-256 of what both fixtures decompress to: text (several 128 KB blocks), 20 KB of random
/// bytes (raw blocks), a long run (RLE and repeat offsets) and a piece of an executable.
const fixture_digest = "0b7456bf1b7c9ad7abc7927daf08a19cc196e18797cc7e4e6dd424b6f3b5e811";
const fixture_len = 307475;

fn decompressAll(gpa: Allocator, compressed: []const u8) ![]u8 {
    var in: Reader = .fixed(compressed);
    const d = try Decompress.create(gpa, &in);
    defer d.destroy();
    var out: std.Io.Writer.Allocating = .init(gpa);
    errdefer out.deinit();
    _ = d.reader.streamRemaining(&out.writer) catch |e| {
        if (d.err) |why| return why;
        return e;
    };
    return out.toOwnedSlice();
}

fn digestHex(bytes: []const u8) [64]u8 {
    var sum: [32]u8 = undefined;
    std.crypto.hash.sha2.Sha256.hash(bytes, &sum, .{});
    return std.fmt.bytesToHex(sum, .lower);
}

test "native oci zstd: the fixtures decompress to what they were, as std's decoder reads them" {
    for ([_][]const u8{ level3, level19 }) |blob| {
        const got = try decompressAll(testing.allocator, blob);
        defer testing.allocator.free(got);
        try testing.expectEqualStrings(fixture_digest, &digestHex(got));

        var in: Reader = .fixed(blob);
        const window = try testing.allocator.alloc(u8, zstd.default_window_len + block_max);
        defer testing.allocator.free(window);
        var oracle: zstd.Decompress = .init(&in, window, .{});
        const want = try oracle.reader.allocRemaining(testing.allocator, .unlimited);
        defer testing.allocator.free(want);
        try testing.expectEqualSlices(u8, want, got);
    }
}

test "native oci zstd: frames one after another, skippable ones between, and nothing at all" {
    const a = testing.allocator;
    var skippable: [13]u8 = undefined;
    std.mem.writeInt(u32, skippable[0..4], 0x184D2A55, .little);
    std.mem.writeInt(u32, skippable[4..8], 5, .little);
    @memcpy(skippable[8..], "hello");
    const stream = try std.mem.concat(a, u8, &.{ &skippable, level3, &skippable, level19 });
    defer a.free(stream);
    const got = try decompressAll(a, stream);
    defer a.free(got);
    try testing.expectEqual(2 * fixture_len, got.len);
    try testing.expectEqualSlices(u8, got[0..fixture_len], got[fixture_len..]);

    const none = try decompressAll(a, "");
    defer a.free(none);
    try testing.expectEqual(0, none.len);
}

test "native oci zstd: a stream that is wrong is refused with a reason, never read out of bounds" {
    const a = testing.allocator;
    try testing.expectError(error.BadMagic, decompressAll(a, "not zstd at all"));
    // Cut anywhere: an error, except at a frame's end.
    var cut: usize = 1;
    while (cut < level3.len) : (cut += 997) {
        if (decompressAll(a, level3[0..cut])) |ok| a.free(ok) else |_| {}
    }
    // Every byte of the first blocks' headers and tables flipped, one at a time.
    const copy = try a.dupe(u8, level19[0..3000]);
    defer a.free(copy);
    for (0..copy.len) |i| {
        const was = copy[i];
        for ([_]u8{ 0x01, 0x80, 0xff }) |x| {
            copy[i] = was ^ x;
            if (decompressAll(a, copy)) |ok| a.free(ok) else |_| {}
        }
        copy[i] = was;
    }
}

test "native oci zstd: random streams behind a valid header never crash it" {
    const a = testing.allocator;
    var prng: std.Random.DefaultPrng = .init(0x5eed);
    const r = prng.random();
    const junk = try a.alloc(u8, 4000);
    defer a.free(junk);
    for (0..300) |_| {
        r.bytes(junk);
        // A frame header (single segment, 100 KB, no checksum) and a compressed block header.
        const head = [_]u8{ 0x28, 0xb5, 0x2f, 0xfd, 0x60, 0xa0, 0x86, 0x01, 0x00 };
        const stream = try std.mem.concat(a, u8, &.{ &head, &.{ 0x15, 0x00, 0x08 }, junk });
        defer a.free(stream);
        if (decompressAll(a, stream)) |ok| a.free(ok) else |_| {}
    }
}

/// A frame by hand: the magic, a descriptor, the fields the descriptor names, and RLE blocks of
/// `byte`, one of `sizes` bytes each (the last one marked so).
fn rleFrame(a: Allocator, descriptor: u8, fields: []const u8, byte: u8, sizes: []const u24) ![]u8 {
    var out: std.ArrayList(u8) = .empty;
    errdefer out.deinit(a);
    try out.appendSlice(a, &.{ 0x28, 0xb5, 0x2f, 0xfd, descriptor });
    try out.appendSlice(a, fields);
    for (sizes, 0..) |size, i| {
        const head: u24 = (size << 3) | 2 | @intFromBool(i + 1 == sizes.len);
        var h: [3]u8 = undefined;
        std.mem.writeInt(u24, &h, head, .little);
        try out.appendSlice(a, &h);
        try out.append(a, byte);
    }
    return out.toOwnedSlice(a);
}

test "native oci zstd: a frame holds as many bytes as its header says, and no block is over its window" {
    const a = testing.allocator;
    // Single segment, content size 200 in one byte (so a window of 200): 200 bytes are right, 199
    // are fewer than it says, and a block of 201 is over the window.
    for ([_]struct { u24, ?Error }{ .{ 200, null }, .{ 199, error.BadContentSize }, .{ 201, error.BlockTooLarge } }) |c| {
        const frame = try rleFrame(a, 0x20, &.{200}, 'x', &.{c[0]});
        defer a.free(frame);
        if (c[1]) |want| {
            try testing.expectError(want, decompressAll(a, frame));
        } else {
            const got = try decompressAll(a, frame);
            defer a.free(got);
            try testing.expectEqual(200, got.len);
        }
    }
    // More than the size by the second block, which is refused before its bytes are handed out.
    const over = try rleFrame(a, 0x20, &.{10}, 'x', &.{ 6, 6 });
    defer a.free(over);
    try testing.expectError(error.BadContentSize, decompressAll(a, over));
    // A window of 1 KiB (descriptor 0, no content size): a block of 1 KiB, not one of 1 KiB + 1.
    const fits = try rleFrame(a, 0x00, &.{0x00}, 'x', &.{1024});
    defer a.free(fits);
    const got = try decompressAll(a, fits);
    defer a.free(got);
    try testing.expectEqual(1024, got.len);
    const big = try rleFrame(a, 0x00, &.{0x00}, 'x', &.{1025});
    defer a.free(big);
    try testing.expectError(error.BlockTooLarge, decompressAll(a, big));
}

/// A frame with a window of 1 KiB and no content size: two RLE blocks of 1000 bytes ('a', 'b'),
/// then a compressed block of five literals and one sequence that takes the offset code `code`,
/// with `extra` for its bits (the tables are RLE: literal length code 5, match length code 2, so
/// five literals and a match of five).
fn matchFrame(a: Allocator, code: u8, extra: u16) ![]u8 {
    const bits = code; // an offset code reads that many bits
    const stream: u32 = std.math.shl(u32, 1, bits) | extra;
    var block: std.ArrayList(u8) = .empty;
    errdefer block.deinit(a);
    try block.appendSlice(a, &.{ 5 << 3, 'h', 'e', 'l', 'l', 'o', 1, 0b01_01_01_00, 5, code, 2 });
    var rest = stream;
    for (0..(bits + 1 + 7) / 8) |_| {
        try block.append(a, @truncate(rest));
        rest >>= 8;
    }
    var out: std.ArrayList(u8) = .empty;
    errdefer out.deinit(a);
    try out.appendSlice(a, &.{ 0x28, 0xb5, 0x2f, 0xfd, 0x00, 0x00 });
    for ("ab") |byte| try out.appendSlice(a, &.{ 0x42, 0x1f, 0x00, byte }); // (1000 << 3) | RLE
    var head: [3]u8 = undefined;
    std.mem.writeInt(u24, &head, @as(u24, @truncate(block.items.len)) << 3 | 4 | 1, .little);
    try out.appendSlice(a, &head);
    try out.appendSlice(a, block.items);
    block.deinit(a);
    return out.toOwnedSlice(a);
}

test "native oci zstd: a match reaches back within the window and no further, as libzstd reads it" {
    const a = testing.allocator;
    // Offset code 9 and 491: the value 512 + 491 = 1003, an offset of 1000, which the window holds.
    const near = try matchFrame(a, 9, 491);
    defer a.free(near);
    const got = try decompressAll(a, near);
    defer a.free(got);
    try testing.expectEqual(2000 + 5 + 5, got.len);
    try testing.expectEqualStrings("hello" ++ "bbbbb", got[2000..]);
    // Code 10 and 4: 1024 + 4 = 1028, an offset of 1025, past a window of 1024 though not past the
    // 2000 bytes before it (std's decoder takes it: it checks its buffer, not the window).
    const far = try matchFrame(a, 10, 4);
    defer a.free(far);
    try testing.expectError(error.BadOffset, decompressAll(a, far));
}

test "native oci zstd: what libzstd refuses and std's decoder takes: a tree that is not complete, a literal stream not used up" {
    const a = testing.allocator;
    // A tree of weights 2, 1, 2 (the last symbol takes what is left: 8 - 5 = 3, not a power of two).
    const tree = @embedFile("../../fuzz_corpus/zstd/hand-huffman-direct-f0.zst");
    const copy = try a.dupe(u8, tree);
    defer a.free(copy);
    try testing.expectEqual(0x11, copy[62]);
    copy[62] = 0x12;
    try testing.expectError(error.IncompleteHuffmanTree, decompressAll(a, copy));
    // One bit of the first of four streams, the last read, changed: the symbols no longer use the stream up.
    const streams = @embedFile("../../fuzz_corpus/zstd/hand-huffman-direct-f1.zst");
    const flipped = try a.dupe(u8, streams);
    defer a.free(flipped);
    flipped[69] ^= 1;
    try testing.expectError(error.BadLiteralStream, decompressAll(a, flipped));
    // Unchanged, both decode.
    const ok = try decompressAll(a, streams);
    a.free(ok);
}

test "native oci zstd: a window over the limit is refused, and a failed stream stays failed" {
    const a = testing.allocator;
    // Window 2 KiB (descriptor 0x08), a limit of 1 KiB.
    const frame = try rleFrame(a, 0x00, &.{0x08}, 'x', &.{16});
    defer a.free(frame);
    var in: Reader = .fixed(frame);
    const d = try Decompress.create(a, &in);
    defer d.destroy();
    d.window_limit = 1024;
    var out: [64]u8 = undefined;
    try testing.expectError(error.ReadFailed, d.reader.readSliceAll(&out));
    try testing.expectEqual(error.WindowTooLarge, d.err.?);
    // Reading on does not decode what follows the refused header.
    try testing.expectError(error.ReadFailed, d.reader.readSliceAll(&out));
    try testing.expectEqual(error.WindowTooLarge, d.err.?);
}
