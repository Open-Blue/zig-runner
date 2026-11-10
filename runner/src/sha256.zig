//! SHA-256 for the runner, with the CPU's SHA-2 instructions when it has them.
//!
//! The release is one binary per architecture, built for the baseline CPU so it runs on any
//! (a Raspberry Pi 4 has no SHA-2 instructions, an old x86_64 has no SHA-NI). Zig's std chooses
//! its instruction-based block function at compile time from the target's features, so a baseline
//! build gets the slow one: 198 MB/s against 1,475 MB/s on a Raspberry Pi 5, where BLAKE3 does
//! 790 MB/s. This file keeps both block functions in the one binary and the first hash asks the
//! CPU which to use: std's for the baseline, and `compressInstructions` (std's instruction
//! sequences, which assemble whatever the target's features say) where the CPU has them. The
//! tests check both against a plain implementation and the FIPS vectors.
//!
//! Why not std's own code compiled a second time with the instructions enabled: Zig compiles
//! `std.crypto.hash.sha2` once per compilation, so a second module with other CPU features in the
//! same compilation shares that one copy (`nm` shows no `sha256rnds2` in the binary), and linking
//! a separately compiled object means every script that builds the runner has to build it too.
//!
//! `Sha256` has the interface of `std.crypto.hash.sha2.Sha256` that the runner uses. The signing
//! and TLS code that hands std's type to std's generics keeps std's, since it hashes a few
//! hundred bytes.
const std = @import("std");
const builtin = @import("builtin");

const Compress = *const fn (state: *[8]u32, blocks: []const u8) void;

pub const Sha256 = struct {
    pub const block_length = 64;
    pub const digest_length = 32;
    pub const Options = struct {};

    s: [8]u32 align(16),
    /// The bytes of the block being filled.
    buf: [64]u8 = undefined,
    buf_len: u8 = 0,
    total_len: u64 = 0,

    const iv: [8]u32 = .{
        0x6A09E667, 0xBB67AE85, 0x3C6EF372, 0xA54FF53A, 0x510E527F, 0x9B05688C, 0x1F83D9AB, 0x5BE0CD19,
    };

    pub fn init(options: Options) Sha256 {
        _ = options;
        return .{ .s = iv };
    }

    pub fn hash(bytes: []const u8, out: *[digest_length]u8, options: Options) void {
        var h = init(options);
        h.update(bytes);
        h.final(out);
    }

    pub fn update(h: *Sha256, bytes: []const u8) void {
        h.updateWith(compressFn(), bytes);
    }

    fn updateWith(h: *Sha256, compress: Compress, bytes: []const u8) void {
        var rest = bytes;
        h.total_len += bytes.len;
        if (h.buf_len != 0) {
            const take = @min(rest.len, block_length - h.buf_len);
            @memcpy(h.buf[h.buf_len..][0..take], rest[0..take]);
            h.buf_len +%= @truncate(take); // at most 64
            rest = rest[take..];
            if (h.buf_len < block_length) return;
            compress(&h.s, &h.buf);
            h.buf_len = 0;
        }
        const whole = rest.len - rest.len % block_length;
        if (whole != 0) compress(&h.s, rest[0..whole]);
        const tail = rest[whole..];
        @memcpy(h.buf[0..tail.len], tail);
        h.buf_len = @truncate(tail.len); // less than 64
    }

    pub fn final(h: *Sha256, out: *[digest_length]u8) void {
        h.finalWith(compressFn(), out);
    }

    fn finalWith(h: *Sha256, compress: Compress, out: *[digest_length]u8) void {
        // The message, 0x80, zeros, and its length in bits as a big-endian u64: one block, or two
        // when fewer than 9 bytes are left in this one.
        var pad: [2 * block_length]u8 = @splat(0);
        const len: usize = h.buf_len;
        @memcpy(pad[0..len], h.buf[0..len]);
        pad[len] = 0x80;
        const end: usize = if (len < block_length - 8) block_length else 2 * block_length;
        std.mem.writeInt(u64, pad[end - 8 ..][0..8], h.total_len *% 8, .big);
        compress(&h.s, pad[0..end]);
        for (h.s, 0..) |word, i| std.mem.writeInt(u32, out[4 * i ..][0..4], word, .big);
    }

    pub fn finalResult(h: *Sha256) [digest_length]u8 {
        var result: [digest_length]u8 = undefined;
        h.final(&result);
        return result;
    }

    pub fn peek(h: Sha256) [digest_length]u8 {
        var copy = h;
        return copy.finalResult();
    }
};

/// What the CPU can do, as far as SHA-256 is concerned. Read once; tests pass their own.
pub const Features = struct {
    /// The architecture's SHA-2 instructions (aarch64's `sha256h`, x86_64's SHA-NI) are usable.
    accelerated: bool = false,
};

/// The CPU's features as the OS reports them: aarch64's `AT_HWCAP` bit for SHA-2 (the kernel sets
/// it only when the CPU has the instructions), x86_64's CPUID.
pub fn detect() Features {
    return .{
        .accelerated = instructions_available and switch (builtin.os.tag) {
            .linux => switch (builtin.cpu.arch) {
                .aarch64 => hasHwcapSha2(std.os.linux.getauxval(std.elf.AT.HWCAP)),
                .x86_64 => hasCpuidSha(cpuid(0, 0), cpuid(1, 0), cpuid(7, 0)),
                else => false,
            },
            else => false,
        },
    };
}

/// `HWCAP_SHA2` in the kernel's arch/arm64/include/uapi/asm/hwcap.h.
fn hasHwcapSha2(hwcap: usize) bool {
    return hwcap & (1 << 6) != 0;
}

const Cpuid = struct { eax: u32, ebx: u32, ecx: u32, edx: u32 };

/// What `compressInstructions` runs on x86_64: SHA-NI, and SSSE3 and SSE4.1 for the `palignr` and
/// vector moves around it (CPUID.1:ECX bits 9 and 19, CPUID.7:EBX bit 29). Every CPU with SHA-NI
/// has them; they are checked so a hypervisor that masks them off is believed.
fn hasCpuidSha(leaf0: Cpuid, leaf1: Cpuid, leaf7: Cpuid) bool {
    if (leaf0.eax < 7) return false;
    const ssse3 = leaf1.ecx >> 9 & 1 != 0;
    const sse41 = leaf1.ecx >> 19 & 1 != 0;
    const sha = leaf7.ebx >> 29 & 1 != 0;
    return ssse3 and sse41 and sha;
}

fn cpuid(leaf: u32, subleaf: u32) Cpuid {
    if (builtin.cpu.arch != .x86_64) unreachable;
    var eax: u32 = undefined;
    var ebx: u32 = undefined;
    var ecx: u32 = undefined;
    var edx: u32 = undefined;
    asm volatile ("cpuid"
        : [eax] "={eax}" (eax),
          [ebx] "={ebx}" (ebx),
          [ecx] "={ecx}" (ecx),
          [edx] "={edx}" (edx),
        : [leaf] "{eax}" (leaf),
          [subleaf] "{ecx}" (subleaf),
    );
    return .{ .eax = eax, .ebx = ebx, .ecx = ecx, .edx = edx };
}

/// The block function for `features`.
fn choose(features: Features) Compress {
    return if (features.accelerated) compressInstructions else compressBaseline;
}

fn compressBaseline(state: *[8]u32, blocks: []const u8) void {
    std.debug.assert(blocks.len % Sha256.block_length == 0);
    var h: std.crypto.hash.sha2.Sha256 = .{ .s = state.* };
    h.update(blocks);
    state.* = h.s;
}

/// Round constants, FIPS 180-4 section 4.2.2.
const k: [64]u32 = .{
    0x428A2F98, 0x71374491, 0xB5C0FBCF, 0xE9B5DBA5, 0x3956C25B, 0x59F111F1, 0x923F82A4, 0xAB1C5ED5,
    0xD807AA98, 0x12835B01, 0x243185BE, 0x550C7DC3, 0x72BE5D74, 0x80DEB1FE, 0x9BDC06A7, 0xC19BF174,
    0xE49B69C1, 0xEFBE4786, 0x0FC19DC6, 0x240CA1CC, 0x2DE92C6F, 0x4A7484AA, 0x5CB0A9DC, 0x76F988DA,
    0x983E5152, 0xA831C66D, 0xB00327C8, 0xBF597FC7, 0xC6E00BF3, 0xD5A79147, 0x06CA6351, 0x14292967,
    0x27B70A85, 0x2E1B2138, 0x4D2C6DFC, 0x53380D13, 0x650A7354, 0x766A0ABB, 0x81C2C92E, 0x92722C85,
    0xA2BFE8A1, 0xA81A664B, 0xC24B8B70, 0xC76C51A3, 0xD192E819, 0xD6990624, 0xF40E3585, 0x106AA070,
    0x19A4C116, 0x1E376C08, 0x2748774C, 0x34B0BCB5, 0x391C0CB3, 0x4ED8AA4A, 0x5B9CCA4F, 0x682E6FF3,
    0x748F82EE, 0x78A5636F, 0x84C87814, 0x8CC70208, 0x90BEFFFA, 0xA4506CEB, 0xBEF9A3F7, 0xC67178F2,
};

/// Whether `compressSha2` can be compiled for this build. The compiler's own x86_64 backend (Debug
/// builds, and any build with `-fno-llvm`) encodes inline assembly itself and refuses `sha256msg1`
/// unless the target has SHA-NI ("InvalidInstruction (Zig compiler bug)"); LLVM assembles it
/// whatever the target says. There the baseline stands in and `detect` reports no instructions.
const instructions_available = switch (builtin.cpu.arch) {
    .aarch64 => true,
    .x86_64 => builtin.zig_backend != .stage2_x86_64 or
        builtin.cpu.hasAll(.x86, &.{ .sha, .ssse3, .sse4_1 }),
    else => false,
};

const compressInstructions = if (instructions_available) compressSha2 else compressBaseline;

/// The block function on the SHA-2 instructions, the sequences `std.crypto.hash.sha2` uses when
/// built for a CPU that has them. Only called after `detect` said the CPU does.
///
/// The instructions are in inline assembly, which LLVM assembles against the target's features: on
/// x86_64 any instruction assembles, but aarch64's `sha256h` is refused for the baseline CPU, so
/// each block starts with `.arch_extension sha2`, which lets the assembler take it. That changes
/// nothing the compiler generates, only what the assembler accepts afterwards.
fn compressSha2(state: *[8]u32, blocks: []const u8) void {
    std.debug.assert(blocks.len % Sha256.block_length == 0);
    const V4u32 = @Vector(4, u32);
    var rest = blocks;
    while (rest.len != 0) : (rest = rest[Sha256.block_length..]) {
        var w: [16]V4u32 = undefined;
        for (w[0..4], 0..) |*quad, q| {
            inline for (0..4) |j| quad[j] = std.mem.readInt(u32, rest[16 * q + 4 * j ..][0..4], .big);
        }
        switch (builtin.cpu.arch) {
            .aarch64 => {
                var x: V4u32 = state[0..4].*;
                var y: V4u32 = state[4..8].*;
                comptime var i: u8 = 0;
                inline while (i < 16) : (i += 1) {
                    if (i > 3) {
                        w[i] = asm (
                            \\.arch_extension sha2
                            \\sha256su0.4s %[w0_3], %[w4_7]
                            \\sha256su1.4s %[w0_3], %[w8_11], %[w12_15]
                            : [w0_3] "=&w" (-> V4u32),
                            : [_] "0" (w[i - 4]),
                              [w4_7] "w" (w[i - 3]),
                              [w8_11] "w" (w[i - 2]),
                              [w12_15] "w" (w[i - 1]),
                        );
                    }
                    const wk: V4u32 = w[i] +% @as(V4u32, k[4 * i ..][0..4].*);
                    asm volatile (
                        \\.arch_extension sha2
                        \\mov.4s v0, %[x]
                        \\sha256h.4s %[x], %[y], %[wk]
                        \\sha256h2.4s %[y], v0, %[wk]
                        : [x] "=w" (x),
                          [y] "=w" (y),
                        : [_] "0" (x),
                          [_] "1" (y),
                          [wk] "w" (wk),
                        : .{ .v0 = true });
                }
                state[0..4].* = x +% @as(V4u32, state[0..4].*);
                state[4..8].* = y +% @as(V4u32, state[4..8].*);
            },
            .x86_64 => {
                // SHA-NI keeps the state as ABEF and CDGH, each word order reversed.
                var x: V4u32 = .{ state[5], state[4], state[1], state[0] };
                var y: V4u32 = .{ state[7], state[6], state[3], state[2] };
                comptime var i: u8 = 0;
                inline while (i < 16) : (i += 1) {
                    if (i < 12) {
                        var tmp = w[i];
                        w[i + 4] = asm (
                            \\sha256msg1 %[w4_7], %[tmp]
                            \\movdqa %[w12_15], %[result]
                            \\palignr $4, %[w8_11], %[result]
                            \\paddd %[tmp], %[result]
                            \\sha256msg2 %[w12_15], %[result]
                            : [tmp] "=&x" (tmp),
                              [result] "=&x" (-> V4u32),
                            : [_] "0" (tmp),
                              [w4_7] "x" (w[i + 1]),
                              [w8_11] "x" (w[i + 2]),
                              [w12_15] "x" (w[i + 3]),
                        );
                    }
                    const wk: V4u32 = w[i] +% @as(V4u32, k[4 * i ..][0..4].*);
                    y = asm ("sha256rnds2 %[x], %[y]"
                        : [y] "=x" (-> V4u32),
                        : [_] "0" (y),
                          [x] "x" (x),
                          [_] "{xmm0}" (wk),
                    );
                    x = asm ("sha256rnds2 %[y], %[x]"
                        : [x] "=x" (-> V4u32),
                        : [_] "0" (x),
                          [y] "x" (y),
                          [_] "{xmm0}" (V4u32{ wk[2], wk[3], 0, 0 }),
                    );
                }
                state[0] +%= x[3];
                state[1] +%= x[2];
                state[4] +%= x[1];
                state[5] +%= x[0];
                state[2] +%= y[3];
                state[3] +%= y[2];
                state[6] +%= y[1];
                state[7] +%= y[0];
            },
            else => unreachable,
        }
    }
}

/// The block function in use, chosen by the first hash. Two threads may both choose; they choose
/// the same, so whichever store lands is right.
var chosen: std.atomic.Value(?Compress) = .init(null);

fn compressFn() Compress {
    return chosen.load(.monotonic) orelse {
        const f = choose(detect());
        chosen.store(f, .monotonic);
        return f;
    };
}

const testing = std.testing;
const StdSha256 = std.crypto.hash.sha2.Sha256;

fn expectDigest(hex: []const u8, bytes: []const u8) !void {
    var want: [32]u8 = undefined;
    _ = try std.fmt.hexToBytes(&want, hex);
    var got: [32]u8 = undefined;
    Sha256.hash(bytes, &got, .{});
    try testing.expectEqualSlices(u8, &want, &got);
}

test "sha256: the FIPS 180-4 test vectors" {
    try expectDigest("e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855", "");
    try expectDigest("ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad", "abc");
    try expectDigest(
        "248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1",
        "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq",
    );
    const million_a = try testing.allocator.alloc(u8, 1_000_000);
    defer testing.allocator.free(million_a);
    @memset(million_a, 'a');
    try expectDigest("cdc76e5c9914fb9281a1c7e284d73e67f1809a48a497200e046d39ccc7112cd0", million_a);
}

test "sha256: every length around the block and padding boundaries matches std" {
    var prng: std.Random.DefaultPrng = .init(0x5ba2_56);
    var data: [700]u8 = undefined;
    prng.random().bytes(&data);
    for (0..data.len + 1) |len| {
        var want: [32]u8 = undefined;
        StdSha256.hash(data[0..len], &want, .{});
        var got: [32]u8 = undefined;
        Sha256.hash(data[0..len], &got, .{});
        try testing.expectEqualSlices(u8, &want, &got);
    }
}

test "sha256: each block function hashes every length around the boundaries as std does" {
    var prng: std.Random.DefaultPrng = .init(0xb10c);
    var data: [300]u8 = undefined;
    prng.random().bytes(&data);
    // The instructions are only run where the CPU has them, as in production.
    const functions = [_]Compress{ compressBaseline, compressReference, compressInstructions };
    for (functions) |compress| {
        if (compress == &compressInstructions and !detect().accelerated) continue;
        for (0..data.len + 1) |len| {
            var want: [32]u8 = undefined;
            StdSha256.hash(data[0..len], &want, .{});
            var h: Sha256 = .init(.{});
            // Split in two, so the partial block and the whole ones are both used.
            h.updateWith(compress, data[0 .. len / 3]);
            h.updateWith(compress, data[len / 3 .. len]);
            var got: [32]u8 = undefined;
            h.finalWith(compress, &got);
            try testing.expectEqualSlices(u8, &want, &got);
        }
    }
}

test "sha256: updates of any sizes give the digest of the whole" {
    var prng: std.Random.DefaultPrng = .init(0xc0ffee);
    const rand = prng.random();
    const data = try testing.allocator.alloc(u8, 20_000);
    defer testing.allocator.free(data);
    rand.bytes(data);
    for (0..40) |_| {
        const len = rand.uintAtMost(usize, data.len);
        var want: [32]u8 = undefined;
        StdSha256.hash(data[0..len], &want, .{});
        var h: Sha256 = .init(.{});
        var at: usize = 0;
        while (at < len) {
            const n = @min(len - at, rand.uintAtMost(usize, 200));
            h.update(data[at..][0..n]);
            at += n;
        }
        // `peek` leaves the hasher as it was.
        try testing.expectEqualSlices(u8, &want, &h.peek());
        try testing.expectEqualSlices(u8, &want, &h.finalResult());
    }
}

/// FIPS 180-4 section 6.2.2, written plainly: what both block functions must agree with.
fn compressReference(state: *[8]u32, blocks: []const u8) void {
    var rest = blocks;
    while (rest.len != 0) : (rest = rest[64..]) {
        var w: [64]u32 = undefined;
        for (w[0..16], 0..) |*word, i| word.* = std.mem.readInt(u32, rest[4 * i ..][0..4], .big);
        for (16..64) |i| {
            const s0 = std.math.rotr(u32, w[i - 15], 7) ^ std.math.rotr(u32, w[i - 15], 18) ^ (w[i - 15] >> 3);
            const s1 = std.math.rotr(u32, w[i - 2], 17) ^ std.math.rotr(u32, w[i - 2], 19) ^ (w[i - 2] >> 10);
            w[i] = w[i - 16] +% s0 +% w[i - 7] +% s1;
        }
        var v = state.*;
        for (0..64) |i| {
            const e = v[4];
            const a = v[0];
            const big1 = std.math.rotr(u32, e, 6) ^ std.math.rotr(u32, e, 11) ^ std.math.rotr(u32, e, 25);
            const ch = (e & v[5]) ^ (~e & v[6]);
            const t1 = v[7] +% big1 +% ch +% k[i] +% w[i];
            const big0 = std.math.rotr(u32, a, 2) ^ std.math.rotr(u32, a, 13) ^ std.math.rotr(u32, a, 22);
            const maj = (a & v[1]) ^ (a & v[2]) ^ (v[1] & v[2]);
            // Through a temporary: an array literal assigned to `v` is built in place, and its
            // `v[0]` would read the new first element.
            const next: [8]u32 = .{ t1 +% big0 +% maj, v[0], v[1], v[2], v[3] +% t1, v[4], v[5], v[6] };
            v = next;
        }
        for (state, v) |*word, add| word.* +%= add;
    }
}

test "sha256: both block functions agree with the plain one" {
    var prng: std.Random.DefaultPrng = .init(0xacce1);
    const rand = prng.random();
    var data: [64 * 33]u8 = undefined;
    for (0..200) |_| {
        rand.bytes(&data);
        var want: [8]u32 = undefined;
        for (&want) |*word| word.* = rand.int(u32);
        var baseline = want;
        var instructions = want;
        const n = rand.uintAtMost(usize, 33) * 64;
        compressReference(&want, data[0..n]);
        compressBaseline(&baseline, data[0..n]);
        try testing.expectEqualSlices(u32, &want, &baseline);
        // Where the CPU has no such instructions there is nothing to run, as in production.
        if (!detect().accelerated) continue;
        compressInstructions(&instructions, data[0..n]);
        try testing.expectEqualSlices(u32, &want, &instructions);
    }
    if (!detect().accelerated) return error.SkipZigTest;
}

test "sha256: the CPU's features choose the block function" {
    try testing.expect(choose(.{ .accelerated = false }) == &compressBaseline);
    try testing.expect(choose(.{ .accelerated = true }) == &compressInstructions);
}

test "sha256: aarch64 accelerates only when the kernel reports HWCAP_SHA2" {
    try testing.expect(!hasHwcapSha2(0));
    try testing.expect(!hasHwcapSha2(~@as(usize, 1 << 6)));
    try testing.expect(hasHwcapSha2(1 << 6));
    try testing.expect(hasHwcapSha2(~@as(usize, 0)));
}

test "sha256: x86_64 accelerates only with SHA-NI, SSSE3 and SSE4.1" {
    const leaf0: Cpuid = .{ .eax = 7, .ebx = 0, .ecx = 0, .edx = 0 };
    const leaf1: Cpuid = .{ .eax = 0, .ebx = 0, .ecx = 1 << 9 | 1 << 19, .edx = 0 };
    const leaf7: Cpuid = .{ .eax = 0, .ebx = 1 << 29, .ecx = 0, .edx = 0 };
    try testing.expect(hasCpuidSha(leaf0, leaf1, leaf7));
    try testing.expect(!hasCpuidSha(leaf0, .{ .eax = 0, .ebx = 0, .ecx = 1 << 19, .edx = 0 }, leaf7));
    try testing.expect(!hasCpuidSha(leaf0, .{ .eax = 0, .ebx = 0, .ecx = 1 << 9, .edx = 0 }, leaf7));
    try testing.expect(!hasCpuidSha(leaf0, leaf1, .{ .eax = 0, .ebx = ~@as(u32, 1 << 29), .ecx = 0, .edx = 0 }));
    // No leaf 7 at all: older than any CPU with SHA-NI.
    try testing.expect(!hasCpuidSha(.{ .eax = 6, .ebx = 0, .ecx = 0, .edx = 0 }, leaf1, leaf7));
}
