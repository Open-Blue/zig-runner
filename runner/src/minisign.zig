//! Minisign signature checks (https://jedisct1.github.io/minisign/), natively: what the runner
//! uses to trust a Zig release tarball before it seeds Zig's global cache from it. Only the
//! prehashed algorithm (`ED`: Ed25519 over the file's BLAKE2b-512) is accepted, the one Zig's
//! releases are signed with; the legacy `Ed` (Ed25519 over the whole file) is refused.
const std = @import("std");
const Ed25519 = std.crypto.sign.Ed25519;
const Blake2b512 = std.crypto.hash.blake2.Blake2b512;
const base64 = std.base64.standard.Decoder;

pub const PublicKey = struct {
    key_id: [8]u8,
    key: Ed25519.PublicKey,

    /// The base64 line minisign prints for a public key: `Ed`, the key id, the Ed25519 key.
    pub fn parse(text: []const u8) error{InvalidPublicKey}!PublicKey {
        var raw: [42]u8 = undefined;
        const line = std.mem.trim(u8, text, " \r\n");
        if ((base64.calcSizeForSlice(line) catch 0) != raw.len) return error.InvalidPublicKey;
        base64.decode(&raw, line) catch return error.InvalidPublicKey;
        if (!std.mem.eql(u8, raw[0..2], "Ed")) return error.InvalidPublicKey;
        return .{
            .key_id = raw[2..10].*,
            .key = Ed25519.PublicKey.fromBytes(raw[10..42].*) catch return error.InvalidPublicKey,
        };
    }
};

pub const Error = error{ InvalidSignature, UnsupportedAlgorithm, WrongKey, BadSignature };

/// Checks a `.minisig` file's signature of `content`, and its trusted comment's, against `pk`.
/// Returns the trusted comment (a slice of `minisig`).
pub fn verify(pk: PublicKey, content: []const u8, minisig: []const u8) Error![]const u8 {
    var digest: [Blake2b512.digest_length]u8 = undefined;
    Blake2b512.hash(content, &digest, .{});
    return verifyDigest(pk, digest, minisig);
}

/// `verify` of content whose BLAKE2b-512 `digest` has been taken already (as it streamed in).
pub fn verifyDigest(pk: PublicKey, digest: [Blake2b512.digest_length]u8, minisig: []const u8) Error![]const u8 {
    var lines = std.mem.splitScalar(u8, minisig, '\n');
    const untrusted = lines.next() orelse return error.InvalidSignature;
    if (!std.mem.startsWith(u8, untrusted, "untrusted comment: ")) return error.InvalidSignature;
    var sig_raw: [74]u8 = undefined;
    try decodeLine(&sig_raw, lines.next());
    const trusted_line = std.mem.trimEnd(u8, lines.next() orelse "", "\r");
    const trusted_prefix = "trusted comment: ";
    if (!std.mem.startsWith(u8, trusted_line, trusted_prefix)) return error.InvalidSignature;
    const trusted = trusted_line[trusted_prefix.len..];
    var global: [64]u8 = undefined;
    try decodeLine(&global, lines.next());

    if (!std.mem.eql(u8, sig_raw[0..2], "ED")) return error.UnsupportedAlgorithm;
    if (!std.mem.eql(u8, sig_raw[2..10], &pk.key_id)) return error.WrongKey;
    const sig = sig_raw[10..74].*;
    Ed25519.Signature.fromBytes(sig).verify(&digest, pk.key) catch return error.BadSignature;
    // The global signature covers the signature and the trusted comment, so neither can be
    // swapped for another file's.
    var signed: [64 + 1024]u8 = undefined;
    if (trusted.len > signed.len - 64) return error.InvalidSignature;
    @memcpy(signed[0..64], &sig);
    @memcpy(signed[64..][0..trusted.len], trusted);
    Ed25519.Signature.fromBytes(global).verify(signed[0 .. 64 + trusted.len], pk.key) catch
        return error.BadSignature;
    return trusted;
}

fn decodeLine(out: []u8, line: ?[]const u8) error{InvalidSignature}!void {
    const l = std.mem.trimEnd(u8, line orelse return error.InvalidSignature, "\r");
    if ((base64.calcSizeForSlice(l) catch 0) != out.len) return error.InvalidSignature;
    base64.decode(out, l) catch return error.InvalidSignature;
}

/// A `.minisig` for `content` and a public key line, as minisign writes them, from a test key.
const Fixture = struct {
    pk: [56]u8,
    minisig: []const u8,

    fn make(
        arena: std.mem.Allocator,
        kp: Ed25519.KeyPair,
        content: []const u8,
        trusted: []const u8,
    ) !Fixture {
        const enc = std.base64.standard.Encoder;
        const key_id = [8]u8{ 1, 2, 3, 4, 5, 6, 7, 8 };
        var pk_raw: [42]u8 = undefined;
        @memcpy(pk_raw[0..2], "Ed");
        @memcpy(pk_raw[2..10], &key_id);
        @memcpy(pk_raw[10..], &kp.public_key.toBytes());
        var out: Fixture = .{ .pk = undefined, .minisig = "" };
        _ = enc.encode(&out.pk, &pk_raw);
        var digest: [64]u8 = undefined;
        Blake2b512.hash(content, &digest, .{});
        const sig = (try kp.sign(&digest, null)).toBytes();
        var sig_raw: [74]u8 = undefined;
        @memcpy(sig_raw[0..2], "ED");
        @memcpy(sig_raw[2..10], &key_id);
        @memcpy(sig_raw[10..], &sig);
        const signed = try std.mem.concat(arena, u8, &.{ &sig, trusted });
        const global = (try kp.sign(signed, null)).toBytes();
        var sig_b64: [100]u8 = undefined;
        var global_b64: [88]u8 = undefined;
        const format = "untrusted comment: test\n{s}\ntrusted comment: {s}\n{s}\n";
        out.minisig = try std.fmt.allocPrint(arena, format, .{
            enc.encode(&sig_b64, &sig_raw), trusted, enc.encode(&global_b64, &global),
        });
        return out;
    }
};

test "minisign: a test key's signature verifies; tampered content, signature or comment does not" {
    var a: std.heap.ArenaAllocator = .init(std.testing.allocator);
    defer a.deinit();
    const arena = a.allocator();
    const kp = try Ed25519.KeyPair.generateDeterministic(@splat(7));
    const blob = "zig-x86_64-linux-0.17.0.tar.xz, as a fixture";
    const f = try Fixture.make(arena, kp, blob, "timestamp:1 file:zig.tar.xz");
    const pk = try PublicKey.parse(&f.pk);
    try std.testing.expectEqualStrings("timestamp:1 file:zig.tar.xz", try verify(pk, blob, f.minisig));
    // Content changed by one byte.
    try std.testing.expectError(error.BadSignature, verify(pk, "zig-x86_64-linux-0.17.0.tar.xz, as a fixturf", f.minisig));
    // The trusted comment changed: the global signature no longer matches.
    const swapped = try std.mem.replaceOwned(u8, arena, f.minisig, "timestamp:1", "timestamp:2");
    try std.testing.expectError(error.BadSignature, verify(pk, blob, swapped));
    // A signature line from another file.
    const other = try Fixture.make(arena, kp, "another file", "timestamp:1 file:zig.tar.xz");
    var it = std.mem.splitScalar(u8, other.minisig, '\n');
    _ = it.next();
    const other_sig = it.next().?;
    var mine = std.mem.splitScalar(u8, f.minisig, '\n');
    _ = mine.next();
    const forged = try std.mem.replaceOwned(u8, arena, f.minisig, mine.next().?, other_sig);
    try std.testing.expectError(error.BadSignature, verify(pk, blob, forged));
    // Another key.
    const kp2 = try Ed25519.KeyPair.generateDeterministic(@splat(9));
    const f2 = try Fixture.make(arena, kp2, blob, "timestamp:1 file:zig.tar.xz");
    try std.testing.expectError(error.BadSignature, verify(pk, blob, f2.minisig));
    // Garbage, and a signature cut short.
    try std.testing.expectError(error.InvalidSignature, verify(pk, blob, "not a signature"));
    try std.testing.expectError(error.InvalidSignature, verify(pk, blob, f.minisig[0..40]));
    // The legacy, non-prehashed algorithm is refused.
    const legacy = try std.mem.replaceOwned(u8, arena, f.minisig, "\nRUQ", "\nRWQ");
    try std.testing.expect(!std.mem.eql(u8, legacy, f.minisig));
    try std.testing.expectError(error.UnsupportedAlgorithm, verify(pk, blob, legacy));
}

test "minisign: Zig's published public key parses" {
    const pk = try PublicKey.parse("RWSGOq2NVecA2UPNdBUZykf1CCb147pkmdtYxgb3Ti+JO/wCYvhbAb/U");
    try std.testing.expectEqual(@as(u8, 0x86), pk.key_id[0]);
    try std.testing.expectError(error.InvalidPublicKey, PublicKey.parse("RWSG"));
    // The same key under another algorithm's tag (`Et`, not `Ed`).
    try std.testing.expectError(error.InvalidPublicKey, PublicKey.parse("RXSGOq2NVecA2UPNdBUZykf1CCb147pkmdtYxgb3Ti+JO/wCYvhbAb/U"));
}

test "minisign: the trusted comment: its prefix, and up to 1024 bytes of it" {
    var a: std.heap.ArenaAllocator = .init(std.testing.allocator);
    defer a.deinit();
    const arena = a.allocator();
    const kp = try Ed25519.KeyPair.generateDeterministic(@splat(7));
    const blob = "a release";
    const longest = try arena.alloc(u8, 1024);
    @memset(longest, 'c');
    const f = try Fixture.make(arena, kp, blob, longest);
    const pk = try PublicKey.parse(&f.pk);
    try std.testing.expectEqualStrings(longest, try verify(pk, blob, f.minisig));
    // One byte more is refused before it is checked, signed or not.
    const too_long = try Fixture.make(arena, kp, blob, try std.mem.concat(arena, u8, &.{ longest, "c" }));
    try std.testing.expectError(error.InvalidSignature, verify(pk, blob, too_long.minisig));
    // Its line must say what it is.
    const short = try Fixture.make(arena, kp, blob, "timestamp:1");
    const renamed = try std.mem.replaceOwned(u8, arena, short.minisig, "\ntrusted comment: ", "\ntrusted_comment: ");
    try std.testing.expectError(error.InvalidSignature, verify(pk, blob, renamed));
}

pub const testing = struct {
    pub const fixture = Fixture.make;
};
