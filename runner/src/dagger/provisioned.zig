//! The default image with `set_up.provision_script` already run, published to GHCR by the
//! "provisioned image" workflow and pinned by digest (provisioned_pin.zig): a pull instead of an
//! `apt-get install` that takes 22 to 45 s and needs Ubuntu's mirrors.
//!
//! One image per way steps run: `root` (`provision_script`) and `runner` (`provision_runner_script`,
//! which adds the step user). Each is tagged by its `fingerprint`, a hash of the script and of the
//! image it runs on, so a changed script, or a new Ubuntu digest, names an image that does not
//! exist yet. The pin carries the fingerprint it was published for, and `choose` gives the image
//! only when that is still the current one: a stale pin means provisioning with apt, never running
//! an image the current script did not make. A test fails the build in that state, so it is a pull
//! request's to fix (`provisioned-pin.sh --update`), not a runner's to find.
//!
//! Dagger `from`s the reference and skips the provisioning exec; the native backend pulls it as
//! any image (`Backend.fetchRootfs`). Either falls back to provisioning when the pull fails.

const std = @import("std");
const set_up = @import("set_up.zig");
const default_image = @import("../dagger.zig").default_image;
const pin = @import("provisioned_pin.zig");

pub const Pin = pin.Pin;

/// Both variants' pins, and the repository they are in (the tests' registry, in the tests).
pub const Pins = struct {
    root: Pin,
    runner: Pin,
    repository: []const u8 = repository,
};

/// What this build was released with.
pub const pinned: Pins = .{ .root = pin.root, .runner = pin.runner };

/// Where the images are, one tag per variant and fingerprint: `<fingerprint>-root`.
pub const repository = "ghcr.io/open-blue/zig-runner-base";

pub const Variant = enum {
    root,
    runner,

    pub fn of(as_runner: bool) Variant {
        return if (as_runner) .runner else .root;
    }

    /// The script the image is made by: the one a locally provisioned base runs.
    pub fn script(v: Variant) []const u8 {
        return switch (v) {
            .root => set_up.provision_script,
            .runner => set_up.provision_runner_script,
        };
    }

    fn pinOf(v: Variant, pins: Pins) Pin {
        return switch (v) {
            .root => pins.root,
            .runner => pins.runner,
        };
    }
};

pub const fingerprint_len = 12;

/// The script and the image it runs on, hashed: `sha256(default_image ++ "\n" ++ script)`, 12 hex
/// digits. Not the installed packages' fingerprint (`set_up.package_fingerprint_script`), which
/// follows the archive's day and so cannot be known before the image is built; the workflow logs
/// that one.
pub fn fingerprint(v: Variant) [fingerprint_len]u8 {
    var h: std.crypto.hash.sha2.Sha256 = .init(.{});
    h.update(default_image);
    h.update("\n");
    h.update(v.script());
    var digest: [32]u8 = undefined;
    h.final(&digest);
    return std.fmt.bytesToHex(digest[0 .. fingerprint_len / 2].*, .lower);
}

/// What `pins` says of `v`.
pub const Choice = union(enum) {
    /// `<repository>:<fingerprint>-<variant>@<digest>`.
    image: []const u8,
    /// Nothing is pinned.
    unpinned,
    /// The pin is for another script or base image than this build's.
    stale,
};

pub fn choose(arena: std.mem.Allocator, pins: Pins, v: Variant) !Choice {
    const p = v.pinOf(pins);
    if (p.digest.len == 0) return .unpinned;
    const now = fingerprint(v);
    if (!std.mem.eql(u8, p.fingerprint, &now)) return .stale;
    return .{ .image = try std.fmt.allocPrint(arena, "{s}:{s}-{s}@{s}", .{
        pins.repository, p.fingerprint, @tagName(v), p.digest,
    }) };
}

/// The image to pull for a job or the warm, or null to provision with apt. `enabled` is the
/// operator's setting (`RUNNER_PROVISIONED_IMAGE`).
pub fn reference(arena: std.mem.Allocator, enabled: bool, pins: Pins, v: Variant) !?[]const u8 {
    if (!enabled) return null;
    return switch (try choose(arena, pins, v)) {
        .image => |ref| ref,
        .unpinned, .stale => null,
    };
}

/// "Set up job" when the image was used.
pub fn usedNote(arena: std.mem.Allocator, ref: []const u8) ![]const u8 {
    return std.fmt.allocPrint(arena, "Provisioned image: {s} (no apt-get install)", .{ref});
}

/// "Set up job" when it could not be pulled.
pub fn fallbackNote(arena: std.mem.Allocator, ref: []const u8, why: []const u8) ![]const u8 {
    return std.fmt.allocPrint(
        arena,
        "Provisioned image: could not pull {s} ({s}); provisioning with apt-get instead",
        .{ ref, why },
    );
}

/// What `--provisioned-image=VARIANT` prints for the workflow, which builds the image from it:
/// the image to build on and the fingerprint to tag with.
pub fn describe(w: *std.Io.Writer, v: Variant) !void {
    try w.print("{s} {s}\n", .{ default_image, fingerprint(v) });
}

test "the fingerprint follows the script and the image, and names each variant apart" {
    const root = fingerprint(.root);
    const runner = fingerprint(.runner);
    try std.testing.expect(!std.mem.eql(u8, &root, &runner));
    for (root) |c| try std.testing.expect(std.ascii.isHex(c));
    var h: std.crypto.hash.sha2.Sha256 = .init(.{});
    h.update(default_image ++ "\n" ++ set_up.provision_script);
    var d: [32]u8 = undefined;
    h.final(&d);
    const want = std.fmt.bytesToHex(d, .lower);
    try std.testing.expectEqualStrings(want[0..fingerprint_len], &root);
}

test "a pin is used only for the script and image it was published for" {
    var a: std.heap.ArenaAllocator = .init(std.testing.allocator);
    defer a.deinit();
    const arena = a.allocator();
    const digest = "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
    const root_fp = fingerprint(.root);
    const current: Pins = .{
        .root = .{ .fingerprint = &root_fp, .digest = digest },
        .runner = .{ .fingerprint = "", .digest = "" },
    };
    // Current: pulled by tag and digest.
    const ref = (try reference(arena, true, current, .root)).?;
    try std.testing.expectEqualStrings(repository ++ ":" ++ root_fp ++ "-root@" ++ digest, ref);
    // The operator turned it off.
    try std.testing.expect((try reference(arena, false, current, .root)) == null);
    // Nothing pinned for the runner variant: apt.
    try std.testing.expect(try choose(arena, current, .runner) == .unpinned);
    try std.testing.expect((try reference(arena, true, current, .runner)) == null);
    // A pin made for another script (or another Ubuntu digest) is stale, whatever its digest.
    const stale: Pins = .{
        .root = .{ .fingerprint = "000000000000", .digest = digest },
        .runner = current.runner,
    };
    try std.testing.expect(try choose(arena, stale, .root) == .stale);
    try std.testing.expect((try reference(arena, true, stale, .root)) == null);
}

test "the pins this build carries are for its provision scripts (provisioned-pin.sh --update after a change)" {
    var a: std.heap.ArenaAllocator = .init(std.testing.allocator);
    defer a.deinit();
    for ([_]Variant{ .root, .runner }) |v| {
        // An empty digest pins none, which is allowed; a pin of a script that has changed is not.
        try std.testing.expect(try choose(a.allocator(), pinned, v) != .stale);
        const p = v.pinOf(pinned);
        if (p.digest.len > 0) try std.testing.expect(std.mem.startsWith(u8, p.digest, "sha256:") and p.digest.len == 71);
    }
}
