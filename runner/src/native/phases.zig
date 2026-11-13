//! Where a native job's time goes: each phase of its set-up, of every sandbox a step runs in, of
//! every layer it publishes, and of its teardown, as samples in microseconds. "Set up job" shows
//! the set-up phases and each step its own with step debug (ACTIONS_STEP_DEBUG); the runner's log
//! gets one line per job with all of them (`summary`), which .github/scripts/native-phases.sh
//! turns into per-phase medians.
//!
//! The helper's own phases (its namespaces, idmapped lowers, overlay, binds and the step's root)
//! come back on its stderr as one line (`Helper`), on the host's monotonic clock, which the runner
//! and its helper share.

const std = @import("std");
const linux = std.os.linux;

const Allocator = std.mem.Allocator;

pub const Phase = enum {
    // The job's set-up (`Backend.initWhy`, then `Backend.base`).
    store,
    sweep,
    dir,
    cgroup,
    resolver,
    slot,
    nat,
    netns,
    image,
    provision,
    caches,
    actions,
    base,
    // Each exec: its key claimed, then its sandbox (`sandbox.run`): the helper started and given
    // its spec, its namespaces, the lowers idmapped, the overlay, the binds, the step's own
    // namespaces and root up to its first process, the step itself, and the helper's end.
    claim,
    spawn,
    namespaces,
    idmap,
    overlay,
    binds,
    root,
    run,
    exit,
    // Each layer published (`Backend.publishTop`, `Store.publish`).
    unshift,
    size,
    record,
    sync,
    // The sync's parts: the write-back wait, the entries' fsyncs, the meta's write and fsync, and
    // `syncfs`, which is there only when the entry took it (too many entries, or a file unreadable).
    sync_wb,
    sync_fsync,
    sync_meta,
    syncfs,
    rename,
    flatten,
    // The job's teardown (`Backend.deinit`).
    // The job's last layer made durable (`Store.settlePending`), after its result was reported; also
    // sampled by a publish that makes the job's previous one durable.
    settle,
    services,
    cgroup_rm,
    // The tool cache's trees walked once no job holds them (`Backend.walkToolCacheIdle`).
    tool_walk,
    veth_rm,
    tree_rm,
    // The parts of `collect`, which is the whole of what follows the job's directory: the layers'
    // use marked and its locks let go, the layers' directory synced, then `Store.collect`'s scan
    // of the layers, its evictions, and the rest (key locks, the step index, the other areas).
    collect_touch,
    collect_syncdir,
    collect_scan,
    collect_evict,
    collect_rest,
    collect,

    pub fn setUp(p: Phase) bool {
        return @backingInt(p) <= @backingInt(Phase.base);
    }
};

const phases_in_order = std.enums.values(Phase);
const n = phases_in_order.len;

/// Nanoseconds on the host's monotonic clock: the runner's and its helpers' alike.
pub fn now() u64 {
    var ts: linux.timespec = undefined;
    _ = linux.clock_gettime(.MONOTONIC, &ts);
    const sec = std.math.cast(u64, ts.sec) orelse 0;
    const nsec = std.math.cast(u64, ts.nsec) orelse 0;
    return sec * std.time.ns_per_s + nsec;
}

pub const Phases = struct {
    samples: [n]std.ArrayList(u32) = @splat(.empty),

    /// One sample of `p`, from `from` (`now`) to now; returns now, the next phase's start.
    pub fn since(ps: *Phases, arena: Allocator, p: Phase, from: u64) u64 {
        const t = now();
        ps.add(arena, p, t -| from);
        return t;
    }

    pub fn add(ps: *Phases, arena: Allocator, p: Phase, ns: u64) void {
        const us = std.math.cast(u32, ns / std.time.ns_per_us) orelse std.math.maxInt(u32);
        ps.samples[@backingInt(p)].append(arena, us) catch {};
    }

    /// The helper's phases (`Helper`), between `spawned` (before it was started) and `ended` (once
    /// it was waited for).
    pub fn helper(ps: *Phases, arena: Allocator, h: Helper, spawned: u64, ended: u64) void {
        if (h.start == 0) return;
        ps.add(arena, .spawn, h.start -| spawned);
        ps.add(arena, .namespaces, h.namespaces -| h.start);
        ps.add(arena, .idmap, h.idmap -| h.namespaces);
        ps.add(arena, .overlay, h.overlay -| h.idmap);
        ps.add(arena, .binds, h.binds -| h.overlay);
        ps.add(arena, .root, h.root -| h.binds);
        ps.add(arena, .run, h.end -| h.root);
        ps.add(arena, .exit, ended -| h.end);
    }

    /// How many samples each phase has: a mark that `write` then shows only what came after.
    pub const Mark = [n]u32;

    pub fn mark(ps: *const Phases) Mark {
        var m: Mark = undefined;
        for (&m, ps.samples) |*c, s| c.* = std.math.cast(u32, s.items.len) orelse std.math.maxInt(u32);
        return m;
    }

    /// `name=ms` for each phase `which` takes that has samples since `from`, its samples joined by
    /// commas, in milliseconds to a tenth.
    pub fn write(
        ps: *const Phases,
        w: *std.Io.Writer,
        from: ?Mark,
        which: enum { all, set_up, steps },
    ) std.Io.Writer.Error!void {
        var first = true;
        for (ps.samples, phases_in_order, 0..) |s, p, i| {
            switch (which) {
                .all => {},
                .set_up => if (!p.setUp()) continue,
                .steps => if (p.setUp()) continue,
            }
            const start = if (from) |m| m[i] else 0;
            if (s.items.len <= start) continue;
            if (!first) try w.writeByte(' ');
            first = false;
            try w.print("{s}=", .{@tagName(p)});
            for (s.items[start..], 0..) |us, k| {
                if (k > 0) try w.writeByte(',');
                try w.print("{d}.{d}", .{ us / 1000, us % 1000 / 100 });
            }
        }
    }

    /// What `p` sampled since `from` (`mark`) added up, in microseconds.
    pub fn sinceMark(ps: *const Phases, from: Mark, p: Phase) u64 {
        const i = @backingInt(p);
        if (ps.samples[i].items.len <= from[i]) return 0;
        var us: u64 = 0;
        for (ps.samples[i].items[from[i]..]) |v| us += v;
        return us;
    }

    /// The latest sample of `p`, in milliseconds; 0 when it has none.
    pub fn lastMs(ps: *const Phases, p: Phase) u64 {
        const s = ps.samples[@backingInt(p)].getLastOrNull() orelse return 0;
        return s / 1000;
    }

    /// The set-up phases' total, in milliseconds.
    pub fn setUpMs(ps: *const Phases) u64 {
        var us: u64 = 0;
        for (ps.samples, phases_in_order) |s, p| if (p.setUp()) {
            for (s.items) |v| us += v;
        };
        return us / 1000;
    }

    pub fn text(ps: *const Phases, arena: Allocator, from: ?Mark, which: anytype) ![]const u8 {
        var out: std.Io.Writer.Allocating = .init(arena);
        try ps.write(&out.writer, from, which);
        return out.written();
    }
};

/// The helper's marks, on the monotonic clock (`now`): its start (its spec read), then the end of
/// each phase. Rootless, the binds are made in the step's namespaces, so `binds` covers those and
/// `root` the rest. Zero when the helper said nothing (it failed first).
pub const Helper = struct {
    start: u64 = 0,
    namespaces: u64 = 0,
    idmap: u64 = 0,
    overlay: u64 = 0,
    binds: u64 = 0,
    root: u64 = 0,
    end: u64 = 0,

    /// What starts the helper's line on its stderr, which is otherwise only its failure.
    pub const prefix = "\x1ezig-runner phases ";

    /// The line the helper writes, from its own stack: it allocates nothing.
    pub fn line(h: Helper, buf: []u8) []const u8 {
        return std.fmt.bufPrint(buf, prefix ++ "{d} {d} {d} {d} {d} {d} {d}\n", .{
            h.start, h.namespaces, h.idmap, h.overlay, h.binds, h.root, h.end,
        }) catch "";
    }

    /// `text`, the helper's stderr, without its phases' line, and the marks that line held.
    pub fn take(text_in: []const u8) struct { rest: []const u8, helper: Helper } {
        const at = std.mem.indexOf(u8, text_in, prefix) orelse return .{ .rest = text_in, .helper = .{} };
        const end = if (std.mem.indexOfScalarPos(u8, text_in, at, '\n')) |e| e + 1 else text_in.len;
        var h: Helper = .{};
        var it = std.mem.tokenizeAny(u8, text_in[at + prefix.len .. end], " \n");
        inline for (.{ "start", "namespaces", "idmap", "overlay", "binds", "root", "end" }) |f| {
            @field(h, f) = std.fmt.parseInt(u64, it.next() orelse "0", 10) catch 0;
        }
        // Only the line's own bytes go: what came before and after it is the failure, if any.
        const rest = if (at == 0) text_in[end..] else if (end == text_in.len) text_in[0..at] else text_in;
        return .{ .rest = rest, .helper = h };
    }
};

test "phases: samples written by phase, from a mark, in milliseconds to a tenth" {
    var arena_state: std.heap.ArenaAllocator = .init(std.testing.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();
    var ps: Phases = .{};
    ps.add(arena, .cgroup, 1_250_000);
    ps.add(arena, .run, 12_000_000);
    const m = ps.mark();
    ps.add(arena, .run, 3_460_000);
    ps.add(arena, .sync, 900_000);
    try std.testing.expectEqualStrings("cgroup=1.2 run=12.0,3.4 sync=0.9", try ps.text(arena, null, .all));
    try std.testing.expectEqualStrings("cgroup=1.2", try ps.text(arena, null, .set_up));
    try std.testing.expectEqualStrings("run=3.4 sync=0.9", try ps.text(arena, m, .steps));
    try std.testing.expectEqual(@as(u64, 1), ps.setUpMs());
}

test "phases: the helper's line is taken out of its stderr, whatever else it said" {
    const h: Helper = .{ .start = 10, .namespaces = 20, .idmap = 30, .overlay = 40, .binds = 50, .root = 60, .end = 70 };
    var buf: [256]u8 = undefined;
    const l = h.line(&buf);
    const alone = Helper.take(l);
    try std.testing.expectEqualStrings("", alone.rest);
    try std.testing.expectEqual(h, alone.helper);
    const failed = try std.mem.concat(std.testing.allocator, u8, &.{ l, "native step: x failed (errno 2)" });
    defer std.testing.allocator.free(failed);
    const after = Helper.take(failed);
    try std.testing.expectEqualStrings("native step: x failed (errno 2)", after.rest);
    try std.testing.expectEqual(@as(u64, 70), after.helper.end);
    const none = Helper.take("native step: y failed (errno 1)\n");
    try std.testing.expectEqual(@as(u64, 0), none.helper.start);
    var ps: Phases = .{};
    var arena_state: std.heap.ArenaAllocator = .init(std.testing.allocator);
    defer arena_state.deinit();
    ps.helper(arena_state.allocator(), h, 5, 80);
    try std.testing.expectEqualStrings(
        "spawn=0.0 namespaces=0.0 idmap=0.0 overlay=0.0 binds=0.0 root=0.0 run=0.0 exit=0.0",
        try ps.text(arena_state.allocator(), null, .all),
    );
}
