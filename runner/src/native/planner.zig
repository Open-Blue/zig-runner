//! The planner of an API build (`native-parse`, #448, design revision 2): the one process that
//! reads the client's bytes. It runs confined (`sandbox.Spec.confined`: its own pid, mount and empty
//! network namespaces, no capability, `no_new_privs`, Docker's seccomp profile, a root of nothing
//! but the spooled tar, the context directory and the plan directory), unpacks the tar into the
//! context directory (`docker_build.unpack`), reads and plans the Dockerfile
//! (`dockerfile.planWith`), and writes **one frame** (`build_frames.Out`) to `/plan/out.bin`: a plan
//! with no key and no host path in it, or the bases it needs, or why it cannot. The privileged side
//! reads the frame as hostile input (`build_frames.decode`) after this process is dead.
//!
//! What it cannot do: reach the store, the network, the runner or another job; what a bug in it
//! gives is a confined process that writes two directories of one build.

const std = @import("std");
const dockerfile = @import("dockerfile.zig");
const images = @import("images.zig");
const docker_build = @import("docker_build.zig");
const layer_view = @import("layer_view.zig");
const frames = @import("build_frames.zig");

const Allocator = std.mem.Allocator;

pub const command = "native-parse";

/// The paths inside the planner's root (`docker_action.Adapter.planFn` binds them).
pub const request_at = "/plan/request.json";
pub const out_at = "/plan/out.bin";
pub const tar_at = "/spool.tar";
pub const context_at = "/ctx";

const max_request = 4 << 20;

/// `native-parse <request> <tar> <context> <out>`: 0 when a frame was written (whatever it says).
pub fn main(arena: Allocator, io: std.Io, args: []const []const u8) u8 {
    if (args.len != 4) return 2;
    const out = run(arena, io, args[0], args[1], args[2]) catch |e| frames.Out{
        .status = .failed,
        .why = std.fmt.allocPrint(arena, "the planner failed: {s}", .{@errorName(e)}) catch "the planner failed",
    };
    const bytes = frames.encode(arena, out) catch return 3;
    std.Io.Dir.cwd().writeFile(io, .{ .sub_path = args[3], .data = bytes }) catch return 4;
    return 0;
}

fn run(arena: Allocator, io: std.Io, request_path: []const u8, tar: []const u8, ctx_dir: []const u8) !frames.Out {
    const cwd = std.Io.Dir.cwd();
    const text = try cwd.readFileAlloc(io, request_path, arena, .limited(max_request));
    const req = try std.json.parseFromSliceLeaky(frames.Request, arena, text, .{
        .ignore_unknown_fields = false,
        .allocate = .alloc_always,
    });
    // The context: unpacked the first time (the directory is empty); the rounds after find it.
    var empty = true;
    {
        var d = cwd.openDir(io, ctx_dir, .{ .iterate = true }) catch return error.NoContext;
        defer d.close(io);
        var it = d.iterate();
        if (try it.next(io)) |_| empty = false;
    }
    if (empty) {
        var why: []const u8 = "";
        _ = docker_build.unpack(arena, io, ctx_dir, tar, .{}, null, &why) catch |e| switch (e) {
            error.BadContext => return .{ .status = .failed, .why = why },
            else => return e,
        };
    }
    const view = (try layer_view.View.open(arena, io, &.{ctx_dir}, "", "user.overlay.opaque")) orelse
        return .{ .status = .failed, .why = "the build context is empty" };
    defer view.close();
    const missing = try std.fmt.allocPrint(arena, "Cannot locate specified Dockerfile: {s}", .{req.dockerfile});
    const df = (try view.resolve(req.dockerfile, true)) orelse return .{ .status = .failed, .why = missing };
    if (df.kind != .file) return .{ .status = .failed, .why = missing };
    const dockerfile_text = try df.parent().readFileAlloc(io, df.name, arena, .limited(1 << 20));

    const ins = switch (try dockerfile.parse(arena, dockerfile_text)) {
        .ok => |i| i,
        .refused => |r| return .{ .status = .refused, .line = r.line, .why = r.why },
    };
    var world: World = .{ .arena = arena, .req = req };
    var args: std.ArrayList(dockerfile.Var) = .empty;
    for (req.build_args) |p| try args.append(arena, .{ .name = p.name, .value = p.value });
    var labels: std.ArrayList(dockerfile.Var) = .empty;
    for (req.labels) |p| try labels.append(arena, .{ .name = p.name, .value = p.value });
    // The salt is the executor's (it makes the keys): none here.
    const planned = try dockerfile.planWith(arena, ins, &world.bases, &world.context, .{
        .build_args = args.items,
        .target = req.target,
        .labels = labels.items,
    });
    if (world.need.items.len > 0) return .{ .status = .need, .need = world.need.items };
    const plan = switch (planned) {
        .ok => |p| p,
        .refused => |r| return .{ .status = .refused, .line = r.line, .why = r.why },
    };
    for (plan.stages) |stage| for (stage.steps) |st| if (st.op == .run and !images.runsAsRoot(st.op.run.user))
        return .{
            .status = .refused,
            .line = st.line,
            .why = try std.fmt.allocPrint(arena, "a RUN as USER {s} is not native yet", .{st.op.run.user}),
        };
    const lite = try arena.alloc(frames.Ins, ins.len);
    for (ins, lite) |x, *l| l.* = .{ .line = x.line, .kind = x.kind, .text = x.text };
    return .{ .status = .plan, .plan = try cleaned(arena, plan), .ins = lite };
}

/// The plan as the wire carries it: the keys the planner made mean nothing and are zeroed, so
/// no byte of them is the planner's say.
fn cleaned(arena: Allocator, plan: dockerfile.Plan) !dockerfile.Plan {
    const stages = try arena.dupe(dockerfile.Stage, plan.stages);
    for (stages) |*st| {
        st.key = @splat('0');
        const steps = try arena.dupe(dockerfile.Step, st.steps);
        for (steps) |*s| s.key = @splat('0');
        st.steps = steps;
        st.config.rootfs = "";
    }
    return .{ .stages = stages, .final = plan.final };
}

/// What the planner asks of the world, answered by the request (the bases the executor has
/// resolved) and by nothing else: a base it does not have is asked for (`need`), the context's
/// files are not read (the executor digests them), an `ADD`'s URL is not fetched (no network).
const World = struct {
    arena: Allocator,
    req: frames.Request,
    need: std.ArrayList([]const u8) = .empty,
    bases: dockerfile.Bases = .{ .resolveFn = resolve },
    context: dockerfile.Context = .{ .digestFn = digest, .fetchFn = fetch },

    fn resolve(iface: *dockerfile.Bases, arena: Allocator, ref: []const u8, why: *[]const u8) anyerror!?dockerfile.BaseImage {
        const w: *World = @fieldParentPtr("bases", iface);
        for (w.req.bases, 0..) |b, i| if (std.mem.eql(u8, b.ref, ref)) {
            if (b.missing.len > 0) {
                why.* = b.missing;
                return null;
            }
            var cfg = b.config;
            cfg.rootfs = try std.fmt.allocPrint(arena, "/base/{d}", .{i});
            // A job's own image has layers the planner is only told of: `COPY --from` it is refused.
            if (b.local) cfg.layers = &.{"/local"};
            return .{ .config = cfg, .id = "" };
        };
        for (w.need.items) |n| if (std.mem.eql(u8, n, ref)) return placeholder();
        try w.need.append(w.arena, try w.arena.dupe(u8, ref));
        return placeholder();
    }

    fn placeholder() dockerfile.BaseImage {
        return .{ .config = .{ .rootfs = "/base/0" }, .id = "" };
    }

    fn digest(_: *dockerfile.Context, _: Allocator, _: []const []const u8) anyerror![64]u8 {
        return @splat('0');
    }

    fn fetch(_: *dockerfile.Context, _: Allocator, _: []const u8) anyerror!dockerfile.Fetched {
        return .{ .file = "", .digest = @splat('0') };
    }
};
