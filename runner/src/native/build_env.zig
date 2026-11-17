//! What a Dockerfile build asks of the job it is made for, as plain data and one small interface
//! (#448): the build (`docker_action.zig`: the planner's world, `BuildRunner`, `buildImage`,
//! `buildApi`) reads nothing of `Backend` but this. A Docker action's build makes it from the
//! job's `Backend` in its own process (`docker_action.Adapter`); the builder process of the Docker
//! API (`native-build`) makes it from a request, with a `Host` of its own. Nothing here points into
//! a `Backend`, and a build's own results (why a plan was refused) are the `Env`'s.

const std = @import("std");
const images = @import("images.zig");
const sandbox = @import("sandbox.zig");
const Store = @import("Store.zig");

const Allocator = std.mem.Allocator;

pub const Env = struct {
    io: std.Io,
    gpa: Allocator,
    /// What lives as long as the job's lists that the store's calls grow (`held`, the sync log).
    arena: Allocator,
    /// The job's directory: where a build's layers begin and its scratch directories are.
    dir: []const u8,
    store_cfg: Store,
    /// The locks of the layers the job uses, held until it ends.
    held: *std.ArrayList(std.Io.File),
    /// The job's trust scope and how its ids are mapped (the userns mode's name), in every key.
    scope: []const u8,
    userns: []const u8,
    /// A root runner's mapped ids: a `RUN`'s layer is given the canonical ids afterwards.
    mapped: bool,
    id_base: u32,
    slot_ids: Store.Ids,
    /// The image directory, if the runner has one (tests, operators), and the pulled tags' ttl.
    images_dir: []const u8,
    image_tag_ttl_s: u32,
    opaque_xattr: [:0]const u8,
    /// Why the last plan was refused.
    build_reason: []const u8 = "",
    host: *Host,
};

/// What a build cannot do for itself: run a `RUN` (in a sandbox, in the job's cgroup), and say what
/// the job's own images are.
pub const Host = struct {
    runFn: *const fn (h: *Host, call: RunCall) anyerror!sandbox.Ended,
    localImageFn: *const fn (h: *Host, arena: Allocator, ref: []const u8) anyerror!?LocalImage,
    planFn: *const fn (h: *Host, call: PlanCall) anyerror!sandbox.Ended,

    pub fn run(h: *Host, call: RunCall) !sandbox.Ended {
        return h.runFn(h, call);
    }

    pub fn plan(h: *Host, call: PlanCall) !sandbox.Ended {
        return h.planFn(h, call);
    }

    pub fn localImage(h: *Host, arena: Allocator, ref: []const u8) !?LocalImage {
        return h.localImageFn(h, arena, ref);
    }
};

pub const RunCall = struct {
    argv: []const []const u8,
    env: []const []const u8,
    /// The `RUN`'s working directory.
    workdir: []const u8,
    container: sandbox.Spec.Container,
    /// A build the job's Docker API makes runs its `RUN`s under its own (`Api.running`); null for a
    /// Docker action's.
    running: ?*sandbox.Running,
    out: sandbox.Output,
};

/// The planner's run (`planner.zig`): in a root of its own (made under the job's directory, `dir`
/// relative to it), with the spooled tar, the context and the plan directory bound in, confined.
pub const PlanCall = struct {
    /// `px-<n>` under the job's directory: `root`, `upper`, `work`, `merged` and `plan` below it.
    dir: []const u8,
    tar: []const u8,
    ctx: []const u8,
    running: *sandbox.Running,
    out: sandbox.Output,
};

/// An image the job built and tagged: a later `FROM` of it starts here.
pub const LocalImage = struct { config: images.Image, id: []const u8 };
