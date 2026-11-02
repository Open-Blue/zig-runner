//! The native backend for one job: its steps run in sandboxes of the runner's own (`sandbox.zig`)
//! instead of Dagger execs, each on an overlay of the layers the steps before it left
//! (docs/native-backend.md).
//!
//! It sits below the step script. Everything above it is the code the Dagger backend runs:
//! `dagger.runSteps` evaluates conditions, env, timeouts and `continue-on-error`,
//! `scripts.stepScriptFc` writes the same `sh -c` script, `JobLog` reads the same markers and
//! workflow commands, and `Exec.collect` applies the same file commands. What this file owns is
//! what the engine did: the base the steps start from, the container's environment between
//! steps, running one script, reading its combined file commands back, and on a root runner the
//! job's ids and network (`net.zig`).

const Backend = @This();

const std = @import("std");
const job_mod = @import("../job.zig");
const config = @import("../config.zig");
const dagger = @import("../dagger.zig");
const sandbox = @import("sandbox.zig");
const net = @import("net.zig");
const Store = @import("Store.zig");
const oci = @import("oci/image.zig");
const registry = @import("oci/registry.zig");
const ImageStore = @import("oci/Store.zig");
const http = @import("../github/http.zig");
const docker = @import("../dagger/docker.zig");
const cgroup = @import("cgroup.zig");
const volumes = @import("volumes.zig");
const admission = @import("../admission.zig");
const services = @import("services.zig");
const images = @import("images.zig");
const Exec = @import("../dagger/Exec.zig");
const Evaluator = @import("../dagger/Evaluator.zig");
const SpanDemux = @import("../dagger/JobLog.zig").SpanDemux;
const checkout = @import("../dagger/checkout.zig");
const scripts = @import("../dagger/scripts.zig");
const set_up = @import("../dagger/set_up.zig");

const Allocator = std.mem.Allocator;

arena: Allocator,
io: std.Io,
/// Backs each exec's log demultiplexer (`SpanDemux`), as for a direct Dagger session.
gpa: Allocator,
/// The job's directory under the store: its layers (`L<n>`, and `l<n>` linking to the store's,
/// `F<n>` flattened), the overlay work directory, the mount points, its lock and its network
/// namespace. Removed when the job ends.
dir: []const u8,
/// The lowest layer every step sees: the job's image, provisioned when it is the default one
/// (`prepareRootfs`), or the operator's rootfs.
rootfs: []const u8,
/// `Config.rootfs`: the operator's provisioned default image, used instead of a native pull of
/// it; "" for none.
operator_rootfs: []const u8 = "",
/// The job's image, once pulled (`prepareRootfs`); null with the operator's rootfs.
image: ?oci.Image = null,
/// The image's own env (`NAME=value`), which every step starts from.
image_env: []const []const u8 = &.{"PATH=" ++ image_path},
/// Who the image's `USER` is, for steps that do not run as the runner user.
image_uid: u32 = 0,
image_gid: u32 = 0,
/// A `container:` job's PATH once its env is set (`dagger.Base.runtime_path`).
runtime_path: ?[]const u8 = null,
/// What "Set up job" says of the image and its provisioning, the job's cgroup and its caches.
notes: std.ArrayList([]const u8) = .empty,
binds: []const sandbox.Spec.Bind,
/// The host's resolver and hosts file over the image's (`jobBinds`), in `binds` too; services get
/// these and `service_binds` (`serviceBinds`).
etc_binds: []const sandbox.Spec.Bind = &.{},
service_binds: []const sandbox.Spec.Bind = &.{},
/// `Config.images`: the tests' images directory, "" to pull (`pullImage`).
images_dir: []const u8 = "",
/// This binary, for helpers that are not a step's (`forward.zig`).
self_exe: []const u8 = "",
/// The job's running services (`services.zig`), stopped however the job ends (`deinit`).
service_set: services.Set = .{},
/// Held while the job runs (`lock`): a directory whose lock is free is stale (`sweep`).
lock: std.Io.File,
/// The overlay's layers above the rootfs, oldest first.
layers: std.ArrayList(Layer) = .empty,
/// The number in the next layer's name (`L<n>`, `l<n>`, `F<n>`): never reused in a job, as a
/// flattened stack restarts the list.
next_layer: u32 = 0,
/// The layer store, under step caching (`Options.step_cache`, decided in `base`); null otherwise,
/// and the job's layers stay its own.
store: ?Store = null,
/// The store's settings, for `base` to turn it on.
store_cfg: Store = .{ .root = "" },
/// `Config.vouched`, and the job's cache scope and repository from it (`base`): a vouched fork's
/// pull request keys its layers apart from its repository's own jobs, as its package caches are
/// (`set_up.packageCacheScope`).
vouched: bool = false,
scope: []const u8 = "untrusted",
repository: []const u8 = "",
/// The store's layers the job uses, held shared until it ends (`Store.Layer`).
held: std.ArrayList(std.Io.File) = .empty,
/// Past this many layers, the stack is merged into one (`flatten`).
flatten_at: usize = default_flatten_at,
/// `abort` while an exec waits for its key's lock (`Store.lockKey`): the wait ends.
waiting: std.atomic.Value(bool) = .init(false),
stop_wait: std.atomic.Value(bool) = .init(false),
/// The container's environment: what Dagger's container held between execs (the image's, the
/// runner's defaults, the job's `env:`, and what `GITHUB_ENV` and `GITHUB_PATH` added).
env: std.ArrayList(job_mod.EnvVar) = .empty,
/// Who steps run as, and where they start.
uid: u32 = 0,
gid: u32 = 0,
workdir: []const u8 = "/",
how: Launch,
/// On a root runner: the job's slot (its range of ids and its address), held by a lock, and its
/// network namespace's file.
slot: ?Slot = null,
netns: ?[]const u8 = null,
/// `Config.subid_base`: the job's ids start at it plus its slot's offset (`idBase`).
subid_base: u32 = default_subid_base,
/// `Config.subnet`: the job's address is its slot's in it.
subnet: net.Subnet = .default,
running: sandbox.Running = .{},
/// The job's cgroup (`cgroup.zig`), when it has one; its events as last seen, so a step is told
/// of the OOM kills and refused forks that happened while it ran.
job_cgroup: ?cgroup.Job = null,
limits: cgroup.Limits = .{ .memory_max = null, .pids_max = null },
oom_kills: u64 = 0,
pids_max_hits: u64 = 0,
/// `Config.gate`: told of the job's cgroup, which it measures the job in.
gate: ?*admission.Gate = null,
/// What the job's options say of caches, and what it got of them (`setUpCaches`).
caches: volumes.Options = .{},
cache_plan: volumes.Plan = .{},
/// The Zig cache seeds' layers, between the job's layers and the rootfs.
seed_layers: std.ArrayList([]const u8) = .empty,
/// Tests: the Zig cache seed's build, in place of downloading and running a Zig release.
test_seed_script: ?[]const u8 = null,

/// What the runner configures (`RUNNER_BACKEND=native`).
pub const Config = struct {
    /// A directory holding the default image's filesystem, provisioned (`set_up.provision_script`,
    /// or `provision_runner_script` for the runner user), used instead of pulling and provisioning
    /// it natively; "" to pull it (`RUNNER_NATIVE_ROOTFS`).
    rootfs: []const u8 = "",
    /// Where jobs' layers live while they run, and pulled images and provisioned rootfs
    /// (`RUNNER_NATIVE_STORE`).
    store: []const u8 = "",
    /// This binary, which runs each step's sandbox (`sandbox.command`).
    self_exe: []const u8 = "",
    /// The runner vouches for the job (`trust.vouches`). Jobs it does not vouch for run natively
    /// only once `job_limits` holds, on a root runner (`untrustedRefusal`).
    vouched: bool = false,
    /// Each job runs in a cgroup of its own with `memory.max` and `pids.max` (phase 4): set by
    /// `configFor` when there is a parent to make it under and neither limit is configured away.
    /// False, a job the runner does not vouch for runs on Dagger, where a fork bomb or a memory
    /// hog stays in the engine's limits.
    job_limits: bool = false,
    /// Rootless native steps (`RUNNER_NATIVE_ROOTLESS`): only root is mapped inside, so apt's
    /// `_apt`, `chown` to other users and `tar` with owners fail, and steps share the host's
    /// network. Off: a rootless runner sends every job to Dagger.
    rootless: bool = false,
    /// The first host id of the jobs' ranges on a root runner (`RUNNER_NATIVE_SUBID_BASE`): slot
    /// n's 65536 ids start at `subid_base + n * 65536`.
    subid_base: u32 = default_subid_base,
    /// The jobs' network on a root runner (`RUNNER_NATIVE_SUBNET`). The bridge is the host's, so
    /// every runner on a host must use the same one.
    subnet: net.Subnet = .default,
    /// Host paths mounted into every step. Tests bind the host's /usr into a rootfs of a few
    /// directories; phase 4's cache volumes will be these.
    binds: []const sandbox.Spec.Bind = &.{},
    /// Past this many bytes, the store's least recently used layers go
    /// (`RUNNER_NATIVE_STORE_MAX_MB`, `Store.collect`).
    store_max_bytes: u64 = Store.default_max_bytes,
    /// Tests: the stack of layers is flattened past this many (`flatten`).
    flatten_at: usize = default_flatten_at,
    /// Tests: services' images from a directory filled ahead (`images.find`: `rootfs/` and
    /// `config.json` per reference) instead of P3's pull; "" pulls them, as in production.
    images: []const u8 = "",
    /// Host paths mounted into every service: tests bind the host's /usr into a fixture image.
    service_binds: []const sandbox.Spec.Bind = &.{},
    /// Tests: services on a rootless runner, in the host's network, as its steps are. Never
    /// configurable: a service listening there would be the host's neighbours' to reach.
    test_rootless_services: bool = false,
    /// Tests: `init` fails once the job's lock is the Backend's, as a failed network does.
    test_fail_after_lock: bool = false,
    /// Where the jobs' cgroups go and their limits (`RUNNER_NATIVE_CGROUP`,
    /// `RUNNER_NATIVE_MEMORY_MAX_MB`, `RUNNER_NATIVE_PIDS_MAX`).
    cgroup: cgroup.Config = .{},
    /// The runner's place at the memory gate: told of the job's cgroup (`admission.Gate.native`).
    gate: ?*admission.Gate = null,
    /// Tests: see `Backend.test_seed_script`.
    test_seed_script: ?[]const u8 = null,
    /// Tests: off, as their stores are under a checkout a non-root user owns
    /// (`Store.Prepare.check_parents`).
    check_store_parents: bool = true,
};

/// One layer of the job's overlay.
pub const Layer = struct {
    /// Its name in the job's directory, as overlay's `lowerdir=` takes it (`Spec.lowers`): short
    /// however long the store's path, so a hundred layers keep the mount's options under a page.
    name: []const u8,
    /// Where it is, for the runner's reads (`readFile`): in the job's directory, or the store's.
    path: []const u8,
    /// The key of the state the stack up to this layer is (`keyFor`), when it is in the store:
    /// replayed from it or published to it. Only a stored layer's key is a parent's.
    key: ?Store.Key = null,
    /// On a root runner, whether its files have the canonical ids (0 to 65535, as the job's
    /// namespace sees them: `Store.unshift`), so every step sees it through the job's ids, an
    /// idmapped mount (`Spec.canonical`). A stored layer has, and so does a flattened one; the
    /// job's own uppers, not published, keep its slot's host ids. Rootless, ids are never shifted.
    canonical: bool = false,
    /// Its shift to the canonical ids failed part way (`canonicalize`): never shifted again.
    poisoned: bool = false,
};

/// Past systemd's ranges: its containers' (systemd-nspawn's private users and nsresourced's,
/// 524288 to 1879048191) end below it, and its foreign range (2147352576 onwards) starts above
/// the last slot's ids (1916383999), which stay below 2^31 for tools that take ids as signed.
pub const default_subid_base: u32 = 1_900_000_000;
/// Every id below it may be a host user's or group's (`useradd` gives up to 60000, and LDAP or
/// SSSD ranges commonly start at 10000 or 100000).
pub const min_subid_base: u32 = 100_000;
/// The ids each job has on a root runner: 0 to 65535, as an image expects.
pub const ids_per_slot: u32 = 65536;

/// The first on-disk id of the cache volumes' files on a root runner (`volumes.zig`): the range
/// just past the last slot's, owned by no host user and by no job, which each job sees as its
/// own ids through an idmapped mount.
pub fn volumeIdBase(subid_base: u32) u32 {
    return subid_base + net.max_slots * ids_per_slot;
}

/// The native backend's settings from the runner's, or null when it runs steps on Dagger alone.
pub fn configFor(
    arena: Allocator,
    io: std.Io,
    environ: *const std.process.Environ.Map,
    cfg: *const config.Config,
    vouched: bool,
) !?Config {
    if (cfg.backend != .native) return null;
    const cg: cgroup.Config = .{
        .parent = cfg.native_cgroup,
        .memory_max_mb = cfg.native_memory_max_mb,
        .pids_max = cfg.native_pids_max,
    };
    return .{
        .rootfs = cfg.native_rootfs,
        .store = try cfg.nativeStore(arena, environ),
        .self_exe = std.process.executablePathAlloc(io, arena) catch "",
        .vouched = vouched,
        .rootless = cfg.native_rootless,
        .subid_base = cfg.native_subid_base,
        .subnet = try net.Subnet.parse(cfg.native_subnet),
        .store_max_bytes = cfg.native_store_max_mb * 1024 * 1024,
        .cgroup = cg,
        .job_limits = jobLimits(arena, io, cg),
    };
}

/// Whether each job gets a cgroup of its own with `memory.max` and `pids.max` (P5's
/// `Config.job_limits`): a parent to make it under, and neither limit configured away. `init`
/// fails a job the runner does not vouch for when its cgroup could not be made after all
/// (`jobCgroup`), so this never lets one run unlimited.
fn jobLimits(arena: Allocator, io: std.Io, cg: cgroup.Config) bool {
    const l = cgroup.Limits.of(io, cg);
    if (l.memory_max == null or l.pids_max == null) return false;
    return cgroup.parent(arena, io, cg.parent) == .dir;
}

/// How sandboxes are started on this machine (`launch`).
pub const Launch = struct {
    argv_prefix: []const []const u8,
    userns: sandbox.Userns,
};

/// A job's slot on a root runner: its number and the lock that holds it.
pub const Slot = struct { n: u32, lock: std.Io.File };

/// The default image's PATH (`ubuntu:24.04`'s config), with the operator's rootfs, and BuildKit's
/// default for an image whose config sets none.
const image_path = "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin";
/// `runner_user`'s ids in the provisioned image (`set_up.provision_runner_script`).
const runner_uid = 1001;
/// Overlay takes at most 500 lower layers, and its options one page: past this many, the stack
/// is merged into one layer (`flatten`), which costs directories and hard links.
pub const default_flatten_at = 100;

/// Why this job cannot run natively yet, or null when it can: the first thing it uses that the
/// native backend does not do yet (docs/native-backend.md, "Phases"). Decided before anything
/// runs, for the whole job: native and Dagger never share one. What this machine can do is
/// `usable`'s.
pub fn unsupported(io: std.Io, job: job_mod.Job, opts: dagger.Options, cfg: Config) ?[]const u8 {
    if (cfg.rootfs.len > 0) std.Io.Dir.accessAbsolute(io, cfg.rootfs, .{}) catch
        return "the native rootfs (RUNNER_NATIVE_ROOTFS) cannot be read";
    if (oci.hostPlatform() == null) return "there are no images for this machine's architecture";
    if (cfg.self_exe.len == 0 or cfg.store.len == 0) return "the native store is not set up";
    if (!cfg.vouched) if (untrustedRefusal(cfg)) |why| return why;
    if (std.os.linux.geteuid() != 0 and !cfg.rootless) return "the runner is not root, and " ++
        "rootless native steps have only one id mapped (RUNNER_NATIVE_ROOTLESS=1 runs them " ++
        "anyway; subordinate ids are phase 5's)";
    if (job.container) |jc| if (jc.ports.len > 0 or jc.volumes.len > 0 or jc.options != null)
        return "a job container's `ports:`, `volumes:` and `options:` are not native yet (phase 6)";
    if (job.services.len > 0) if (servicesUnsupported(job, cfg)) |why| return why;
    if (opts.nesting) return "steps that use the Dagger engine (RUNNER_DAGGER_NESTING) need Dagger";
    if (usesHashFiles(job)) return "`hashFiles()` reads the job's container through Dagger";
    // dpkg gives files to other users and groups (`root:adm`), which one mapped id cannot hold.
    if (std.os.linux.geteuid() != 0 and cfg.rootfs.len == 0 and opts.provision and
        std.mem.eql(u8, dagger.resolveImage(if (job.container) |jc| switch (jc.image) {
            .lit => |l| l,
            .expr => "",
        } else opts.image), dagger.default_image))
        return "provisioning the default image needs a range of ids, which a rootless runner " ++
            "does not have (RUNNER_NATIVE_ROOTFS, or a root runner)";
    const as_runner = opts.step_user == .runner;
    if (as_runner and std.os.linux.geteuid() != 0) return "steps run as the runner user need a " ++
        "range of ids, which a rootless runner does not have (RUNNER_STEP_USER=root, or a root " ++
        "runner)";
    for (job.steps) |step| switch (step.action) {
        .uses => return "`uses:` actions are not native yet (phase 7)",
        .docker => return "`docker://` steps are not native yet (phase 7)",
        .checkout => |inputs| for (inputs) |in| {
            if (!std.mem.eql(u8, in.name, "submodules")) continue;
            const lit = switch (in.value) {
                .lit => |l| l,
                else => "true",
            };
            if (!std.mem.eql(u8, lit, "false")) return "a checkout with submodules is not " ++
                "native yet";
        },
        .script, .unsupported => {},
    };
    return null;
}

/// Why a job the runner does not vouch for cannot run natively here, or null when it can: only
/// with every phase 5 isolation in place (Docker's seccomp allow list, the nftables rules) and
/// phase 4's per-job resource limits (`Config.job_limits`), and only on a root runner, since a
/// rootless one has neither the job's own network nor its own range of ids yet.
pub fn untrustedRefusal(cfg: Config) ?[]const u8 {
    if (!cfg.job_limits) return "native steps run only in jobs this runner vouches for " ++
        "(RUNNER_TRUSTED_REFS) until each job has cgroup limits of its own (phase 4)";
    if (std.os.linux.geteuid() != 0) return "native steps run jobs this runner does not vouch " ++
        "for only on a root runner (a rootless job's own network and ids are phase 5's)";
    return null;
}

/// Why the job's services cannot be native: they need the job's own network (a root runner), and
/// each its image named literally (pulled natively, `pullImage`). Null when they can.
fn servicesUnsupported(job: job_mod.Job, cfg: Config) ?[]const u8 {
    if (std.os.linux.geteuid() != 0 and !cfg.test_rootless_services) return "native `services:` " ++
        "need the job's own network, which a rootless runner does not give (phase 5)";
    for (job.services) |svc| switch (svc.image) {
        .lit => {},
        .expr => return "a service's image given by an expression is not native yet",
    };
    return null;
}

/// Whether any expression of the job calls `hashFiles` (function names are not case-sensitive).
fn usesHashFiles(job: job_mod.Job) bool {
    const call = "hashfiles(";
    for (job.env) |e| if (std.ascii.findIgnoreCase(templateText(e.value), call) != null)
        return true;
    for (job.outputs) |o| if (std.ascii.findIgnoreCase(templateText(o.value), call) != null)
        return true;
    if (job.environment.url) |u| if (std.ascii.findIgnoreCase(templateText(u), call) != null)
        return true;
    for (job.steps) |step| {
        const texts = [_][]const u8{
            step.condition,
            step.name_expr orelse "",
            templateText(step.continue_on_error),
            if (step.timeout_minutes) |t| templateText(t) else "",
        };
        for (texts) |t| if (std.ascii.findIgnoreCase(t, call) != null) return true;
        for (step.env) |e| if (std.ascii.findIgnoreCase(templateText(e.value), call) != null)
            return true;
        switch (step.action) {
            .script => |sc| {
                const more = [_]?job_mod.Template{ sc.script, sc.shell, sc.working_directory };
                for (more) |m| if (m) |t|
                    if (std.ascii.findIgnoreCase(templateText(t), call) != null) return true;
            },
            .checkout => |inputs| for (inputs) |in| {
                if (std.ascii.findIgnoreCase(templateText(in.value), call) != null) return true;
            },
            else => {},
        }
    }
    return false;
}

fn templateText(t: job_mod.Template) []const u8 {
    return switch (t) {
        .lit, .expr => |s| s,
    };
}

/// Whether this machine can run native steps, found with one sandbox; null when it can, else
/// why not, and every native job then runs on Dagger. A success holds for the process's life; a
/// failure is tried again once `probe_backoff_ms` have passed, so a machine that was not ready
/// (nftables busy, a module not loaded yet) does not keep native off until a restart. On a root
/// runner, it also makes the network's NAT rules (`net.natRules`) and checks the jobs' ids and
/// subnet against the host's.
pub fn usable(arena: Allocator, io: std.Io, gpa: Allocator, cfg: Config) ?[]const u8 {
    probe_mu.lockUncancelable(io);
    defer probe_mu.unlock(io);
    const now = std.Io.Clock.awake.now(io).toMilliseconds();
    if (probe_cache.fresh(now)) return probe_cache.why();
    const why = probe(arena, io, gpa, cfg) catch |e| @errorName(e);
    return probe_cache.store(now, why);
}

var probe_mu: std.Io.Mutex = .init;
var probe_cache: ProbeCache = .{};
pub const probe_backoff_ms = 5 * 60 * 1000;

/// The probe's last answer and when it was found (`usable`), kept in a buffer of its own since
/// the arena it came from is a job's.
const ProbeCache = struct {
    probed: bool = false,
    failed: bool = false,
    at_ms: i64 = 0,
    buf: [1024]u8 = undefined,
    len: usize = 0,

    /// Whether the last answer stands without probing again: a success always, a failure within
    /// its back-off.
    fn fresh(c: *const ProbeCache, now_ms: i64) bool {
        return c.probed and (!c.failed or now_ms - c.at_ms < probe_backoff_ms);
    }

    /// Null for "usable", else why not.
    fn why(c: *const ProbeCache) ?[]const u8 {
        return if (c.failed) c.buf[0..c.len] else null;
    }

    fn store(c: *ProbeCache, now_ms: i64, answer: ?[]const u8) ?[]const u8 {
        c.probed = true;
        c.failed = answer != null;
        c.at_ms = now_ms;
        const text: []const u8 = answer orelse "";
        c.len = @min(text.len, c.buf.len);
        @memcpy(c.buf[0..c.len], text[0..c.len]);
        return c.why();
    }
};

fn probe(arena: Allocator, io: std.Io, gpa: Allocator, cfg: Config) !?[]const u8 {
    if (std.os.linux.geteuid() == 0) {
        if (try idsClash(arena, io, cfg.subid_base, host_id_files)) |why| return why;
        if (try net.subnetClash(arena, io, cfg.subnet)) |why| return why;
        if (try natRulesFor(arena, io, cfg.subnet, true)) |why| return why;
    }
    // A store another user could reach or replace would hand them the host's root (its layers'
    // set-uid files and capabilities are the host's on disk): native stays off, saying why.
    if (try Store.secure(arena, io, cfg.store, .{ .check_parents = cfg.check_store_parents })) |why|
        return why;
    // Not a job: the gate measures none in it.
    var probing = cfg;
    probing.gate = null;
    // What the machine can do, whoever's job asked: an untrusted job's need of limits is
    // `init`'s to enforce for that job, not the probe's for every job.
    probing.vouched = true;
    var b = try init(arena, io, gpa, probing);
    defer b.deinit();
    // Without the operator's rootfs, the default image as pulled: the probe then also says
    // whether this machine can pull.
    if (b.rootfs.len == 0) {
        var why: []const u8 = "";
        b.rootfs = (b.pull(dagger.default_image, null, &why) catch
            return try std.fmt.allocPrint(arena, "this machine cannot pull the default image " ++
                "natively ({s})", .{why})).rootfs;
    }
    var out: Captured = .{ .arena = arena };
    const ended = try b.exec("true", &.{"PATH=/usr/bin:/bin"}, &.{}, 0, 0, out.output());
    if (ended.failure.len > 0 or ended.code != 0) return try std.fmt.allocPrint(
        arena,
        "this machine cannot make a native step's sandbox ({s}, exit {d})",
        .{ ended.failure, ended.code },
    );
    return null;
}

/// The NAT rules for the host's uplinks now, remembered so a job finds out cheaply whether the
/// uplinks changed since (a laptop moving from cable to Wi-Fi), and makes the new ones' rules
/// (`jobNetwork`). With no default route, the probe fails, and a job goes on without the rules:
/// it has no way out, as the host has none.
fn natRulesFor(arena: Allocator, io: std.Io, subnet: net.Subnet, probing: bool) !?[]const u8 {
    const ups = try net.uplinks(arena, io);
    if (ups.len == 0 and !probing) return null;
    const joined = try std.mem.join(arena, "\x00", ups);
    rules_mu.lockUncancelable(io);
    defer rules_mu.unlock(io);
    if (ups.len > 0 and std.mem.eql(u8, joined, rules_for[0..rules_len])) return null;
    if (try net.natRules(arena, io, subnet, ups)) |why| return why;
    // Too long to keep: the rules are made again next time.
    rules_len = if (joined.len <= rules_for.len) joined.len else 0;
    @memcpy(rules_for[0..rules_len], joined[0..rules_len]);
    return null;
}

var rules_mu: std.Io.Mutex = .init;
/// The uplinks the rules were made for, joined by zero bytes.
var rules_for: [256]u8 = undefined;
var rules_len: usize = 0;

/// The host's files that say which ids are taken (`idsClash`).
pub const IdFiles = struct {
    subuid: []const u8,
    subgid: []const u8,
    passwd: []const u8,
    group: []const u8,
};

pub const host_id_files: IdFiles = .{
    .subuid = "/etc/subuid",
    .subgid = "/etc/subgid",
    .passwd = "/etc/passwd",
    .group = "/etc/group",
};

/// Why the jobs' ranges of ids (`first` onwards, `ids_per_slot` per slot) cannot be used: below
/// `min_subid_base`, past 2^32, given to someone in /etc/subuid or /etc/subgid (a rootless
/// container runtime's range), or holding a user's or a group's id from /etc/passwd or
/// /etc/group. A job's root would then share host ids with them. Users only a directory service
/// knows (LDAP, SSSD) are not seen: `min_subid_base` is above their usual ranges. Null when none
/// of that is so.
pub fn idsClash(arena: Allocator, io: std.Io, first: u32, files: IdFiles) !?[]const u8 {
    if (first < min_subid_base) return try std.fmt.allocPrint(
        arena,
        "RUNNER_NATIVE_SUBID_BASE ({d}) is below {d}, where the host's own users and groups are",
        .{ first, min_subid_base },
    );
    // The slots' ranges, and the cache volumes' after them (`volumeIdBase`).
    const end = @as(u64, first) + @as(u64, ids_per_slot) * (net.max_slots + 1);
    if (end > std.math.maxInt(u32)) return "RUNNER_NATIVE_SUBID_BASE leaves no room for the " ++
        "jobs' ids below 2^32";
    const cwd = std.Io.Dir.cwd();
    const ranges = [_][]const u8{ files.subuid, files.subgid };
    for (ranges) |path| {
        const text = cwd.readFileAlloc(io, path, arena, .limited(1 << 20)) catch continue;
        var lines = std.mem.splitScalar(u8, text, '\n');
        while (lines.next()) |line| {
            var f = std.mem.splitScalar(u8, line, ':');
            const user = f.next() orelse continue;
            const start = std.fmt.parseInt(u64, f.next() orelse continue, 10) catch continue;
            const count = std.fmt.parseInt(u64, f.next() orelse continue, 10) catch continue;
            if (start < end and first < start + count) return try std.fmt.allocPrint(
                arena,
                "the jobs' ids ({d}-{d}, RUNNER_NATIVE_SUBID_BASE) overlap {s}'s in {s}",
                .{ first, end - 1, user, path },
            );
        }
    }
    const owners = [_][]const u8{ files.passwd, files.group };
    for (owners) |path| {
        const text = cwd.readFileAlloc(io, path, arena, .limited(16 << 20)) catch continue;
        var lines = std.mem.splitScalar(u8, text, '\n');
        while (lines.next()) |line| {
            var f = std.mem.splitScalar(u8, line, ':');
            const name = f.next() orelse continue;
            _ = f.next() orelse continue;
            const id = std.fmt.parseInt(u64, f.next() orelse continue, 10) catch continue;
            if (id >= first and id < end) return try std.fmt.allocPrint(arena, "the jobs' ids " ++
                "({d}-{d}, RUNNER_NATIVE_SUBID_BASE) hold {s}'s id {d} in {s}", .{
                first, end - 1, name, id, path,
            });
        }
    }
    return null;
}

/// How to start a sandbox here. As root, the helper maps the job's range itself. Rootless, it
/// makes a user namespace itself, unless the kernel lets only allow-listed programs do that
/// (Ubuntu's `apparmor_restrict_unprivileged_userns`), where it is started under util-linux's
/// `unshare`, which is on that list where its profile is installed.
pub fn launch(arena: Allocator, io: std.Io, cfg: Config) !Launch {
    const self: []const []const u8 = try arena.dupe([]const u8, &.{cfg.self_exe});
    const userns = usernsHere(io);
    if (userns != .inherited) return .{ .argv_prefix = self, .userns = userns };
    const unshare = [_][]const u8{ "unshare", "--user", "--map-root-user", "--mount", "--" };
    return .{
        .argv_prefix = try std.mem.concat(arena, []const u8, &.{ &unshare, self }),
        .userns = .inherited,
    };
}

fn usernsHere(io: std.Io) sandbox.Userns {
    if (std.os.linux.geteuid() == 0) return .mapped;
    var buf: [8]u8 = undefined;
    const restricted = std.Io.Dir.cwd().readFile(
        io,
        "/proc/sys/kernel/apparmor_restrict_unprivileged_userns",
        &buf,
    ) catch "0";
    return if (std.mem.startsWith(u8, restricted, "1")) .inherited else .self;
}

/// A job's directory in the store, locked, and on a root runner its slot and network. Stale
/// directories (a runner that died) are removed first (`sweep`).
pub fn init(arena: Allocator, io: std.Io, gpa: Allocator, cfg: Config) !Backend {
    try Store.prepare(arena, io, cfg.store, .{ .check_parents = cfg.check_store_parents });
    const cg_parent = cgroup.parent(arena, io, cfg.cgroup.parent);
    sweep(arena, io, cfg.store, switch (cg_parent) {
        .dir => |d| d,
        .none => null,
    });
    var raw: [8]u8 = undefined;
    io.random(&raw);
    const id = std.fmt.bytesToHex(raw, .lower);
    // Made under a name the sweep leaves alone, and renamed once it is locked.
    const new = try std.fmt.allocPrint(arena, "{s}/jobs/.new-{s}", .{ cfg.store, &id });
    const dir = try std.fmt.allocPrint(arena, "{s}/jobs/{s}", .{ cfg.store, &id });
    const cwd = std.Io.Dir.cwd();
    try cwd.createDirPath(io, new);
    // Until the lock is the Backend's, a failure removes the directory and closes the lock here;
    // from then on `deinit` does both, once.
    errdefer removeTree(arena, io, new);
    for ([_][]const u8{ "W", "M", sandbox.secrets_dir }) |d|
        try cwd.createDirPath(io, try std.fmt.allocPrint(arena, "{s}/{s}", .{ new, d }));
    const lock = try lockFile(arena, io, try std.fmt.allocPrint(arena, "{s}/lock", .{new}), true);
    const how = launch(arena, io, cfg) catch |e| {
        lock.close(io);
        return e;
    };
    cwd.rename(new, cwd, dir, io) catch |e| {
        lock.close(io);
        return e;
    };
    var b: Backend = .{
        .arena = arena,
        .io = io,
        .gpa = gpa,
        .dir = dir,
        .rootfs = cfg.rootfs,
        .operator_rootfs = cfg.rootfs,
        .binds = cfg.binds,
        .lock = lock,
        .how = how,
        .subid_base = cfg.subid_base,
        .subnet = cfg.subnet,
        .store_cfg = .{ .root = cfg.store, .max_bytes = cfg.store_max_bytes },
        .vouched = cfg.vouched,
        .flatten_at = @max(2, cfg.flatten_at),
        .gate = cfg.gate,
        .test_seed_script = cfg.test_seed_script,
        .images_dir = cfg.images,
        .service_binds = cfg.service_binds,
        .self_exe = cfg.self_exe,
    };
    errdefer b.deinit();
    if (cfg.test_fail_after_lock) return error.TestFailure;
    try b.jobCgroup(cfg, cg_parent, &id);
    b.binds = try b.jobBinds(cfg);
    if (b.how.userns == .mapped) try b.jobNetwork(cfg);
    return b;
}

/// The job's cgroup under `parent`, named as its directory is, with its limits; or none, and
/// "Set up job" says why. The gate measures the job in it, or not at all.
fn jobCgroup(b: *Backend, cfg: Config, parent: cgroup.Parent, name: []const u8) !void {
    const arena = b.arena;
    b.limits = cgroup.Limits.of(b.io, cfg.cgroup);
    // A job the runner does not vouch for runs natively only within limits of its own
    // (`untrustedRefusal`, decided on `Config.job_limits`): without them it does not run.
    const limited = b.limits.memory_max != null and b.limits.pids_max != null;
    if (!cfg.vouched and !limited) return error.NoJobLimits;
    const why: []const u8 = switch (parent) {
        .none => |w| w,
        .dir => |dir| if (cgroup.Job.make(arena, dir, name, b.limits)) |j| {
            b.job_cgroup = j;
            try b.notes.append(arena, try std.fmt.allocPrint(arena, "Native steps: the job's " ++
                "cgroup is {s}, with memory.max {f} and pids.max {f}.", .{
                j.dir,
                Limit.memory(b.limits.memory_max),
                Limit.count(b.limits.pids_max),
            }));
            if (b.gate) |g| g.native(j.dir);
            return;
        } else |e| try std.fmt.allocPrint(arena, "it could not be made under {s}: {s}", .{
            dir,
            @errorName(e),
        }),
    };
    if (!cfg.vouched) return error.NoJobLimits;
    try b.notes.append(arena, try std.fmt.allocPrint(arena, "Native steps: the job has no " ++
        "cgroup of its own ({s}), so no memory or process limit of its own, and the memory " ++
        "gate does not measure it.", .{why}));
    if (b.gate) |g| g.native(null);
}

/// A limit for the log: bytes as GB, or a count; `max` for none.
const Limit = struct {
    value: ?u64,
    bytes: bool = false,

    fn memory(v: ?u64) Limit {
        return .{ .value = v, .bytes = true };
    }

    fn count(v: ?u32) Limit {
        return .{ .value = if (v) |c| c else null };
    }

    pub fn format(l: Limit, w: *std.Io.Writer) std.Io.Writer.Error!void {
        const v = l.value orelse return w.writeAll("max");
        if (l.bytes and v < 1 << 30) return w.print("{d} MB", .{v >> 20});
        if (l.bytes) return w.print("{f}", .{admission.gb(v >> 20)});
        try w.print("{d}", .{v});
    }
};

/// The host's resolver and hosts over the image's (over files the image has), and the
/// configured binds. On a root runner, the job's own network cannot reach a resolver on the
/// host's loopback (`net.resolvConf`).
fn jobBinds(b: *Backend, cfg: Config) ![]const sandbox.Spec.Bind {
    const resolv = if (b.how.userns == .mapped)
        net.resolvConf(b.arena, b.io) orelse return error.NoReachableResolver
    else
        "/etc/resolv.conf";
    b.etc_binds = try b.arena.dupe(sandbox.Spec.Bind, &.{
        .{ .host = resolv, .at = "/etc/resolv.conf", .optional = true },
        .{ .host = "/etc/hosts", .at = "/etc/hosts", .optional = true },
    });
    return std.mem.concat(b.arena, sandbox.Spec.Bind, &.{ cfg.binds, b.etc_binds });
}

/// The job's services by name, for its steps and its services: a hosts file of the job's (the
/// host's, as steps get it, and a line naming the loopback, `services.hostsLine`) bound in place
/// of the host's, read-only.
pub fn serviceHosts(b: *Backend, names: []const []const u8) !void {
    const line = try services.hostsLine(b.arena, names);
    if (line.len == 0) return;
    const cwd = std.Io.Dir.cwd();
    const host = cwd.readFileAlloc(b.io, "/etc/hosts", b.arena, .limited(1 << 20)) catch
        "127.0.0.1\tlocalhost\n::1\tlocalhost ip6-localhost ip6-loopback\n";
    const sep: []const u8 = if (host.len > 0 and host[host.len - 1] != '\n') "\n" else "";
    const path = try std.fmt.allocPrint(b.arena, "{s}/hosts", .{b.dir});
    try cwd.writeFile(b.io, .{
        .sub_path = path,
        .data = try std.mem.concat(b.arena, u8, &.{ host, sep, line }),
    });
    b.binds = try withHosts(b.arena, b.binds, path);
    b.etc_binds = try withHosts(b.arena, b.etc_binds, path);
}

fn withHosts(
    arena: Allocator,
    binds: []const sandbox.Spec.Bind,
    path: []const u8,
) ![]const sandbox.Spec.Bind {
    const out = try arena.dupe(sandbox.Spec.Bind, binds);
    for (out) |*bd| if (std.mem.eql(u8, bd.at, "/etc/hosts")) {
        bd.host = path;
    };
    return out;
}

/// What every service gets mounted (`services.zig`): the job's resolver and hosts file, and
/// `Config.service_binds`. Never the steps' binds (phase 4's cache volumes will be those).
pub fn serviceBinds(b: *Backend) []const sandbox.Spec.Bind {
    return std.mem.concat(b.arena, sandbox.Spec.Bind, &.{ b.service_binds, b.etc_binds }) catch
        b.etc_binds;
}

pub const ServiceDirs = struct {
    image: []const u8,
    upper: []const u8,
    work: []const u8,
    merged: []const u8,
    status: []const u8,
};

/// Service `n`'s directories in the job's (`V<n>`): its layer, overlay work directory and mount
/// point, its status file (empty), and `I`, a link to its image's filesystem, so the image's path
/// (which may hold a `:`, overlay's separator) never reaches overlay's options.
pub fn serviceDirs(b: *Backend, n: u32, rootfs: []const u8) !ServiceDirs {
    const arena = b.arena;
    const cwd = std.Io.Dir.cwd();
    const v = try std.fmt.allocPrint(arena, "V{d}", .{n});
    const out: ServiceDirs = .{
        .image = try std.fmt.allocPrint(arena, "{s}/I", .{v}),
        .upper = try std.fmt.allocPrint(arena, "{s}/U", .{v}),
        .work = try std.fmt.allocPrint(arena, "{s}/W", .{v}),
        .merged = try std.fmt.allocPrint(arena, "{s}/M", .{v}),
        .status = try std.fmt.allocPrint(arena, "{s}/{s}/status", .{ b.dir, v }),
    };
    for ([_][]const u8{ out.upper, out.work, out.merged }) |d|
        try cwd.createDirPath(b.io, try std.fmt.allocPrint(arena, "{s}/{s}", .{ b.dir, d }));
    const full_image = try std.fmt.allocPrint(arena, "{s}/{s}", .{ b.dir, out.image });
    try cwd.symLink(b.io, rootfs, full_image, .{ .is_directory = true });
    try cwd.writeFile(b.io, .{ .sub_path = out.status, .data = "" });
    // The layer's root is the overlay's `/`: the job's root's, as for a step's (`exec`).
    if (b.how.userns == .mapped) {
        const base_id = b.idBase();
        const p = try arena.dupeSentinel(u8, try std.fmt.allocPrint(arena, "{s}/{s}", .{
            b.dir,
            out.upper,
        }), 0);
        _ = std.os.linux.chown(p, base_id, base_id);
        _ = std.os.linux.chmod(p, 0o755);
    }
    return out;
}

/// A slot of its own (the first free one on the host, held by its lock, `net.slots_dir`), and
/// the job's network namespace on the runner's bridge (`net.zig`), made by a helper
/// (`net.command`), since a thread of the runner must not change its namespace.
fn jobNetwork(b: *Backend, cfg: Config) !void {
    const arena = b.arena;
    b.slot = try lockSlot(arena, b.io, net.slots_dir);
    const n = b.slot.?.n;
    // A veth of this slot is a dead job's: its runner let the lock go, by ending or dying. Only
    // the slot's holder removes it, so a live job's network is never touched.
    var sock = try net.Socket.open();
    sock.deleteVeth(n);
    sock.close();
    // The host's uplinks may have changed since the probe made their rules.
    if (try natRulesFor(arena, b.io, cfg.subnet, false)) |why| {
        std.log.warn("native: the jobs' NAT rules: {s}", .{why});
        return error.JobNetworkFailed;
    }
    const path = try std.fmt.allocPrint(arena, "{s}/netns", .{b.dir});
    const slot = try std.fmt.allocPrint(arena, "{d}", .{n});
    const subnet = try std.fmt.allocPrint(arena, "{f}", .{cfg.subnet});
    var child = try std.process.spawn(b.io, .{
        .argv = &.{ cfg.self_exe, net.command, path, slot, subnet },
        .stdin = .ignore,
        .stdout = .ignore,
        .stderr = .pipe,
    });
    var err: std.ArrayList(u8) = .empty;
    var buf: [4096]u8 = undefined;
    while (true) {
        const got = child.stderr.?.readStreaming(b.io, &.{&buf}) catch break;
        if (got == 0) break;
        try err.appendSlice(arena, buf[0..got]);
    }
    const term = try child.wait(b.io);
    b.netns = path;
    if (term != .exited or term.exited != 0) {
        std.log.warn("native: the job's network: {s}", .{std.mem.trim(u8, err.items, " \n")});
        return error.JobNetworkFailed;
    }
}

/// The first slot whose lock in `dir` no process holds, locked. The directory is made only
/// root's, so no other user can take a slot's lock. A lock file removed and made again while it
/// was being taken is not trusted: the lock is taken only on the file the path names.
fn lockSlot(arena: Allocator, io: std.Io, dir: []const u8) !Slot {
    const linux = std.os.linux;
    const cwd = std.Io.Dir.cwd();
    try cwd.createDirPath(io, std.fs.path.dirname(dir) orelse "/");
    const d = try arena.dupeSentinel(u8, dir, 0);
    _ = linux.mkdir(d, 0o700);
    if (linux.errno(linux.chmod(d, 0o700)) != .SUCCESS) return error.SlotsDirectory;
    for (0..net.max_slots) |n| {
        const path = try std.fmt.allocPrint(arena, "{s}/{d}.lock", .{ dir, n });
        const lock = lockFile(arena, io, path, false) catch continue;
        if (!sameFile(arena, lock, path)) {
            lock.close(io);
            continue;
        }
        return .{ .n = @intCast(n), .lock = lock };
    }
    return error.NoFreeSlot;
}

const sameFile = Store.sameFile;

/// What "Set up job" says of the job's ids and network: a range of its own and a network of its
/// own on a root runner; only root, and the host's network, rootless.
pub fn idsNote(b: *const Backend, arena: Allocator) ![]const u8 {
    if (b.how.userns != .mapped) return "Native steps, rootless: only root is mapped inside " ++
        "(apt's _apt user, chown to other users and tar with owners fail), and steps share the " ++
        "host's network.";
    const addr = b.subnet.jobAddress(b.slot.?.n);
    return std.fmt.allocPrint(arena, "Native steps: ids 0-65535 are host ids {d}-{d}, and the " ++
        "job's network is its own ({d}.{d}.{d}.{d} on {s}).", .{
        b.idBase(),
        b.idBase() + ids_per_slot - 1,
        addr[0],
        addr[1],
        addr[2],
        addr[3],
        net.bridge,
    });
}

/// The first of the 65536 host ids the job's slot maps.
pub fn idBase(b: *const Backend) u32 {
    return b.subid_base + (if (b.slot) |s| s.n else 0) * ids_per_slot;
}

/// An exclusive lock on `path`: waited for (`wait`), or `error.Locked` at once.
fn lockFile(arena: Allocator, io: std.Io, path: []const u8, wait: bool) !std.Io.File {
    _ = arena;
    const f = try std.Io.Dir.cwd().createFile(io, path, .{ .truncate = false });
    const lock_ex: i32 = 2;
    const lock_nb: i32 = 4;
    const rc = std.os.linux.flock(f.handle, lock_ex | (if (wait) 0 else lock_nb));
    if (std.os.linux.errno(rc) != .SUCCESS) {
        f.close(io);
        return error.Locked;
    }
    return f;
}

/// The job's network taken down, its layers removed, its volumes, cgroup, slot and lock let go.
pub fn deinit(b: *Backend) void {
    const arena = b.arena;
    // First: their helpers hold the job's directory and network, and are in its cgroup.
    b.service_set.stopAll(b.io);
    b.cache_plan.release(b.io);
    if (b.job_cgroup) |j| {
        if (b.gate) |g| g.nativeDone();
        j.remove(arena, b.io);
    }
    if (b.slot) |s| {
        var sock = net.Socket.open() catch null;
        if (sock) |*so| {
            so.deleteVeth(s.n);
            so.close();
        }
    }
    if (b.netns) |p| detachNetns(arena, p);
    removeTree(arena, b.io, b.dir);
    for (b.held.items) |f| f.close(b.io);
    if (b.slot) |s| s.lock.close(b.io);
    b.lock.close(b.io);
    // The store kept under its cap, now that this job holds none of its layers.
    if (b.store) |s| s.collect(arena, b.io);
}

fn detachNetns(arena: Allocator, path: []const u8) void {
    const p = arena.dupeSentinel(u8, path, 0) catch return;
    _ = std.os.linux.umount2(p, std.os.linux.MNT.DETACH);
}

const removeTree = Store.removeTree;

/// Removes the job directories no runner holds (their runner died), their network namespaces'
/// mounts, and their cgroups under `cg_parent`. A directory still being made (`.new-`) is left
/// alone.
fn sweep(arena: Allocator, io: std.Io, store: []const u8, cg_parent: ?[]const u8) void {
    const jobs = std.fmt.allocPrint(arena, "{s}/jobs", .{store}) catch return;
    var dir = std.Io.Dir.cwd().openDir(io, jobs, .{ .iterate = true }) catch return;
    defer dir.close(io);
    var it = dir.iterate();
    while (it.next(io) catch null) |e| {
        if (e.kind != .directory or std.mem.startsWith(u8, e.name, ".new-")) continue;
        const path = std.fmt.allocPrint(arena, "{s}/{s}", .{ jobs, e.name }) catch return;
        const lock = std.fmt.allocPrint(arena, "{s}/lock", .{path}) catch return;
        const held = lockFile(arena, io, lock, false) catch continue;
        defer held.close(io);
        detachNetns(arena, std.fmt.allocPrint(arena, "{s}/netns", .{path}) catch return);
        if (cg_parent) |p| (cgroup.Job{
            .dir = std.fmt.allocPrint(arena, "{s}/{s}", .{ p, e.name }) catch return,
        }).remove(arena, io);
        removeTree(arena, io, path);
    }
}

/// The base every step starts from, as `set_up.baseContainerId` builds Dagger's: the image's
/// env, the step user and its HOME, the job's workspace and RUNNER_TEMP, the event payload, the
/// step markers' secret, GitHub's default variables and the job's `env:`, and its caches
/// (`setUpCaches`). On failure the reason is in `err_msg`.
///
/// Under step caching the store is on for the job, and the base is a layer like a step's: under
/// a key (`keyFor`), replayed when the store has it. As `set_up.writeRunEnv` does, the event
/// payload is then a volatile variable that each step writes to the file, and the job's ran
/// marker one too, so the base is the same for every run.
pub fn base(
    b: *Backend,
    ev: *Evaluator,
    plan: anytype,
    err_msg: *[]const u8,
) !void {
    const arena = b.arena;
    try b.prepareRootfs(ev, plan, err_msg);
    // On the job's image (the seed's build and the roll run on `b.rootfs`).
    try b.setUpCaches(ev, plan);
    try b.baseEnv(ev, plan);
    // Not with services (P6): what a step got from a service (its image, its env, its data) is
    // in no key, so a replay could stand for a run against another service.
    if (plan.step_cache and ev.job.services.len == 0) b.store = b.store_cfg;
    b.repository = ev.job.github.repository;
    b.scope = try set_up.packageCacheScope(arena, ev, b.repository, b.vouched);
    const event = try ev.eventJson();
    const event_in_env = plan.step_cache and event.len <= set_up.max_event_env;
    if (event_in_env) try b.put(dagger.event_env, event);
    if (plan.step_cache) try b.put(dagger.ran_env, plan.ran_marker);

    // The workspace and RUNNER_TEMP, made as Dagger's base makes them: in the provisioned image by
    // root, owned by the step user when it is not root; in any other image by its own user, who
    // may be unable to (its steps then say so). From `/`, as the workspace is not there yet. The
    // event payload goes in as `withNewFile` does.
    //
    // And RUNNER_TOOL_CACHE, which Dagger mounts in every job (`set_up.cachesUsed`) owned by the
    // step user: the job's `toolcache` volume, bound there in every step (`volumes.plan`). A job
    // with no volumes (package caches off, or no repository to key them by) has it in the base
    // layer instead, made here: the step user cannot make it under /opt, and what a step puts
    // there is then in the step's layer and comes back with its replay.
    const tool_dir = if (b.cache_plan.tool_cache == null) " " ++ set_up.tool_cache_dir else "";
    const chown = if (plan.as_runner) try std.fmt.allocPrint(arena, " && chown -R {s}:{s} {s}{s}", .{
        dagger.runner_user,
        dagger.runner_user,
        dagger.work_root,
        tool_dir,
    }) else "";
    // With `uv_env_in_cache`, `.venv` in the workspace links to uv's environment in its volume,
    // as `set_up.writeProvisionAndWorkspace` makes it.
    const link = if (b.cache_plan.uv_env) |e|
        try std.fmt.allocPrint(arena, " && ln -sfn {s} {s}/.venv", .{ e, ev.workspace })
    else
        "";
    const mk = if (plan.provision) try std.fmt.allocPrint(arena, "mkdir -p {s} {s}{s}{s}{s}", .{
        ev.workspace,
        ev.temp,
        tool_dir,
        link,
        chown,
    }) else try std.fmt.allocPrint(arena, "mkdir -p {s} {s}{s} 2>/dev/null{s} || true", .{
        ev.workspace,
        ev.temp,
        tool_dir,
        link,
    });
    const mk_uid: u32 = if (plan.provision) 0 else b.uid;
    const mk_gid: u32 = if (plan.provision) 0 else b.gid;
    const event_file = [_]sandbox.Spec.File{.{
        .path = dagger.event_path,
        .contents = event,
        .mode = 0o644,
        .keep = true,
    }};
    const files: []const sandbox.Spec.File = if (event_in_env) &.{} else &event_file;
    var out: Captured = .{ .arena = arena };
    const workdir = b.workdir;
    b.workdir = "/";
    defer b.workdir = workdir;
    const key = try b.keyFor(.base, mk, files, mk_uid, mk_gid);
    // Nothing can stop the base: no step is running, so no cancel reaches it.
    const claim = b.claimKey(key) catch |e| {
        err_msg.* = @errorName(e);
        return error.BaseContainerFailed;
    };
    defer claim.release(b.io);
    if (claim.hit != null) return;
    const ended = try b.exec(mk, try b.envStrings(&.{}), files, mk_uid, mk_gid, out.output());
    if (ended.failure.len == 0 and ended.code == 0) {
        if (claim.key) |k| try b.publishTop(k, .base, .{ .log = "", .fc = "" });
    } else {
        err_msg.* = try std.fmt.allocPrint(arena, "could not set up the job's base: {s}{s}", .{
            ended.failure,
            out.tail(),
        });
        return error.BaseContainerFailed;
    }
}

/// The base's environment, user and working directory (`base`), as `set_up.writeImage`,
/// `writeProvisionAndWorkspace`, `writeRunEnv` and `writeJobEnv` set them on Dagger's container.
/// What carries a secret is a plain variable here, as a Dagger secret variable is in the
/// process: there is no engine whose cache could keep it.
fn baseEnv(b: *Backend, ev: *Evaluator, plan: anytype) !void {
    // The image's env, as Dagger's `from` gives it, with BuildKit's PATH when it sets none.
    for (b.image_env) |kv| {
        const eq = std.mem.indexOfScalar(u8, kv, '=') orelse continue;
        try b.put(kv[0..eq], kv[eq + 1 ..]);
    }
    if (b.envValue("PATH") == null) try b.put("PATH", image_path);
    // Right after the image's own env, as `set_up.writeFrom` sets it.
    for (b.cache_plan.early_env.items) |e| try b.put(e.name, e.value);
    // A `container:` job's own env, as `docker create -e` sets it; its PATH is the container's
    // (`Exec.container_path`).
    for (plan.container_env) |e| try b.put(e.name, e.value);
    if (ev.job.container != null) b.runtime_path = b.envValue("PATH");
    b.uid = b.image_uid;
    b.gid = b.image_gid;
    if (plan.as_runner) {
        b.uid = runner_uid;
        b.gid = runner_uid;
        try b.put("HOME", dagger.runner_home);
    }
    try b.put(dagger.mark_env, plan.mark);
    for (b.cache_plan.env.items) |e| try b.put(e.name, e.value);
    for (try ev.defaultEnv()) |e| try b.put(e.name, e.value);
    for (try ev.withoutReapplied(ev.job_env.items)) |e| try b.put(e.name, e.value);
    b.workdir = ev.workspace;
}

/// `Exec.execScript` on this backend: one step's script, its output streamed into the job's log,
/// its file commands applied. `error.EngineFailed` (with `x.err_msg`) when the sandbox failed or
/// the step was stopped (`abort`).
///
/// Under step caching, a step that does not always run (`Resolved.run.always_run`: no secret, no
/// OIDC, no run-specific value) after a step in the store has a key (`keyFor`). When the store has
/// it, nothing runs: its layer joins the stack, and its recorded output and file commands go
/// through `Exec.collect` as Dagger's replayed exec does, with the earlier job's ran marker, so
/// the log is the live one's by construction. Otherwise it runs, and is published when it exited
/// 0 and its file commands took (`publishTop`): a failure is never replayed (#69).
pub fn execScript(
    b: *Backend,
    x: *Exec,
    num: u32,
    fc: u32,
    resolved_in: dagger.Resolved,
    action_name: []const u8,
    secret_env_in: []const dagger.SecretRef,
) !Exec.Out {
    const arena = b.arena;
    try b.applyPendingEnv(x);
    // Why the step runs again rather than replay its record (`Exec.execScript`'s, #229).
    var rerun: ?[]const u8 = null;
    while (true) {
        const step_run = try x.resolveRunStep(resolved_in, secret_env_in, rerun);
        const resolved = step_run.resolved;
        const script = try scripts.stepScriptFc(arena, num, fc, resolved, action_name);

        // Secret variables reach the script under their aliases (`scripts.secretAlias`), as Dagger's
        // `withSecretVariable` gives them: only the name is in the script, so the value is in no
        // command line (which any user on the host can read).
        var extra: std.ArrayList(job_mod.EnvVar) = .empty;
        for (step_run.secret_env, 0..) |s, i| try extra.append(arena, .{
            .name = try scripts.secretAlias(arena, i),
            .value = plaintext(x, s.id),
        });
        // A script holding a secret is a file the sandbox writes and removes, as Dagger mounts it.
        var files: std.ArrayList(sandbox.Spec.File) = .empty;
        if (step_run.script_secret != null) try files.append(arena, .{
            .path = try scripts.scriptPath(arena, fc, resolved.run.shell),
            .contents = resolved.run.script,
        });

        const step_env = switch (resolved) {
            .run => |r| r.env,
            .checkout => &.{},
        };
        x.sh.beginCommands(num, try dagger.envContext(arena, x.ev.job_env.items, step_env));
        x.beginExec(num);
        const always_run = switch (resolved) {
            .run => |r| r.always_run != null,
            .checkout => false,
        };
        // A step with a secret file always runs already; the check keeps any such file out of a key.
        const key = if (always_run or files.items.len > 0)
            null
        else
            try b.keyFor(.step, script, &.{}, b.uid, b.gid);
        const claim = b.claimKey(key) catch |e| switch (e) {
            error.Stopped => {
                x.err_msg = "the step was stopped";
                return error.EngineFailed;
            },
            else => return e,
        };
        defer claim.release(b.io);
        if (claim.hit) |rec| {
            const data = try recordAnswer(arena, rec);
            // A record that points into the tool cache's volume, which is in no layer: the volume
            // may have lost the tree since, and no tree is checked natively, so the step runs again.
            if (rerun == null) if (try x.toolDirNotHeld(data)) |dir| {
                rerun = try std.fmt.allocPrint(arena, "its record names {s} in the tool cache, " ++
                    "a volume in no layer", .{dir});
                continue;
            };
            const out = try x.collect(num, data, .{ .doc = "", .at = 0 });
            x.loadPendingMatchers(num);
            return out;
        }

        var demux: SpanDemux = .{ .sh = x.sh, .gpa = b.gpa };
        defer demux.deinit();
        var live: Live = .{
            .demux = &demux,
            .arena = arena,
            .record = if (claim.key != null) .empty else null,
        };
        const ended = try b.exec(
            script,
            try b.envStrings(extra.items),
            files.items,
            b.uid,
            b.gid,
            live.output(),
        );
        const layer = b.layers.items[b.layers.items.len - 1].path;
        // The helper removes it; when it was stopped before it could, the runner does, so no later
        // step's layers hold the secret.
        for (files.items) |f| sandbox.unlinkIn(arena, layer, f.path);
        // Every line is in: the pipe is closed only once every process of the step has ended.
        demux.flushPartial();
        try b.limitsReached(x, num);
        x.sh.ended[num - 1].store(true, .release);
        x.sh.flush();
        if (ended.failure.len > 0) {
            x.err_msg = ended.failure;
            return error.EngineFailed;
        }
        if (ended.killed) {
            x.err_msg = "the step was stopped";
            return error.EngineFailed;
        }
        const all_path = try scripts.fcPath(arena, "all", fc);
        const all = switch (try sandbox.readIn(arena, layer, all_path, max_read)) {
            .text => |t| t,
            .missing, .whiteout => null,
        };
        var answer: std.Io.Writer.Allocating = .init(arena);
        try std.json.Stringify.value(.{
            .exitCode = ended.code,
            .fc_all = if (all) |text| .{ .contents = text } else null,
        }, .{ .emit_null_optional_fields = false }, &answer.writer);
        const data = try std.json.parseFromSliceLeaky(std.json.Value, arena, answer.written(), .{});
        const out = try x.collect(num, data, .{ .doc = "", .at = 0 });
        x.loadPendingMatchers(num);
        if (claim.key) |k| if (ended.code == 0 and out.code == 0) if (live.record) |r|
            try b.publishTop(k, .step, .{ .log = r.items, .fc = all orelse "" });
        return out;
    }
}

/// A stored step's record as Dagger's answer for an exec served from its cache gives it
/// (`execScript` replays it): its exit code 0, its output and its file commands. Its file
/// commands' ran marker is the earlier job's, so `Exec.collect` replays the output
/// (`JobLog.replayNotLive`) and the job's end notes the step as reused
/// (`JobLog.native_reused_note`).
fn recordAnswer(arena: Allocator, rec: Store.Record) !std.json.Value {
    // Built as values, not JSON text: a log need not be UTF-8.
    var fc_all: std.json.ObjectMap = .empty;
    try fc_all.put(arena, "contents", .{ .string = rec.fc });
    var data: std.json.ObjectMap = .empty;
    try data.put(arena, "exitCode", .{ .integer = 0 });
    try data.put(arena, "stdout", .{ .string = rec.log });
    try data.put(arena, "stderr", .{ .string = "" });
    try data.put(arena, "fc_all", .{ .object = fc_all });
    return .{ .object = data };
}

/// Says in the step's log when the job's cgroup killed a process of the step for memory or
/// refused it a process (`cgroup.Usage`): a step otherwise sees only an exit code 137 or a
/// failed fork, and the job would not know it hit its own limits.
fn limitsReached(b: *Backend, x: *Exec, num: u32) !void {
    const j = b.job_cgroup orelse return;
    const u = j.usage(b.io);
    defer {
        b.oom_kills = u.oom_kills;
        b.pids_max_hits = u.pids_max_hits;
    }
    if (u.oom_kills > b.oom_kills) x.sh.errorLine(num, try std.fmt.allocPrint(
        b.arena,
        "The job reached its memory limit ({f}, RUNNER_NATIVE_MEMORY_MAX_MB): the kernel " ++
            "killed {d} process(es) of this step to stay within it.",
        .{ Limit.memory(b.limits.memory_max), u.oom_kills - b.oom_kills },
    ));
    if (u.pids_max_hits > b.pids_max_hits) x.sh.errorLine(num, try std.fmt.allocPrint(
        b.arena,
        "The job reached its process limit ({f}, RUNNER_NATIVE_PIDS_MAX): this step was " ++
            "refused {d} new process(es) or thread(s).",
        .{ Limit.count(b.limits.pids_max), u.pids_max_hits - b.pids_max_hits },
    ));
}

/// The job's cache volumes, as the Dagger backend gives them (`volumes.plan`): held for the job
/// and bound into every step, Zig's local cache rolled to its next generation when it is over
/// its limit, and the Zig cache seeds built when missing and added below the job's layers. A
/// seed that cannot be built is left out, as on Dagger: caches never fail a job.
fn setUpCaches(b: *Backend, ev: *Evaluator, plan: anytype) !void {
    const arena = b.arena;
    const job = ev.job.*;
    const scope = try set_up.packageCacheScope(arena, ev, job.github.repository, b.caches.trusted);
    const owner: ?u32 = if (b.how.userns == .mapped) volumeIdBase(b.subid_base) else null;
    b.cache_plan = try volumes.plan(
        arena,
        b.io,
        b.store_cfg.root,
        b.caches,
        scope,
        job,
        plan.job_image,
        plan.as_runner,
        plan.step_cache,
        owner,
    );
    try b.notes.appendSlice(arena, b.cache_plan.notes.items);
    // Before the volumes are bound: nothing a job wrote may reach a seed, which every scope's
    // jobs run with.
    if (b.cache_plan.seeds.items.len > 0) try b.seeds(plan.as_runner);
    b.binds = try std.mem.concat(arena, sandbox.Spec.Bind, &.{ b.binds, b.cache_plan.binds.items });
    if (b.cache_plan.zig_local_roll != null) b.rollZigLocal(plan.as_runner);
}

/// `set_up.zig_local_roll_script` on the job's Zig local-cache volume, as root, in a sandbox
/// whose layer is dropped, as the Dagger backend runs it in a container of its own. Nothing of
/// it fails the job: a cache that did not roll is only bigger.
fn rollZigLocal(b: *Backend, as_runner: bool) void {
    const arena = b.arena;
    // A nonce for the script's temporary link, as on Dagger.
    var raw: [8]u8 = undefined;
    b.io.random(&raw);
    const script = std.fmt.allocPrint(arena, "set -- {s} {d} '{s}' {s}\n{s}", .{
        set_up.zigLocalCacheDir(as_runner),
        @as(u64, b.caches.zig_local_cache_max_mb) * 1024,
        if (as_runner) "1001:1001" else "",
        &std.fmt.bytesToHex(raw, .lower),
        set_up.zig_local_roll_script,
    }) catch return;
    var out: Captured = .{ .arena = arena };
    const ended = b.exec(script, &.{"PATH=" ++ image_path}, &.{}, 0, 0, out.output()) catch |e| {
        std.log.warn("native: Zig local cache not rolled: {s}", .{@errorName(e)});
        return;
    };
    b.dropLastLayer();
    if (ended.failure.len > 0 or ended.code != 0)
        std.log.warn("native: Zig local cache not rolled: {s}{s}", .{ ended.failure, out.tail() });
}

/// The job's Zig cache seeds, each built once per release, architecture and step user, under a
/// lock so two jobs do not build one twice (`volumes.adoptSeed`), and stacked below the job's
/// layers; "Set up job" says which.
fn seeds(b: *Backend, as_runner: bool) !void {
    const arena = b.arena;
    var seeded: std.ArrayList([]const u8) = .empty;
    var failure: ?[]const u8 = null;
    for (b.cache_plan.seeds.items) |s| {
        if (b.seed(s, as_runner)) |why| {
            failure = why;
            continue;
        }
        try b.seed_layers.append(arena, s.dir);
        try seeded.append(arena, s.seed.version);
    }
    if (try volumes.seedNote(arena, b.caches, seeded.items, failure)) |note|
        try b.notes.append(arena, note);
}

/// Builds `seed` unless it is there; null when it is, else why not.
fn seed(b: *Backend, s: volumes.Seed, as_runner: bool) ?[]const u8 {
    const arena = b.arena;
    const cwd = std.Io.Dir.cwd();
    if (cwd.access(b.io, s.dir, .{})) |_| return null else |_| {}
    const seeds_dir = std.fs.path.dirname(s.dir).?;
    cwd.createDirPath(b.io, seeds_dir) catch |e| return @errorName(e);
    // Only the runner's user may look in, as in the volumes'.
    const seeds_z = arena.dupeSentinel(u8, seeds_dir, 0) catch return "out of memory";
    _ = std.os.linux.chmod(seeds_z, 0o700);
    const lock = lockFile(arena, b.io, std.fmt.allocPrint(arena, "{s}.lock", .{s.dir}) catch
        return "out of memory", true) catch |e| return @errorName(e);
    defer lock.close(b.io);
    if (cwd.access(b.io, s.dir, .{})) |_| return null else |_| {}
    const script = b.test_seed_script orelse set_up.zigSeedScript(arena, s.seed) catch
        return "out of memory";
    const files = [_]sandbox.Spec.File{.{
        .path = set_up.zig_seed_project ++ "/build.zig",
        .contents = set_up.zig_seed_build_zig,
        .mode = 0o644,
        .keep = true,
    }};
    var out: Captured = .{ .arena = arena };
    const env = [_][]const u8{ "PATH=" ++ image_path, "HOME=/root" };
    const ended = b.exec(script, &env, &files, 0, 0, out.output()) catch |e| return @errorName(e);
    defer b.dropLastLayer();
    if (ended.failure.len > 0) return ended.failure;
    if (ended.code != 0) return std.fmt.allocPrint(arena, "its build exited {d}: {s}", .{
        ended.code,
        out.tail(),
    }) catch "its build failed";
    const built = std.fmt.allocPrint(arena, "{s}/{s}", .{
        b.layers.items[b.layers.items.len - 1].path,
        std.mem.trimStart(u8, set_up.zig_seed_dir, "/"),
    }) catch return "out of memory";
    const user: ?u32 = if (b.how.userns != .mapped) null else if (as_runner) runner_uid else 0;
    volumes.adoptSeed(arena, b.io, built, s, b.rootfs, user) catch |e| return @errorName(e);
    return null;
}

/// The last exec's layer removed: it was not a step's (a seed's build, a roll).
fn dropLastLayer(b: *Backend) void {
    removeTree(b.arena, b.io, b.layers.items[b.layers.items.len - 1].path);
    _ = b.layers.pop();
}

/// The built-in checkout on this backend: the repository fetched by git in the job's image, as
/// actions/checkout fetches it, into the tree Dagger's `git` gives (`checkout.query`): the commit
/// checked out with its `.git` and no refs (the step's script adds them, `checkout.refCommands`)
/// and every file at `checkout.mtime`. Its output is not the step's, as Dagger's fetch is not:
/// on failure the step says why.
pub fn fetchCheckout(b: *Backend, x: *Exec, co: job_mod.Checkout) !dagger.Fetched {
    const arena = b.arena;
    var f = try checkout.describe(arena, x.job.*, co);
    f.fetched_with = "git in the job's image";
    if (f.repo.len == 0) {
        f.result = .{ .failed = "no repository to check out (the job has no github.repository)" };
        return f;
    }
    var aw: std.Io.Writer.Allocating = .init(arena);
    const w = &aw.writer;
    try w.writeAll("set -e\nmkdir -p ");
    try dagger.shellQuote(w, f.mount);
    try w.writeAll(" && cd ");
    try dagger.shellQuote(w, f.mount);
    try w.writeAll("\ngit init -q\ngit remote add origin ");
    try dagger.shellQuote(w, try std.fmt.allocPrint(arena, "{s}.git", .{f.url}));
    try w.writeAll("\ngit -c protocol.version=2 fetch -q --no-tags");
    if (f.depth > 0) try w.print(" --depth={d}", .{f.depth});
    try w.writeAll(" origin ");
    try dagger.shellQuote(w, f.want);
    if (f.tags) try w.writeAll("\ngit fetch -q --tags origin");
    try w.print("\ngit checkout -q --detach FETCH_HEAD\nrm -f .git/FETCH_HEAD\n" ++
        "find . -exec touch -h -d @{d} {{}} +\n", .{checkout.mtime});

    // The job's token as GitHub expects it over HTTPS, in git's environment, never on its
    // command line.
    var extra: std.ArrayList(job_mod.EnvVar) = .empty;
    if (x.gitAuth()) |id| {
        const basic = try std.fmt.allocPrint(arena, "x-access-token:{s}", .{plaintext(x, id)});
        const enc = std.base64.standard.Encoder;
        const b64 = try arena.alloc(u8, enc.calcSize(basic.len));
        try extra.appendSlice(arena, &.{
            .{ .name = "GIT_CONFIG_COUNT", .value = "1" },
            .{
                .name = "GIT_CONFIG_KEY_0",
                .value = try std.fmt.allocPrint(arena, "http.{s}/.extraheader", .{
                    std.mem.trimEnd(u8, x.job.github.server_url, "/"),
                }),
            },
            .{
                .name = "GIT_CONFIG_VALUE_0",
                .value = try std.fmt.allocPrint(arena, "AUTHORIZATION: basic {s}", .{
                    enc.encode(b64, basic),
                }),
            },
        });
    }
    try extra.append(arena, .{ .name = "GIT_TERMINAL_PROMPT", .value = "0" });
    // A commit fetched is the same tree every time, as Dagger's `git` keys it, so under step
    // caching it is a layer like a step's, keyed on its script (the URL and the commit), never
    // on the token in `extra`. A branch or tag moves, so its fetch always runs.
    const key = if (checkout.isSha(f.want))
        try b.keyFor(.step, aw.written(), &.{}, b.uid, b.gid)
    else
        null;
    const claim = b.claimKey(key) catch |e| switch (e) {
        error.Stopped => {
            f.result = .{ .failed = "the step was stopped" };
            return f;
        },
        else => return e,
    };
    defer claim.release(b.io);
    if (claim.hit != null) {
        f.result = .{ .dir = "native" };
        return f;
    }
    var out: Captured = .{ .arena = arena };
    const ended = try b.exec(
        aw.written(),
        try b.envStrings(extra.items),
        &.{},
        b.uid,
        b.gid,
        out.output(),
    );
    if (ended.code == 0 and ended.failure.len == 0 and !ended.killed) {
        if (claim.key) |k| try b.publishTop(k, .fetch, .{ .log = "", .fc = "" });
        f.result = .{ .dir = "native" };
        return f;
    }
    // The sandbox's own failure fails the step, as a fetch Dagger could not make does.
    const why = if (ended.failure.len > 0) ended.failure else out.tail();
    const msg = x.sh.redacted(arena, why) catch why;
    f.result = .{ .failed = try std.fmt.allocPrint(arena, "could not fetch {s}@{s}: {s}{s}", .{
        f.repo, f.ref_label, msg,
        if (checkout.looksLikeAuthFailure(msg)) " (the job's GITHUB_TOKEN reads only " ++
            "the job's own repository; another private one cannot be checked out)" else "",
    }) };
    return f;
}

/// The contents of `path` as the job's last step left it (a problem matcher's file), relative
/// to the working directory unless absolute, as Dagger reads it from the container; null when
/// it is not there. Read layer by layer, newest first, each inside itself and through no
/// symlink (`sandbox.readIn`); a whiteout ends the search, as it hides the file below.
pub fn readFile(b: *Backend, path: []const u8) ?[]const u8 {
    const arena = b.arena;
    const full = if (std.fs.path.isAbsolutePosix(path))
        path
    else
        std.fmt.allocPrint(arena, "{s}/{s}", .{ b.workdir, path }) catch return null;
    var i = b.layers.items.len;
    while (i > 0) {
        i -= 1;
        switch (sandbox.readIn(arena, b.layers.items[i].path, full, max_read) catch return null) {
            .text => |t| return t,
            .whiteout => return null,
            .missing => {},
        }
    }
    return switch (sandbox.readIn(arena, b.rootfs, full, max_read) catch return null) {
        .text => |t| t,
        .missing, .whiteout => null,
    };
}

const max_read = 16 * 1024 * 1024;

/// `dagger.Transport` for the shared code: the native backend has no Dagger session, so a query
/// is a bug in what decided the job could run here (`unsupported`).
pub fn transport(b: *Backend) dagger.Transport {
    return .{ .ptr = b, .sendFn = send, .abortFn = abort };
}

fn send(ptr: *anyopaque, arena: Allocator, doc: []const u8, limit: usize) anyerror![]const u8 {
    _ = .{ ptr, arena, doc, limit };
    return error.NativeBackendHasNoDaggerSession;
}

/// Stops the running step (`dagger.Watch`, for a timeout or a cancel), or ends its wait for
/// another job running the same key (`claimKey`).
fn abort(ptr: *anyopaque) bool {
    const b: *Backend = @ptrCast(@alignCast(ptr));
    if (b.running.kill(b.io)) return true;
    if (!b.waiting.load(.acquire)) return false;
    b.stop_wait.store(true, .release);
    return true;
}

/// Runs one script on a new layer over the others, which it joins when it ends.
fn exec(
    b: *Backend,
    script: []const u8,
    env: []const []const u8,
    files: []const sandbox.Spec.File,
    uid: u32,
    gid: u32,
    out: sandbox.Output,
) !sandbox.Ended {
    const arena = b.arena;
    if (b.layers.items.len >= b.flatten_at) b.flatten() catch |e| return if (e == error.LayerNotShifted) e else .{
        .code = 1,
        .failure = try std.fmt.allocPrint(arena, "could not flatten the job's {d} layers " ++
            "into one: {s}", .{ b.layers.items.len, @errorName(e) }),
    };
    const upper = try b.layerName('L');
    const upper_path = try std.fmt.allocPrint(arena, "{s}/{s}", .{ b.dir, upper });
    try std.Io.Dir.cwd().createDirPath(b.io, upper_path);
    const base_id = b.idBase();
    // The upper's root is the overlay's `/`: the job's root's, as the image's `/` is, so a step
    // as root can make files there. Rootless, the runner's own user is the job's root already.
    if (b.how.userns == .mapped) {
        const p = try arena.dupeSentinel(u8, upper_path, 0);
        _ = std.os.linux.chown(p, base_id, base_id);
        _ = std.os.linux.chmod(p, 0o755);
    }
    // The job's layers, newest first, then the seeds' and the rootfs: the image's own.
    const n = b.layers.items.len;
    const lowers = try arena.alloc([]const u8, n + b.seed_layers.items.len + 1);
    // Which of the job's layers to see through the job's ids: those with the canonical ids.
    const canonical = try arena.alloc(bool, n);
    for (b.layers.items, 0..) |l, i| {
        lowers[n - 1 - i] = l.name;
        canonical[n - 1 - i] = l.canonical;
    }
    @memcpy(lowers[n .. lowers.len - 1], b.seed_layers.items);
    lowers[lowers.len - 1] = b.rootfs;
    const ended = try sandbox.run(arena, b.io, b.how.argv_prefix, .{
        .root = b.dir,
        .lowers = lowers,
        .upper = upper,
        .work = "W",
        .merged = "M",
        .workdir = b.workdir,
        .uid = uid,
        .gid = gid,
        .argv = &.{ "sh", "-c", script },
        .env = env,
        .files = files,
        .binds = b.binds,
        .userns = b.how.userns,
        .id_base = base_id,
        .id_count = ids_per_slot,
        .netns = b.netns,
        .cgroup = if (b.job_cgroup) |j| j.dir else null,
        .image_layers = @intCast(b.seed_layers.items.len + 1),
        .canonical = canonical,
        .volume_id_base = volumeIdBase(b.subid_base),
    }, &b.running, out);
    try b.layers.append(arena, .{ .name = upper, .path = upper_path });
    return ended;
}

/// The next layer's name in the job's directory: `L<n>` for a step's upper, `l<n>` for a link to
/// a store's layer, `F<n>` for a flattened stack.
fn layerName(b: *Backend, kind: u8) ![]const u8 {
    defer b.next_layer += 1;
    return std.fmt.allocPrint(b.arena, "{c}{d}", .{ kind, b.next_layer });
}

/// The key of an exec of `script` on the stack as it is, in P8's format (`Store.KeyHasher`):
/// the model's `Key = parent · script · stable env` (proofs/Runner/Model.lean, `keyOf`). Null
/// without the store, or when the stack's top is not in it (a step that always runs, or failed,
/// or was not published): nothing after such a step is replayed or published, as under Dagger a
/// new parent makes every later key new. The env is the container's in its order, without the
/// volatile names (`Store.stableEnv`). After P8's core come what its model does not have yet: who
/// runs it and where, and the files written for it that stay (the event file, when it is not a
/// variable). A base has no parent: in its place, the digest of what every layer above it
/// depends on (`below`).
fn keyFor(
    b: *Backend,
    tag: Store.Tag,
    script: []const u8,
    files: []const sandbox.Spec.File,
    uid: u32,
    gid: u32,
) !?Store.Key {
    _ = b.store orelse return null;
    const parent = if (b.layers.items.len > 0)
        b.layers.items[b.layers.items.len - 1].key orelse return null
    else
        b.below() orelse return null;
    var h: Store.KeyHasher = .init(tag);
    h.core(parent, script, b.env.items);
    h.int(uid);
    h.int(gid);
    h.field(b.workdir);
    h.int(files.len);
    for (files) |f| {
        if (!f.keep) return null;
        h.field(f.path);
        h.field(f.contents);
        h.int(f.mode);
    }
    return h.final();
}

/// What a base's layer, and so every layer above it, depends on besides its own script: the
/// store's format (`Store.store_format`), the job's cache scope and repository (a vouched fork's
/// pull request never replays, or leaves, a layer its repository's own jobs use), the rootfs's
/// fingerprint, how ids are mapped (a rootless runner's layers are owned by its own user, a root
/// runner's have the canonical ids), the binds (where, not what: mounts' content is in no key), and
/// the Zig cache seeds' layers between the rootfs and the job's (a layer replayed over another seed
/// would show the wrong files). Not the slot: a stored layer has the canonical ids, which every
/// slot's job sees as its own (`Store.unshift`, `Spec.canonical`). Null, and the job uncached, when
/// the rootfs cannot be read.
fn below(b: *Backend) ?Store.Key {
    const fp = Store.rootfsFingerprint(b.arena, b.io, b.rootfs) catch |e| {
        std.log.warn("native: the rootfs's fingerprint: {s}; the job's steps are not cached", .{
            @errorName(e),
        });
        b.store = null;
        return null;
    };
    return belowKey(.{
        .format = Store.store_format,
        .scope = b.scope,
        .repository = b.repository,
        .fingerprint = &fp,
        .userns = @tagName(b.how.userns),
        .binds = b.binds,
        .seeds = b.seed_layers.items,
    }, null);
}

/// What `below` hashes, as values: the store's format and what it reads from the job.
pub const Below = struct {
    format: []const u8,
    scope: []const u8,
    repository: []const u8,
    fingerprint: []const u8,
    userns: []const u8,
    binds: []const sandbox.Spec.Bind,
    /// The Zig cache seeds' layers (`volumes.Seed`), by path, which names the release,
    /// architecture and step user each was built for, once.
    seeds: []const []const u8 = &.{},
};

/// `below`'s digest (`KeyHasher.plain("below a base")`, then each field). `bytes`, when given,
/// receives the preimage: P8's key vectors (`key_vectors.zig`) check it against the model's.
/// The seeds and which binds are cache volumes (`Bind.volume`) come last, and only when the job
/// has either (the model's `belowTail`): a job with neither hashes what it did before P4.
pub fn belowKey(in: Below, bytes: ?*std.Io.Writer) Store.Key {
    var h: Store.KeyHasher = .{ .h = .init(.{}), .bytes = bytes };
    h.field("below a base");
    h.field(in.format);
    h.field(in.scope);
    h.field(in.repository);
    h.field(in.fingerprint);
    h.field(in.userns);
    h.int(in.binds.len);
    for (in.binds) |bd| {
        h.field(bd.host);
        h.field(bd.at);
        h.int(@intFromBool(bd.read_only));
        h.int(@intFromBool(bd.optional));
    }
    var volumes_bound = false;
    for (in.binds) |bd| volumes_bound = volumes_bound or bd.volume;
    if (in.seeds.len > 0 or volumes_bound) {
        h.int(in.seeds.len);
        for (in.seeds) |l| h.field(l);
        // Each bind's flag, or none when no bind is a volume (the model's empty `volumes`).
        h.int(if (volumes_bound) in.binds.len else 0);
        if (volumes_bound) for (in.binds) |bd| h.int(@intFromBool(bd.volume));
    }
    return h.final();
}

/// How the job's namespace sees a stored layer's ids (`Store.Ids`), for its digest: on a root
/// runner they are the canonical ids already (`Store.unshift`), rootless the runner's own user's.
fn ids(b: *const Backend) Store.Ids {
    return if (b.how.userns == .mapped)
        .{ .base = 0, .count = ids_per_slot }
    else
        .{ .base = std.os.linux.getuid(), .count = 1 };
}

/// How the job's namespace sees the host ids of the job's own uppers: its slot's range on a root
/// runner.
fn slotIds(b: *const Backend) Store.Ids {
    return .{ .base = b.idBase(), .count = ids_per_slot };
}

/// The job's own upper `l` given the canonical ids (`Store.unshift`), on a root runner, before it
/// is published or flattened; each step then sees it through the job's ids. A failure ends the
/// job (`error.LayerNotShifted`, which no step's `if: always()` survives) and poisons the layer:
/// half shifted, it is never shifted again, which would take its canonical ids for outsiders.
fn canonicalize(b: *Backend, l: *Layer) error{LayerNotShifted}!void {
    if (b.how.userns != .mapped or l.canonical) return;
    if (l.poisoned) return error.LayerNotShifted;
    Store.unshift(b.arena, b.io, l.path, b.slotIds()) catch |e| {
        l.poisoned = true;
        std.log.err("native: a step's layer could not be given the canonical ids: {s}", .{@errorName(e)});
        return error.LayerNotShifted;
    };
    l.canonical = true;
}

/// The digest of the store's layer under `key` (`Store.layerDigest`): what output keys will key
/// on, computed when first asked for.
pub fn layerDigest(b: *Backend, key: Store.Key) !Store.Key {
    const s = b.store orelse return error.NoStore;
    return s.layerDigest(b.arena, b.io, key, b.ids());
}

/// An exec's key claimed (`Store.lockKey`, waited for while another job runs it), and its layer
/// when the store has it, on the stack already. Without a key, nothing is claimed. A store that
/// cannot be used now (its lock or its record unreadable) leaves the exec to run uncached.
const Claim = struct {
    key: ?Store.Key = null,
    lock: ?std.Io.File = null,
    hit: ?Store.Record = null,

    fn release(c: Claim, io: std.Io) void {
        if (c.lock) |l| l.close(io);
    }
};

fn claimKey(b: *Backend, key: ?Store.Key) error{ Stopped, OutOfMemory }!Claim {
    const k = key orelse return .{};
    const s = b.store.?;
    const arena = b.arena;
    b.stop_wait.store(false, .release);
    b.waiting.store(true, .release);
    const lock = s.lockKey(arena, b.io, k, &b.stop_wait) catch |e| {
        b.waiting.store(false, .release);
        if (e == error.Stopped) return error.Stopped;
        std.log.warn("native: the step store's lock: {s}", .{@errorName(e)});
        return .{};
    };
    b.waiting.store(false, .release);
    // A stored entry another job holds, but that cannot be replayed: run, and keep nothing.
    const hit = (s.open(arena, b.io, k) catch |e| {
        std.log.warn("native: a stored layer cannot be replayed ({s}); the step runs", .{
            @errorName(e),
        });
        lock.close(b.io);
        return .{};
    }) orelse return .{ .key = k, .lock = lock };
    errdefer hit.layer.lock.close(b.io);
    errdefer lock.close(b.io);
    try b.layers.ensureUnusedCapacity(arena, 1);
    try b.held.ensureUnusedCapacity(arena, 1);
    const name = try b.layerName('l');
    const link = try std.fmt.allocPrint(arena, "{s}/{s}", .{ b.dir, name });
    std.Io.Dir.cwd().symLink(b.io, hit.layer.fs, link, .{}) catch |e| {
        std.log.warn("native: a stored layer cannot be linked ({s}); the step runs", .{
            @errorName(e),
        });
        hit.layer.lock.close(b.io);
        lock.close(b.io);
        return .{};
    };
    b.held.appendAssumeCapacity(hit.layer.lock);
    b.layers.appendAssumeCapacity(.{
        .name = name,
        .path = hit.layer.fs,
        .key = k,
        .canonical = b.how.userns == .mapped,
    });
    return .{ .key = k, .lock = lock, .hit = hit.rec };
}

/// The stack's top layer, which an exec under `key` just left, given the canonical ids
/// (`canonicalize`, so any slot's job can use it) and moved into the store (`Store.publish`) with
/// its record, and the job's stack then links to it. Its parent is in the store (`keyFor`). A
/// failure to publish leaves the layer the job's own, and is logged: the job goes on, uncached from
/// here. One to shift its ids is the job's: the layer is then half one range's, half the other's.
fn publishTop(b: *Backend, key: Store.Key, kind: Store.Kind, rec: Store.Record) !void {
    const s = b.store orelse return;
    const arena = b.arena;
    if (rec.log.len > Store.max_record_bytes) return;
    // Room first: once the layer has moved, the job must hold it and point at it.
    b.held.ensureUnusedCapacity(arena, 1) catch return;
    const top = &b.layers.items[b.layers.items.len - 1];
    try b.canonicalize(top);
    const name = b.layerName('l') catch return;
    const link = std.fmt.allocPrint(arena, "{s}/{s}", .{ b.dir, name }) catch return;
    const layer_fs = std.fmt.allocPrint(arena, "{s}/layers/{s}/fs", .{
        s.root,
        &Store.hex(key),
    }) catch return;
    // Made first, dangling until the layer is there: once it moved, the stack must reach it.
    const cwd = std.Io.Dir.cwd();
    cwd.symLink(b.io, layer_fs, link, .{}) catch |e| {
        std.log.warn("native: cannot link a layer into the store: {s}", .{@errorName(e)});
        return;
    };
    const layer = s.publish(arena, b.io, key, kind, top.path, rec) catch |e| {
        std.log.warn("native: cannot publish a layer to the store: {s}", .{@errorName(e)});
        cwd.deleteFile(b.io, link) catch {};
        return;
    };
    b.held.appendAssumeCapacity(layer.lock);
    const canonical = top.canonical;
    top.* = .{ .name = name, .path = layer.fs, .key = key, .canonical = canonical };
}

/// The job's stack merged into one layer (`Store.flatten`), before overlay's limits on layers and
/// on its options' length are reached. The merged layer stands for the stack's top: its key is
/// the top's, so the steps after it are keyed and published as before.
fn flatten(b: *Backend) !void {
    const arena = b.arena;
    const paths = try arena.alloc([]const u8, b.layers.items.len);
    // One tree, so one set of ids: the job's own uppers, consumed here, get the canonical ids the
    // stored layers have, and the merged layer is seen through the job's ids as they are.
    for (b.layers.items, paths) |*l, *p| {
        try b.canonicalize(l);
        p.* = l.path;
    }
    const name = try b.layerName('F');
    const out = try std.fmt.allocPrint(arena, "{s}/{s}", .{ b.dir, name });
    // Overlay's xattrs are `trusted.` when mounted as the host's root, `user.` under `userxattr`.
    const opaque_xattr = if (b.how.userns == .mapped)
        "trusted.overlay.opaque"
    else
        "user.overlay.opaque";
    try Store.flatten(arena, b.io, paths, out, opaque_xattr);
    const top_key = b.layers.items[b.layers.items.len - 1].key;
    b.layers.clearRetainingCapacity();
    try b.layers.append(arena, .{
        .name = name,
        .path = out,
        .key = top_key,
        .canonical = b.how.userns == .mapped,
    });
}

fn put(b: *Backend, name: []const u8, value: []const u8) !void {
    try Evaluator.putEnv(b.arena, &b.env, name, value);
}

fn envValue(b: *const Backend, name: []const u8) ?[]const u8 {
    for (b.env.items) |e| if (std.mem.eql(u8, e.name, name)) return e.value;
    return null;
}

// --- the job's image ---

/// How long a pull (its manifests, blobs and unpacking) may take before the job fails: a
/// registry that stopped answering must not hold "Set up job" for ever, and no step's timeout
/// runs yet.
const pull_deadline: std.Io.Duration = .fromSeconds(30 * 60);

/// The rootfs the job's steps start from, made natively: the job's image pulled (or found in the
/// store), and provisioned when it is the default one, as a native step of its own keyed like any
/// other (`provision`). With the operator's rootfs (`Config.rootfs`), the provisioned default
/// image is that directory instead, as in P1. Then who the image's `USER` is.
fn prepareRootfs(b: *Backend, ev: *Evaluator, plan: anytype, err_msg: *[]const u8) !void {
    const arena = b.arena;
    const default = std.mem.eql(u8, plan.job_image, dagger.default_image);
    if (b.operator_rootfs.len > 0 and default and plan.provision) {
        b.rootfs = b.operator_rootfs;
        return;
    }
    var creds: ?registry.Credentials = null;
    if (ev.job.container) |jc| if (try docker.registryCredentials(ev, jc)) |c| {
        creds = .{ .username = c.user, .password = c.pass };
    };
    var why: []const u8 = "";
    const img = b.pull(plan.job_image, creds, &why) catch |e| {
        err_msg.* = try std.fmt.allocPrint(arena, "could not pull {s} natively: {s}", .{
            plan.job_image,
            if (why.len > 0) why else @errorName(e),
        });
        return error.BaseContainerFailed;
    };
    b.image = img;
    b.image_env = img.env;
    try b.notes.append(arena, if (img.pulled) |p| try std.fmt.allocPrint(
        arena,
        "Image: pulled natively in {d} ms ({d} layers, {d} KB fetched){s}",
        .{
            p.ms,                                                                                                  p.layers, p.bytes / 1024,
            if (p.devices > 0) try std.fmt.allocPrint(arena, "; {d} device nodes left out", .{p.devices}) else "",
        },
    ) else "Image: from the native store");
    b.rootfs = img.rootfs;
    if (plan.provision) b.rootfs = try b.provision(
        img,
        if (plan.as_runner) set_up.provision_runner_script else set_up.provision_script,
        err_msg,
    );
    if (!plan.as_runner and img.user.len > 0) {
        const user_ids = b.imageUser(img.user) catch |e| {
            err_msg.* = try std.fmt.allocPrint(arena, "the image's USER {s}: {s}", .{
                img.user,
                switch (e) {
                    error.UnknownUser => "not in its /etc/passwd",
                    error.UnknownGroup => "its group is not in its /etc/group",
                    error.Unmapped => "a rootless runner maps only root (a root runner, or an image that runs as root)",
                    else => @errorName(e),
                },
            });
            return error.BaseContainerFailed;
        };
        b.image_uid = user_ids[0];
        b.image_gid = user_ids[1];
    }
}

/// `image` pulled into the store, or found there (`oci/image.zig`), within `pull_deadline`.
fn pull(b: *Backend, image: []const u8, creds: ?registry.Credentials, why: *[]const u8) !oci.Image {
    var local: std.http.Client = .{
        .allocator = b.gpa,
        .io = b.io,
        .write_buffer_size = http.write_buffer_size,
    };
    defer local.deinit();
    const store: ImageStore = .{ .root = b.store_cfg.root };
    const req: oci.Request = .{ .image = image, .creds = creds, .owners = b.how.userns == .mapped };
    const r = try http.within(b.io, pull_deadline, pullWithin, .{
        b.arena, b.gpa, b.io, http.client(&local), store, req, why,
    });
    return (r orelse {
        why.* = "it took longer than 30 minutes";
        return error.Timeout;
    });
}

/// A service's or an action's image (`images.Image`: its rootfs and its configuration), pulled
/// natively or found in the store (`pull`). Tests may give a directory of images instead
/// (`Config.images`).
pub fn pullImage(
    b: *Backend,
    image: []const u8,
    creds: ?registry.Credentials,
    why: *[]const u8,
) !images.Image {
    if (b.images_dir.len > 0) return (try images.find(b.arena, b.io, b.images_dir, image)) orelse {
        why.* = try std.fmt.allocPrint(b.arena, "it is not in the tests' images ({s})", .{b.images_dir});
        return error.ImageNotFound;
    };
    const img = try b.pull(image, creds, why);
    return images.fromPulled(b.arena, b.io, img.rootfs, img.digest) catch |e| {
        why.* = "its configuration cannot be read";
        return e;
    };
}

fn pullWithin(
    arena: Allocator,
    gpa: Allocator,
    io: std.Io,
    client: *std.http.Client,
    store: ImageStore,
    req: oci.Request,
    why: *[]const u8,
) anyerror!oci.Image {
    return oci.pull(arena, gpa, io, client, store, req, why);
}

/// The default image provisioned (`set_up.provision_script`, or `provision_runner_script` when
/// steps run as the runner user), as Dagger's base does in one cached exec: here a native step
/// on the pulled image, its layer keyed by the image, the script and its env (P2's
/// `Store.KeyHasher`) and flattened onto the image (`ImageStore.flatten`), so it runs once per
/// store. The provisioned rootfs is a whole tree with the image's ids, shared across slots and
/// across stores' keys, not one of P2's stacked layers with a record.
fn provision(b: *Backend, img: oci.Image, script: []const u8, err_msg: *[]const u8) ![]const u8 {
    const arena = b.arena;
    var env: std.ArrayList([]const u8) = .empty;
    try env.appendSlice(arena, img.env);
    if (for (img.env) |e| {
        if (std.mem.startsWith(u8, e, "PATH=")) break false;
    } else true) try env.append(arena, "PATH=" ++ image_path);
    // P2's key (`Store.KeyHasher`, P8's preimage): the image's manifest (and whether its files
    // are a rootless runner's) as the parent, the script, and the env in the container's order.
    var vars: std.ArrayList(job_mod.EnvVar) = .empty;
    for (env.items) |kv| {
        const eq = std.mem.indexOfScalar(u8, kv, '=') orelse continue;
        try vars.append(arena, .{ .name = kv[0..eq], .value = kv[eq + 1 ..] });
    }
    var ph: Store.KeyHasher = .plain("below a provisioning");
    ph.field(img.manifest);
    ph.field(if (b.how.userns == .mapped) "" else "rootless");
    var kh: Store.KeyHasher = .init(.step);
    kh.core(ph.final(), script, vars.items);
    const key_hex = Store.hex(kh.final());
    const key: []const u8 = &key_hex;
    const started = std.Io.Clock.awake.now(b.io).toMilliseconds();
    var p: Provision = .{ .b = b, .img = img, .script = script, .env = env.items };
    const store: ImageStore = .{ .root = b.store_cfg.root };
    // Under `rootfs/`, not P2's `layers/`: a provisioned rootfs is a whole tree with the image's
    // ids, not a stacked layer with a record, and P2's `collect` must not take it for a broken
    // entry (nor its `.tmp-` for a dead publisher's).
    const made = store.ensure(arena, b.io, "rootfs", key, .{ .ptr = &p, .makeFn = Provision.make }) catch |e| {
        err_msg.* = try std.fmt.allocPrint(arena, "could not provision the image natively: {s}", .{
            if (p.why.len > 0) p.why else @errorName(e),
        });
        return error.BaseContainerFailed;
    };
    try b.notes.append(arena, if (made.made) try std.fmt.allocPrint(
        arena,
        "Provisioned natively in {d} ms (layer {s})",
        .{ std.Io.Clock.awake.now(b.io).toMilliseconds() - started, key[0..12] },
    ) else try std.fmt.allocPrint(arena, "Provisioned: the native layer {s}, made before", .{key[0..12]}));
    return std.fmt.allocPrint(arena, "{s}/rootfs", .{made.dir});
}

/// The provisioning step, run in the job's sandbox on the pulled image and flattened into the
/// directory `ImageStore.ensure` publishes.
const Provision = struct {
    b: *Backend,
    img: oci.Image,
    script: []const u8,
    env: []const []const u8,
    why: []const u8 = "",

    fn make(ptr: *anyopaque, dir: []const u8) anyerror!void {
        const p: *Provision = @ptrCast(@alignCast(ptr));
        const b = p.b;
        const arena = b.arena;
        const workdir = b.workdir;
        b.rootfs = p.img.rootfs;
        b.workdir = "/";
        defer b.workdir = workdir;
        var out: Captured = .{ .arena = arena };
        const ended = try b.exec(p.script, p.env, &.{}, 0, 0, out.output());
        const upper = b.layers.items[b.layers.items.len - 1].path;
        // The step's layer is consumed: the next exec of the job starts again from L0.
        defer {
            removeTree(arena, b.io, upper);
            b.layers.clearRetainingCapacity();
        }
        if (ended.failure.len > 0 or ended.code != 0) {
            // Its last lines: apt's own last line ("dpkg returned an error code") says little.
            p.why = try std.fmt.allocPrint(arena, "{s}{s} (exit {d})", .{ ended.failure, out.tailLines(8), ended.code });
            return error.ProvisionFailed;
        }
        // On a root runner the layer belongs to the job's range of ids: back to the image's.
        const shift: u32 = if (b.how.userns == .mapped) b.idBase() else 0;
        ImageStore.flatten(arena, b.io, p.img.rootfs, .{ .dir = upper, .id_shift = shift }, try std.fmt.allocPrint(arena, "{s}/rootfs", .{dir})) catch |e| {
            p.why = try std.fmt.allocPrint(arena, "its layer could not be flattened: {s}", .{@errorName(e)});
            return e;
        };
    }
};

/// The ids of an image's `USER`: `name`, `uid`, `name:group`, `uid:gid`, looked up in the image's
/// own /etc/passwd and /etc/group (a uid not there has gid 0, as runc gives it).
fn imageUser(b: *Backend, user: []const u8) ![2]u32 {
    const arena = b.arena;
    const colon = std.mem.indexOfScalar(u8, user, ':');
    const u = if (colon) |c| user[0..c] else user;
    const g: ?[]const u8 = if (colon) |c| user[c + 1 ..] else null;
    const passwd = switch (try sandbox.readIn(arena, b.rootfs, "/etc/passwd", 1 << 20)) {
        .text => |t| t,
        else => "",
    };
    var uid: u32 = 0;
    var gid: u32 = 0;
    if (std.fmt.parseInt(u32, u, 10)) |n| {
        uid = n;
        gid = if (lookup(passwd, null, n)) |e| e[1] else 0;
    } else |_| {
        const e = lookup(passwd, u, null) orelse return error.UnknownUser;
        uid = e[0];
        gid = e[1];
    }
    if (g) |grp| {
        gid = std.fmt.parseInt(u32, grp, 10) catch gid: {
            const group = switch (try sandbox.readIn(arena, b.rootfs, "/etc/group", 1 << 20)) {
                .text => |t| t,
                else => "",
            };
            var lines = std.mem.splitScalar(u8, group, '\n');
            while (lines.next()) |line| {
                var f = std.mem.splitScalar(u8, line, ':');
                const name = f.next() orelse continue;
                _ = f.next();
                const id = std.fmt.parseInt(u32, f.next() orelse continue, 10) catch continue;
                if (std.mem.eql(u8, name, grp)) break :gid id;
            }
            return error.UnknownGroup;
        };
    }
    if (b.how.userns != .mapped and (uid != 0 or gid != 0)) return error.Unmapped;
    return .{ uid, gid };
}

/// A passwd line's uid and gid, by name or by uid.
fn lookup(passwd: []const u8, name: ?[]const u8, uid: ?u32) ?[2]u32 {
    var lines = std.mem.splitScalar(u8, passwd, '\n');
    while (lines.next()) |line| {
        var f = std.mem.splitScalar(u8, line, ':');
        const n = f.next() orelse continue;
        _ = f.next();
        const id = std.fmt.parseInt(u32, f.next() orelse continue, 10) catch continue;
        const g = std.fmt.parseInt(u32, f.next() orelse continue, 10) catch continue;
        if (name) |want| if (std.mem.eql(u8, n, want)) return .{ id, g };
        if (uid) |want| if (id == want) return .{ id, g };
    }
    return null;
}

/// What `Exec.writePendingEnv` adds to Dagger's container before a step: the variables and PATH
/// entries the steps before it asked for (`GITHUB_ENV`, `GITHUB_PATH`), then forgotten. A PATH
/// set through GITHUB_ENV gets every GITHUB_PATH directory in front, as GitHub's runner puts
/// them; otherwise the new directories go in front of the container's PATH.
fn applyPendingEnv(b: *Backend, x: *Exec) !void {
    const ev = x.ev;
    var path_set = false;
    for (ev.pending_env.items) |e| {
        const path = std.mem.eql(u8, e.name, "PATH") and ev.path_prepend.items.len > 0;
        const value = if (path) try std.fmt.allocPrint(b.arena, "{s}:{s}", .{
            try Evaluator.prependPath(b.arena, ev.path_prepend.items),
            e.value,
        }) else e.value;
        path_set = path_set or path;
        try b.put(e.name, value);
    }
    if (ev.pending_path.items.len > 0 and !path_set) {
        const current = for (b.env.items) |e| {
            if (std.mem.eql(u8, e.name, "PATH")) break e.value;
        } else "";
        try b.put("PATH", try std.fmt.allocPrint(b.arena, "{s}:{s}", .{
            try Evaluator.prependPath(b.arena, ev.pending_path.items),
            current,
        }));
    }
    ev.pending_env.clearRetainingCapacity();
    ev.pending_path.clearRetainingCapacity();
}

/// The container's environment and `extra` as `NAME=value`, `extra` winning.
fn envStrings(b: *Backend, extra: []const job_mod.EnvVar) ![]const []const u8 {
    var all: std.ArrayList(job_mod.EnvVar) = .empty;
    try all.appendSlice(b.arena, b.env.items);
    for (extra) |e| try Evaluator.putEnv(b.arena, &all, e.name, e.value);
    const out = try b.arena.alloc([]const u8, all.items.len);
    for (all.items, out) |e, *o| o.* = try std.fmt.allocPrint(b.arena, "{s}={s}", .{
        e.name,
        e.value,
    });
    return out;
}

/// A secret's value from its id. On this backend `Secrets` registers values without a session
/// (`Secrets.local`), so the id is only a name for the value.
fn plaintext(x: *Exec, id: []const u8) []const u8 {
    var it = x.secrets.ids.iterator();
    while (it.next()) |e| if (std.mem.eql(u8, e.value_ptr.*, id)) return e.key_ptr.*;
    return "";
}

/// A step's output fed to the job's log as Dagger's log stream feeds it: one span per exec.
const Live = struct {
    demux: *SpanDemux,
    arena: Allocator,
    /// Under step caching, the output as printed, for the store (`Store.Record.log`); null past
    /// `Store.max_record_bytes`, and the step is then not published.
    record: ?std.ArrayList(u8),

    fn output(l: *Live) sandbox.Output {
        return .{ .ptr = l, .chunkFn = chunk };
    }

    fn chunk(ptr: *anyopaque, bytes: []const u8) void {
        const l: *Live = @ptrCast(@alignCast(ptr));
        SpanDemux.onRecord(l.demux, .{ .span = "native", .stream = 1, .text = bytes });
        if (l.record) |*r| {
            if (r.items.len + bytes.len > Store.max_record_bytes) {
                l.record = null;
            } else r.appendSlice(l.arena, bytes) catch {
                l.record = null;
            };
        }
    }
};

/// The output of an exec that is not a step's (the base, a checkout's fetch), kept for the
/// reason when it fails: its last lines.
const Captured = struct {
    arena: Allocator,
    text: std.ArrayList(u8) = .empty,

    const keep = 4096;

    fn output(c: *Captured) sandbox.Output {
        return .{ .ptr = c, .chunkFn = chunk };
    }

    fn chunk(ptr: *anyopaque, bytes: []const u8) void {
        const c: *Captured = @ptrCast(@alignCast(ptr));
        c.text.appendSlice(c.arena, bytes) catch return;
        if (c.text.items.len > 2 * keep)
            c.text.replaceRangeAssumeCapacity(0, c.text.items.len - keep, &.{});
    }

    /// The last `n` lines, joined by " | ".
    fn tailLines(c: *const Captured, n: usize) []const u8 {
        const t = std.mem.trim(u8, c.text.items, " \n");
        var start = t.len;
        var seen: usize = 0;
        while (start > 0 and seen < n) {
            start = std.mem.lastIndexOfScalar(u8, t[0..start], '\n') orelse 0;
            seen += 1;
        }
        const lines = std.mem.trimStart(u8, t[start..], "\n");
        return std.mem.replaceOwned(u8, c.arena, lines, "\n", " | ") catch lines;
    }

    fn tail(c: *const Captured) []const u8 {
        const t = std.mem.trim(u8, c.text.items, " \n");
        const last = std.mem.lastIndexOfScalar(u8, t, '\n') orelse return t;
        return t[last + 1 ..];
    }
};

// --- tests ---

const sink = @import("../sink.zig");
const testStep = @import("../dagger/testing.zig").testStep;
const testJob = @import("../dagger/testing.zig").testJob;
const FakeSession = @import("../dagger/testing.zig").FakeSession;
const fake_child = @import("../dagger/testing.zig").fake_child;
const base_answer = @import("../dagger/testing.zig").base_answer;
const execAnswer = @import("../dagger/testing.zig").exec;

/// A native backend for tests, or `error.SkipZigTest` with the reason printed when this machine
/// cannot run one (a failure instead where `ZIG_RUNNER_REQUIRE_NATIVE=1`, as CI sets: there they
/// must run): a rootfs of a few directories with the host's /usr bound over it, in the
/// test's directory, and the runner binary the build copied for the tests (`ZIG_RUNNER_TEST_EXE`).
/// Rootless unless the tests run as root, where the job gets its range of ids and its network.
pub fn testConfig(arena: Allocator, tmp: *std.testing.TmpDir) !Config {
    const io = std.testing.io;
    var env = try std.testing.environ.createMap(arena);
    const required = std.mem.eql(u8, env.get("ZIG_RUNNER_REQUIRE_NATIVE") orelse "", "1");
    const exe_rel = env.get("ZIG_RUNNER_TEST_EXE") orelse
        return skip(required, "ZIG_RUNNER_TEST_EXE is not set (`zig build test` sets it)");
    const exe = std.Io.Dir.cwd().realPathFileAlloc(io, exe_rel, arena) catch
        return skip(required, "the runner binary for native steps is not built");
    const d = tmp.dir;
    const dirs = [_][]const u8{
        "rootfs/etc/ssl", "rootfs/usr",  "rootfs/tmp",  "rootfs/dev", "rootfs/proc",
        "rootfs/sys",     "rootfs/root", "rootfs/home", "store",
    };
    for (dirs) |p| try d.createDirPath(io, p);
    const links = [_][2][]const u8{
        .{ "usr/bin", "bin" }, .{ "usr/sbin", "sbin" },
        .{ "usr/lib", "lib" }, .{ "usr/lib64", "lib64" },
    };
    for (links) |l|
        try d.symLink(io, l[0], try std.fmt.allocPrint(arena, "rootfs/{s}", .{l[1]}), .{});
    try d.writeFile(io, .{
        .sub_path = "rootfs/etc/passwd",
        .data = "root:x:0:0:root:/root:/bin/bash\nrunner:x:1001:1001::/home/runner:/bin/bash\n",
    });
    try d.writeFile(io, .{ .sub_path = "rootfs/etc/group", .data = "root:x:0:\nrunner:x:1001:\n" });
    for ([_][]const u8{ "hosts", "resolv.conf", "ld.so.cache" }) |f| try d.writeFile(io, .{
        .sub_path = try std.fmt.allocPrint(arena, "rootfs/etc/{s}", .{f}),
        .data = "",
    });
    const root = try d.realPathFileAlloc(io, ".", arena);
    const cfg: Config = .{
        .rootfs = try std.fmt.allocPrint(arena, "{s}/rootfs", .{root}),
        .store = try std.fmt.allocPrint(arena, "{s}/store", .{root}),
        .self_exe = exe,
        .vouched = true,
        .rootless = true,
        .check_store_parents = false,
        .binds = &.{
            .{ .host = "/usr", .at = "/usr" },
            .{ .host = "/etc/ld.so.cache", .at = "/etc/ld.so.cache" },
            // CA certificates, for the outbound test's HTTPS.
            .{ .host = "/etc/ssl", .at = "/etc/ssl" },
        },
    };
    // One sandbox, to see whether this machine lets us make them at all.
    var b = try init(arena, io, std.testing.allocator, cfg);
    defer b.deinit();
    var out: Captured = .{ .arena = arena };
    const ended = try b.exec("true", &.{"PATH=/usr/bin"}, &.{}, 0, 0, out.output());
    if (ended.failure.len > 0 or ended.code != 0)
        return skip(required, try std.fmt.allocPrint(arena, "this machine cannot make a " ++
            "native step's sandbox ({s}, exit {d})", .{ ended.failure, ended.code }));
    // What `dagger.run` asks before a job goes native: a refusal here would send the tests' jobs
    // to Dagger, which is not there.
    if (usable(arena, io, std.testing.allocator, cfg)) |why| return skip(required, why);
    return cfg;
}

pub fn skip(required: bool, why: []const u8) error{ SkipZigTest, NativeTestsRequired } {
    std.debug.print("native backend test {s}: {s}\n", .{
        if (required) "failed (ZIG_RUNNER_REQUIRE_NATIVE=1)" else "skipped",
        why,
    });
    return if (required) error.NativeTestsRequired else error.SkipZigTest;
}

test "a run-only job on the native backend: file commands, masks, exit codes and conditions" {
    var a: std.heap.ArenaAllocator = .init(std.testing.allocator);
    defer a.deinit();
    const arena = a.allocator();
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    const cfg = try testConfig(arena, &tmp);

    var s1 = testStep("echo hello; echo FOO=bar >> $GITHUB_ENV; echo out=42 >> $GITHUB_OUTPUT\n" ++
        "echo /opt/x >> $GITHUB_PATH; echo ::add-mask::s3cr3t-value; echo the s3cr3t-value\n" ++
        "echo '# summary' >> $GITHUB_STEP_SUMMARY; echo to stderr >&2; whoami; pwd\n" ++
        // A secret written into the script: its file is written by the sandbox, not by the
        // script's command, and removed after it (`Spec.files`), which step 2 checks.
        ": j0b-secret-value");
    s1.context_name = "first";
    var s2 = testStep("echo FOO=$FOO; echo PATH=$PATH; echo OUT=$OUT; " ++
        "test -e /tmp/zig-runner-step-1.sh && echo leftover || echo no script left; exit 3");
    s2.env = &.{.{ .name = "OUT", .value = .{ .expr = "steps.first.outputs.out" } }};
    var s3 = testStep("echo not reached");
    s3.name = "skipped";
    var s4 = testStep("echo always; echo HOME=$HOME");
    s4.condition = "always()";
    var s5 = testStep("exit 1");
    s5.condition = "always()";
    s5.continue_on_error = .{ .lit = "true" };
    var job = testJob(&.{ s1, s2, s3, s4, s5 });
    job.secrets = &.{"j0b-secret-value"};

    var env: std.process.Environ.Map = .init(arena);
    var w: std.Io.Writer.Allocating = .init(arena);
    var log: sink.LogSink = .{ .stdout = .{ .writer = &w.writer } };
    const res = try dagger.run(arena, std.testing.io, &env, .{
        .native = cfg,
        .step_user = .root,
        .gpa = std.testing.allocator,
    }, job, &log);
    const text = w.written();

    try std.testing.expectEqual(dagger.Outcome.success, res.steps[0].outcome);
    try std.testing.expectEqual(dagger.Outcome.failure, res.steps[1].outcome);
    try std.testing.expectEqual(@as(i32, 3), res.steps[1].exit_code);
    try std.testing.expectEqual(dagger.Outcome.skipped, res.steps[2].outcome);
    try std.testing.expectEqual(dagger.Outcome.success, res.steps[3].outcome);
    try std.testing.expectEqual(dagger.Outcome.failure, res.steps[4].outcome);
    try std.testing.expect(res.steps[4].continued);
    try std.testing.expect(!res.succeeded);
    const expect = [_][]const u8{
        "Engine: native",
        "hello",
        // The mask applies from the line after it, as on Dagger.
        "the ***",
        // stderr is the step's stdout (`scripts.stream_prologue`).
        "to stderr",
        "root",
        "/home/runner/work/r/r",
        "FOO=bar",
        "PATH=/opt/x:/usr/local/sbin:",
        "OUT=42",
        "no script left",
        "##[error]Process completed with exit code 3.",
        "always",
        "HOME=/root",
    };
    for (expect) |e| if (std.mem.indexOf(u8, text, e) == null) {
        std.debug.print("missing {s} in:\n{s}\n", .{ e, text });
        return error.TestUnexpectedResult;
    };
    // The script's own text, logged before the mask, has it; its output does not.
    try std.testing.expect(std.mem.indexOf(u8, text, "stdout] the s3cr3t-value") == null);
    try std.testing.expect(std.mem.indexOf(u8, text, "not reached") == null);
    try std.testing.expectEqualStrings("# summary\n", res.summaries[0]);
    // The job's layers went with it.
    const jobs_path = try std.fmt.allocPrint(arena, "{s}/jobs", .{cfg.store});
    var jobs = try std.Io.Dir.cwd().openDir(std.testing.io, jobs_path, .{ .iterate = true });
    defer jobs.close(std.testing.io);
    var it = jobs.iterate();
    try std.testing.expect(try it.next(std.testing.io) == null);
}

test "a cancel stops a native step at once, and every process it started" {
    var a: std.heap.ArenaAllocator = .init(std.testing.allocator);
    defer a.deinit();
    const arena = a.allocator();
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    const cfg = try testConfig(arena, &tmp);

    var s1 = testStep("sleep 60 & sleep 60");
    s1.name = "long";
    var s2 = testStep("echo after");
    s2.condition = "always()";
    const job = testJob(&.{ s1, s2 });
    var cancel: dagger.Cancel = .{};
    var env: std.process.Environ.Map = .init(arena);
    var w: std.Io.Writer.Allocating = .init(arena);
    var log: sink.LogSink = .{ .stdout = .{ .writer = &w.writer } };
    const io = std.testing.io;
    var canceller = try io.concurrent(cancelSoon, .{ io, &cancel });
    defer canceller.cancel(io);
    const started = std.Io.Clock.awake.now(io).toMilliseconds();
    const res = try dagger.run(arena, io, &env, .{
        .native = cfg,
        .step_user = .root,
        .gpa = std.testing.allocator,
        .cancel = &cancel,
    }, job, &log);
    const took = std.Io.Clock.awake.now(io).toMilliseconds() - started;
    try std.testing.expectEqual(dagger.Outcome.cancelled, res.steps[0].outcome);
    try std.testing.expectEqual(dagger.Outcome.success, res.steps[1].outcome);
    try std.testing.expect(res.cancelled);
    // The backgrounded `sleep 60` went with the step: its pipe closed, so the job went on.
    try std.testing.expect(took < 10_000);
}

fn cancelSoon(io: std.Io, cancel: *dagger.Cancel) void {
    io.sleep(.fromMilliseconds(500), .awake) catch return;
    cancel.request(std.Io.Clock.real.now(io).toMilliseconds() + 60_000);
}

test "unsupported: what sends a job to Dagger, and the first reason given" {
    const io = std.testing.io;
    const ok: Config = .{
        .rootfs = "/",
        .store = "/tmp/x",
        .self_exe = "/bin/true",
        .vouched = true,
        .rootless = true,
    };
    const root: dagger.Options = .{ .step_user = .root };
    const run_only = testJob(&.{testStep("true")});
    try std.testing.expect(unsupported(io, run_only, root, ok) == null);

    var co = testStep("");
    co.action = .{ .checkout = &.{} };
    try std.testing.expect(unsupported(io, testJob(&.{co}), root, ok) == null);
    co.action = .{ .checkout = &.{.{ .name = "submodules", .value = .{ .lit = "true" } }} };
    try expectReason("submodules", unsupported(io, testJob(&.{co}), root, ok));

    var uses = testStep("");
    uses.action = .{ .uses = .{ .owner = "actions", .name = "setup-node", .ref = "v4" } };
    try expectReason("`uses:`", unsupported(io, testJob(&.{uses}), root, ok));

    var with_services = run_only;
    with_services.services = &.{.{ .name = "pg", .image = .{ .lit = "postgres" } }};
    // Services are native on a root runner, their images pulled by P3 (before, P6 refused them
    // without its images directory); rootless they have no network of the job's own.
    if (std.os.linux.geteuid() == 0)
        try std.testing.expect(unsupported(io, with_services, root, ok) == null)
    else
        try expectReason("`services:`", unsupported(io, with_services, root, ok));
    // An image given by an expression is not native on a root runner either.
    if (std.os.linux.geteuid() == 0) {
        with_services.services = &.{.{ .name = "pg", .image = .{ .expr = "matrix.db" } }};
        try expectReason("expression", unsupported(io, with_services, root, ok));
    }
    // `container:` jobs and any image are pulled natively; a job container's ports, volumes and
    // options are not native yet.
    var container = run_only;
    container.container = .{ .name = "", .image = .{ .lit = "node:22" } };
    try std.testing.expect(unsupported(io, container, root, ok) == null);
    container.container.?.ports = &.{.{ .lit = "8080:80" }};
    try expectReason("`ports:`", unsupported(io, container, root, ok));
    container.container.?.ports = &.{};
    container.container.?.options = .{ .lit = "--cpus 1" };
    try expectReason("`options:`", unsupported(io, container, root, ok));
    var custom = root;
    custom.image = "alpine:3";
    try std.testing.expect(unsupported(io, run_only, custom, ok) == null);
    custom.provision = false;
    try std.testing.expect(unsupported(io, run_only, custom, ok) == null);
    var nesting = root;
    nesting.nesting = true;
    try expectReason("Dagger engine", unsupported(io, run_only, nesting, ok));

    // A job the runner does not vouch for, from GitHub or a saved one (`--exec-job`).
    var remote = ok;
    remote.vouched = false;
    try expectReason("vouches", unsupported(io, run_only, root, remote));
    try expectReason("cgroup limits", unsupported(io, run_only, root, remote));
    // With phase 4's limits, on a root runner only.
    remote.job_limits = true;
    if (std.os.linux.geteuid() == 0)
        try std.testing.expect(unsupported(io, run_only, root, remote) == null)
    else
        try expectReason("root runner", unsupported(io, run_only, root, remote));
    if (std.os.linux.geteuid() != 0) {
        var rootless = ok;
        rootless.rootless = false;
        try expectReason("RUNNER_NATIVE_ROOTLESS", unsupported(io, run_only, root, rootless));
    }

    // `hashFiles()` anywhere in the job's expressions, in any case.
    var hashed = testStep("true");
    hashed.env = &.{.{ .name = "K", .value = .{ .expr = "HASHFILES('**/go.sum')" } }};
    try expectReason("hashFiles", unsupported(io, testJob(&.{hashed}), root, ok));
    var hashed_if = testStep("true");
    hashed_if.condition = "hashFiles('x') != ''";
    try expectReason("hashFiles", unsupported(io, testJob(&.{hashed_if}), root, ok));

    // Without the operator's rootfs the default image is pulled natively; one that is set must
    // be there.
    var no_rootfs = ok;
    no_rootfs.rootfs = "";
    if (std.os.linux.geteuid() == 0)
        try std.testing.expect(unsupported(io, run_only, root, no_rootfs) == null)
    else
        try expectReason("range of ids", unsupported(io, run_only, root, no_rootfs));
    no_rootfs.rootfs = "/nonexistent/rootfs";
    try expectReason("cannot be read", unsupported(io, run_only, root, no_rootfs));

    // Steps as the runner user need ids a rootless runner cannot map; on a root runner they may
    // call sudo.
    const as_runner: dagger.Options = .{ .step_user = .runner };
    const why = unsupported(io, run_only, as_runner, ok);
    if (std.os.linux.geteuid() == 0) {
        try std.testing.expect(why == null);
        const sudo = testJob(&.{testStep("sudo apt-get update")});
        try std.testing.expect(unsupported(io, sudo, as_runner, ok) == null);
    } else try expectReason("runner user", why);
}

fn expectReason(part: []const u8, why: ?[]const u8) !void {
    const w = why orelse return error.TestExpectedReason;
    if (std.mem.indexOf(u8, w, part) == null) {
        std.debug.print("expected {s} in: {s}\n", .{ part, w });
        return error.TestUnexpectedResult;
    }
}

test "a job that cannot be native runs on Dagger, and Set up job says why" {
    var a: std.heap.ArenaAllocator = .init(std.testing.allocator);
    defer a.deinit();
    const arena = a.allocator();
    var env: std.process.Environ.Map = .init(arena);
    const answers = [_][]const u8{ base_answer, try execAnswer(arena, "C1", 0, "hi\\n") };
    var fake: FakeSession = .{ .answers = &answers, .arena = arena };
    var w: std.Io.Writer.Allocating = .init(arena);
    var log: sink.LogSink = .{ .stdout = .{ .writer = &w.writer } };
    const res = try dagger.run(arena, std.testing.io, &env, .{
        .test_session_argv = &.{ "sh", "-c", fake_child },
        .test_transport = fake.transport(),
        .native = .{ .vouched = true, .rootless = true },
    }, testJob(&.{testStep("echo hi")}), &log);
    try std.testing.expectEqual(dagger.Outcome.success, res.steps[0].outcome);
    try std.testing.expect(std.mem.indexOf(u8, w.written(), "This job runs on Dagger: the " ++
        "native store is not set up") != null);
    try std.testing.expect(std.mem.indexOf(u8, w.written(), "Engine: Dagger") != null);
}

test "parity: a native job's base has the environment of Dagger's base container" {
    var a: std.heap.ArenaAllocator = .init(std.testing.allocator);
    defer a.deinit();
    const arena = a.allocator();
    var job = testJob(&.{testStep("true")});
    job.env = &.{
        .{ .name = "WORKFLOW_VAR", .value = .{ .lit = "w" } },
        .{ .name = "CI", .value = .{ .lit = "overridden" } },
    };
    var env: std.process.Environ.Map = .init(arena);
    var w: std.Io.Writer.Discarding = .init(&.{});
    var log: sink.LogSink = .{ .stdout = .{ .writer = &w.writer } };
    for ([_]config.StepUser{ .root, .runner }) |user| {
        // Dagger's base container, the job's first query, with what `runNative` turns off off.
        const answers = [_][]const u8{ base_answer, try execAnswer(arena, "C1", 0, "") };
        var fake: FakeSession = .{ .answers = &answers, .arena = arena };
        _ = try dagger.run(arena, std.testing.io, &env, .{
            .test_session_argv = &.{ "sh", "-c", fake_child },
            .test_transport = fake.transport(),
            .test_step_mark = "m4rk",
            .step_user = user,
            .step_cache = false,
            .package_caches = false,
        }, job, &log);
        const doc = fake.seen.items[0];

        var ev = try Evaluator.init(arena, &job);
        var b: Backend = .{
            .arena = arena,
            .io = std.testing.io,
            .gpa = std.testing.allocator,
            .dir = "",
            .rootfs = "",
            .binds = &.{},
            .lock = undefined,
            .how = .{ .argv_prefix = &.{}, .userns = .mapped },
        };
        try b.baseEnv(&ev, .{
            .as_runner = user == .runner,
            .mark = "m4rk",
            .container_env = &[_]job_mod.EnvVar{},
        });
        // Every variable Dagger sets is set natively, to the same value...
        var dagger_names: std.StringHashMapUnmanaged(void) = .empty;
        var rest: []const u8 = doc;
        const call = "withEnvVariable(name:\"";
        while (std.mem.indexOf(u8, rest, call)) |i| {
            rest = rest[i + call.len ..];
            const name = rest[0..std.mem.indexOfScalar(u8, rest, '"').?];
            try dagger_names.put(arena, name, {});
            const native = for (b.env.items) |e| {
                if (std.mem.eql(u8, e.name, name)) break e.value;
            } else {
                std.debug.print("{s} is in Dagger's base, not the native one\n", .{name});
                return error.TestUnexpectedResult;
            };
            const both = try std.fmt.allocPrint(arena, call ++ "{s}\",value:\"{s}\"", .{
                name,
                native,
            });
            if (std.mem.indexOf(u8, doc, both) == null) {
                std.debug.print("{s} is {s} natively, not Dagger's value\n", .{ name, native });
                return error.TestUnexpectedResult;
            }
        }
        // ...and nothing more but the image's PATH, which Dagger's container has from the image.
        try std.testing.expectEqual(dagger_names.count() + 1, b.env.items.len);
        try std.testing.expectEqualStrings("PATH", b.env.items[0].name);
        try std.testing.expectEqualStrings(ev.workspace, b.workdir);
        try std.testing.expectEqual(@as(u32, if (user == .runner) runner_uid else 0), b.uid);
    }
}

test "the native checkout: the commit, its .git, and the checkout's fixed time" {
    var a: std.heap.ArenaAllocator = .init(std.testing.allocator);
    defer a.deinit();
    const arena = a.allocator();
    const io = std.testing.io;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    var cfg = try testConfig(arena, &tmp);
    // A repository to fetch, at a file:// URL the steps see at the same path.
    const root = try tmp.dir.realPathFileAlloc(io, ".", arena);
    const make = try std.fmt.allocPrint(arena, "set -e; cd '{s}'; git init -q --bare o/r.git; " ++
        "git init -q src; cd src; echo from-the-repo > file; git add file; " ++
        "git -c user.name=t -c user.email=t@t commit -q -m first; " ++
        "git push -q ../o/r.git HEAD:refs/heads/main", .{root});
    const made = std.process.run(arena, io, .{ .argv = &.{ "sh", "-c", make } }) catch
        return skip(false, "git is not installed");
    if (made.term != .exited or made.term.exited != 0)
        return skip(false, "git could not make a repository");
    try tmp.dir.createDirPath(io, try std.fmt.allocPrint(arena, "rootfs/{s}", .{root}));
    cfg.binds = try std.mem.concat(arena, sandbox.Spec.Bind, &.{
        cfg.binds,
        &.{.{ .host = root, .at = root }},
    });

    var co = testStep("");
    co.name = "checkout";
    co.action = .{ .checkout = &.{.{ .name = "ref", .value = .{ .lit = "main" } }} };
    const check = testStep("cat file; stat -c %Y file; git log -1 --format=%s; " ++
        "git rev-parse --abbrev-ref HEAD; git config remote.origin.url");
    var job = testJob(&.{ co, check });
    job.github.server_url = try std.fmt.allocPrint(arena, "file://{s}", .{root});
    // On a root runner the repository made above is the host's root's, nobody in the job's
    // namespace, and git refuses to fetch from a repository someone else owns. A repository on
    // GitHub, fetched over HTTPS, has no owner to check.
    job.env = &.{.{ .name = "GIT_CONFIG_PARAMETERS", .value = .{ .lit = "'safe.directory=*'" } }};
    var env: std.process.Environ.Map = .init(arena);
    var w: std.Io.Writer.Allocating = .init(arena);
    var log: sink.LogSink = .{ .stdout = .{ .writer = &w.writer } };
    const res = try dagger.run(arena, io, &env, .{
        .native = cfg,
        .step_user = .root,
        .gpa = std.testing.allocator,
    }, job, &log);
    const text = w.written();
    if (res.steps[0].outcome != .success or res.steps[1].outcome != .success) {
        std.debug.print("checkout {s}, check {s}, engine {s}\n{s}\n", .{
            @tagName(res.steps[0].outcome),
            @tagName(res.steps[1].outcome),
            res.engine_error orelse "-",
            text,
        });
        return error.TestUnexpectedResult;
    }
    const expect = [_][]const u8{
        "with git in the job's image",
        "Ref: main",
        "HEAD is detached at origin/main",
        "from-the-repo",
        "946684800",
        "first",
        // `checkout.refCommands` gave it the ref, as Dagger's checkout does.
        "HEAD",
        "/o/r.git",
    };
    for (expect) |e| if (std.mem.indexOf(u8, text, e) == null) {
        std.debug.print("missing {s} in:\n{s}\n", .{ e, text });
        return error.TestUnexpectedResult;
    };
}

test "a native checkout that cannot fetch fails its step with why" {
    var a: std.heap.ArenaAllocator = .init(std.testing.allocator);
    defer a.deinit();
    const arena = a.allocator();
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    const cfg = try testConfig(arena, &tmp);
    var co = testStep("");
    co.action = .{ .checkout = &.{} };
    var job = testJob(&.{co});
    job.github.server_url = "file:///nonexistent";
    var env: std.process.Environ.Map = .init(arena);
    var w: std.Io.Writer.Allocating = .init(arena);
    var log: sink.LogSink = .{ .stdout = .{ .writer = &w.writer } };
    const res = try dagger.run(arena, std.testing.io, &env, .{
        .native = cfg,
        .step_user = .root,
        .gpa = std.testing.allocator,
    }, job, &log);
    try std.testing.expectEqual(dagger.Outcome.failure, res.steps[0].outcome);
    try std.testing.expect(std.mem.indexOf(u8, w.written(), "could not fetch o/r@0123456") != null);
}

test "parity: a run-only job gives the same results and step output on Dagger and native" {
    // Needs a Dagger engine (`dagger` on PATH) and a provisioned rootfs, so it runs only when
    // asked for: ZIG_RUNNER_PARITY_ROOTFS=<dir>. Not on CI, which has neither.
    var a: std.heap.ArenaAllocator = .init(std.testing.allocator);
    defer a.deinit();
    const arena = a.allocator();
    const io = std.testing.io;
    var env = try std.testing.environ.createMap(arena);
    const rootfs = env.get("ZIG_RUNNER_PARITY_ROOTFS") orelse return error.SkipZigTest;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    var cfg = try testConfig(arena, &tmp);
    cfg.rootfs = rootfs;
    cfg.binds = &.{};

    var s1 = testStep("echo a; echo K=v >> $GITHUB_ENV; echo o=1 >> $GITHUB_OUTPUT; " ++
        "echo /opt/p >> $GITHUB_PATH; echo ::add-mask::hidden-value; echo hidden-value; " ++
        "id -u; echo HOME=$HOME; pwd; ls /github; echo e >&2");
    s1.context_name = "one";
    var s2 = testStep("echo K=$K PATH=$PATH O=$O; env | grep -c ^GITHUB_ ; exit 2");
    s2.env = &.{.{ .name = "O", .value = .{ .expr = "steps.one.outputs.o" } }};
    var s3 = testStep("echo always");
    s3.condition = "always()";
    const job = testJob(&.{ s1, s2, s3 });
    const common: dagger.Options = .{
        .step_user = .root,
        .step_cache = false,
        .package_caches = false,
        .gpa = std.testing.allocator,
        .test_step_mark = "parity",
    };
    var outs: [2][]const []const u8 = undefined;
    var results: [2]dagger.Result = undefined;
    for (0..2) |i| {
        var opts = common;
        if (i == 1) opts.native = cfg;
        var w: std.Io.Writer.Allocating = .init(arena);
        var log: sink.LogSink = .{ .stdout = .{ .writer = &w.writer } };
        results[i] = try dagger.run(arena, io, &env, opts, job, &log);
        outs[i] = try stepLines(arena, w.written());
    }
    for (results[0].steps, results[1].steps) |d, n| {
        try std.testing.expectEqual(d.outcome, n.outcome);
        try std.testing.expectEqual(d.exit_code, n.exit_code);
    }
    try std.testing.expectEqual(outs[0].len, outs[1].len);
    for (outs[0], outs[1]) |d, n| try std.testing.expectEqualStrings(d, n);
}

/// The lines logged under the job's steps (not "Set up job"), as the console sink writes them.
fn stepLines(arena: Allocator, text: []const u8) ![]const []const u8 {
    var out: std.ArrayList([]const u8) = .empty;
    var lines = std.mem.splitScalar(u8, text, '\n');
    while (lines.next()) |l| {
        if (std.mem.indexOf(u8, l, " step 0 ") != null) continue;
        try out.append(arena, l);
    }
    return out.items;
}

/// Runs `job` natively with `cfg` as `user`, and its log.
pub fn runNativeJob(
    arena: Allocator,
    cfg: Config,
    job: job_mod.Job,
    user: config.StepUser,
) !struct { res: dagger.Result, text: []const u8 } {
    var env: std.process.Environ.Map = .init(arena);
    var w: std.Io.Writer.Allocating = .init(arena);
    var log: sink.LogSink = .{ .stdout = .{ .writer = &w.writer } };
    const res = try dagger.run(arena, std.testing.io, &env, .{
        .native = cfg,
        .step_user = user,
        .gpa = std.testing.allocator,
    }, job, &log);
    return .{ .res = res, .text = w.written() };
}

pub fn expectLines(text: []const u8, expect: []const []const u8) !void {
    for (expect) |e| if (std.mem.indexOf(u8, text, e) == null) {
        std.debug.print("missing {s} in:\n{s}\n", .{ e, text });
        return error.TestUnexpectedResult;
    };
}

test "secrets reach native steps under their aliases, in scripts and in working directories" {
    var a: std.heap.ArenaAllocator = .init(std.testing.allocator);
    defer a.deinit();
    const arena = a.allocator();
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    const cfg = try testConfig(arena, &tmp);
    var s1 = testStep("echo token-length=${#TOKEN}; mkdir -p /tmp/wd-s3cr3t-token");
    s1.env = &.{.{ .name = "TOKEN", .value = .{ .lit = "s3cr3t-token" } }};
    var s2 = testStep("pwd");
    s2.action.script.working_directory = .{ .lit = "/tmp/wd-s3cr3t-token" };
    // A script holding the secret: a file bound from a tmpfs of the step's own, never written
    // into the layer, which is on the store's disk.
    const s3 = testStep(": s3cr3t-token; stat -f -c script-fs=%T \"$0\"; " ++
        "python3 -c 'import sys\n" ++
        "for line in open(\"/proc/self/mountinfo\"):\n" ++
        "    f = line.split()\n" ++
        "    if f[4] == sys.argv[1]: print(\"script-mount\", f[f.index(\"-\") + 1])' \"$0\"");
    const s4 = testStep("ls /tmp/zig-runner-step-3* 2>/dev/null | wc -l | " ++
        "sed 's/^/scripts-left=/'");
    var job = testJob(&.{ s1, s2, s3, s4 });
    job.secrets = &.{"s3cr3t-token"};
    const r = try runNativeJob(arena, cfg, job, .root);
    for (r.res.steps) |st| if (st.outcome != .success) {
        std.debug.print("{s}\n", .{r.text});
        return error.TestUnexpectedResult;
    };
    // The value arrived (its length), and the working directory holding it was entered through
    // its alias. (Masking is the log sink's, which this test's does not do.)
    try expectLines(r.text, &.{
        "token-length=12",
        "stdout] /tmp/wd-s3cr3t-token",
        "script-fs=tmpfs",
        "script-mount tmpfs",
        "scripts-left=0",
    });
}

test "a native job's tool cache is the step user's, as on Dagger; a later step finds what one put there" {
    var a: std.heap.ArenaAllocator = .init(std.testing.allocator);
    defer a.deinit();
    const arena = a.allocator();
    const io = std.testing.io;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    const cfg = try testConfig(arena, &tmp);
    // What `install-zig.sh` does (v0.22.0 on Dagger; natively until this was made): make its
    // tree under RUNNER_TOOL_CACHE, which is under /opt, as the step user. The directory is there
    // before any step, as Dagger's mount is (root could make it, the runner user could not).
    const s1 = testStep("set -e; echo cache=$RUNNER_TOOL_CACHE; " ++
        "test -d \"$RUNNER_TOOL_CACHE\" && echo cache-there; " ++
        "mkdir -p \"$RUNNER_TOOL_CACHE/zig/0.17.0/x64\"; " ++
        "echo installed > \"$RUNNER_TOOL_CACHE/zig/0.17.0/x64/zig\"; " ++
        "stat -c 'owner=%u mode=%a' \"$RUNNER_TOOL_CACHE\" \"$RUNNER_TOOL_CACHE/zig/0.17.0/x64/zig\"");
    const s2 = testStep("cat \"$RUNNER_TOOL_CACHE/zig/0.17.0/x64/zig\" | sed 's/^/found-/'");
    // The runner user only on a root runner: a rootless one maps only root.
    const users: []const config.StepUser = if (std.os.linux.geteuid() == 0)
        &.{ .root, .runner }
    else
        &.{.root};
    for (users) |user| {
        // What `set_up.provision_runner_script` gives the runner user: /tmp for all, /github and
        // its home its own.
        if (user == .runner) {
            const rootfs = try std.fmt.allocPrint(arena, "{s}/rootfs", .{
                try tmp.dir.realPathFileAlloc(io, ".", arena),
            });
            const give = "cd \"$0\" && chmod 1777 tmp && mkdir -p github home/runner && " ++
                "chown 1001:1001 github home/runner";
            const made = try std.process.run(arena, io, .{
                .argv = &.{ "sh", "-c", give, rootfs },
            });
            try std.testing.expect(made.term == .exited and made.term.exited == 0);
        }
        // Without package caches the base makes it, in the base layer; with them it is the
        // job's `toolcache` volume (`volumes.plan`), seen as the step user's through the
        // volumes' idmapped mount on a root runner.
        for ([_]bool{ false, true }) |caches| {
            const r = try runCachedJob(arena, cfg, testJob(&.{ s1, s2 }), .{
                .package_caches = caches,
                .trusted = true,
            }, .{ .user = user });
            const uid: u32 = if (user == .runner) runner_uid else 0;
            // Its output, not the script's text, which the log has too.
            try expectLines(r.text, &.{
                "stdout] cache=" ++ set_up.tool_cache_dir,
                "stdout] cache-there",
                try std.fmt.allocPrint(arena, "stdout] owner={d} mode=755", .{uid}),
                try std.fmt.allocPrint(arena, "stdout] owner={d} mode=644", .{uid}),
                "stdout] found-installed",
            });
        }
    }
}

test "native tool cache volume: a replayed step that points into it runs again (#229)" {
    var a: std.heap.ArenaAllocator = .init(std.testing.allocator);
    defer a.deinit();
    const arena = a.allocator();
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    const c = try cachedConfig(arena, &tmp);
    const caches: volumes.Options = .{ .package_caches = true, .trusted = true };
    // With the volumes bound, a step is replayed as before.
    const plain = testJob(&.{testStep("echo x >> /shared/plain")});
    _ = try runCachedJob(arena, c.cfg, plain, caches, .{ .ran = "j1" });
    _ = try runCachedJob(arena, c.cfg, plain, caches, .{ .ran = "j2" });
    try std.testing.expectEqual(@as(usize, 1), runs(arena, c.shared, "plain"));
    // One that installs into the tool cache and puts the tree on PATH: its tree is in the
    // volume, in no layer, and no tree is checked natively, so its record is not trusted.
    const install = testJob(&.{testStep("echo x >> /shared/install; " ++
        "mkdir -p $RUNNER_TOOL_CACHE/t/1 && echo $RUNNER_TOOL_CACHE/t/1 >> $GITHUB_PATH")});
    _ = try runCachedJob(arena, c.cfg, install, caches, .{ .ran = "j3" });
    _ = try runCachedJob(arena, c.cfg, install, caches, .{ .ran = "j4" });
    try std.testing.expectEqual(@as(usize, 2), runs(arena, c.shared, "install"));
    // Without the volume, the tree is in the step's layer and comes back with its replay.
    const in_layer = testJob(&.{testStep("echo x >> /shared/layer; " ++
        "mkdir -p $RUNNER_TOOL_CACHE/t/2 && echo $RUNNER_TOOL_CACHE/t/2 >> $GITHUB_PATH")});
    _ = try runCachedJob(arena, c.cfg, in_layer, .{}, .{ .ran = "j5" });
    _ = try runCachedJob(arena, c.cfg, in_layer, .{}, .{ .ran = "j6" });
    try std.testing.expectEqual(@as(usize, 1), runs(arena, c.shared, "layer"));
}

test "a native step is contained: pivot_root, masked /proc, Docker's capabilities, no_new_privs" {
    var a: std.heap.ArenaAllocator = .init(std.testing.allocator);
    defer a.deinit();
    const arena = a.allocator();
    const io = std.testing.io;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    const cfg = try testConfig(arena, &tmp);
    // A file on the host, outside the rootfs, that a step that got out would find.
    try tmp.dir.writeFile(io, .{ .sub_path = "host-marker", .data = "on the host" });
    const marker = try std.fmt.allocPrint(arena, "{s}/host-marker", .{
        try tmp.dir.realPathFileAlloc(io, ".", arena),
    });
    const script = try std.fmt.allocPrint(arena,
        \\echo h > /proc/sysrq-trigger 2>/dev/null && echo sysrq-written || echo sysrq-refused
        \\test -s /proc/kcore && echo kcore-visible || echo kcore-masked
        \\grep -E '^(CapEff|CapBnd|NoNewPrivs|Seccomp):' /proc/self/status
        \\python3 -c 'import ctypes
        \\print("mount", ctypes.CDLL(None).mount(b"none", b"/mnt", b"tmpfs", 0, None))'
        \\python3 -c '
        \\import os
        \\os.makedirs("/tmp/jail", exist_ok=True)
        \\try:
        \\    os.chroot("/tmp/jail")
        \\    for _ in range(64): os.chdir("..")
        \\    os.chroot(".")
        \\except OSError as e: print("chroot", e.errno)
        \\print("host", os.path.exists("{s}"))
        \\'
        \\test -e {s} && echo marker-visible || echo marker-hidden
        \\[ "$(wc -c < /proc/interrupts)" = 0 ] && echo interrupts-masked || echo interrupts-visible
        \\echo zr 2>/dev/null > /proc/sys/kernel/hostname && echo procsys-written ||
        \\  echo procsys-refused
        \\python3 -c '
        \\for line in open("/proc/self/mountinfo"):
        \\    f = line.split()
        \\    if f[4] in ("/proc/sys", "/proc/sysrq-trigger", "/proc/irq"):
        \\        print("ro-mount", f[4], f[5].split(",")[0])
        \\'
        \\python3 -c '
        \\import ctypes
        \\libc = ctypes.CDLL(None, use_errno=True)
        \\params = ctypes.create_string_buffer(120)
        \\r = libc.syscall(425, 1, params); print("io_uring_setup", r, ctypes.get_errno())
        \\for name, p in (("addr-no-randomize", 0x0040000), ("read-implies-exec", 0x0400000)):
        \\    ctypes.set_errno(0)
        \\    r = libc.personality(ctypes.c_ulong(p))
        \\    print("personality", name, r, ctypes.get_errno())
        \\print("personality query", libc.personality(ctypes.c_ulong(0xffffffff)))
        \\'
    , .{ marker, marker });
    const r = try runNativeJob(arena, cfg, testJob(&.{testStep(script)}), .root);
    if (r.res.steps[0].outcome != .success) {
        std.debug.print("{s}\n", .{r.text});
        return error.TestUnexpectedResult;
    }
    try expectLines(r.text, &.{
        "sysrq-refused",
        "kcore-masked",
        try std.fmt.allocPrint(arena, "CapEff:\t{x:0>16}", .{sandbox.docker_caps}),
        "NoNewPrivs:\t1",
        "Seccomp:\t2",
        "mount -1",
        "host False",
        "marker-hidden",
        // runc's masks and read-only paths, each applied or the step would not have run: from
        // the step's own /proc, with every mount under it, wherever the host has binfmt_misc
        // mounted under its /proc/sys (GitHub's runner does).
        "interrupts-masked",
        "procsys-refused",
        "ro-mount /proc/sys ro",
        "ro-mount /proc/sysrq-trigger ro",
        "ro-mount /proc/irq ro",
        // io_uring is refused, as moby 25 refuses it, and personality takes only Docker's values.
        "io_uring_setup -1 1",
        "personality addr-no-randomize -1 1",
        "personality read-implies-exec -1 1",
        "personality query 0",
    });
    const mounts = net.readProc(arena, io, "/proc/self/mountinfo") orelse "";
    if (std.mem.indexOf(u8, mounts, " /proc/sys/fs/binfmt_misc ") != null)
        std.debug.print("native backend test: the host's /proc/sys has binfmt_misc\n", .{});
}

test "a native step cannot follow a symlink it planted out to the host's files" {
    var a: std.heap.ArenaAllocator = .init(std.testing.allocator);
    defer a.deinit();
    const arena = a.allocator();
    const io = std.testing.io;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    const cfg = try testConfig(arena, &tmp);
    try tmp.dir.createDirPath(io, "host-dir");
    const root = try tmp.dir.realPathFileAlloc(io, ".", arena);
    const host_dir = try std.fmt.allocPrint(arena, "{s}/host-dir", .{root});
    // A problem matcher on the host the runner must not read for a step.
    try tmp.dir.writeFile(io, .{
        .sub_path = "host-dir/matcher.json",
        .data = "{\"problemMatcher\":[]}",
    });
    // Step 1 turns /tmp into a symlink to a host directory and plants a matcher link; step 2
    // holds a secret, so the sandbox writes its script into /tmp, inside the overlay.
    const plant = try std.fmt.allocPrint(arena, "ln -s {s}/matcher.json /m.json; " ++
        "rm -rf /tmp; ln -s {s} /tmp; echo ::add-matcher::/m.json", .{ host_dir, host_dir });
    const s2 = testStep("echo s3cr3t-in-script > /dev/null; echo second");
    var job = testJob(&.{ testStep(plant), s2 });
    job.secrets = &.{"s3cr3t-in-script"};
    const r = try runNativeJob(arena, cfg, job, .root);
    try expectLines(r.text, &.{ "Could not read the problem matcher '/m.json'", "second" });
    var dir = try tmp.dir.openDir(io, "host-dir", .{ .iterate = true });
    defer dir.close(io);
    var it = dir.iterate();
    while (try it.next(io)) |e| try std.testing.expectEqualStrings("matcher.json", e.name);
}

/// Skips a test that needs the runner to be root (its ids and network): CI runs the native tests
/// a second time under sudo for them.
pub fn requireRoot() !void {
    if (std.os.linux.geteuid() != 0) {
        std.debug.print("native backend test skipped: it needs root\n", .{});
        return error.SkipZigTest;
    }
}

/// What `set_up.provision_runner_script` gives the runner user (/tmp for all, /github and its home
/// its own), and a sudo the job's root owns at /opt/sudo, as the provisioned image has (the
/// host's, in the bound /usr, is owned by an id the job does not map), with its sudoers and PAM
/// configuration, in the tests' rootfs under `root`.
fn sudoRootfs(arena: Allocator, root: []const u8) !void {
    const setup = try std.fmt.allocPrint(arena,
        \\set -e
        \\cd '{s}'
        \\mkdir -p rootfs/opt rootfs/run rootfs/var/lib rootfs/etc/sudoers.d
        \\chmod 1777 rootfs/tmp
        \\mkdir -p rootfs/github rootfs/home/runner
        \\chown 1001:1001 rootfs/github rootfs/home/runner
        \\cp /usr/bin/sudo rootfs/opt/sudo && chmod 4755 rootfs/opt/sudo
        \\mkdir -p rootfs/opt/sudo-plugins
        \\cp /usr/libexec/sudo/sudoers.so rootfs/opt/sudo-plugins/
        \\cp -a /etc/pam.d rootfs/etc/
        \\for f in /etc/security /etc/login.defs /etc/nsswitch.conf; do
        \\  [ -e "$f" ] && cp -a "$f" rootfs/etc/ || true
        \\done
        \\for p in sudoers_policy sudoers_io sudoers_audit; do
        \\  echo "Plugin $p /opt/sudo-plugins/sudoers.so"
        \\done > rootfs/etc/sudo.conf
        \\printf 'root ALL=(ALL:ALL) ALL\nrunner ALL=(ALL) NOPASSWD:ALL\n' > rootfs/etc/sudoers
        \\chmod 0440 rootfs/etc/sudoers
        \\printf 'root:*:19000:0:99999:7:::\nrunner:*:19000:0:99999:7:::\n' > rootfs/etc/shadow
        \\chmod 0640 rootfs/etc/shadow
    , .{root});
    const made = try std.process.run(arena, std.testing.io, .{ .argv = &.{ "sh", "-c", setup } });
    try std.testing.expect(made.term == .exited and made.term.exited == 0);
}

test "root runner: a job's own ids, its runner user, and sudo gaining nothing" {
    try requireRoot();
    var a: std.heap.ArenaAllocator = .init(std.testing.allocator);
    defer a.deinit();
    const arena = a.allocator();
    const io = std.testing.io;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    var cfg = try testConfig(arena, &tmp);
    const root = try tmp.dir.realPathFileAlloc(io, ".", arena);
    try sudoRootfs(arena, root);
    // A file only the host's root may read, bound in.
    const setup = try std.fmt.allocPrint(arena,
        \\set -e
        \\cd '{s}'
        \\echo host-only > host-secret && chmod 0600 host-secret
        \\: > rootfs/opt/host-secret
    , .{root});
    const made = try std.process.run(arena, io, .{ .argv = &.{ "sh", "-c", setup } });
    try std.testing.expect(made.term == .exited and made.term.exited == 0);
    cfg.binds = try std.mem.concat(arena, sandbox.Spec.Bind, &.{ cfg.binds, &.{.{
        .host = try std.fmt.allocPrint(arena, "{s}/host-secret", .{root}),
        .at = "/opt/host-secret",
    }} });
    const script = "id -u; echo HOME=$HOME; cat /proc/self/uid_map; " ++
        "touch \"$GITHUB_WORKSPACE/mine\" && stat -c owner=%u \"$GITHUB_WORKSPACE/mine\"\n" ++
        "echo sudo-uid=$(/opt/sudo -n id -u)\n" ++
        "/opt/sudo -n cat /opt/host-secret 2>/dev/null && echo host-file-read || " ++
        "echo host-file-refused\n" ++
        "/opt/sudo -n grep -E '^CapEff' /proc/self/status\n" ++
        "/opt/sudo -n cat /proc/self/uid_map | sed 's/^/sudo-map /'";
    const r = try runNativeJob(arena, cfg, testJob(&.{testStep(script)}), .runner);
    if (r.res.steps[0].outcome != .success) {
        std.debug.print("step {s}, engine {s}\n{s}\n", .{
            @tagName(r.res.steps[0].outcome),
            r.res.engine_error orelse "-",
            r.text,
        });
        return error.TestUnexpectedResult;
    }
    try expectLines(r.text, &.{
        "stdout] 1001",
        "HOME=/home/runner",
        "owner=1001",
        // sudo works: the runner user becomes the job's root...
        "sudo-uid=0",
        // ...and that root is nobody on the host: not the host's root's file, no more than
        // Docker's capabilities, and the same range of host ids.
        "host-file-refused",
        try std.fmt.allocPrint(arena, "CapEff:\t{x:0>16}", .{sandbox.docker_caps}),
        "sudo-map ",
        "Native steps: ids 0-65535 are host ids",
    });
    const map = try std.fmt.allocPrint(arena, "0 {d}", .{default_subid_base});
    var lines = std.mem.splitScalar(u8, r.text, '\n');
    var maps: u32 = 0;
    while (lines.next()) |l| {
        if (std.mem.indexOf(u8, l, "sudo-map") == null and std.mem.indexOf(u8, l, "65536") == null)
            continue;
        const words = try std.mem.join(arena, " ", try collectWords(arena, l));
        if (std.mem.indexOf(u8, words, map) != null) maps += 1;
    }
    // The step's map and sudo's: both the job's range.
    try std.testing.expect(maps >= 2);
}

fn collectWords(arena: Allocator, line: []const u8) ![]const []const u8 {
    var out: std.ArrayList([]const u8) = .empty;
    var it = std.mem.tokenizeAny(u8, line, " \t");
    while (it.next()) |w| try out.append(arena, w);
    return out.items;
}

test "root runner: a job's own network, out of reach of the host's services and other jobs" {
    try requireRoot();
    var a: std.heap.ArenaAllocator = .init(std.testing.allocator);
    defer a.deinit();
    const arena = a.allocator();
    const io = std.testing.io;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    const cfg = try testConfig(arena, &tmp);

    // Listeners on the host's 127.0.0.1 and on all its addresses (the bridge's among them), which
    // a step must not reach.
    const loopback = try listen(47123, 0x7f000001);
    defer _ = std.os.linux.close(loopback);
    const any = try listen(47124, 0);
    defer _ = std.os.linux.close(any);

    // Two jobs at once, both serving on :5432 and on their own lo, neither reaching the host's
    // listeners, and neither reaching the other's :5432 (bridge ports isolated, and the host
    // routes nothing between jobs).
    const gw = cfg.subnet.gateway();
    const first = cfg.subnet.jobAddress(0);
    const script = try std.fmt.allocPrint(arena,
        \\python3 - <<'EOF'
        \\import socket, time
        \\s = socket.socket(); s.bind(("0.0.0.0", 5432)); s.listen(); print("bound 5432")
        \\c = socket.create_connection(("127.0.0.1", 5432), 2); print("own lo works")
        \\u = socket.socket(socket.AF_INET, socket.SOCK_DGRAM); u.connect(("192.0.2.1", 9))
        \\me = u.getsockname()[0]
        \\def reach(host, port):
        \\    try:
        \\        socket.create_connection((host, port), 2).close(); return True
        \\    except OSError: return False
        \\print("host loopback", "reached" if reach("127.0.0.1", 47123) else "unreachable")
        \\print("host via bridge", "reached" if reach("{d}.{d}.{d}.{d}", 47124) else "unreachable")
        \\time.sleep(2)
        \\base = "{d}.{d}.{d}."
        \\peers = [base + str(i) for i in range({d}, {d} + 4) if base + str(i) != me]
        \\print("peers", "reached" if any(reach(p, 5432) for p in peers) else "unreachable")
        \\time.sleep(8)
        \\EOF
    , .{ gw[0], gw[1], gw[2], gw[3], first[0], first[1], first[2], first[3], first[3] });
    const Run = struct {
        fn one(
            arena_: Allocator,
            cfg_: Config,
            script_: []const u8,
            out: *[]const u8,
            ok: *bool,
        ) void {
            const r = runNativeJob(arena_, cfg_, testJob(&.{testStep(script_)}), .root) catch {
                ok.* = false;
                return;
            };
            out.* = r.text;
            ok.* = r.res.steps[0].outcome == .success;
        }
    };
    var texts: [2][]const u8 = .{ "", "" };
    var oks: [2]bool = .{ false, false };
    var arenas: [2]std.heap.ArenaAllocator = .{
        .init(std.testing.allocator),
        .init(std.testing.allocator),
    };
    defer for (&arenas) |*x| x.deinit();
    const args = .{ arenas[0].allocator(), cfg, script, &texts[0], &oks[0] };
    var other = try io.concurrent(Run.one, args);
    Run.one(arenas[1].allocator(), cfg, script, &texts[1], &oks[1]);
    other.await(io);
    for (texts, oks) |t, ok| {
        if (!ok) std.debug.print("{s}\n", .{t});
        try std.testing.expect(ok);
        try expectLines(t, &.{
            "bound 5432",
            "own lo works",
            "host loopback unreachable",
            "host via bridge unreachable",
            "peers unreachable",
        });
    }

    // Out to the world, when the host itself gets there: DNS through the job's resolver, HTTP
    // through the NAT.
    const resolve: []const []const u8 = &.{ "getent", "hosts", "github.com" };
    const host = std.process.run(arena, io, .{ .argv = resolve }) catch null;
    if (host == null or host.?.term != .exited or host.?.term.exited != 0) {
        std.debug.print("native backend test: outbound part skipped, the host cannot " ++
            "resolve github.com\n", .{});
        return;
    }
    const out = testStep("getent hosts github.com >/dev/null && echo dns-ok; " ++
        "python3 -c 'import urllib.request; print(\"http\", " ++
        "urllib.request.urlopen(\"https://github.com\", timeout=20).status)'");
    const r = try runNativeJob(arena, cfg, testJob(&.{out}), .root);
    try expectLines(r.text, &.{ "dns-ok", "http 200" });
}

/// A TCP listener of the test's on the host, on `port` at `addr` (host order; 0 for every
/// address).
pub fn listen(port: u16, addr: u32) !std.os.linux.fd_t {
    const linux = std.os.linux;
    const sock = linux.socket(linux.AF.INET, linux.SOCK.STREAM | linux.SOCK.CLOEXEC, 0);
    if (linux.errno(sock) != .SUCCESS) return error.Socket;
    const fd: linux.fd_t = @intCast(sock);
    errdefer _ = linux.close(fd);
    const one: i32 = 1;
    const reuse = linux.SO.REUSEADDR;
    _ = linux.setsockopt(fd, linux.SOL.SOCKET, reuse, std.mem.asBytes(&one), @sizeOf(i32));
    var sa: linux.sockaddr.in = .{
        .port = std.mem.nativeToBig(u16, port),
        .addr = std.mem.nativeToBig(u32, addr),
    };
    if (linux.errno(linux.bind(fd, @ptrCast(&sa), @sizeOf(linux.sockaddr.in))) != .SUCCESS)
        return error.Bind;
    if (linux.errno(linux.listen(fd, 4)) != .SUCCESS) return error.Listen;
    return fd;
}

test "the jobs' ids: each range the host already uses, or may, is refused" {
    var a: std.heap.ArenaAllocator = .init(std.testing.allocator);
    defer a.deinit();
    const arena = a.allocator();
    const io = std.testing.io;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    const root = try tmp.dir.realPathFileAlloc(io, ".", arena);
    const Case = struct { file: []const u8, text: []const u8, reason: []const u8 };
    const first: u32 = 2_000_000;
    // The slots' ranges and the cache volumes' after them.
    const end = first + ids_per_slot * (net.max_slots + 1);
    const cases = [_]Case{
        .{
            .file = "subuid",
            .text = "lement:100000:65536\npodman:1999000:2000\n",
            .reason = "podman's in",
        },
        .{
            .file = "subgid",
            .text = "lement:100000:65536\nbuilder:16000000:1\n",
            .reason = "builder's in",
        },
        .{
            .file = "passwd",
            .text = "root:x:0:0::/root:/bin/sh\nldap-user:x:2000000:100::/:/bin/sh\n",
            .reason = "ldap-user's id 2000000",
        },
        .{
            .file = "group",
            .text = try std.fmt.allocPrint(arena, "root:x:0:\nlast:x:{d}:\n", .{end - 1}),
            .reason = "last's id",
        },
    };
    const files: IdFiles = .{
        .subuid = try std.fmt.allocPrint(arena, "{s}/subuid", .{root}),
        .subgid = try std.fmt.allocPrint(arena, "{s}/subgid", .{root}),
        .passwd = try std.fmt.allocPrint(arena, "{s}/passwd", .{root}),
        .group = try std.fmt.allocPrint(arena, "{s}/group", .{root}),
    };
    // Nothing there, and files that name only others' ids: usable.
    try std.testing.expect(try idsClash(arena, io, first, files) == null);
    for (cases) |c| try tmp.dir.writeFile(io, .{ .sub_path = c.file, .data = "x:1000:1000\n" });
    try std.testing.expect(try idsClash(arena, io, first, files) == null);
    for (cases) |c| {
        try tmp.dir.writeFile(io, .{ .sub_path = c.file, .data = c.text });
        try expectReason(c.reason, try idsClash(arena, io, first, files));
        try tmp.dir.writeFile(io, .{ .sub_path = c.file, .data = "x:1000:1000\n" });
    }
    // The id just past the cache volumes' range is someone else's to have.
    try tmp.dir.writeFile(io, .{
        .sub_path = "passwd",
        .data = try std.fmt.allocPrint(arena, "next:x:{d}:1::/:/bin/sh\n", .{end}),
    });
    try std.testing.expect(try idsClash(arena, io, first, files) == null);
    try expectReason("below 100000", try idsClash(arena, io, 99_999, files));
    try expectReason("2^32", try idsClash(arena, io, std.math.maxInt(u32) - ids_per_slot, files));
    // The default range clears systemd's container and foreign ranges, below 2^31.
    try std.testing.expect(default_subid_base > 1_879_048_191);
    try std.testing.expect(volumeIdBase(default_subid_base) + ids_per_slot <= 2_147_352_576);
}

test "a failed probe is tried again after its back-off; a success holds" {
    var c: ProbeCache = .{};
    try std.testing.expect(!c.fresh(0));
    try std.testing.expectEqualStrings("iptables is locked", c.store(1000, "iptables is locked").?);
    try std.testing.expect(c.fresh(1000 + probe_backoff_ms - 1));
    try std.testing.expectEqualStrings("iptables is locked", c.why().?);
    try std.testing.expect(!c.fresh(1000 + probe_backoff_ms));
    try std.testing.expect(c.store(1000 + probe_backoff_ms, null) == null);
    try std.testing.expect(c.fresh(std.math.maxInt(i64)));
}

test "root runner: slots are the host's, so two runners with different stores never share one" {
    try requireRoot();
    var a: std.heap.ArenaAllocator = .init(std.testing.allocator);
    defer a.deinit();
    const arena = a.allocator();
    const io = std.testing.io;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    const cfg = try testConfig(arena, &tmp);
    var other = cfg;
    try tmp.dir.createDirPath(io, "store-2");
    const root = try tmp.dir.realPathFileAlloc(io, ".", arena);
    other.store = try std.fmt.allocPrint(arena, "{s}/store-2", .{root});
    var first = try init(arena, io, std.testing.allocator, cfg);
    defer first.deinit();
    var second = try init(arena, io, std.testing.allocator, other);
    defer second.deinit();
    try std.testing.expect(first.slot.?.n != second.slot.?.n);
    try std.testing.expect(first.idBase() != second.idBase());
    // The second job's set-up left the first's veth alone, and both are on the bridge.
    var sock = try net.Socket.open();
    defer sock.close();
    var buf: [16]u8 = undefined;
    try std.testing.expect(sock.index(net.hostLink(&buf, first.slot.?.n)) != null);
    try std.testing.expect(sock.index(net.hostLink(&buf, second.slot.?.n)) != null);
}

test "a job's directory and lock are let go once, when its set-up fails after the lock is taken" {
    var a: std.heap.ArenaAllocator = .init(std.testing.allocator);
    defer a.deinit();
    const arena = a.allocator();
    const io = std.testing.io;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    try tmp.dir.createDirPath(io, "store");
    try tmp.dir.createDirPath(io, "rootfs");
    const root = try tmp.dir.realPathFileAlloc(io, ".", arena);
    var cfg: Config = .{
        .rootfs = try std.fmt.allocPrint(arena, "{s}/rootfs", .{root}),
        .store = try std.fmt.allocPrint(arena, "{s}/store", .{root}),
        .self_exe = "/bin/true",
        .vouched = true,
        .test_fail_after_lock = true,
        .check_store_parents = false,
    };
    // Closing an fd twice would panic here (Zig's own check for a file closed twice).
    try std.testing.expectError(error.TestFailure, init(arena, io, std.testing.allocator, cfg));
    var jobs = try tmp.dir.openDir(io, "store/jobs", .{ .iterate = true });
    defer jobs.close(io);
    var it = jobs.iterate();
    try std.testing.expect(try it.next(io) == null);
    // Nothing is left holding a lock: the next job's set-up goes through.
    cfg.test_fail_after_lock = false;
    var b = try init(arena, io, std.testing.allocator, cfg);
    b.deinit();
}

const testregistry = @import("oci/testregistry.zig");
const oci_layer = @import("oci/layer.zig");

/// A small image for the native pull's job tests, as layers: the directories and links of the
/// tests' rootfs (`testConfig`, whose binds bring the host's /usr), its own passwd and a marker,
/// then a layer that removes a file of the first.
fn testImageLayers(arena: Allocator) ![]const []const u8 {
    var t: oci_layer.TestTar = .{ .a = arena };
    for ([_][]const u8{ "usr/", "etc/", "etc/ssl/", "tmp/", "dev/", "proc/", "sys/", "root/", "home/", "home/app/" }) |d|
        try t.add(.{ .path = d, .kind = .directory, .mode = if (std.mem.eql(u8, d, "tmp/")) 0o1777 else 0o755 });
    for ([_][2][]const u8{ .{ "bin", "usr/bin" }, .{ "sbin", "usr/sbin" }, .{ "lib", "usr/lib" }, .{ "lib64", "usr/lib64" } }) |l|
        try t.add(.{ .path = l[0], .kind = .symlink, .link = l[1] });
    try t.add(.{ .path = "etc/passwd", .body = "root:x:0:0:root:/root:/bin/sh\napp:x:1002:1003::/home/app:/bin/sh\n" });
    try t.add(.{ .path = "etc/group", .body = "root:x:0:\napp:x:1003:\nstaff:x:50:\n" });
    for ([_][]const u8{ "etc/hosts", "etc/resolv.conf", "etc/ld.so.cache" }) |f| try t.add(.{ .path = f });
    try t.add(.{ .path = "etc/marker", .body = "from the image\n" });
    try t.add(.{ .path = "etc/gone", .body = "x" });
    var t2: oci_layer.TestTar = .{ .a = arena };
    try t2.add(.{ .path = "etc/.wh.gone" });
    return arena.dupe([]const u8, &.{ try t.finish(), try t2.finish() });
}

test "a container job on the native backend: its image pulled with its credentials, its env, no Dagger" {
    var a: std.heap.ArenaAllocator = .init(std.testing.allocator);
    defer a.deinit();
    const arena = a.allocator();
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    const cfg = try testConfig(arena, &tmp);

    const img = try testregistry.testImage(arena, "test/img", "1", try testImageLayers(arena), "\"PATH=/usr/bin:/bin\",\"FROM_IMAGE=yes\",\"BOTH=image\"", true);
    var server: testregistry.Server = .{ .routes = img.routes, .private = true };
    try server.start();
    defer server.stop();

    var job = testJob(&.{testStep("echo FROM_IMAGE=$FROM_IMAGE BOTH=$BOTH; cat /etc/marker; " ++
        "test -e /etc/gone && echo gone-is-there || echo gone-is-gone; echo uid=$(id -u); pwd")});
    job.container = .{
        .name = "",
        .image = .{ .lit = try server.image(arena, "test/img:1") },
        .env = &.{.{ .name = "BOTH", .value = .{ .lit = "container" } }},
        .username = .{ .lit = "user" },
        .password = .{ .lit = "pass" },
    };
    var env: std.process.Environ.Map = .init(arena);
    var w: std.Io.Writer.Allocating = .init(arena);
    var log: sink.LogSink = .{ .stdout = .{ .writer = &w.writer } };
    const res = try dagger.run(arena, std.testing.io, &env, .{
        .native = cfg,
        .step_user = .root,
        .gpa = std.testing.allocator,
    }, job, &log);
    const text = w.written();
    if (!res.succeeded) std.debug.print("{s}\n", .{text});
    try std.testing.expect(res.succeeded);
    const expect = [_][]const u8{
        "Engine: native",
        "Image: pulled natively in",
        try std.fmt.allocPrint(arena, "Digest: {s}", .{img.index}),
        // The container's env over the image's.
        "FROM_IMAGE=yes BOTH=container",
        "from the image",
        "gone-is-gone",
        "uid=0",
        "/__w/r/r",
    };
    for (expect) |e| if (std.mem.indexOf(u8, text, e) == null) {
        std.debug.print("missing {s} in:\n{s}\n", .{ e, text });
        return error.TestUnexpectedResult;
    };

    // A second job finds the image in the store, asking the registry only what the tag is now
    // (the challenge, the token, the index and the platform's manifest).
    const before = server.requests.load(.acquire);
    var w2: std.Io.Writer.Allocating = .init(arena);
    var log2: sink.LogSink = .{ .stdout = .{ .writer = &w2.writer } };
    const res2 = try dagger.run(arena, std.testing.io, &env, .{ .native = cfg, .step_user = .root, .gpa = std.testing.allocator }, job, &log2);
    try std.testing.expect(res2.succeeded);
    try std.testing.expect(std.mem.indexOf(u8, w2.written(), "Image: from the native store") != null);
    try std.testing.expect(server.requests.load(.acquire) - before <= 4);

    // Without its credentials, the job fails in "Set up job", saying why.
    job.container.?.password = null;
    var w3: std.Io.Writer.Allocating = .init(arena);
    var log3: sink.LogSink = .{ .stdout = .{ .writer = &w3.writer } };
    const res3 = try dagger.run(arena, std.testing.io, &env, .{ .native = cfg, .step_user = .root, .gpa = std.testing.allocator }, job, &log3);
    try std.testing.expect(!res3.succeeded);
    try std.testing.expect(std.mem.indexOf(u8, res3.engine_error.?, "credentials") != null);
}

test "native provisioning: a step on the pulled image, flattened and kept under its key" {
    var a: std.heap.ArenaAllocator = .init(std.testing.allocator);
    defer a.deinit();
    const arena = a.allocator();
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    const cfg = try testConfig(arena, &tmp);
    const img = try testregistry.testImage(arena, "test/prov", "1", try testImageLayers(arena), "\"PATH=/usr/bin:/bin\"", false);
    var server: testregistry.Server = .{ .routes = img.routes };
    try server.start();
    defer server.stop();

    var b = try init(arena, std.testing.io, std.testing.allocator, cfg);
    defer b.deinit();
    var why: []const u8 = "";
    const pulled = try b.pull(try server.image(arena, "test/prov:1"), null, &why);
    // What overlay records in the step's layer: a removed file (a whiteout), a directory removed
    // and made again (opaque), a new file and a changed one.
    const script = "rm /etc/marker && mkdir -p /opt/tool && echo new > /opt/tool/f && " ++
        "echo changed > /etc/passwd2 && rm -r /home/app && mkdir /home/app && echo fresh > /home/app/x";
    var err_msg: []const u8 = "";
    const rootfs = b.provision(pulled, script, &err_msg) catch |e| {
        std.debug.print("provision: {s}\n", .{err_msg});
        return e;
    };
    // The last note: `init`'s about the job's cgroup come first.
    try std.testing.expect(std.mem.indexOf(u8, b.notes.getLast(), "Provisioned natively") != null);
    var root = try std.Io.Dir.cwd().openDir(std.testing.io, rootfs, .{});
    defer root.close(std.testing.io);
    const io = std.testing.io;
    try std.testing.expectError(error.FileNotFound, root.access(io, "etc/marker", .{}));
    try std.testing.expectEqualStrings("new\n", try root.readFileAlloc(io, "opt/tool/f", arena, .limited(64)));
    try std.testing.expectEqualStrings("fresh\n", try root.readFileAlloc(io, "home/app/x", arena, .limited(64)));
    try std.testing.expectEqualStrings("changed\n", try root.readFileAlloc(io, "etc/passwd2", arena, .limited(64)));
    // The image itself is untouched, and the next job's steps start from L0 again.
    var image_root = try std.Io.Dir.cwd().openDir(io, pulled.rootfs, .{});
    defer image_root.close(io);
    try std.testing.expectEqualStrings("from the image\n", try image_root.readFileAlloc(io, "etc/marker", arena, .limited(64)));
    try std.testing.expectEqual(@as(usize, 0), b.layers.items.len);
    // Made once: a second job reuses it.
    _ = try b.provision(pulled, script, &err_msg);
    try std.testing.expect(std.mem.indexOf(u8, b.notes.getLast(), "made before") != null);
    // A failing script fails with its output's last line, and leaves nothing under its key.
    try std.testing.expectError(error.BaseContainerFailed, b.provision(pulled, "echo the reason; exit 7", &err_msg));
    try std.testing.expect(std.mem.indexOf(u8, err_msg, "the reason (exit 7)") != null);
}

test "an image's USER: by name, by uid, with a group, and what a rootless runner cannot map" {
    var a: std.heap.ArenaAllocator = .init(std.testing.allocator);
    defer a.deinit();
    const arena = a.allocator();
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    const io = std.testing.io;
    try tmp.dir.createDirPath(io, "etc");
    try tmp.dir.writeFile(io, .{ .sub_path = "etc/passwd", .data = "root:x:0:0::/root:/bin/sh\napp:x:1002:1003::/home/app:/bin/sh\n" });
    try tmp.dir.writeFile(io, .{ .sub_path = "etc/group", .data = "root:x:0:\nstaff:x:50:\n" });
    var b: Backend = .{
        .arena = arena,
        .io = io,
        .gpa = std.testing.allocator,
        .dir = "",
        .rootfs = try tmp.dir.realPathFileAlloc(io, ".", arena),
        .binds = &.{},
        .lock = undefined,
        .how = .{ .argv_prefix = &.{}, .userns = .mapped },
    };
    try std.testing.expectEqual([2]u32{ 1002, 1003 }, try b.imageUser("app"));
    try std.testing.expectEqual([2]u32{ 1002, 1003 }, try b.imageUser("1002"));
    try std.testing.expectEqual([2]u32{ 4000, 0 }, try b.imageUser("4000"));
    try std.testing.expectEqual([2]u32{ 1002, 50 }, try b.imageUser("app:staff"));
    try std.testing.expectEqual([2]u32{ 7, 8 }, try b.imageUser("7:8"));
    try std.testing.expectEqual([2]u32{ 0, 0 }, try b.imageUser("root"));
    try std.testing.expectError(error.UnknownUser, b.imageUser("nobody"));
    try std.testing.expectError(error.UnknownGroup, b.imageUser("app:wheel"));
    b.how.userns = .self;
    try std.testing.expectError(error.Unmapped, b.imageUser("app"));
    try std.testing.expectEqual([2]u32{ 0, 0 }, try b.imageUser("0"));
}

test "the default image pulled and provisioned natively, then a job in it (ZIG_RUNNER_TEST_PULL=1; needs the network)" {
    var a: std.heap.ArenaAllocator = .init(std.testing.allocator);
    defer a.deinit();
    const arena = a.allocator();
    const environ = try std.testing.environ.createMap(arena);
    if (!std.mem.eql(u8, environ.get("ZIG_RUNNER_TEST_PULL") orelse "", "1")) return error.SkipZigTest;
    // Rootless, dpkg's chowns to other ids fail, and such a job goes to Dagger (`unsupported`).
    if (std.os.linux.geteuid() != 0) return error.SkipZigTest;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    var cfg = try testConfig(arena, &tmp);
    // No operator rootfs, nor the tests' binds: the image as pulled, provisioned.
    cfg.rootfs = "";
    cfg.binds = &.{};
    var job = testJob(&.{testStep("git --version; python3 --version; jq --version; " ++
        "grep PRETTY /etc/os-release")});
    job.github.repository = "o/r";
    var env: std.process.Environ.Map = .init(arena);
    var w: std.Io.Writer.Allocating = .init(arena);
    var log: sink.LogSink = .{ .stdout = .{ .writer = &w.writer } };
    const res = try dagger.run(arena, std.testing.io, &env, .{
        .native = cfg,
        .step_user = .root,
        .gpa = std.testing.allocator,
    }, job, &log);
    const text = w.written();
    std.debug.print("{s}\n", .{text});
    if (res.engine_error) |e| std.debug.print("engine error: {s}\n", .{e});
    try std.testing.expect(res.succeeded);
    for ([_][]const u8{ "Image: ", "Provisioned natively in", "git version", "Python 3", "jq-", "Ubuntu 24.04" }) |e|
        try std.testing.expect(std.mem.indexOf(u8, text, e) != null);
}

// --- the step cache (the layer store) ---

/// `testConfig`, with a host directory every step sees at `/shared`, writable: steps count their
/// runs there, since a mount's content is in no key.
fn cachedConfig(arena: Allocator, tmp: *std.testing.TmpDir) !struct { cfg: Config, shared: []const u8 } {
    var cfg = try testConfig(arena, tmp);
    const io = std.testing.io;
    try tmp.dir.createDirPath(io, "shared");
    try tmp.dir.createDirPath(io, "rootfs/shared");
    const root = try tmp.dir.realPathFileAlloc(io, ".", arena);
    const shared = try std.fmt.allocPrint(arena, "{s}/shared", .{root});
    // On a root runner the job's root is nobody on the host.
    _ = std.os.linux.chmod(try arena.dupeSentinel(u8, shared, 0), 0o777);
    cfg.binds = try std.mem.concat(arena, sandbox.Spec.Bind, &.{
        cfg.binds,
        &.{.{ .host = shared, .at = "/shared", .read_only = false }},
    });
    return .{ .cfg = cfg, .shared = shared };
}

/// Runs `job` natively under step caching as the job whose ran marker is `ran`, and its log.
fn runCached(
    arena: Allocator,
    cfg: Config,
    job: job_mod.Job,
    ran: []const u8,
) !CachedRun {
    return runCachedAs(arena, cfg, job, ran, .root);
}

const CachedRun = struct { res: dagger.Result, text: []const u8 };

fn runCachedAs(
    arena: Allocator,
    cfg: Config,
    job: job_mod.Job,
    ran: []const u8,
    user: config.StepUser,
) !CachedRun {
    var env: std.process.Environ.Map = .init(arena);
    var w: std.Io.Writer.Allocating = .init(arena);
    var log: sink.LogSink = .{ .stdout = .{ .writer = &w.writer } };
    const res = try dagger.run(arena, std.testing.io, &env, .{
        .native = cfg,
        .step_user = user,
        .step_cache = true,
        .test_ran_marker = ran,
        .gpa = std.testing.allocator,
    }, job, &log);
    return .{ .res = res, .text = w.written() };
}

/// How many times a step counted itself in `shared/name`.
fn runs(arena: Allocator, shared: []const u8, name: []const u8) usize {
    const p = std.fmt.allocPrint(arena, "{s}/{s}", .{ shared, name }) catch return 0;
    const text = std.Io.Dir.cwd().readFileAlloc(std.testing.io, p, arena, .limited(1 << 16)) catch
        return 0;
    return std.mem.count(u8, text, "\n");
}

fn expectSucceeded(r: anytype) !void {
    for (r.res.steps) |st| if (st.outcome != .success) {
        std.debug.print("engine {s}\n{s}\n", .{ r.res.engine_error orelse "-", r.text });
        return error.TestUnexpectedResult;
    };
}

/// The step lines of a log, without the note a replayed step ends with.
fn replayableLines(arena: Allocator, text: []const u8) ![]const []const u8 {
    var out: std.ArrayList([]const u8) = .empty;
    for (try stepLines(arena, text)) |l| {
        if (std.mem.indexOf(u8, l, dagger.native_reused_note) != null) continue;
        try out.append(arena, l);
    }
    return out.items;
}

fn storeLayers(arena: Allocator, store: []const u8) !usize {
    const p = try std.fmt.allocPrint(arena, "{s}/layers", .{store});
    var dir = try std.Io.Dir.cwd().openDir(std.testing.io, p, .{ .iterate = true });
    defer dir.close(std.testing.io);
    var n: usize = 0;
    var it = dir.iterate();
    while (try it.next(std.testing.io)) |_| n += 1;
    return n;
}

test "native step cache: a job run again is replayed, its log byte for byte, its file commands applied" {
    var a: std.heap.ArenaAllocator = .init(std.testing.allocator);
    defer a.deinit();
    const arena = a.allocator();
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    const c = try cachedConfig(arena, &tmp);

    var s1 = testStep("echo x >> /shared/s1; echo hello; printf 'no newline'; echo; echo\n" ++
        "echo FOO=bar >> $GITHUB_ENV; echo out=42 >> $GITHUB_OUTPUT; echo /opt/x >> $GITHUB_PATH\n" ++
        "echo '# sum' >> $GITHUB_STEP_SUMMARY; echo ::add-mask::m4sked-value; " ++
        "echo the m4sked-value; echo to stderr >&2; mkdir -p /tmp/kept && echo layer > /tmp/kept/f");
    s1.context_name = "first";
    var s2 = testStep("echo x >> /shared/s2; echo FOO=$FOO OUT=$OUT; cat /tmp/kept/f; " ++
        "echo \"$PATH\" | cut -d: -f1; echo '::warning::careful'");
    s2.env = &.{.{ .name = "OUT", .value = .{ .expr = "steps.first.outputs.out" } }};
    const job = testJob(&.{ s1, s2 });
    const first = try runCached(arena, c.cfg, job, "j1");
    try expectSucceeded(first);
    // Another commit: the commit is run-specific, in no key.
    var again = job;
    again.github.sha = "fedcba9876fedcba9876fedcba9876fedcba9876";
    const second = try runCached(arena, c.cfg, again, "j2");
    try expectSucceeded(second);

    // The second job ran nothing: both steps, and its base, came from the store.
    try std.testing.expectEqual(@as(usize, 1), runs(arena, c.shared, "s1"));
    try std.testing.expectEqual(@as(usize, 1), runs(arena, c.shared, "s2"));
    try std.testing.expectEqual(@as(usize, 0), std.mem.count(u8, first.text, dagger.native_reused_note));
    try std.testing.expectEqual(@as(usize, 2), std.mem.count(u8, second.text, dagger.native_reused_note));
    try std.testing.expectEqual(@as(usize, 3), try storeLayers(arena, c.cfg.store));
    // The replayed log is the live one, line for line: blank lines, a last line without a
    // newline, stderr, masks and workflow commands.
    const live = try replayableLines(arena, first.text);
    const replayed = try replayableLines(arena, second.text);
    if (live.len != replayed.len) {
        std.debug.print("live:\n{s}\nreplayed:\n{s}\n", .{ first.text, second.text });
        return error.TestUnexpectedResult;
    }
    for (live, replayed) |l, r| try std.testing.expectEqualStrings(l, r);
    try expectLines(second.text, &.{ "FOO=bar OUT=42", "stdout] layer", "/opt/x", "the ***" });
    // The step's file commands were applied again: its summary and its outputs.
    try std.testing.expectEqualStrings("# sum\n", second.res.summaries[0]);
    // The store is no host user's to read.
    var st: std.os.linux.Statx = undefined;
    const store_z = try arena.dupeSentinel(u8, c.cfg.store, 0);
    _ = std.os.linux.statx(std.os.linux.AT.FDCWD, store_z, 0, .{ .MODE = true }, &st);
    try std.testing.expectEqual(@as(u32, 0o700), st.mode & 0o777);
}

test "native step cache: a failure is not replayed, and the steps before it are" {
    var a: std.heap.ArenaAllocator = .init(std.testing.allocator);
    defer a.deinit();
    const arena = a.allocator();
    const io = std.testing.io;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    const c = try cachedConfig(arena, &tmp);
    const s1 = testStep("echo x >> /shared/s1; echo MODE=ci >> $GITHUB_ENV");
    const s2 = testStep("echo x >> /shared/s2; echo MODE=$MODE; test -e /shared/pass");
    const job = testJob(&.{ s1, s2 });

    const first = try runCached(arena, c.cfg, job, "j1");
    try std.testing.expectEqual(dagger.Outcome.failure, first.res.steps[1].outcome);
    // #69: the failure was not kept, so it runs again, on the step before it replayed (with
    // its export), and passes this time.
    try tmp.dir.writeFile(io, .{ .sub_path = "shared/pass", .data = "" });
    const second = try runCached(arena, c.cfg, job, "j2");
    try expectSucceeded(second);
    try std.testing.expectEqual(@as(usize, 1), runs(arena, c.shared, "s1"));
    try std.testing.expectEqual(@as(usize, 2), runs(arena, c.shared, "s2"));
    try expectLines(second.text, &.{"MODE=ci"});
    try std.testing.expectEqual(@as(usize, 1), std.mem.count(u8, second.text, dagger.native_reused_note));
    // Now it passed, it is kept.
    const third = try runCached(arena, c.cfg, job, "j3");
    try expectSucceeded(third);
    try std.testing.expectEqual(@as(usize, 2), runs(arena, c.shared, "s2"));
}

test "native step cache: steps with secrets or run-specific values always run, and nothing after them is kept" {
    var a: std.heap.ArenaAllocator = .init(std.testing.allocator);
    defer a.deinit();
    const arena = a.allocator();
    const io = std.testing.io;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    const c = try cachedConfig(arena, &tmp);
    const s0 = testStep("echo x >> /shared/s0");
    const s1 = testStep("echo x >> /shared/s1; echo sha=$GITHUB_SHA");
    const s2 = testStep("echo x >> /shared/s2");
    var secret = testStep("echo x >> /shared/secret; echo the token is $TOKEN; " ++
        "echo $TOKEN > /tmp/token-file");
    secret.env = &.{.{ .name = "TOKEN", .value = .{ .lit = "s3cr3t-token-value" } }};
    var job = testJob(&.{ s0, s1, s2, secret });
    job.secrets = &.{"s3cr3t-token-value"};
    for ([_][]const u8{ "j1", "j2" }) |ran| try expectSucceeded(try runCached(arena, c.cfg, job, ran));
    try std.testing.expectEqual(@as(usize, 1), runs(arena, c.shared, "s0"));
    try std.testing.expectEqual(@as(usize, 2), runs(arena, c.shared, "s1"));
    try std.testing.expectEqual(@as(usize, 2), runs(arena, c.shared, "s2"));
    try std.testing.expectEqual(@as(usize, 2), runs(arena, c.shared, "secret"));
    // Only the base and the first step were kept: no layer or log holds the secret.
    try std.testing.expectEqual(@as(usize, 2), try storeLayers(arena, c.cfg.store));
    var store = try std.Io.Dir.cwd().openDir(io, c.cfg.store, .{ .iterate = true });
    defer store.close(io);
    var walker = try store.walk(arena);
    defer walker.deinit();
    while (try walker.next(io)) |e| {
        if (e.kind != .file) continue;
        const text = e.dir.readFileAlloc(io, e.basename, arena, .limited(1 << 20)) catch continue;
        try std.testing.expect(std.mem.indexOf(u8, text, "s3cr3t") == null);
    }

    // A workflow that opts out runs everything every time.
    var out = testJob(&.{testStep("echo x >> /shared/opted-out")});
    out.env = &.{.{ .name = "ZIG_RUNNER_STEP_CACHE", .value = .{ .lit = "false" } }};
    for ([_][]const u8{ "j3", "j4" }) |ran| try expectSucceeded(try runCached(arena, c.cfg, out, ran));
    try std.testing.expectEqual(@as(usize, 2), runs(arena, c.shared, "opted-out"));
}

test "native step cache: two jobs with one key at once run it once; the other replays it" {
    // On a root runner too, though two jobs at once have two slots: a stored layer has the
    // canonical ids, and its key no slot's.
    var a: std.heap.ArenaAllocator = .init(std.testing.allocator);
    defer a.deinit();
    const arena = a.allocator();
    const io = std.testing.io;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    const c = try cachedConfig(arena, &tmp);
    // A file of its own each time: the other job's root may be another host id.
    const job = testJob(&.{testStep("sleep 1; mktemp /shared/slow.XXXXXX")});
    const Other = struct {
        fn run(cfg: Config, j: job_mod.Job, text: *[]const u8, ok: *bool) void {
            var b: std.heap.ArenaAllocator = .init(std.testing.allocator);
            const r = runCached(b.allocator(), cfg, j, "j2") catch {
                b.deinit();
                return;
            };
            ok.* = r.res.succeeded;
            text.* = std.testing.allocator.dupe(u8, r.text) catch "";
            b.deinit();
        }
    };
    var other_text: []const u8 = "";
    var other_ok = false;
    var other = try io.concurrent(Other.run, .{ c.cfg, job, &other_text, &other_ok });
    const mine = try runCached(arena, c.cfg, job, "j1");
    other.await(io);
    defer std.testing.allocator.free(other_text);
    try expectSucceeded(mine);
    try std.testing.expect(other_ok);
    var made: usize = 0;
    var dir = try std.Io.Dir.cwd().openDir(io, c.shared, .{ .iterate = true });
    defer dir.close(io);
    var it = dir.iterate();
    while (try it.next(io)) |e| made += @intFromBool(std.mem.startsWith(u8, e.name, "slow."));
    try std.testing.expectEqual(@as(usize, 1), made);
    const notes = std.mem.count(u8, mine.text, dagger.native_reused_note) +
        std.mem.count(u8, other_text, dagger.native_reused_note);
    try std.testing.expectEqual(@as(usize, 1), notes);
}

/// The first host id of the job's range, from "Set up job" ("ids 0-65535 are host ids N-...").
fn hostIdsOf(text: []const u8) ?u32 {
    const at = std.mem.indexOf(u8, text, "are host ids ") orelse return null;
    const rest = text[at + "are host ids ".len ..];
    const end = std.mem.indexOfScalar(u8, rest, '-') orelse return null;
    return std.fmt.parseInt(u32, rest[0..end], 10) catch null;
}

test "root runner: jobs in different slots share a stored layer, its owners their own, a set-id file harmless" {
    try requireRoot();
    var a: std.heap.ArenaAllocator = .init(std.testing.allocator);
    defer a.deinit();
    const arena = a.allocator();
    const io = std.testing.io;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    const c = try cachedConfig(arena, &tmp);
    try sudoRootfs(arena, try tmp.dir.realPathFileAlloc(io, ".", arena));
    // Steps as the runner user, whose sudo reaches the job's root: a file of its own, and a
    // set-uid copy of `id` owned by the job's root.
    const make = testStep("echo x >> /shared/made; /opt/sudo -n mkdir -p /w && " ++
        "/opt/sudo -n chown 1001:1001 /w && echo mine > /w/mine && " ++
        "/opt/sudo -n cp /usr/bin/id /w/suid && /opt/sudo -n chmod 4755 /w/suid");
    // Run as the runner user, the set-uid file works through the stored layer (euid 0), and
    // that 0 is the second job's root: its own range of host ids.
    const look = testStep("stat -c 'seen %n %u:%g %a' /w/mine /w/suid; echo suid-euid=$(/w/suid -u); " ++
        "head -n1 /proc/self/uid_map | tr -s ' ' | sed 's/^ //; s/^/map /'; " ++
        "echo more >> /w/mine && stat -c 'copied up %u:%g' /w/mine");
    // The first job in another slot than the first free one, which a second runner holds.
    var other = c.cfg;
    try tmp.dir.createDirPath(io, "store-2");
    other.store = try std.fmt.allocPrint(arena, "{s}/store-2", .{try tmp.dir.realPathFileAlloc(io, ".", arena)});
    var holder = try init(arena, io, std.testing.allocator, other);
    const first = try runCachedAs(arena, c.cfg, testJob(&.{make}), "j1", .runner);
    holder.deinit();
    try expectSucceeded(first);
    const second = try runCachedAs(arena, c.cfg, testJob(&.{ make, look }), "j2", .runner);
    try expectSucceeded(second);
    const first_ids = hostIdsOf(first.text).?;
    const second_ids = hostIdsOf(second.text).?;
    try std.testing.expect(first_ids != second_ids);

    // The second job replayed the first's layer (its base's and its step's), in its own range.
    try std.testing.expectEqual(@as(usize, 1), runs(arena, c.shared, "made"));
    try std.testing.expectEqual(@as(usize, 1), std.mem.count(u8, second.text, dagger.native_reused_note));
    try expectLines(second.text, &.{
        "seen /w/mine 1001:1001 644",
        "seen /w/suid 0:0 4755",
        "suid-euid=0",
        try std.fmt.allocPrint(arena, "map 0 {d} 65536", .{second_ids}),
        // Copied up from the stored layer into the step's own, as the job's runner user still.
        "copied up 1001:1001",
    });

    // On disk the layer has the canonical ids, the set-uid file the host's root's: harmless, as
    // the store is the host's root's alone (0700), so no host user reaches it.
    const layers = try std.fmt.allocPrint(arena, "{s}/layers", .{c.cfg.store});
    var dir = try std.Io.Dir.cwd().openDir(io, layers, .{ .iterate = true });
    defer dir.close(io);
    var it = dir.iterate();
    var found: ?[:0]const u8 = null;
    while (try it.next(io)) |e| {
        const p = try std.fmt.allocPrintSentinel(arena, "{s}/{s}/fs/w/suid", .{ layers, e.name }, 0);
        var st: std.os.linux.Statx = undefined;
        if (std.os.linux.errno(std.os.linux.statx(std.os.linux.AT.FDCWD, p, std.os.linux.AT.SYMLINK_NOFOLLOW, .{ .UID = true, .MODE = true }, &st)) != .SUCCESS) continue;
        try std.testing.expectEqual(@as(u32, 0), st.uid);
        try std.testing.expectEqual(@as(u32, 0o4755), st.mode & 0o7777);
        const mine = try std.fmt.allocPrintSentinel(arena, "{s}/{s}/fs/w/mine", .{ layers, e.name }, 0);
        _ = std.os.linux.statx(std.os.linux.AT.FDCWD, mine, 0, .{ .UID = true }, &st);
        try std.testing.expectEqual(@as(u32, 1001), st.uid);
        found = p;
    }
    var st: std.os.linux.Statx = undefined;
    _ = std.os.linux.statx(std.os.linux.AT.FDCWD, try arena.dupeSentinel(u8, c.cfg.store, 0), 0, .{ .MODE = true }, &st);
    try std.testing.expectEqual(@as(u32, 0o700), st.mode & 0o777);
    const nobody = try std.process.run(arena, io, .{ .argv = &.{
        "setpriv", "--reuid=65534", "--regid=65534", "--clear-groups", "test", "-e", found.?,
    } });
    try std.testing.expect(nobody.term == .exited and nobody.term.exited != 0);
}

test "native step cache: a long job's layers are flattened, files, deletions and replays intact" {
    var a: std.heap.ArenaAllocator = .init(std.testing.allocator);
    defer a.deinit();
    const arena = a.allocator();
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    var c = try cachedConfig(arena, &tmp);
    // The base and two steps, then a merge; and again two steps later.
    c.cfg.flatten_at = 3;
    const job = testJob(&.{
        testStep("mkdir -p /w/d && echo 1 > /w/a && echo 1 > /w/d/x && echo 1 > /w/gone"),
        testStep("echo 2 > /w/a && rm /w/gone"),
        // A directory removed and made again: opaque in its layer.
        testStep("rm -rf /w/d && mkdir /w/d && echo 3 > /w/d/y"),
        testStep("echo 4 > /w/b"),
        testStep("echo x >> /shared/last; ls /w /w/d | tr '\\n' ' '; echo; cat /w/a /w/b /w/d/y; " ++
            "test ! -e /w/gone && test ! -e /w/d/x && echo state-ok"),
    });
    // Without the store, with it, and replayed from it over links to its layers.
    var uncached = c.cfg;
    uncached.store = try std.fmt.allocPrint(arena, "{s}-uncached", .{c.cfg.store});
    const plain = try runNativeJob(arena, uncached, job, .root);
    try expectSucceeded(plain);
    for ([_][]const u8{ "j1", "j2" }) |ran| {
        const r = try runCached(arena, c.cfg, job, ran);
        try expectSucceeded(r);
        try expectLines(r.text, &.{ "stdout] 2", "stdout] 4", "stdout] 3", "state-ok" });
    }
    try std.testing.expectEqual(@as(usize, 2), runs(arena, c.shared, "last"));
    try expectLines(plain.text, &.{"state-ok"});
}

test "native step cache: past its cap the store lets go of every layer no job holds" {
    var a: std.heap.ArenaAllocator = .init(std.testing.allocator);
    defer a.deinit();
    const arena = a.allocator();
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    var c = try cachedConfig(arena, &tmp);
    c.cfg.store_max_bytes = 0;
    const job = testJob(&.{testStep("echo x >> /shared/s")});
    for ([_][]const u8{ "j1", "j2" }) |ran| try expectSucceeded(try runCached(arena, c.cfg, job, ran));
    try std.testing.expectEqual(@as(usize, 2), runs(arena, c.shared, "s"));
    try std.testing.expectEqual(@as(usize, 0), try storeLayers(arena, c.cfg.store));
}

test "native step cache: measured, replay per step and the store's size over 50 jobs" {
    // A measurement, not a check: ZIG_RUNNER_NATIVE_BENCH=1 runs it (docs/native-backend.md, P2's
    // numbers), best under `-Doptimize=ReleaseSafe`.
    var a: std.heap.ArenaAllocator = .init(std.testing.allocator);
    defer a.deinit();
    const arena = a.allocator();
    const io = std.testing.io;
    var env = try std.testing.environ.createMap(arena);
    if (!std.mem.eql(u8, env.get("ZIG_RUNNER_NATIVE_BENCH") orelse "", "1"))
        return error.SkipZigTest;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    const c = try cachedConfig(arena, &tmp);
    const now = struct {
        fn ms() i64 {
            return std.Io.Clock.awake.now(std.testing.io).toMilliseconds();
        }
    }.ms;
    // Per step: (50-step job - 1-step job) / 49, cold (run and published) and replayed.
    var steps: [50]job_mod.Step = undefined;
    for (&steps, 0..) |*s, i| s.* = testStep(try std.fmt.allocPrint(arena, "true {d}", .{i}));
    var t: [2][2]i64 = undefined; // [cold, replayed][1 step, 50 steps]
    for ([_]usize{ 1, 50 }, 0..) |n, col| {
        const job = testJob(steps[0..n]);
        for (0..2) |row| {
            const ran = try std.fmt.allocPrint(arena, "b{d}{d}", .{ n, row });
            const started = now();
            try expectSucceeded(try runCached(arena, c.cfg, job, ran));
            t[row][col] = now() - started;
        }
    }
    std.debug.print("native bench: cold job 1 step {d} ms, 50 steps {d} ms, per step {d:.1} ms\n", .{
        t[0][0], t[0][1], @as(f64, @floatFromInt(t[0][1] - t[0][0])) / 49.0,
    });
    std.debug.print("native bench: replayed job 1 step {d} ms, 50 steps {d} ms, per step {d:.2} ms\n", .{
        t[1][0], t[1][1], @as(f64, @floatFromInt(t[1][1] - t[1][0])) / 49.0,
    });

    // 50 jobs of one workflow, as 50 commits: five steps that never change (one of them writes
    // 1 MiB), one that does every time, and four after it, which are new with it.
    const layers = try std.fmt.allocPrint(arena, "{s}/layers", .{c.cfg.store});
    var job_steps: [10]job_mod.Step = undefined;
    for (0..50) |j| {
        for (&job_steps, 0..) |*s, i| s.* = testStep(switch (i) {
            0 => "head -c 1048576 /dev/zero > /tmp/setup.bin",
            5 => try std.fmt.allocPrint(arena, "echo commit {d} > /tmp/commit", .{j}),
            else => try std.fmt.allocPrint(arena, "echo step {d} > /tmp/s{d}", .{ i, i }),
        });
        const ran = try std.fmt.allocPrint(arena, "s{d}", .{j});
        try expectSucceeded(try runCached(arena, c.cfg, testJob(&job_steps), ran));
    }
    std.debug.print("native bench: store after 50 jobs: {d} layers, {d} KiB\n", .{
        try storeLayers(arena, c.cfg.store),
        (try Store.treeBytes(arena, io, layers)) / 1024,
    });
}

test "native step cache: a fork's pull request keys its layers apart from its repository's jobs" {
    var a: std.heap.ArenaAllocator = .init(std.testing.allocator);
    defer a.deinit();
    const arena = a.allocator();
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    const c = try cachedConfig(arena, &tmp);
    // Two pull requests, alike but for the head's repository: the repository's own, and a fork's.
    const pr = struct {
        fn job(ar: Allocator, head: []const u8) !job_mod.Job {
            // The steps in the arena: a literal's would not outlive this call.
            const steps = try ar.dupe(job_mod.Step, &.{testStep("echo x >> /shared/s")});
            var j = testJob(steps);
            j.context_data = try std.json.parseFromSliceLeaky(
                std.json.Value,
                ar,
                try std.fmt.allocPrint(ar, "{{\"github\":{{\"t\":2,\"d\":[" ++
                    "{{\"k\":\"repository\",\"v\":\"o/r\"}},{{\"k\":\"event\",\"v\":{{\"t\":2,\"d\":[" ++
                    "{{\"k\":\"pull_request\",\"v\":{{\"t\":2,\"d\":[{{\"k\":\"head\",\"v\":{{\"t\":2," ++
                    "\"d\":[{{\"k\":\"repo\",\"v\":{{\"t\":2,\"d\":[{{\"k\":\"full_name\",\"v\":" ++
                    "\"{s}\"}}]}}}}]}}}}]}}}}]}}}}]}}}}", .{head}),
                .{},
            );
            return j;
        }
    }.job;
    const own = try pr(arena, "o/r");
    const fork = try pr(arena, "fork/r");
    try expectSucceeded(try runCached(arena, c.cfg, own, "j1"));
    try expectSucceeded(try runCached(arena, c.cfg, own, "j2"));
    try std.testing.expectEqual(@as(usize, 1), runs(arena, c.shared, "s"));
    // The fork's does not replay the repository's layer, but replays its own.
    try expectSucceeded(try runCached(arena, c.cfg, fork, "j3"));
    try std.testing.expectEqual(@as(usize, 2), runs(arena, c.shared, "s"));
    try expectSucceeded(try runCached(arena, c.cfg, fork, "j4"));
    try std.testing.expectEqual(@as(usize, 2), runs(arena, c.shared, "s"));
}

/// A native job with the cache options a runner gives it (`volumes.Options`), as `how.user`
/// (root by default), under step caching as the job whose ran marker is `how.ran` when given.
fn runCachedJob(
    arena: Allocator,
    cfg: Config,
    job: job_mod.Job,
    caches: volumes.Options,
    how: struct { user: config.StepUser = .root, ran: ?[]const u8 = null },
) !struct { res: dagger.Result, text: []const u8 } {
    var env: std.process.Environ.Map = .init(arena);
    var w: std.Io.Writer.Allocating = .init(arena);
    var log: sink.LogSink = .{ .stdout = .{ .writer = &w.writer } };
    const res = try dagger.run(arena, std.testing.io, &env, .{
        .native = cfg,
        .step_user = how.user,
        .step_cache = how.ran != null,
        .test_ran_marker = how.ran,
        .gpa = std.testing.allocator,
        .package_caches = caches.package_caches,
        .trusted = caches.trusted,
        .uv_env_in_cache = caches.uv_env_in_cache,
        .zig_local_cache = caches.zig_local_cache,
        .zig_local_cache_max_mb = caches.zig_local_cache_max_mb,
        .zig_seeds = caches.zig_seeds,
        .zig_seeds_unverified = caches.zig_seeds_unverified,
    }, job, &log);
    const text = w.written();
    for (res.steps) |s| if (s.outcome != .success) {
        std.debug.print("a step {s}, engine {s}\n{s}\n", .{
            @tagName(s.outcome),
            res.engine_error orelse "-",
            text,
        });
        return error.TestUnexpectedResult;
    };
    return .{ .res = res, .text = text };
}

test "native cache volumes: kept between jobs, apart by scope, Zig's local cache rolled, the seed below" {
    var a: std.heap.ArenaAllocator = .init(std.testing.allocator);
    defer a.deinit();
    const arena = a.allocator();
    const io = std.testing.io;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    var cfg = try testConfig(arena, &tmp);
    // The seed's build, without a Zig release to download: a file where Zig's cache would be.
    cfg.test_seed_script = "mkdir -p /zig-seed/o/s && echo seeded > /zig-seed/o/s/f";
    const caches: volumes.Options = .{
        .package_caches = true,
        .trusted = true,
        .zig_local_cache = true,
        .zig_local_cache_max_mb = 1,
        .zig_seeds = &.{.{ .version = "0.0.1", .sha256 = "00" }},
    };

    // The first job fills npm's volume, Zig's package volume and its local cache (2 MB, over
    // its 1 MB limit), and finds the seed under Zig's global cache.
    const fill = testStep("echo from-the-first > /root/.npm/marker # npm\n" ++
        "stat -c 'npm owner %u:%g' /root/.npm\n" ++
        "grep ' /root/.npm ' /proc/self/mountinfo | grep -q 'nosuid,nodev' && echo npm-nosuid\n" ++
        "echo tarball > /root/.cache/zig/p/t # zig\n" ++
        "cat /root/.cache/zig/o/s/f; echo own > /root/.cache/zig/o/mine\n" ++
        "echo ZIG_LOCAL=$ZIG_LOCAL_CACHE_DIR\n" ++
        "head -c 2000000 /dev/zero > $ZIG_LOCAL_CACHE_DIR/big");
    const first = try runCachedJob(arena, cfg, testJob(&.{fill}), caches, .{});
    try expectLines(first.text, &.{
        "npm owner 0:0",
        "npm-nosuid",
        "seeded",
        "ZIG_LOCAL=/root/.cache/zig-local/current",
        "Zig global cache seeded from Zig 0.0.1",
    });
    const npm = try std.fmt.allocPrint(arena, "{s}/volumes/o/r/repo/npm", .{cfg.store});
    try std.testing.expectEqualStrings("from-the-first\n", try std.Io.Dir.cwd().readFileAlloc(
        io,
        try std.fmt.allocPrint(arena, "{s}/marker", .{npm}),
        arena,
        .limited(64),
    ));
    if (std.os.linux.geteuid() == 0) {
        // On disk, the volumes' own range, which no host user and no slot has.
        var st: std.os.linux.Statx = undefined;
        const p = try arena.dupeSentinel(u8, npm, 0);
        _ = std.os.linux.statx(std.os.linux.AT.FDCWD, p, 0, .{ .UID = true }, &st);
        try std.testing.expectEqual(volumeIdBase(cfg.subid_base), st.uid);
    }

    // The next job of the repository finds them; what the first added to its global cache was
    // its own; the local cache rolled to its next generation; the seed was not built again.
    cfg.test_seed_script = "exit 1";
    const read = testStep("cat /root/.npm/marker # npm\ncat /root/.cache/zig/p/t # zig\n" ++
        "test -e /root/.cache/zig/o/mine && echo leaked || echo global-cache-own\n" ++
        "readlink /root/.cache/zig-local/current");
    const second = try runCachedJob(arena, cfg, testJob(&.{read}), caches, .{});
    try expectLines(second.text, &.{
        "from-the-first",
        "tarball",
        "global-cache-own",
        "gen-1",
        "Zig global cache seeded from Zig 0.0.1",
    });

    // A job the runner does not trust with the repository's caches (a fork's pull request) has
    // its own, empty, and no shared Zig local cache.
    var untrusted = caches;
    untrusted.trusted = false;
    const apart = testStep("test -e /root/.npm/marker && echo leaked || echo npm-own # npm\n" ++
        "test -e /root/.cache/zig-local/big && echo leaked || echo zig-local-own");
    const third = try runCachedJob(arena, cfg, testJob(&.{apart}), untrusted, .{});
    try expectLines(third.text, &.{
        "npm-own",
        "zig-local-own",
        "Zig local cache: this job's own (not kept between untrusted jobs)",
    });
    try std.testing.expect(std.mem.indexOf(u8, third.text, "stdout] leaked") == null);
}

/// The cgroup parent the cgroup tests use: a tree of the tests' own as root (its memory.max is
/// set by the gate's test), or `ZIG_RUNNER_TEST_CGROUP` (`self` under `systemd-run --user
/// --scope -p Delegate=yes`) rootless; else the test is skipped.
fn testCgroup(arena: Allocator, cfg: *Config) !void {
    var env = try std.testing.environ.createMap(arena);
    if (std.os.linux.geteuid() == 0) {
        cfg.cgroup.parent = cgroup.mount_point ++ "/zig-runner-test";
    } else if (env.get("ZIG_RUNNER_TEST_CGROUP")) |p| {
        cfg.cgroup.parent = p;
    } else {
        std.debug.print("native backend test skipped: it needs root, or a delegated cgroup " ++
            "(ZIG_RUNNER_TEST_CGROUP=self)\n", .{});
        return error.SkipZigTest;
    }
}

test "root runner: a native job's runaway is OOM-killed in its own cgroup, a fork bomb stops at pids.max" {
    var a: std.heap.ArenaAllocator = .init(std.testing.allocator);
    defer a.deinit();
    const arena = a.allocator();
    const io = std.testing.io;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    var cfg = try testConfig(arena, &tmp);
    try testCgroup(arena, &cfg);
    var runaway = cfg;
    // Room for the step's shell and the helper: the kernel kills the largest process first, but
    // a limit near their own size takes them too (seen on the root pass at 64 MB).
    runaway.cgroup.memory_max_mb = 256;
    runaway.cgroup.pids_max = 64;

    // The runaway job holds more and more memory, and a fork bomb after it; its neighbour, at
    // the same time, holds 200 MB under the default limit and must not notice.
    const hog = testStep("python3 -c 'x = []\nwhile True: x.append(b\"x\" * (8 << 20))' || " ++
        "echo exit=$?");
    // The bomb in a process group of its own (`set -m`), for 2 s of builtins only (nothing else
    // can fork while it holds every process), then killed, and waited out until no process of
    // the group is left, so the step's own end (`scripts.stepScriptFc`'s epilogue, whose `sh`
    // must fork) finds its processes free again. Left running, the bomb still held them there:
    // the wrapper's `sh` could not fork, and the step failed with exit 2 (#265's CI, once).
    var bomb = testStep("set -m\n" ++
        "( set +m; bomb() { bomb | bomb & }; bomb; while :; do :; done ) &\n" ++
        "pg=$!\nset +m\n" ++
        "end=$((SECONDS + 2)); while [ $SECONDS -lt $end ]; do :; done\n" ++
        "kill -9 -- -$pg\n" ++
        "while kill -0 -- -$pg 2>/dev/null; do :; done\n" ++
        "echo after-the-bomb");
    bomb.condition = "always()";
    var near = testStep("python3 -c 'import time; x = b\"x\" * (200 << 20); time.sleep(6); " ++
        "print(\"neighbour held\", len(x) >> 20)'");
    near.name = "neighbour";
    const Run = struct {
        fn one(arena_: Allocator, cfg_: Config, job: job_mod.Job, out: *[]const u8, res: *?dagger.Result) void {
            const r = runNativeJob(arena_, cfg_, job, .root) catch return;
            out.* = r.text;
            res.* = r.res;
        }
    };
    var texts: [2][]const u8 = .{ "", "" };
    var results: [2]?dagger.Result = .{ null, null };
    var arenas: [2]std.heap.ArenaAllocator = .{
        .init(std.testing.allocator),
        .init(std.testing.allocator),
    };
    defer for (&arenas) |*x| x.deinit();
    const started = std.Io.Clock.awake.now(io).toMilliseconds();
    var neighbour = try io.concurrent(Run.one, .{
        arenas[1].allocator(),
        cfg,
        testJob(&.{near}),
        &texts[1],
        &results[1],
    });
    Run.one(arenas[0].allocator(), runaway, testJob(&.{ hog, bomb }), &texts[0], &results[0]);
    neighbour.await(io);
    const took = std.Io.Clock.awake.now(io).toMilliseconds() - started;

    const r = results[0] orelse return error.TestUnexpectedResult;
    std.debug.print("runaway job:\n{s}\n", .{texts[0]});
    try expectLines(texts[0], &.{
        "The job reached its memory limit (256 MB, RUNNER_NATIVE_MEMORY_MAX_MB): the kernel " ++
            "killed ",
        "after-the-bomb",
        "The job reached its process limit (64, RUNNER_NATIVE_PIDS_MAX)",
        "with memory.max 256 MB and pids.max 64",
    });
    // The hog itself was killed (its step goes on to say so, or ends with it: 137), and the bomb
    // stopped at the limit and the job went on.
    try std.testing.expect(std.mem.indexOf(u8, texts[0], "exit=137") != null or
        r.steps[0].exit_code == 137);
    // The bomb's step succeeded: once it ended the bomb, its end could fork again.
    if (r.steps[1].outcome != .success) std.debug.print("bomb step: exit {d}\n", .{r.steps[1].exit_code});
    try std.testing.expectEqual(dagger.Outcome.success, r.steps[1].outcome);
    // The neighbour ran through, its 200 MB held, nothing of its own killed or refused.
    const n = results[1] orelse return error.TestUnexpectedResult;
    if (n.steps[0].outcome != .success) std.debug.print("neighbour:\n{s}\n", .{texts[1]});
    try std.testing.expectEqual(dagger.Outcome.success, n.steps[0].outcome);
    try expectLines(texts[1], &.{"neighbour held 200"});
    try std.testing.expect(std.mem.indexOf(u8, texts[1], "reached its") == null);
    try std.testing.expect(took < 60_000);
}

test "root runner: native gate accuracy, each job's own cgroup against the engine-wide reading" {
    var a: std.heap.ArenaAllocator = .init(std.testing.allocator);
    defer a.deinit();
    const arena = a.allocator();
    const io = std.testing.io;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    var cfg = try testConfig(arena, &tmp);
    try testCgroup(arena, &cfg);
    const parent = switch (cgroup.parent(arena, io, cfg.cgroup.parent)) {
        .dir => |d| d,
        .none => |why| return skip(true, why),
    };
    // The jobs' parent stands for the engine's cgroup: one cgroup for every job, as the engine
    // is, read as the gate reads the engine's (which needs a cap to be read at all).
    const cap = try std.fmt.allocPrintSentinel(arena, "{s}/memory.max", .{parent}, 0);
    const fd = std.os.linux.open(cap, .{ .ACCMODE = .WRONLY, .CLOEXEC = true }, 0);
    if (std.os.linux.errno(fd) != .SUCCESS) return skip(true, "the cgroup parent's memory.max");
    _ = std.os.linux.write(@intCast(fd), "68719476736", 11);
    _ = std.os.linux.close(@intCast(fd));

    // Two jobs as on razorbill's soak: the second starts while the first holds its memory.
    const mb = 300;
    var slots: [4]admission.Admission.Slot = undefined;
    var pool: admission.Admission = .init(io, .{}, &slots);
    pool.paths = .{ .meminfo = "/nonexistent", .pressure = "/nonexistent" };
    pool.engine.dir = parent;
    var gates: [4]admission.Gate = undefined;
    for (&gates, 0..) |*g, i| g.* = .{ .pool = &pool, .slot = i };
    var sampling = try io.concurrent(admission.Admission.sample, .{&pool});
    defer sampling.cancel(io);
    const Run = struct {
        fn one(arena_: Allocator, cfg_: Config, hold_s: u32, pool_mb: u32, out: *?dagger.Result) void {
            const script = std.fmt.allocPrint(arena_, "python3 -c 'import time; " ++
                "x = b\"x\" * ({d} << 20); time.sleep({d})'", .{ pool_mb, hold_s }) catch return;
            const r = runNativeJob(arena_, cfg_, testJob(&.{testStep(script)}), .root) catch return;
            out.* = r.res;
        }
    };
    var results: [2]?dagger.Result = .{ null, null };
    var arenas: [2]std.heap.ArenaAllocator = .{
        .init(std.testing.allocator),
        .init(std.testing.allocator),
    };
    defer for (&arenas) |*x| x.deinit();
    // Each job twice at the gate: natively (its cgroup), and as the engine-wide reading saw it
    // (a slot measured from the parent from the same moment).
    var first_cfg = cfg;
    first_cfg.gate = &gates[0];
    gates[0].leave(true);
    gates[0].assigned(admission.jobKey("o/r", "ci.yml", "first"));
    gates[2].leave(true);
    gates[2].assigned(admission.jobKey("o/r", "ci.yml", "first (engine-wide)"));
    var first = try io.concurrent(Run.one, .{ arenas[0].allocator(), first_cfg, 8, mb, &results[0] });
    try io.sleep(.fromSeconds(3), .awake);
    var second_cfg = cfg;
    second_cfg.gate = &gates[1];
    gates[1].leave(true);
    gates[1].assigned(admission.jobKey("o/r", "ci.yml", "second"));
    gates[3].leave(true);
    gates[3].assigned(admission.jobKey("o/r", "ci.yml", "second (engine-wide)"));
    Run.one(arenas[1].allocator(), second_cfg, 3, mb, &results[1]);
    first.await(io);
    for (results) |r| try std.testing.expect(r != null and r.?.steps[0].outcome == .success);
    var seen: [4]u32 = undefined;
    for (&gates, &seen) |*g, *s| s.* = (g.ended() orelse return error.TestUnexpectedResult).seen_mb;
    std.debug.print("native gate accuracy ({d} MB held by each of two overlapping jobs): " ++
        "first job {d} MB own cgroup, {d} MB engine-wide; second job {d} MB own cgroup, {d} MB " ++
        "engine-wide\n", .{ mb, seen[0], seen[2], seen[1], seen[3] });
    // Each job's own reading is its own memory (python's, and the helper's and shell's few MB);
    // the engine-wide reading charges the first job for both.
    for ([_]u32{ seen[0], seen[1] }) |own| {
        try std.testing.expect(own >= mb - 10);
        try std.testing.expect(own <= mb + 60);
    }
    try std.testing.expect(seen[2] >= 2 * mb - 20);
}
