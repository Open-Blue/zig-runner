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
const builtin = @import("builtin");
const Sha256 = @import("../sha256.zig").Sha256;
const job_mod = @import("../job.zig");
const config = @import("../config.zig");
const pg = @import("../pg.zig");
const expr = @import("../expr.zig");
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
const evict = @import("evict.zig");
const reaper = @import("reaper.zig");
const collector = @import("collector.zig");
const volumes = @import("volumes.zig");
const trees_check = @import("tool_trees.zig");
const admission = @import("../admission.zig");
const services = @import("services.zig");
const images = @import("images.zig");
const container_options = @import("container_options.zig");
const publish = @import("publish.zig");
const host_paths = @import("host_paths.zig");
const native_actions = @import("actions.zig");
const Exec = @import("../dagger/Exec.zig");
const Evaluator = @import("../dagger/Evaluator.zig");
const SpanDemux = @import("../dagger/JobLog.zig").SpanDemux;
const checkout = @import("../dagger/checkout.zig");
const scripts = @import("../dagger/scripts.zig");
const set_up = @import("../dagger/set_up.zig");
const provisioned = @import("../dagger/provisioned.zig");
const phases = @import("phases.zig");
const hash_files = @import("hash_files.zig");
const key_diff = @import("key_diff.zig");

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
/// `Config.provisioned_image` and `Config.provisioned_pins`.
provisioned_image: bool = true,
provisioned_pins: provisioned.Pins = provisioned.pinned,
/// The job's image, once pulled (`prepareRootfs`); null with the operator's rootfs.
image: ?oci.Image = null,
/// The image's own env (`NAME=value`), which every step starts from.
image_env: []const []const u8 = &.{"PATH=" ++ image_path},
/// Who the image's `USER` is, for steps that do not run as the runner user.
image_uid: u32 = 0,
image_gid: u32 = 0,
/// The steps' supplementary groups (`stepGroups`).
groups: []const u32 = &.{},
/// What a `container:` job's `options:` ask for (`container_options.zig`), read by `base`.
container_opts: container_options.Options = .{},
/// What of them the sandbox carries out in each of the job's own steps (`readContainerOptions`),
/// and the same as the text `below` keys the job's layers by ("" when none is set).
sandbox_opts: sandbox.Spec.ContainerOpts = .{},
opts_key: []const u8 = "",
/// The `/etc/hosts` lines of `--add-host` and `--hostname`, added to the job's hosts file.
hosts_extra: []const u8 = "",
/// `Config.port_addresses`: the host addresses a job container may publish on (`publishPorts`).
port_addresses: []const [4]u8 = &publish.default_addresses,
/// `Config.port_range`, `Config.port_idle_ms` and `Config.reserved_ports`.
port_range: publish.Range = publish.default_range,
port_idle_ms: u64 = 300_000,
reserved_ports: []const u16 = &.{},
/// `Config.host_paths`: where a job container's host-path volumes may be (`hostVolumes`).
allowed_host_paths: []const host_paths.Entry = &.{},
/// `Config.host_paths_unmapped`.
host_paths_unmapped: bool = false,
/// `Config.host_paths_closed`, said in "Set up job" when the job binds a host path.
host_paths_closed: []const []const u8 = &.{},
/// The shell that makes the job container's anonymous volumes in the base (`containerVolumes`),
/// and how many named ones it binds from the store.
volume_dirs: ?[]const u8 = null,
named_volumes: usize = 0,
/// A `container:` job's PATH once its env is set (`dagger.Base.runtime_path`).
runtime_path: ?[]const u8 = null,
/// Where the job's time went (`phases.zig`): its set-up, each sandbox and publish, its teardown.
timings: phases.Phases = .{},
/// What "Set up job" says of the image and its provisioning, the job's cgroup and its caches.
notes: std.ArrayList([]const u8) = .empty,
/// Remote actions fetched before "Set up job" (`actions.preload`), by `Exec.loadAction`'s key.
actions: std.StringHashMapUnmanaged(Exec.LoadResult) = .empty,
/// The JavaScript runtime JavaScript actions run with (`Options.js_runtime`, `actions.preload`).
js_runtime: config.JsRuntime = .bun,
/// Set when the job is cancelled, which ends a `hashFiles()` in the middle of a file; the runner's
/// (`dagger.runNative` hands it over).
cancel: ?*dagger.Cancel = null,
/// What a `hashFiles()` may use (`Config.hash_files`).
hash_settings: hash_files.Settings = .{},
/// Local actions read so far before the job (`actions.readOwn`), naming their files.
preflights: u32 = 0,
/// Why the last Dockerfile could not be planned or built, for the step's message.
build_reason: []const u8 = "",
/// Why the job runs on Dagger after all, found in `base` (`error.NativeToDagger`): one of its
/// actions is something native steps cannot run yet (`actions.preload`).
to_dagger: []const u8 = "",
/// Set when `base` failed because of the job itself, which Dagger would not mend (a `--user` the
/// image does not know): the job fails with the reason instead of falling back, where the
/// option would be dropped and the steps run as root.
job_fault: bool = false,
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
/// The relay that publishes a job container's `ports:` (`publishPorts`), stopped first.
publisher: ?forward.Running = null,
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
/// A layer of the job's was published (`publishTop`): its end syncs the layers' directory, so
/// the renames outlive a crash (`Store.syncLayers`).
published: bool = false,
/// What a step is across runs, without its place in the job (`stepIdent`): the cache scope, the
/// repository, the workflow, the job and its display name. Set in `base`.
ident: [5][]const u8 = .{ "", "", "", "", "" },
/// GitHub's id of the job (`check_run_id`), 0 when unknown: what its store upkeep's log line names.
check_run_id: u64 = 0,
/// The base's key parts (`below`), which stand where a step's parent layer does in its components.
below_parts: []const key_diff.Component = &.{},
/// The components of the key `keyFor` made last, for `claimKey` to compare and `publishTop` to
/// keep (`key_diff.zig`).
pending: ?Pending = null,
/// The first reason in this job that a keyed layer was not replayed, for the steps above it that
/// miss only because it did (`explainMiss`).
first_miss: ?[]const u8 = null,
/// `Config.vouched`, and the job's cache scope and repository from it (`base`): a vouched fork's
/// pull request keys its layers apart from its repository's own jobs, as its package caches are
/// (`set_up.packageCacheScope`).
vouched: bool = false,
scope: []const u8 = "untrusted",
repository: []const u8 = "",
/// The store's layers the job uses, held shared until it ends (`Store.Layer`).
held: std.ArrayList(std.Io.File) = .empty,
/// The locks (also in `held`) of the stored layers the job's stack has used, oldest first, kept
/// past a flatten, which leaves the stack one layer; `Store.touchChain` at the job's end.
chain: std.ArrayList(std.Io.File) = .empty,
/// Past this many layers, the stack is merged into one (`flatten`).
flatten_at: usize = default_flatten_at,
/// The file keeping the user namespace the idmapped uppers' mounts use (`keepUserns`), once made.
upper_userns: ?[]const u8 = null,
upper_userns_tried: bool = false,
/// Whether a step's upper may be written through an idmapped mount (`idmappedUpper`): the
/// config's say, `Config.idmapped_upper`.
idmapped_upper: bool = true,
/// `Config.idmapped_min_entries`.
idmapped_min_entries: u64 = idmapped_min_entries_default,
/// The most entries any layer of this job's earlier steps held, as published or as their step last
/// published it (`key_diff.readEntries`): what a step with no history of its own is guessed from.
earlier_entries: u64 = 0,
/// `abort` while an exec waits for its key's lock (`Store.lockKey`): the wait ends.
waiting: std.atomic.Value(bool) = .init(false),
stop_wait: std.atomic.Value(bool) = .init(false),
/// The container's environment: what Dagger's container held between execs (the image's, the
/// runner's defaults, the job's `env:`, and what `GITHUB_ENV` and `GITHUB_PATH` added).
env: std.ArrayList(job_mod.EnvVar) = .empty,
/// Who steps run as, and where they start.
uid: u32 = 0,
gid: u32 = 0,
/// `uid` as it was given (the image's `USER`, or `dagger.runner_user`): `hashFiles()` needs its
/// form, which `uid` and `gid` have lost (`hash_files.Step.user`).
user: []const u8 = "",
workdir: []const u8 = "/",
how: Launch,
/// On a root runner: the job's slot (its range of ids and its address), held by a lock, and its
/// network namespace's file.
slot: ?Slot = null,
netns: ?[]const u8 = null,
/// The network helper (`jobNetwork`) while it runs beside the job's set-up, until the first use of
/// the namespace waits for it (`networkPath`). `net_mu` serialises that wait, `net_why` is what
/// it said when it failed, and `net_ns` the time the job spent on it (starting it, then waiting).
net_helper: ?NetHelper = null,
net_mu: std.Io.Mutex = .init,
net_why: ?[]const u8 = null,
net_ns: u64 = 0,
/// On a root runner, the nameservers the job's resolver names (`net.Resolver`), which the jobs'
/// rules let its DNS through to (`natRulesFor`).
nameservers: []const [4]u8 = &.{},
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
ooms: u64 = 0,
parent_ooms: u64 = 0,
pids_max_hits: u64 = 0,
/// `Config.gate`: told of the job's cgroup, which it measures the job in.
gate: ?*admission.Gate = null,
/// What the job's options say of caches, and what it got of them (`setUpCaches`).
caches: volumes.Options = .{},
cache_plan: volumes.Plan = .{},
/// `ZIG_RUNNER_TOOL_TREES`' value, when "Set up job" checked the tool cache's trees
/// (`checkToolTrees`): a step's key holds it, and `Exec.toolDirNotHeld` reads it.
tool_trees: ?[]const u8 = null,
/// `trees_check.full_env`'s value, set with it.
tool_trees_full: ?[]const u8 = null,
/// The Zig cache seeds' layers, between the job's layers and the rootfs.
seed_layers: std.ArrayList([]const u8) = .empty,
/// What the keys know each seed by (`volumes.seedId`): its path, and which build it is.
seed_ids: std.ArrayList([]const u8) = .empty,
/// Tests: the Zig cache seed's build, in place of downloading and running a Zig release.
test_seed_script: ?[]const u8 = null,
/// How long a new named volume's filling from the image may take (`seedVolume`); tests shorten it.
volume_seed_limit_ms: u64 = volumes.seed_limit_ms,
/// Tests: the filling's script, in place of `cp -a`.
test_volume_seed: ?[]const u8 = null,

/// What the runner configures (`RUNNER_BACKEND=native`).
pub const Config = struct {
    /// A directory holding the default image's filesystem, provisioned (`set_up.provision_script`,
    /// or `provision_runner_script` for the runner user), used instead of pulling and provisioning
    /// it natively; "" to pull it (`RUNNER_NATIVE_ROOTFS`).
    rootfs: []const u8 = "",
    /// Pull the pre-provisioned default image (`provisioned.zig`) instead of pulling Ubuntu and
    /// provisioning it, where `provisioned_pins` pins one (`RUNNER_PROVISIONED_IMAGE`). Failing to
    /// pull it provisions, as without.
    provisioned_image: bool = true,
    provisioned_pins: provisioned.Pins = provisioned.pinned,
    /// Where jobs' layers live while they run, and pulled images and provisioned rootfs
    /// (`RUNNER_NATIVE_STORE`).
    store: []const u8 = "",
    /// This binary, which runs each step's sandbox (`sandbox.command`): `exeOf` the runner.
    self_exe: []const u8 = "",
    /// The path the runner was started from, when a deployment has replaced the binary there
    /// since (`Exe.replaced`): "Set up job" says the helpers run the runner's own until it
    /// restarts.
    self_exe_replaced: []const u8 = "",
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
    /// Whether a job's last layer is made durable after its result is reported
    /// (`RUNNER_NATIVE_DEFER_SYNC`, `Store.defer_sync`).
    defer_sync: bool = true,
    /// The first host id of the jobs' ranges on a root runner (`RUNNER_NATIVE_SUBID_BASE`): slot
    /// n's 65536 ids start at `subid_base + n * 65536`.
    subid_base: u32 = default_subid_base,
    /// The jobs' network on a root runner (`RUNNER_NATIVE_SUBNET`). The bridge is the host's, so
    /// every runner on a host must use the same one.
    subnet: net.Subnet = .default,
    /// Host paths mounted into every step. Tests bind the host's /usr into a rootfs of a few
    /// directories; phase 4's cache volumes will be these.
    binds: []const sandbox.Spec.Bind = &.{},
    /// The host addresses a job container's `ports:` may be published on, the first for an
    /// entry that names none (`RUNNER_NATIVE_PORT_ADDRESSES`, `publish.zig`): 127.0.0.1 alone
    /// by default.
    port_addresses: []const [4]u8 = &publish.default_addresses,
    /// The host ports a job container may name (`RUNNER_NATIVE_PORT_RANGE`): 49152-65535 by
    /// default.
    port_range: publish.Range = publish.default_range,
    /// How long a published port's connection may be quiet before the relay closes it, in
    /// milliseconds (`RUNNER_NATIVE_PORT_IDLE_TIMEOUT`); 0 never closes one for that.
    port_idle_ms: u64 = 300_000,
    /// The ports of the runner's own endpoints (its database, the engine, Docker), never
    /// published (`publish.reservedPorts`).
    reserved_ports: []const u16 = &.{},
    /// The directories a job container's host-path volume may be in (`RUNNER_NATIVE_HOST_PATHS`,
    /// `hostPathsOf`), canonical; none by default.
    host_paths: []const host_paths.Entry = &.{},
    /// Entries of the operator's list left out for this job: changed since the runner started
    /// (`host_paths.recheck`).
    host_paths_closed: []const []const u8 = &.{},
    /// `RUNNER_NATIVE_HOST_PATHS_UNMAPPED`: a host path on a filesystem the kernel cannot idmap
    /// is mounted with the host's ids, instead of failing the step (`sandbox.bindHostIn`).
    host_paths_unmapped: bool = false,
    /// Past this many bytes, the store's least recently used layers go
    /// (`RUNNER_NATIVE_STORE_MAX_MB`, `Store.collect`).
    store_max_bytes: u64 = Store.default_max_bytes,
    /// What the store keeps beside the layers (`evict.zig`).
    store_limits: evict.Limits = .{},
    /// Tests: the stack of layers is flattened past this many (`flatten`).
    flatten_at: usize = default_flatten_at,
    /// `RUNNER_NATIVE_IDMAPPED_UPPER`: on a root runner a step's upper is written through an
    /// idmapped mount, so a layer has the canonical ids without a shift afterwards, where the
    /// kernel and the filesystem allow it (`idmappedUpper`); off, or where they do not, every
    /// layer is shifted (`Store.unshift`) as before.
    idmapped_upper: bool = true,
    /// A step's upper is idmapped only when its layer is expected to hold this many entries
    /// (`upperIdmapped`); 0 for every step, which the tests that compare the two ways ask for.
    idmapped_min_entries: u64 = idmapped_min_entries_default,
    /// Whether a job's store upkeep runs on a thread after its end returns
    /// (`RUNNER_NATIVE_DEFER_COLLECT`, `Store.defer_collect`).
    defer_collect: bool = true,
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
    /// Where the jobs' cgroups go, their limits and all jobs' (`RUNNER_NATIVE_CGROUP`,
    /// `RUNNER_NATIVE_MEMORY_MAX_MB`, `RUNNER_NATIVE_PIDS_MAX`).
    cgroup: cgroup.Config = .{},
    /// What a `hashFiles()` may use: the memory all of them may hold together, and the time one
    /// may take (`RUNNER_NATIVE_HASHFILES_MEMORY_MB`, `RUNNER_NATIVE_HASHFILES_TIMEOUT_S`).
    hash_files: hash_files.Settings = .{},
    /// The runner's place at the memory gate: told of the job's cgroup (`admission.Gate.native`).
    gate: ?*admission.Gate = null,
    /// Tests: see `Backend.test_seed_script`.
    test_seed_script: ?[]const u8 = null,
    /// Tests: see `Backend.volume_seed_limit_ms` and `Backend.test_volume_seed`.
    test_volume_seed_limit_ms: ?u64 = null,
    test_volume_seed: ?[]const u8 = null,
    /// Tests: off, as their stores are under a checkout a non-root user owns
    /// (`Store.Prepare.check_parents`).
    check_store_parents: bool = true,
    /// Tests: the host's resolver file a root runner's jobs get theirs from (`net.jobResolver`),
    /// instead of the host's own (`net.resolv_paths`).
    test_resolv_conf: []const u8 = "",
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
        .memory_total_mb = cfg.native_memory_total_mb,
        .swap = cfg.native_swap,
        .pids_max = cfg.native_pids_max,
    };
    const exe = exeOf(arena, io, std.os.linux.getpid());
    // The list `main.zig` checked when the runner started (it refuses to start on a bad one),
    // never parsed from the setting again: an entry whose path resolves elsewhere now, or is
    // another directory, is closed for this job (`host_paths.recheck`). Never checked (a caller
    // that is not `main`), none is allowed.
    var closed: std.ArrayList([]const u8) = .empty;
    const allowed: []const host_paths.Entry = if (cfg.native_host_allowed) |list|
        try host_paths.recheck(arena, io, list, .{}, &closed)
    else
        &.{};
    if (cfg.native_host_allowed == null and cfg.native_host_paths.len > 0)
        try closed.append(arena, cfg.native_host_paths);
    for (closed.items) |e| std.log.warn("native: {s}: `{s}` is not the directory checked when " ++
        "the runner started (moved, replaced or remounted since); closed for this job", .{ host_paths.setting, e });
    return .{
        // Checked when the configuration is loaded (`Config.load`).
        .port_addresses = publish.parseAddresses(arena, cfg.native_port_addresses) catch &publish.default_addresses,
        .port_range = publish.parseRange(cfg.native_port_range) orelse publish.default_range,
        .port_idle_ms = cfg.native_port_idle_timeout *| 1000,
        // As `main.zig` found them (the database's from `PG*` too); else from the settings.
        .reserved_ports = cfg.native_reserved_ports orelse try publish.reservedPorts(
            arena,
            if (cfg.database_url) |u| if (pg.parseUrl(arena, u)) |c| c.port else |_| null else null,
            &.{ cfg.engine_host, cfg.docker_socket },
        ),
        .host_paths = allowed,
        .host_paths_closed = closed.items,
        .host_paths_unmapped = cfg.native_host_paths_unmapped,
        .rootfs = cfg.native_rootfs,
        .provisioned_image = cfg.provisioned_image,
        .store = try cfg.nativeStore(arena, environ),
        .self_exe = exe.path,
        .self_exe_replaced = exe.replaced,
        .vouched = vouched,
        .rootless = cfg.native_rootless,
        .defer_sync = cfg.native_defer_sync,
        .idmapped_upper = cfg.native_idmapped_upper,
        .defer_collect = cfg.native_defer_collect,
        .subid_base = cfg.native_subid_base,
        .subnet = try net.Subnet.parse(cfg.native_subnet),
        .store_max_bytes = cfg.native_store_max_mb * 1024 * 1024,
        .store_limits = .{
            .volumes_max_bytes = cfg.native_volumes_max_mb * 1024 * 1024,
            .images_max_bytes = cfg.native_images_max_mb * 1024 * 1024,
            .min_free_pct = cfg.native_min_free_pct,
        },
        .cgroup = cg,
        .hash_files = .{
            .memory_mb = cfg.native_hashfiles_memory_mb,
            .timeout_s = cfg.native_hashfiles_timeout_s,
        },
        .job_limits = jobLimits(arena, io, cg),
    };
}

pub const HostPathRefusal = host_paths.Refusal;
pub const HostPathEntry = host_paths.Entry;

/// The env files the deploy files give the runner and its deploy timer (`deploy/*.service`):
/// they hold its token or App key.
const runner_env_files = [_][]const u8{ "/etc/zig-runner.env", "/etc/zig-runner-deploy.env" };

/// `RUNNER_NATIVE_HOST_PATHS` canonicalised (`host_paths.parse`), refusing the runner's own
/// paths: its store, its rootfs, its log spool, its executable, its GitHub App key's directory,
/// systemd's credentials directory for it, and its env files.
pub fn hostPathsOf(
    arena: Allocator,
    io: std.Io,
    environ: *const std.process.Environ.Map,
    cfg: *const config.Config,
    refusal: *host_paths.Refusal,
) ![]const host_paths.Entry {
    if (cfg.native_host_paths.len == 0) return &.{};
    const spool = if (cfg.log_spool_dir.len > 0) try std.fmt.allocPrint(arena, "{s}/zig-runner-{d}", .{
        cfg.log_spool_dir,
        std.os.linux.geteuid(),
    }) else "";
    const key_dir: []const u8 = if (cfg.gh_app) |a| switch (a.key) {
        .file => |f| std.fs.path.dirname(f) orelse f,
        .pem => "",
    } else "";
    const exe = exeOf(arena, io, std.os.linux.getpid());
    const mine = [_][]const u8{
        try cfg.nativeStore(arena, environ),
        cfg.native_rootfs,
        spool,
        exe.path,
        exe.replaced,
        key_dir,
        environ.get("CREDENTIALS_DIRECTORY") orelse "",
    } ++ runner_env_files;
    return host_paths.parse(arena, io, cfg.native_host_paths, &mine, refusal, .{});
}

/// A process's executable, for the helpers it starts (`Config.self_exe`).
pub const Exe = struct {
    /// What runs it: its path, or `/proc/<pid>/exe` once that path is gone.
    path: []const u8,
    /// The path it was started from, once that is gone or another file is there; else "".
    replaced: []const u8 = "",
};

/// Process `pid`'s executable, which its helpers run: its path as `/proc/<pid>/exe` names it,
/// while that is still the file it runs. A deployment that renames a new release over it
/// (`zig-runner-deploy`, `install` then `mv -f`) leaves the link saying "<path> (deleted)", a
/// path that is not there (exec: FileNotFound), and the path itself, if read, the new release,
/// whose helpers need not speak this one's protocol: then `/proc/<pid>/exe`, which the kernel
/// still executes as the very file the process started from, until it restarts onto the new
/// one. Not `/proc/self/exe`: `unshare` (`launch`) would find itself there; nor can `unshare`
/// run `/proc/<pid>/exe` from its new user namespace, so a rootless runner that starts its
/// helpers under it sends its jobs to Dagger until it restarts (`unsupported`). "" when
/// unreadable.
pub fn exeOf(arena: Allocator, io: std.Io, pid: std.os.linux.pid_t) Exe {
    const link = std.fmt.allocPrint(arena, "/proc/{d}/exe", .{pid}) catch return .{ .path = "" };
    var buf: [std.fs.max_path_bytes]u8 = undefined;
    const n = std.Io.Dir.readLinkAbsolute(io, link, &buf) catch return .{ .path = "" };
    const named = arena.dupe(u8, buf[0..n]) catch return .{ .path = "" };
    const deleted = " (deleted)";
    if (std.mem.endsWith(u8, named, deleted))
        return .{ .path = link, .replaced = named[0 .. named.len - deleted.len] };
    return .{ .path = named };
}

/// Whether each job gets a cgroup of its own with `memory.max` and `pids.max` (P5's
/// `Config.job_limits`): a parent to make it under, and no limit configured away, of the job's or
/// of all jobs'. `init` fails a job the runner does not vouch for when its cgroup could not be
/// made after all (`jobCgroup`), so this never lets one run unlimited.
fn jobLimits(arena: Allocator, io: std.Io, cg: cgroup.Config) bool {
    const l = cgroup.Limits.compute(cg, null);
    if (l.memory_max == null or l.pids_max == null) return false;
    if (l.memory_total == null or l.pids_total == null) return false;
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
pub const image_path = "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin";
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
    // `/proc/<pid>/exe` is the runner's to execute, not `unshare`'s from its new user namespace.
    if (cfg.self_exe_replaced.len > 0 and usernsHere(io) == .inherited) return "the runner's " ++
        "binary was replaced since it started, and rootless native steps start under " ++
        "`unshare`, which cannot run the one the runner started from (restarting the runner " ++
        "onto the new one runs them natively again)";
    if (!cfg.vouched) if (untrustedRefusal(cfg)) |why| return why;
    if (std.os.linux.geteuid() != 0 and !cfg.rootless) return "the runner is not root, and " ++
        "rootless native steps have only one id mapped (RUNNER_NATIVE_ROOTLESS=1 runs them " ++
        "anyway; subordinate ids are phase 5's)";
    if (job.container) |jc| {
        const default_image = switch (jc.image) {
            .lit => |l| std.mem.eql(u8, dagger.resolveImage(l), dagger.default_image),
            .expr => true,
        };
        if (container_options.unsupported(jc, opts.provision and default_image, job.services)) |why| return why;
    }
    if (job.services.len > 0) if (servicesUnsupported(job, cfg)) |why| return why;
    if (job.container) |jc| if (jc.ports.len > 0 and std.os.linux.geteuid() != 0)
        return "a job container's `ports:` need the job's own network, which a rootless " ++
            "runner does not give: its steps already share the host's (phase 5)";
    if (opts.nesting) return "`dagger call` in a step (RUNNER_DAGGER_NESTING) needs a Dagger " ++
        "engine, which the native backend does not provide; a pool that needs it keeps an " ++
        "engine (RUNNER_ENGINE not `none`)";
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
        // What they are is in their `action.yml`: decided once fetched (`actions.preload`).
        .uses => {},
        // Native when their image is in the native store (`docker_action.unsupported`).
        .docker => {},
        .checkout, .script, .unsupported => {},
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

/// `usable`, asked again now: the remembered failure is forgotten first. For a start-up that
/// retries (`main.nativeRefusal`), where waiting out the back-off would defeat the retry.
pub fn reprobe(arena: Allocator, io: std.Io, gpa: Allocator, cfg: Config) ?[]const u8 {
    {
        probe_mu.lockUncancelable(io);
        defer probe_mu.unlock(io);
        probe_cache = .{};
    }
    return usable(arena, io, gpa, cfg);
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
        const resolver = try net.jobResolver(arena, io, resolvPaths(&cfg), cfg.subnet);
        if (try natRulesFor(arena, io, cfg.subnet, resolver.nameservers, true)) |why| return why;
    }
    // A store another user could reach or replace would hand them the host's root (its layers'
    // set-uid files and capabilities are the host's on disk): native stays off, saying why.
    if (try Store.secure(arena, io, cfg.store, .{ .check_parents = cfg.check_store_parents })) |why|
        return why;
    // Not a job: the gate measures none in it.
    var probing = cfg;
    probing.gate = null;
    // What the machine can do, whoever's job asked: a job's need of limits is `init`'s to enforce
    // for that job, saying why, not the probe's for every job. The probe's `true` needs none.
    probing.vouched = true;
    probing.cgroup.parent = "none";
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
    if (ended.failure.len > 0 or ended.code != 0) {
        const root = std.os.linux.geteuid() == 0;
        const hint = try usernsHint(arena, restrictSysctl(io), root, cfg.self_exe);
        return try std.fmt.allocPrint(
            arena,
            "this machine cannot make a native step's sandbox ({s}, exit {d}){s}",
            .{ ended.failure, ended.code, hint },
        );
    }
    return null;
}

/// The profile that lets this runner make user namespaces where Ubuntu restricts them
/// (`deploy/apparmor/`), named in the refusal when the restriction is what stops the sandbox: a
/// bare errno does not say so. "" for a root runner or a machine without the restriction.
/// `sysctl` is `restrict_userns_path`'s text.
fn usernsHint(arena: Allocator, sysctl: []const u8, root: bool, exe: []const u8) ![]const u8 {
    if (root or !std.mem.startsWith(u8, sysctl, "1")) return "";
    return try std.fmt.allocPrint(arena, "; Ubuntu restricts user namespaces " ++
        "(kernel.apparmor_restrict_unprivileged_userns=1) and this runner may have no AppArmor " ++
        "profile allowing them: as root, install deploy/apparmor/usr.local.bin.zig-runner into " ++
        "/etc/apparmor.d/ (edited if the runner is not at its path, {s}) and load it with " ++
        "`apparmor_parser -r`, or run the runner as root", .{exe});
}

fn restrictSysctl(io: std.Io) []const u8 {
    var buf: [8]u8 = undefined;
    return std.Io.Dir.cwd().readFile(io, restrict_userns_path, &buf) catch "0";
}

const restrict_userns_path = "/proc/sys/kernel/apparmor_restrict_unprivileged_userns";

/// The NAT rules for the host's uplinks and the jobs' nameservers (`dns`) now, remembered so a
/// job finds out cheaply whether either changed since (a laptop moving from cable to Wi-Fi,
/// Tailscale coming up and naming its resolver), and makes the new rules (`jobNetwork`). With no
/// default route, the probe fails, and a job goes on without the rules: it has no way out, as
/// the host has none.
fn natRulesFor(
    arena: Allocator,
    io: std.Io,
    subnet: net.Subnet,
    dns: []const [4]u8,
    probing: bool,
) !?[]const u8 {
    const ups = try net.uplinks(arena, io);
    if (ups.len == 0 and !probing) return null;
    const joined = try std.mem.concat(arena, u8, &.{
        try std.mem.join(arena, "\x00", ups),
        "\x01",
        std.mem.sliceAsBytes(dns),
    });
    rules_mu.lockUncancelable(io);
    defer rules_mu.unlock(io);
    if (ups.len > 0 and std.mem.eql(u8, joined, rules_for[0..rules_len])) return null;
    if (try net.natRules(arena, io, subnet, ups, dns)) |why| return why;
    // Too long to keep: the rules are made again next time.
    rules_len = if (joined.len <= rules_for.len) joined.len else 0;
    @memcpy(rules_for[0..rules_len], joined[0..rules_len]);
    return null;
}

var rules_mu: std.Io.Mutex = .init;
/// The uplinks the rules were made for, joined by zero bytes, then a one and the nameservers'
/// addresses.
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
    return if (std.mem.startsWith(u8, restrictSysctl(io), "1")) .inherited else .self;
}

/// A job's directory in the store, locked, and on a root runner its slot and network. Stale
/// directories (a runner that died) are removed first (`sweep`).
pub fn init(arena: Allocator, io: std.Io, gpa: Allocator, cfg: Config) !Backend {
    var why: []const u8 = "";
    return initWhy(arena, io, gpa, cfg, &why);
}

/// Set by the first job of the process (`initWhy`).
var verdicts_dropped: std.atomic.Value(bool) = .init(false);

/// `init`, saying in `why` what failed and on which path ("making /var/lib/.../P/etc:
/// FileNotFound"), for "Set up job": an error's name alone does not say which of the job's
/// directories, locks, helpers or files it was.
pub fn initWhy(arena: Allocator, io: std.Io, gpa: Allocator, cfg: Config, why: *[]const u8) !Backend {
    var ph: phases.Phases = .{};
    var t = phases.now();
    if (Store.secure(arena, io, cfg.store, .{ .check_parents = cfg.check_store_parents }) catch |e|
        return failed(why, arena, "preparing the native store", cfg.store, e)) |unsafe|
    {
        why.* = unsafe;
        return error.StoreUnsafe;
    }
    t = ph.since(arena, .store, t);
    const cg_parent = cgroup.parent(arena, io, cfg.cgroup.parent);
    sweep(arena, io, cfg.store, switch (cg_parent) {
        .dir => |d| d,
        .none => null,
    });
    (Store{ .root = cfg.store }).checkOncePerBoot(arena, io);
    // What was done to a volume while no runner was up is not in a verdict from before: the first
    // job of a process drops them all (`tool_trees.takeVerdict`).
    if (!verdicts_dropped.swap(true, .acq_rel)) trees_check.dropVerdicts(arena, io, cfg.store);
    t = ph.since(arena, .sweep, t);
    var raw: [8]u8 = undefined;
    io.random(&raw);
    const id = std.fmt.bytesToHex(raw, .lower);
    // Made under a name the sweep leaves alone, and renamed once it is locked.
    const new = try std.fmt.allocPrint(arena, "{s}/jobs/.new-{s}", .{ cfg.store, &id });
    const dir = try std.fmt.allocPrint(arena, "{s}/jobs/{s}", .{ cfg.store, &id });
    const cwd = std.Io.Dir.cwd();
    cwd.createDirPath(io, new) catch |e| return failed(why, arena, "making", new, e);
    // Until the lock is the Backend's, a failure removes the directory and closes the lock here;
    // from then on `deinit` does both, once.
    errdefer removeTree(arena, io, new);
    for ([_][]const u8{ "W", "M", sandbox.secrets_dir, mount_points ++ "/etc" }) |d| {
        const path = try std.fmt.allocPrint(arena, "{s}/{s}", .{ new, d });
        cwd.createDirPath(io, path) catch |e| return failed(why, arena, "making", path, e);
    }
    for (mount_point_files) |f| {
        const path = try std.fmt.allocPrint(arena, "{s}/{s}{s}", .{ new, mount_points, f });
        cwd.writeFile(io, .{ .sub_path = path, .data = "" }) catch |e|
            return failed(why, arena, "writing", path, e);
    }
    // Before the rename, so no job of this binary is ever seen without it (`evict.jobsInTheWay`).
    const mark = try std.fmt.allocPrint(arena, "{s}/{s}", .{ new, evict.job_mark });
    cwd.writeFile(io, .{ .sub_path = mark, .data = "" }) catch |e|
        return failed(why, arena, "writing", mark, e);
    const lock_path = try std.fmt.allocPrint(arena, "{s}/lock", .{new});
    const lock = lockFile(arena, io, lock_path, true) catch |e|
        return failed(why, arena, "locking", lock_path, e);
    const how = launch(arena, io, cfg) catch |e| {
        lock.close(io);
        return e;
    };
    cwd.rename(new, cwd, dir, io) catch |e| {
        lock.close(io);
        const paths = try std.fmt.allocPrint(arena, "{s} to {s}", .{ new, dir });
        return failed(why, arena, "renaming", paths, e);
    };
    t = ph.since(arena, .dir, t);
    var b: Backend = .{
        .timings = ph,
        .arena = arena,
        .io = io,
        .gpa = gpa,
        .dir = dir,
        .rootfs = cfg.rootfs,
        .operator_rootfs = cfg.rootfs,
        .provisioned_image = cfg.provisioned_image,
        .provisioned_pins = cfg.provisioned_pins,
        .binds = cfg.binds,
        .lock = lock,
        .how = how,
        .subid_base = cfg.subid_base,
        .subnet = cfg.subnet,
        .store_cfg = .{
            .root = cfg.store,
            .max_bytes = cfg.store_max_bytes,
            .limits = cfg.store_limits,
            .sync_fd = Store.syncCursor(arena, cfg.store),
            .sync_log = Store.newSyncLog(arena),
            .defer_sync = cfg.defer_sync,
            .defer_delete = true,
            .defer_collect = cfg.defer_collect,
        },
        .vouched = cfg.vouched,
        .port_addresses = cfg.port_addresses,
        .port_range = cfg.port_range,
        .port_idle_ms = cfg.port_idle_ms,
        .reserved_ports = cfg.reserved_ports,
        .allowed_host_paths = cfg.host_paths,
        .host_paths_unmapped = cfg.host_paths_unmapped,
        .host_paths_closed = cfg.host_paths_closed,
        .flatten_at = @max(2, cfg.flatten_at),
        .idmapped_upper = cfg.idmapped_upper,
        .idmapped_min_entries = cfg.idmapped_min_entries,
        .gate = cfg.gate,
        .test_seed_script = cfg.test_seed_script,
        .volume_seed_limit_ms = cfg.test_volume_seed_limit_ms orelse volumes.seed_limit_ms,
        .test_volume_seed = cfg.test_volume_seed,
        .images_dir = cfg.images,
        .service_binds = cfg.service_binds,
        .self_exe = cfg.self_exe,
        .hash_settings = cfg.hash_files,
    };
    errdefer b.deinit();
    if (cfg.test_fail_after_lock) return error.TestFailure;
    if (cfg.self_exe_replaced.len > 0) try b.notes.append(arena, try std.fmt.allocPrint(arena, "Native " ++
        "steps: {s} was replaced since this runner started (a deployment), so its helpers run " ++
        "the binary it started from ({s}) until it restarts onto the new one.", .{
        cfg.self_exe_replaced,
        cfg.self_exe,
    }));
    t = phases.now();
    b.binds = try b.jobBinds(cfg, why);
    t = b.timings.since(arena, .resolver, t);
    try b.jobLimitsOrRefuse(cfg, cg_parent, why);
    // The network's helper first of what is left, so that it runs beside the cgroup's set-up and
    // the image's and caches': it needs the resolver's nameservers (the NAT rules) and nothing of
    // the cgroup. A job refused for want of limits is refused before (`jobLimitsOrRefuse`).
    if (b.how.userns == .mapped) try b.jobNetwork(cfg, why);
    t = phases.now();
    try b.jobCgroup(cfg, cg_parent, &id, why);
    _ = b.timings.since(arena, .cgroup, t);
    return b;
}

/// Says in `why` that `what` failed on `path` with `e`, as "Set up job" shows it (`initWhy`),
/// and returns `e`.
fn failed(why: *[]const u8, arena: Allocator, what: []const u8, path: []const u8, e: anyerror) anyerror {
    why.* = std.fmt.allocPrint(arena, "{s} {s}: {s}", .{ what, path, @errorName(e) }) catch
        @errorName(e);
    return e;
}

const untrusted_limits_why = "native steps run a job this runner does not vouch for only within " ++
    "a cgroup of its own with memory and process limits, which could not be made for it";

/// The job's limits (`b.limits`), and the refusal of a job the runner does not vouch for that has
/// none (`untrustedRefusal`, decided on `Config.job_limits`): it does not run natively. Before
/// the job takes a slot or makes a network, so that a refusal is never masked by their errors.
fn jobLimitsOrRefuse(b: *Backend, cfg: Config, parent: cgroup.Parent, why_out: *[]const u8) !void {
    b.limits = cgroup.Limits.of(b.io, cfg.cgroup, switch (parent) {
        .dir => |d| d,
        .none => null,
    });
    const limited = b.limits.memory_max != null and b.limits.pids_max != null;
    if (!cfg.vouched and !limited) {
        why_out.* = untrusted_limits_why;
        return error.NoJobLimits;
    }
}

/// The job's cgroup under `parent`, named as its directory is, with its limits, and all jobs'
/// limits on the parent. A job never runs without them unless the operator said so with
/// `RUNNER_NATIVE_CGROUP=none`: on 2026-11-06 a test's job whose cgroup could not be made went on
/// regardless, in a container with no limit, and took a laptop's desktop with it (#367).
/// `error.NoJobLimits` sends it to Dagger, with `why_out`, where the engine holds it, or fails it
/// saying so where there is none. No per-process limit (`RLIMIT_AS`) stands in for the cgroup:
/// each of a job's processes would get the whole of it, so it bounds no job, and the incident's
/// were several `python3` at once.
fn jobCgroup(
    b: *Backend,
    cfg: Config,
    parent: cgroup.Parent,
    name: []const u8,
    why_out: *[]const u8,
) !void {
    const arena = b.arena;
    const why: []const u8 = switch (parent) {
        .none => |w| w,
        .dir => |dir| if (cgroup.Job.make(arena, b.io, dir, name, b.limits)) |j| {
            // No total that could be put on, as beside an older runner's jobs holding more: as
            // a job with no cgroup, for one the runner does not vouch for.
            if (!cfg.vouched and (j.all.memory == null or j.all.pids == null)) {
                j.remove(arena, b.io);
                why_out.* = untrusted_limits_why;
                return error.NoJobLimits;
            }
            b.job_cgroup = j;
            b.parent_ooms = j.usage(b.io).parent_ooms;
            // What holds is what the log says, and what a kill is put down to.
            b.limits.memory_total = j.all.memory;
            b.limits.pids_total = j.all.pids;
            try b.notes.append(arena, try std.fmt.allocPrint(arena, "Native steps: the job's " ++
                "cgroup is {s}, with memory.max {f} and pids.max {f}.", .{
                j.dir,
                Limit.memory(b.limits.memory_max),
                Limit.count(b.limits.pids_max),
            }));
            try b.notes.append(arena, try std.fmt.allocPrint(arena, "Native steps: all native " ++
                "jobs under {s} share memory.max {f} and pids.max {f}, and {s}.", .{
                dir,
                Limit.memory(b.limits.memory_total),
                Limit.count(b.limits.pids_total),
                if (!j.all.accounted)
                    "may swap: this kernel does not account for swap"
                else if (j.all.swap)
                    "may swap (RUNNER_NATIVE_SWAP)"
                else
                    "may not swap",
            }));
            if (j.all.kept) {
                const said = try std.fmt.allocPrint(arena, "Native steps: these are not this " ++
                    "runner's limits for all jobs: another runner's jobs are running under {s} " ++
                    "with these, and changing them could kill those jobs or leave them " ++
                    "unbounded. Runners on one parent must use the same settings.", .{dir});
                try b.notes.append(arena, said);
                std.log.warn("native: {s}", .{said});
            }
            // memory.high from what the gate reserves for the job; under memory.max, which stays
            // the hard cap. Only where it can slow a job, not stop it (`cgroup.canSwap`).
            const g = b.gate orelse return;
            const high_mb = g.native(j.dir) orelse return;
            if (!cgroup.canSwap(j.all, b.io)) {
                g.noHigh(if (b.limits.memory_max) |m| m >> 20 else null);
                try b.notes.append(arena, "Native steps: no memory.high: with no swap it would " ++
                    "stop a job past it instead of slowing it. memory.max ends one that takes " ++
                    "too much.");
                return;
            }
            const high = j.setHigh(arena, b.io, @as(u64, high_mb) << 20) catch |e| {
                try b.notes.append(arena, try std.fmt.allocPrint(arena, "Native steps: the " ++
                    "job's memory.high could not be set ({s}).", .{@errorName(e)}));
                return;
            };
            try b.notes.append(arena, try std.fmt.allocPrint(arena, "Native steps: memory.high " ++
                "{f}, from what the memory gate reserves for the job: past it the kernel " ++
                "reclaims and slows the job instead of letting it take its neighbours' memory.", .{
                Limit.memory(high),
            }));
            return;
        } else |e| try std.fmt.allocPrint(arena, "it could not be made under {s}: {s}", .{
            dir,
            @errorName(e),
        }),
    };
    if (!cfg.vouched) {
        why_out.* = untrusted_limits_why;
        return error.NoJobLimits;
    }
    if (!std.mem.eql(u8, cfg.cgroup.parent, "none")) {
        why_out.* = try std.fmt.allocPrint(arena, "native steps do not run a job with no limits " ++
            "unless told to, and this job would have no cgroup ({s}). " ++
            "RUNNER_NATIVE_CGROUP=none accepts that a runaway job can take the whole machine", .{
            why,
        });
        return error.NoJobLimits;
    }
    try b.notes.append(arena, "Native steps: this job runs UNBOUNDED " ++
        "(RUNNER_NATIVE_CGROUP=none): it has no memory or process limit, a runaway step can " ++
        "exhaust the whole machine, and the memory gate does not measure it.");
    if (b.gate) |g| _ = g.native(null);
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
/// configured binds. On a root runner, a resolver of the job's own, made from the host's for its
/// network (`net.Resolver`: no loopback or IPv6 nameservers), whose nameservers the jobs' rules
/// let its DNS through to (`jobNetwork`).
fn jobBinds(b: *Backend, cfg: Config, why: *[]const u8) ![]const sandbox.Spec.Bind {
    const resolv = if (b.how.userns == .mapped) resolv: {
        const r = net.jobResolver(b.arena, b.io, resolvPaths(&cfg), cfg.subnet) catch |e| {
            const from = try std.mem.join(b.arena, ", ", resolvPaths(&cfg));
            return failed(why, b.arena, "making the job's resolver from", from, e);
        };
        b.nameservers = r.nameservers;
        if (r.fallback) try b.notes.append(b.arena, try std.fmt.allocPrint(b.arena, "Native " ++
            "steps: the host's resolver ({s}) names no nameserver the job's network can reach " ++
            "(only loopback or IPv6 ones), so the job resolves through 8.8.8.8 and 8.8.4.4, as " ++
            "Docker's containers then do.", .{if (r.source.len > 0) r.source else "none"}));
        const path = try std.fmt.allocPrint(b.arena, "{s}/resolv.conf", .{b.dir});
        std.Io.Dir.cwd().writeFile(b.io, .{ .sub_path = path, .data = r.conf }) catch |e|
            return failed(why, b.arena, "writing", path, e);
        break :resolv path;
    } else "/etc/resolv.conf";
    b.etc_binds = try b.arena.dupe(sandbox.Spec.Bind, &.{
        .{ .host = resolv, .at = "/etc/resolv.conf", .optional = true },
        .{ .host = "/etc/hosts", .at = "/etc/hosts", .optional = true },
    });
    return std.mem.concat(b.arena, sandbox.Spec.Bind, &.{ cfg.binds, b.etc_binds });
}

/// The job's mount points' layer, in its directory (`sandbox.Spec.mount_points`): empty files
/// where the job's resolver and hosts file are bound (`jobBinds`), below every image, so an
/// image without them (Alpine's) gets them too, in a step, a Docker action, its build or a
/// service, and no layer of the job's holds them.
pub const mount_points = "P";
const mount_point_files = [_][]const u8{ "/etc/resolv.conf", "/etc/hosts" };

/// The host's resolver files a root runner's jobs get theirs from.
fn resolvPaths(cfg: *const Config) []const []const u8 {
    if (cfg.test_resolv_conf.len > 0) return (&cfg.test_resolv_conf)[0..1];
    return &net.resolv_paths;
}

/// The job's services by name, for its steps and its services: a hosts file of the job's (the
/// host's, as steps get it, and a line naming the loopback, `services.hostsLine`) bound in place
/// of the host's, read-only.
pub fn serviceHosts(b: *Backend, names: []const []const u8) !void {
    try b.writeHosts(try services.hostsLine(b.arena, names));
}

/// The job's hosts file: the host's, `hosts_extra` (the container's `--add-host`s) and `line`
/// (its services' names), in place of the host's in every bind. Nothing to write is no file.
fn writeHosts(b: *Backend, service_line: []const u8) !void {
    const line = try std.mem.concat(b.arena, u8, &.{ b.hosts_extra, service_line });
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
fn jobNetwork(b: *Backend, cfg: Config, why: *[]const u8) !void {
    const arena = b.arena;
    var t = phases.now();
    b.slot = lockSlot(arena, b.io, net.slots_dir) catch |e|
        return failed(why, arena, "taking a slot in", net.slots_dir, e);
    const n = b.slot.?.n;
    t = b.timings.since(arena, .slot, t);
    const subnet = try std.fmt.allocPrint(arena, "{f}", .{cfg.subnet});
    // The host's uplinks and its resolver may have changed since the probe made their rules.
    const rules = natRulesFor(arena, b.io, cfg.subnet, b.nameservers, false) catch |e|
        return failed(why, arena, "making the jobs' NAT rules for", subnet, e);
    if (rules) |no| {
        std.log.warn("native: the jobs' NAT rules: {s}", .{no});
        why.* = try std.fmt.allocPrint(arena, "making the jobs' NAT rules for {s}: {s}", .{ subnet, no });
        return error.JobNetworkFailed;
    }
    t = b.timings.since(arena, .nat, t);
    const path = try std.fmt.allocPrint(arena, "{s}/netns", .{b.dir});
    const slot = try std.fmt.allocPrint(arena, "{d}", .{n});
    const runner_pid = try std.fmt.allocPrint(arena, "{d}", .{std.os.linux.getpid()});
    const child = std.process.spawn(b.io, .{
        .argv = &.{ cfg.self_exe, net.command, path, slot, subnet, runner_pid },
        .stdin = .ignore,
        .stdout = .ignore,
        .stderr = .pipe,
    }) catch |e| return failed(why, arena, "starting the job's network helper", cfg.self_exe, e);
    // A veth of this slot is a dead job's: its runner let the lock go, by ending or dying. Only
    // the slot's holder removes it, so a live job's network is never touched: its helper does,
    // which runs while this runner holds the lock (`networkPath` waits for it, and the teardown
    // does before it lets the lock go). The job's own thread once did, in its `slot` phase, and
    // waited there for the kernel's lock for link changes, which the namespaces of the jobs just
    // ended were still being taken down under (20-30 ms with seven jobs starting together).
    // The helper runs while the job's image and caches are set up, which need no network: the
    // kernel serialises every link change on one lock, so with many jobs starting together each
    // helper waits for the others' (33-130 ms against 8 on a Pi 5 with seven jobs), time a job
    // spends elsewhere. The first thing that needs the namespace waits for it (`networkPath`).
    b.net_helper = .{ .child = child, .path = path };
    b.net_ns += phases.now() -| t;
}

/// What `jobNetwork` started, still running.
const NetHelper = struct {
    child: std.process.Child,
    path: []const u8,
};

/// The job's network namespace's file, once its helper has made it (the wait for it is the
/// job's `netns` phase); null on a job with no namespace of its own. Fails with
/// `error.JobNetworkFailed` when the helper did, every time it is asked: nothing runs in a
/// network that is not there. Every use of `b.netns` outside the teardown asks here.
pub fn networkPath(b: *Backend) !?[]const u8 {
    b.net_mu.lockUncancelable(b.io);
    defer b.net_mu.unlock(b.io);
    if (b.net_helper) |started| {
        var h = started;
        const arena = b.arena;
        const t = phases.now();
        b.net_helper = null;
        b.netns = h.path;
        // Not cancelled: a cancel here would drop the helper still running, and the teardown
        // would let the slot's lock go under it, where another job's helper may remove the
        // slot's veth and the late one make its own (`net.upMain`). Its run is bounded.
        const protection = b.io.swapCancelProtection(.blocked);
        defer _ = b.io.swapCancelProtection(protection);
        var err: std.ArrayList(u8) = .empty;
        var buf: [4096]u8 = undefined;
        while (true) {
            const got = h.child.stderr.?.readStreaming(b.io, &.{&buf}) catch break;
            if (got == 0) break;
            err.appendSlice(arena, buf[0..got]) catch break;
        }
        const term = h.child.wait(b.io) catch |e| {
            b.net_why = std.fmt.allocPrint(arena, "waiting for the job's network helper {s}: {s}", .{
                b.self_exe, @errorName(e),
            }) catch "waiting for the job's network helper";
            b.timings.add(arena, .netns, b.net_ns + (phases.now() -| t));
            return error.JobNetworkFailed;
        };
        b.net_ns += phases.now() -| t;
        b.timings.add(arena, .netns, b.net_ns);
        if (term != .exited or term.exited != 0) {
            const said = std.mem.trim(u8, err.items, " \n");
            std.log.warn("native: the job's network: {s}", .{said});
            b.net_why = std.fmt.allocPrint(arena, "making the job's network {s} ({s} {s}): {s}", .{
                h.path, b.self_exe, net.command, if (said.len > 0) said else "it failed",
            }) catch "making the job's network failed";
        }
    }
    if (b.net_why != null) return error.JobNetworkFailed;
    return b.netns;
}

/// The first slot whose lock in `dir` no process holds, locked. The directory is made only root's,
/// so no other user can take a slot's lock. A lock file removed and made again while it was being
/// taken is not trusted: the lock is taken only on the file the path names.
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
    // The job's own teardown, whatever ended the job: a task's cancel, delivered here once, would
    // leave its cgroup, its directory or its locks behind (`cgroup.Job.remove` gives up on it).
    const protection = b.io.swapCancelProtection(.blocked);
    defer _ = b.io.swapCancelProtection(protection);
    const arena = b.arena;
    var t = phases.now();
    // First: their helpers hold the job's directory and network, and are in its cgroup. The
    // published ports go with their relay.
    if (b.publisher) |*p| p.stop(b.io);
    b.publisher = null;
    b.service_set.stopAll(b.io);
    t = b.timings.since(arena, .services, t);
    // The volumes are let go only once every process of the job is gone, which the removal of its
    // cgroup shows (the kernel refuses while one is left): another job that takes a volume
    // exclusively then knows that no job's process is left in it (`walkToolCacheIdle`).
    var processes_gone = false;
    if (b.job_cgroup) |j| {
        if (b.gate) |g| g.nativeDone();
        processes_gone = j.removed(arena, b.io);
    }
    t = b.timings.since(arena, .cgroup_rm, t);
    if (processes_gone) b.walkToolCacheIdle() else b.noteProcessesMayRemain();
    b.cache_plan.release(b.io);
    t = b.timings.since(arena, .tool_walk, t);
    // The namespace's last reference goes with its mount, and the kernel then takes the veth down
    // with it, in a batch of its own after this returns (`cleanup_net`): about 20 ms on a laptop
    // that an explicit delete waited for. The host's end may outlive this a moment, which the
    // slot's next holder never sees: it removes whatever it finds of the slot's veth under the
    // slot's lock, which is let go below (`jobNetwork`). A job with no namespace (its helper
    // failed) may have a veth of its slot all the same, so that one is deleted here.
    // Its helper first, if one is still running; why it failed is said already.
    _ = b.networkPath() catch |e| std.log.debug("native: teardown: the job's network: {s}", .{@errorName(e)});
    if (b.upper_userns_tried) detachNetns(arena, std.fmt.allocPrint(arena, "{s}/userns", .{b.dir}) catch "");
    if (b.netns) |p| {
        detachNetns(arena, p);
    } else if (b.slot) |s| {
        var sock = net.Socket.open() catch null;
        if (sock) |*so| {
            so.deleteVeth(s.n);
            so.close();
        }
    }
    t = b.timings.since(arena, .veth_rm, t);
    removeJobDir(arena, b.io, b.dir);
    t = b.timings.since(arena, .tree_rm, t);
    // The job's last layer was renamed in with its data not yet on disk, so that the job's result did
    // not wait for it (`Store.settlePending`): now, while the job still holds it and before the runner
    // polls again, so the next job never shares the disk with it. A failure was logged, and marks the
    // job: `dropUnsynced`, below, evicts the layer.
    b.store_cfg.settlePending(arena, b.io, &b.timings) catch |e| std.log.debug("native: the job's last layer is not durable: {t}", .{e});
    t = phases.now();
    // Before the layers are let go: ancestors end up the more recently used (`Store.touchChain`).
    const whole = t;
    Store.touchChain(b.io, b.chain.items);
    for (b.held.items) |f| f.close(b.io);
    if (b.slot) |s| s.lock.close(b.io);
    b.lock.close(b.io);
    t = b.timings.since(arena, .collect_touch, t);
    // The rest of the upkeep is off the way to the runner's next job (`collector`): the layers'
    // directory synced and the store kept under its cap. Not when the job's sync failed (its layers
    // are dropped before it returns), or the store may be past its cap, which is then collected
    // here, after the thread's own pass, so the cap holds however many jobs end at once.
    if (b.store_cfg.defer_collect and b.store_cfg.root.len > 0) {
        if (b.store_cfg.lagFits(arena, b.io) and collector.submit(b.io, b.store_cfg, b.published, b.check_run_id)) {
            _ = b.timings.since(arena, .collect, whole);
            if (b.store_cfg.sync_fd) |fd| _ = std.os.linux.close(fd);
            // Tests read the store when a job returns, as they did; the thread has tests of its own.
            if (builtin.is_test and collector.test_wait) _ = collector.drain(b.io, null);
            return;
        }
        _ = collector.drain(b.io, null);
    }
    if (b.published) b.store_cfg.syncLayers(arena);
    // After a failed sync, what this job renamed since the last good one is evicted.
    b.store_cfg.dropUnsynced(arena, b.io);
    if (b.store_cfg.sync_fd) |fd| _ = std.os.linux.close(fd);
    t = b.timings.since(arena, .collect_syncdir, t);
    // The store kept under its cap, now that this job holds none of its layers: whether or not
    // the job cached steps, as Dockerfile builds publish layers too (`layers.zig`).
    if (b.store_cfg.root.len > 0) b.store_cfg.collectTimed(arena, b.io, &b.timings);
    _ = b.timings.since(arena, .collect, whole);
}

fn detachNetns(arena: Allocator, path: []const u8) void {
    const p = arena.dupeSentinel(u8, path, 0) catch return;
    _ = std.os.linux.umount2(p, std.os.linux.MNT.DETACH);
}

pub const removeTree = Store.removeTree;

/// Removes the job directories no runner holds (their runner died), their network namespaces'
/// mounts, and their cgroups under `cg_parent`. A directory still being made (`.new-`) is left
/// alone.
fn sweep(arena: Allocator, io: std.Io, store: []const u8, cg_parent: ?[]const u8) void {
    const jobs = std.fmt.allocPrint(arena, "{s}/jobs", .{store}) catch return;
    var dir = std.Io.Dir.cwd().openDir(io, jobs, .{ .iterate = true }) catch return;
    defer dir.close(io);
    var it = dir.iterate();
    while (it.next(io) catch null) |e| {
        if (!evict.isDirEntry(arena, jobs, e) or std.mem.startsWith(u8, e.name, ".new-")) continue;
        const path = std.fmt.allocPrint(arena, "{s}/{s}", .{ jobs, e.name }) catch return;
        const lock_path = std.fmt.allocPrint(arena, "{s}/lock", .{path}) catch return;
        // Opened, never made: a directory without its lock is one its runner is removing, lock
        // last (`removeJobDir`), or a dead runner left empty after that; a lock made here would
        // be free, and the directory taken for stale while its runner still removes it.
        const held = std.Io.Dir.cwd().openFile(io, lock_path, .{}) catch |err| {
            if (err == error.FileNotFound) {
                // A crash can leave the mark behind (`removeJobDir` takes the two in listing order).
                const mark = std.fmt.allocPrintSentinel(arena, "{s}/{s}", .{ path, evict.job_mark }, 0) catch return;
                _ = std.os.linux.unlink(mark);
                const z = arena.dupeSentinel(u8, path, 0) catch return;
                _ = std.os.linux.rmdir(z);
            }
            continue;
        };
        defer held.close(io);
        if (std.os.linux.errno(std.os.linux.flock(held.handle, 2 | 4)) != .SUCCESS) continue;
        // Free because its runner let go of it just now, the directory removed: not stale.
        if (!sameFile(arena, held, lock_path)) continue;
        // Only a runner that died leaves one: worth seeing (and the stress test fails on it, as
        // a live job's directory taken for stale did before `removeJobDir`).
        std.log.warn("native: removing {s}, a job directory a runner left (it died)", .{path});
        detachNetns(arena, std.fmt.allocPrint(arena, "{s}/netns", .{path}) catch return);
        detachNetns(arena, std.fmt.allocPrint(arena, "{s}/userns", .{path}) catch return);
        if (cg_parent) |p| (cgroup.Job{
            .dir = std.fmt.allocPrint(arena, "{s}/{s}", .{ p, e.name }) catch return,
        }).remove(arena, io);
        removeJobDir(arena, io, path);
    }
}

/// A job's directory removed with its lock last, while the lock is held: until the directory is
/// empty its lock file is there, held, so `sweep` in another runner finds it taken and leaves it.
fn removeJobDir(arena: Allocator, io: std.Io, path: []const u8) void {
    const cwd = std.Io.Dir.cwd();
    var dir = cwd.openDir(io, path, .{ .iterate = true }) catch return removeTree(arena, io, path);
    var names: std.ArrayList([]const u8) = .empty;
    var it = dir.iterate();
    while (it.next(io) catch null) |e| {
        // The mark too: its job would look like an older runner's while this removes it.
        if (std.mem.eql(u8, e.name, "lock") or std.mem.eql(u8, e.name, evict.job_mark)) continue;
        names.append(arena, arena.dupe(u8, e.name) catch break) catch break;
    }
    dir.close(io);
    for (names.items) |name|
        removeTree(arena, io, std.fmt.allocPrint(arena, "{s}/{s}", .{ path, name }) catch return);
    // Anything left (a name the listing missed, a failure above) is removed whole.
    removeTree(arena, io, path);
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
    try b.readContainerOptions(ev, err_msg);
    try b.prepareRootfs(ev, plan, err_msg);
    var t = phases.now();
    // On the job's image (the seed's build and the roll run on `b.rootfs`).
    try b.setUpCaches(ev, plan);
    try b.containerVolumes(ev, err_msg);
    t = b.timings.since(arena, .caches, t);
    try b.baseEnv(ev, plan);
    // Not with services (P6): what a step got from a service (its image, its env, its data) is
    // in no key, so a replay could stand for a run against another service. Nor with a named
    // volume or a host path: what a step read from it or wrote to it is in no key and no layer,
    // so a replay would stand for a run against other contents and leave the volume as it was.
    if (plan.step_cache and ev.job.services.len == 0) {
        const has_host = hasHostVolume(arena, ev.job.*);
        if (b.named_volumes == 0 and !has_host) b.store = b.store_cfg else try b.notes.append(arena, "Step " ++
            "cache: off for this job, as it mounts named volumes or binds host paths, whose " ++
            "contents no key holds");
    }
    b.repository = ev.job.github.repository;
    b.scope = try set_up.packageCacheScope(arena, ev, b.repository, b.vouched);
    b.check_run_id = ev.job.check_run_id;
    b.ident = .{ b.scope, b.repository, ev.job.github.workflow, ev.job.job_id, ev.job.display_name };
    const event = try ev.eventJson();
    const event_in_env = plan.step_cache and event.len <= set_up.max_event_env;
    if (event_in_env) try b.put(dagger.event_env, event);
    if (plan.step_cache) try b.put(dagger.ran_env, plan.ran_marker);

    // The job's remote actions, fetched by git in its image now that the image is pulled and
    // provisioned, below the base's layer, each keyed by its commit (`actions.preload`,
    // `keyFetched`). One that native steps cannot run sends the job to Dagger
    // (`error.NativeToDagger`), before "Set up job" has said anything. From `/`, as the
    // workspace is not there yet.
    {
        const workdir = b.workdir;
        b.workdir = "/";
        defer b.workdir = workdir;
        if (try native_actions.preload(b, ev.job.*, b.js_runtime)) |why| {
            b.to_dagger = why;
            return error.NativeToDagger;
        }
    }
    t = b.timings.since(arena, .actions, t);
    defer _ = b.timings.since(arena, .base, t);

    // The workspace and RUNNER_TEMP, made as Dagger's base makes them: by root, owned by the step
    // user when it is not root (see `unprivileged` below). From `/`, as the workspace is not there
    // yet. The event payload goes in as `withNewFile` does.
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
    // A user other than root cannot make `/__w` in an image that does not have it writable (GitHub
    // mounts it from the host, so there it exists): made by root and handed to it, as provisioned
    // images do. Root's own mkdir stays tolerant of an image that cannot be written.
    const unprivileged = !plan.provision and (b.uid != 0 or b.gid != 0);
    const mk_work = if (plan.provision or unprivileged)
        try std.fmt.allocPrint(arena, "mkdir -p {s} {s}{s}{s}{s}", .{
            ev.workspace,
            ev.temp,
            tool_dir,
            link,
            if (unprivileged) try ownedBy(arena, b.uid, b.gid, tool_dir, ev.job.container != null) else chown,
        })
    else
        try std.fmt.allocPrint(arena, "mkdir -p {s} {s}{s} 2>/dev/null{s} || true", .{
            ev.workspace,
            ev.temp,
            tool_dir,
            link,
        });
    // The job container's `volumes:`, made after the work root so that handing that to the step
    // user does not reach them: Docker's volumes are root's, as an image's directory is.
    const mk = if (b.volume_dirs) |vols|
        try std.fmt.allocPrint(arena, "{{ {s}; }} && {s}", .{ mk_work, vols })
    else
        mk_work;
    try b.publishPorts(ev, err_msg);
    const mk_uid: u32 = 0;
    const mk_gid: u32 = 0;
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
    const claim = b.claimKey(key, "base") catch |e| {
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
        // A host path the step's helper refused (a link swapped in, a mount without nosuid, a
        // filesystem it cannot idmap, a target inside another mount) is the job's to fail: on
        // Dagger, which ignores a job container's `volumes:`, it would run without it.
        if (hasHostVolume(arena, ev.job.*)) b.job_fault = true;
        return error.BaseContainerFailed;
    }
}

/// The shell that gives the job's work root, and the tool cache when it is made in the base
/// (`tool_dir`, a path with a leading space or empty), to `uid:gid`. The tool cache is only
/// chowned when it is not theirs already: an image's own `/opt/hostedtoolcache` may be large, and
/// a recursive chown copies every file of it up into the layer.
fn ownedBy(arena: Allocator, uid: u32, gid: u32, tool_dir: []const u8, container: bool) ![]const u8 {
    // A `container:` job's work root is /__w.
    const work = if (container) dagger.container_work_root else dagger.work_root;
    const tool = if (tool_dir.len == 0) "" else try std.fmt.allocPrint(
        arena,
        " && {{ [ \"$(stat -c %u:%g{s})\" = {d}:{d} ] || chown -R {d}:{d}{s}; }}",
        .{ tool_dir, uid, gid, uid, gid, tool_dir },
    );
    return std.fmt.allocPrint(arena, " && chown -R {d}:{d} {s}{s}", .{ uid, gid, work, tool });
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
    // A `container:` job's `options: --env` first, then its own `env:` over them: GitHub's
    // `DockerCommandManager.DockerCreate` puts the `options:` string on the command line before
    // the `-e` of the `env:`, and the later `-e` of a name wins. Its PATH is the container's
    // (`Exec.container_path`).
    for (b.container_opts.env) |e| try b.put(e.name, e.value);
    for (plan.container_env) |e| try b.put(e.name, e.value);
    if (ev.job.container != null) b.runtime_path = b.envValue("PATH");
    b.uid = b.image_uid;
    b.gid = b.image_gid;
    b.user = b.container_opts.user orelse if (b.image) |img| img.user else "";
    if (plan.as_runner) {
        b.uid = runner_uid;
        b.gid = runner_uid;
        b.user = dagger.runner_user;
        try b.put("HOME", dagger.runner_home);
    }
    b.groups = try b.stepGroups();
    try b.put(dagger.mark_env, plan.mark);
    for (b.cache_plan.env.items) |e| try b.put(e.name, e.value);
    for (try ev.defaultEnv()) |e| try b.put(e.name, e.value);
    for (try ev.withoutReapplied(ev.job_env.items)) |e| try b.put(e.name, e.value);
    // Last, and set even when no tree was found, so a workflow's own value never stands in for
    // the runner's. Part of every step's key, as on Dagger: see `checkToolTrees`.
    if (b.tool_trees) |v| try b.put(set_up.tool_trees_env, v);
    if (b.tool_trees_full) |v| try b.put(trees_check.full_env, v);
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
    mounts: []const dagger.Mount,
) !Exec.Out {
    const arena = b.arena;
    const mark = b.timings.mark();
    defer b.stepPhases(x, num, mark);
    try b.applyPendingEnv(x);
    // The step's mounts (a JavaScript action's runtime and shims, `js.zig`): bound for every
    // step after, their mount points made once.
    var mount_files: std.ArrayList(sandbox.Spec.File) = .empty;
    try b.applyMounts(mounts, &mount_files);
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
        try files.appendSlice(arena, mount_files.items);
        if (step_run.script_secret != null) try files.append(arena, .{
            .path = try scripts.scriptPath(arena, fc, resolved.run.shell),
            .contents = resolved.run.script,
        });

        const step_env = switch (resolved) {
            .run => |r| r.env,
            .checkout => &.{},
        };
        const env_context = try dagger.envContext(arena, x.ev.job_env.items, step_env);
        x.sh.beginCommands(num, env_context);
        // GitHub's runner reads the oom_score_adj override from the step's environment. Here the
        // script exports the step's env, after the helper has set it, so the helper is told.
        for (env_context) |e| if (std.mem.eql(u8, e.name, sandbox.oom_score_adj_env))
            try extra.append(arena, e);
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
        const label = try std.fmt.allocPrint(arena, "step {d}", .{num});
        const claim = b.claimKey(key, label) catch |e| switch (e) {
            error.Stopped => {
                x.err_msg = "the step was stopped";
                return error.EngineFailed;
            },
            else => return e,
        };
        defer claim.release(b.io);
        if (claim.why) |line| x.sh.append(num, line);
        if (b.settleWarning()) |line| x.sh.append(num, line);
        if (claim.hit) |rec| {
            const data = try recordAnswer(arena, rec);
            // A record that points into the tool cache's volume, which is in no layer: the volume
            // may have lost the tree since, and no checked tree holds it, so the step runs again.
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
        // step's layers hold the secret. A mount's file (a runtime's shim) stays for the steps after.
        for (files.items) |f| if (!f.keep) sandbox.unlinkIn(arena, layer, f.path);
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

/// With step debug: where step `num`'s time went (`phases.zig`), from its key's claim to its
/// layer published.
fn stepPhases(b: *Backend, x: *Exec, num: u32, mark: phases.Phases.Mark) void {
    if (!x.sh.step_debug) return;
    const text = b.timings.text(b.arena, mark, .steps) catch return;
    if (text.len == 0) return;
    x.sh.append(num, std.fmt.allocPrint(b.arena, "##[debug]Native phases (ms): {s}", .{text}) catch
        return);
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
        b.ooms = u.ooms;
        b.parent_ooms = u.parent_ooms;
        b.pids_max_hits = u.pids_max_hits;
    }
    if (u.oom_kills > b.oom_kills) {
        const before: cgroup.Usage = .{
            .working_set_mb = null,
            .peak_mb = null,
            .oom_kills = b.oom_kills,
            .ooms = b.ooms,
            .parent_ooms = b.parent_ooms,
            .pids_max_hits = 0,
        };
        x.sh.errorLine(num, try oomLine(
            b.arena,
            cgroup.Killer.of(before, u),
            b.limits,
            u.oom_kills - b.oom_kills,
        ));
    }
    if (u.pids_max_hits > b.pids_max_hits) x.sh.errorLine(num, try std.fmt.allocPrint(
        b.arena,
        "The job reached its process limit ({f}, RUNNER_NATIVE_PIDS_MAX): this step was " ++
            "refused {d} new process(es) or thread(s).",
        .{ Limit.count(b.limits.pids_max), u.pids_max_hits - b.pids_max_hits },
    ));
}

/// The error line for `killed` processes OOM-killed in a step, by the limit they were killed for.
fn oomLine(
    arena: Allocator,
    killer: cgroup.Killer,
    limits: cgroup.Limits,
    killed: u64,
) ![]const u8 {
    return switch (killer) {
        .job => std.fmt.allocPrint(arena, "The job reached its memory limit ({f}, " ++
            "RUNNER_NATIVE_MEMORY_MAX_MB): the kernel killed {d} process(es) of this step to " ++
            "stay within it.", .{ Limit.memory(limits.memory_max), killed }),
        .all => std.fmt.allocPrint(arena, "All native jobs together reached their memory limit " ++
            "({f}, RUNNER_NATIVE_MEMORY_TOTAL_MB): the kernel killed {d} process(es) of this " ++
            "step to stay within it.", .{ Limit.memory(limits.memory_total), killed }),
        .above => std.fmt.allocPrint(arena, "The machine ran out of memory, or a limit above " ++
            "the native jobs' reached its own: the kernel killed {d} process(es) of this step. " ++
            "This job was within its limits.", .{killed}),
    };
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
    if (b.cache_plan.zig_builtin) |v| {
        if (b.seed_layers.items.len > 0) b.seedBuiltin(v, plan.as_runner);
        b.binds = try std.mem.concat(arena, sandbox.Spec.Bind, &.{ b.binds, &.{v} });
    }
    if (b.cache_plan.zig_local_roll != null) b.rollZigLocal(plan.as_runner);
    if (b.caches.tool_trees) try b.checkToolTrees();
}

/// "Set up job"'s check of the tool cache's trees, as `set_up.verifyToolTrees` does it on Dagger
/// (`tool_trees.zig`): what steps are given is each tree's digest and path (`tool_trees`), and a
/// replayed step that names a directory in the volume replays only when a tree holds it
/// (`Exec.toolDirNotHeld`). The values (the digest `install-zig.sh` pins, and a second over every
/// entry of the tree, `trees_check.full_env`) are in every step's key (the variables are not
/// volatile), so a tree added, removed or changed makes every step of the job new once, and no
/// record made against another state of a tree is replayed. Narrower keys (only the trees a step
/// puts on PATH) are not possible here: a step's key is made before it runs, and which trees it
/// names is in its record.
fn checkToolTrees(b: *Backend) !void {
    const arena = b.arena;
    const volume = b.cache_plan.tool_cache_host orelse return;
    const mount = b.cache_plan.tool_cache.?;
    // What the last job out found when it left the volume, read as this job opened it
    // (`volumes.plan`, `tool_trees.takeVerdict`): no walk then.
    // Only while no step has started in the volume since the walk, which the epoch it was told
    // by says (`volumes.Plan.verdictStands`): else this job walks, as one that opened later does.
    if (b.cache_plan.tool_verdict) |v| if (b.cache_plan.verdictStands(b.io)) {
        b.tool_trees = v.env;
        b.tool_trees_full = v.full;
        try b.notes.append(arena, v.note);
        return;
    };
    // In the runner's store beside the volumes, where no step can write: a list a job could
    // forge would pass a changed file (`tool_trees.zig`).
    const lists = try trees_check.listsDir(arena, b.store_cfg.root, volume);
    const verdict = try trees_check.checkOnce(
        &trees_check.process_flights,
        arena,
        b.gpa,
        b.io,
        volume,
        lists,
        mount,
        b.caches.cancel,
    );
    b.tool_trees = verdict.env;
    b.tool_trees_full = verdict.full;
    try b.notes.append(arena, verdict.note);
}

/// `binds` without the tool cache's volume, for a script of the runner's own that is run in set-up
/// and does not use it: a process started with it mounted could write to its trees
/// (`volumes.endEpochs`), and what is not mounted cannot.
fn withoutToolCache(b: *Backend, binds: []const sandbox.Spec.Bind) []const sandbox.Spec.Bind {
    const volume = b.cache_plan.tool_cache_host orelse return binds;
    return volumes.without(b.arena, binds, volume) catch binds;
}

/// A job that lets the tool cache's volume go with processes that may be alive in it says so,
/// before it lets go, so that no job makes a verdict of the volume (`tool_trees.markUnproven`).
fn noteProcessesMayRemain(b: *Backend) void {
    const volume = b.cache_plan.tool_cache_host orelse return;
    const lists = trees_check.listsDir(b.arena, b.store_cfg.root, volume) catch return;
    if (!trees_check.markUnproven(b.arena, b.io, lists))
        std.log.warn("native: cannot note that {s} may have processes left", .{volume});
}

/// The last job out of the tool cache's volume walks its trees for the next job
/// (`tool_trees.walkIdle`), the walk that job would make first thing. Only when this job's
/// processes are gone (`deinit`: a job without a cgroup, `RUNNER_NATIVE_CGROUP=none`, never
/// gets here), the exclusive lock on the volume is free (no job anywhere holds it, so none can
/// run a step in it, and any other job's processes were gone when it let go), and the job checks
/// the trees at all. A walk that was not whole, or saw a racy file, leaves no verdict, and the next
/// job walks as it always did.
///
/// The walk runs on a thread of its own, holding the locks this takes (`tool_trees.IdleWalks`), so
/// the teardown, and the runner's next poll, do not wait for it. If the thread cannot be had the
/// walk is made here, as it was.
fn walkToolCacheIdle(b: *Backend) void {
    if (!b.caches.tool_trees) return;
    const mount = b.cache_plan.tool_cache orelse return;
    const arena = b.arena;
    const idle = b.cache_plan.idleToolCache(arena) orelse return;
    const lists = trees_check.listsDir(arena, b.store_cfg.root, idle.dir) catch return;
    if (b.cache_plan.idleHandoff()) |held| {
        const started = trees_check.process_idle_walks.start(b.io, .{
            .dir = idle.dir,
            .lists = lists,
            .mount = mount,
            .left = idle.left,
            .lock = held.lock,
            .other = held.other,
        });
        if (started) return;
        _ = std.os.linux.close(held.lock);
        if (held.other) |fd| _ = std.os.linux.close(fd);
    }
    _ = trees_check.walkIdle(arena, b.gpa, b.io, idle.dir, lists, mount, idle.left, trees_check.idle_limits, null);
}

/// `set_up.zig_builtin_seed_script` on the `builtin.zig` volume, bound beside the seed's own `b/`
/// (which its mount over the global cache's hides), in a sandbox whose layer is dropped, as the
/// Dagger backend runs it in a container of its own. Nothing of it fails the job: a volume that
/// was not filled costs one build of Zig's build runner.
fn seedBuiltin(b: *Backend, volume: sandbox.Spec.Bind, as_runner: bool) void {
    const arena = b.arena;
    const saved = b.binds;
    defer b.binds = saved;
    const at = "/zig-runner-builtin";
    var beside = volume;
    beside.at = at;
    b.binds = std.mem.concat(arena, sandbox.Spec.Bind, &.{ b.withoutToolCache(saved), &.{beside} }) catch return;
    const dir = set_up.zigBuiltinDir(arena, as_runner) catch return;
    const script = std.fmt.allocPrint(arena, "set -- {s} {s} ''\n{s}", .{
        at,
        dir,
        set_up.zig_builtin_seed_script,
    }) catch return;
    var out: Captured = .{ .arena = arena };
    const user: u32 = if (as_runner) runner_uid else 0;
    const ended = b.exec(script, &.{"PATH=" ++ image_path}, &.{}, user, user, out.output()) catch |e| {
        std.log.warn("native: Zig builtin volume not filled: {s}", .{@errorName(e)});
        return;
    };
    b.dropLastLayer();
    if (ended.failure.len > 0 or ended.code != 0)
        std.log.warn("native: Zig builtin volume not filled: {s}{s}", .{ ended.failure, out.tail() });
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
    const saved = b.binds;
    defer b.binds = saved;
    b.binds = b.withoutToolCache(saved);
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
        try b.seed_ids.append(arena, try volumes.seedId(arena, s.dir));
        try seeded.append(arena, s.seed.version);
    }
    if (try volumes.seedNote(arena, b.caches, seeded.items, failure)) |note|
        try b.notes.append(arena, note);
}

/// What `warm` makes: what a job with no `container:` starts from, and the seeds a Zig job gets.
pub const Warm = struct {
    /// The job's image (`dagger.resolveImage`).
    image: []const u8,
    /// Provisioned, as the default image is (`set_up.provision_script`).
    provision: bool,
    /// The step user is the runner user, not root (`Options.step_user`).
    as_runner: bool,
    seeds: []const config.ZigSeed = &.{},
};

/// What `warm` found and what it made, in milliseconds each.
pub const Warmed = struct {
    image_ms: u64 = 0,
    provision_ms: u64 = 0,
    seed_ms: u64 = 0,
    /// The image was fetched from its registry now, not found in the store.
    pulled: bool = false,
    seeds_built: u32 = 0,
    seeds_found: u32 = 0,
    /// Why the last seed that was not made was not, for the log; the job would build it itself.
    seed_failure: ?[]const u8 = null,
};

/// The pull, the provisioning and the Zig cache seeds that every job with no `container:` makes
/// before its first step, made with no job, so the first job finds them (`Warmer` in loop.zig).
/// Each is made as `base` makes it, by the same code, under the same locks: a job that comes
/// while this runs waits for the piece being made instead of making it too, and one that comes
/// after finds all of it. A seed that cannot be made is left to the job, as it is there
/// (`Warmed.seed_failure`); the image failing is an error.
pub fn warm(b: *Backend, w: Warm, err_msg: *[]const u8) !Warmed {
    const arena = b.arena;
    var out: Warmed = .{};
    if (b.operator_rootfs.len > 0 and w.provision) {
        b.rootfs = b.operator_rootfs;
    } else {
        const img = try b.fetchRootfs(w.image, null, w.provision, w.as_runner, err_msg);
        out.pulled = img.pulled != null;
    }
    out.image_ms = b.timings.lastMs(.image);
    out.provision_ms = b.timings.lastMs(.provision);
    const started = std.Io.Clock.awake.now(b.io).toMilliseconds();
    for (w.seeds) |sd| {
        const s = try volumes.seedFor(arena, b.store_cfg.root, sd, w.as_runner);
        const there = if (std.Io.Dir.cwd().access(b.io, s.dir, .{})) |_| true else |_| false;
        if (b.seed(s, w.as_runner)) |why| {
            out.seed_failure = why;
        } else if (there) {
            out.seeds_found += 1;
        } else {
            out.seeds_built += 1;
        }
    }
    out.seed_ms = std.math.cast(u64, std.Io.Clock.awake.now(b.io).toMilliseconds() - started) orelse 0;
    return out;
}

/// Builds `seed` unless it is there; null when it is, else why not.
fn seed(b: *Backend, s: volumes.Seed, as_runner: bool) ?[]const u8 {
    const arena = b.arena;
    const cwd = std.Io.Dir.cwd();
    const seeds_dir = std.fs.path.dirname(s.dir).?;
    cwd.createDirPath(b.io, seeds_dir) catch |e| return @errorName(e);
    // Only the runner's user may look in, as in the volumes'.
    const seeds_z = arena.dupeSentinel(u8, seeds_dir, 0) catch return "out of memory";
    _ = std.os.linux.chmod(seeds_z, 0o700);
    // Built under the seed's lock, then held as any job holds it, past the lock let go
    // (`ImageStore.ensure`): an eviction can come between, and a seed evicted at once is built
    // again. A few times at most, so an eviction that takes each one cannot keep the job here.
    for (0..seed_builds_max) |_| {
        if (b.holdSeed(s.dir)) |held| {
            if (held) return null;
        } else |e| return @errorName(e);
        const lock = ImageStore.lockDir(arena, b.io, s.dir, 2) catch |e| return @errorName(e);
        defer lock.close(b.io);
        if (cwd.access(b.io, s.dir, .{})) |_| {} else |_| if (b.buildSeed(s, as_runner)) |why| return why;
    }
    const held = b.holdSeed(s.dir) catch |e| return @errorName(e);
    return if (held) null else "it was evicted as it was built, each time";
}

/// How many times `seed` builds a seed that an eviction takes as soon as it is built.
const seed_builds_max = 3;

/// Whether the seed `dir` is there, then held for the job (`ImageStore.holdDir`).
fn holdSeed(b: *Backend, dir: []const u8) !bool {
    const lock = try ImageStore.holdDir(b.arena, b.io, dir) orelse return false;
    errdefer lock.close(b.io);
    try b.held.append(b.arena, lock);
    return true;
}

/// `seed`'s build, under the seed's lock, moved into place (`volumes.adoptSeed`); null when it
/// worked, else why not.
fn buildSeed(b: *Backend, s: volumes.Seed, as_runner: bool) ?[]const u8 {
    const arena = b.arena;
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

/// Dagger's mounts for a step, as the native backend has them (`Exec.execScript`). A new file
/// (a shim) is written into the step's layer, as `withNewFile` leaves it. A file or directory
/// whose id is a host path (`host_id`: the JavaScript runtime from the image store, `js.zig`) is
/// bound read-only from then on, into this step and every later one, as Dagger's copy stays in
/// the container; its mount point is made first, by a step of its own. Other ids are trees the
/// native backend has in the job's layers already (a fetched action, a checkout): nothing to do.
fn applyMounts(b: *Backend, mounts: []const dagger.Mount, files: *std.ArrayList(sandbox.Spec.File)) !void {
    const arena = b.arena;
    var binds: std.ArrayList(sandbox.Spec.Bind) = .empty;
    var points: std.ArrayList(sandbox.Spec.File) = .empty;
    var dirs: std.Io.Writer.Allocating = .init(arena);
    for (mounts) |m| switch (m) {
        .new_file => |f| try files.append(arena, .{
            .path = f.path,
            .contents = f.contents,
            .mode = f.permissions,
            .keep = true,
        }),
        .file => |f| if (std.mem.startsWith(u8, f.id, host_id)) {
            try points.append(arena, .{ .path = f.path, .contents = "", .mode = 0o755, .keep = true });
            try binds.append(arena, .{ .host = f.id[host_id.len..], .at = f.path, .nosuid = true });
        },
        .dir => |d| if (std.mem.startsWith(u8, d.id, host_id)) {
            try dirs.writer.writeAll(" ");
            try dagger.shellQuote(&dirs.writer, d.path);
            try binds.append(arena, .{ .host = d.id[host_id.len..], .at = d.path, .nosuid = true });
        },
    };
    if (binds.items.len == 0) return;
    var out: Captured = .{ .arena = arena };
    const script = try std.fmt.allocPrint(arena, "mkdir -p /{s}", .{dirs.written()});
    const ended = try b.exec(script, &.{"PATH=" ++ image_path}, points.items, 0, 0, out.output());
    if (ended.failure.len > 0 or ended.code != 0) return error.MountPointsFailed;
    b.binds = try std.mem.concat(arena, sandbox.Spec.Bind, &.{ b.binds, binds.items });
}

/// A mount's id that names a host path (`applyMounts`): `host:<absolute path>`.
pub const host_id = "host:";

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
    try w.writeAll("\ngit checkout -q --detach FETCH_HEAD\nrm -f .git/FETCH_HEAD\n");
    // Submodules as actions/checkout fetches them: `true` the first level, `recursive` all, each
    // to the commit the tree records and as shallow as the checkout (`fetch-depth`), with
    // `git@<host>:` rewritten to HTTPS, where the token's header applies. The script is the
    // step's key (below), so it holds the flags: a checkout with and without them never
    // replays one another, and the recorded commits are in the tree of the key's commit.
    if (co.submodules) {
        const recursive: []const u8 = if (co.submodules_recursive) " --recursive" else "";
        const server = std.mem.trimEnd(u8, x.job.github.server_url, "/");
        try w.print("git submodule sync -q{s}\ngit ", .{recursive});
        if (std.mem.startsWith(u8, server, "https://")) {
            try w.writeAll("-c ");
            try dagger.shellQuote(w, try std.fmt.allocPrint(
                arena,
                "url.{s}/.insteadOf=git@{s}:",
                .{ server, server["https://".len..] },
            ));
            try w.writeAll(" ");
        }
        try w.writeAll("-c protocol.version=2 submodule update -q --init --force");
        if (f.depth > 0) try w.print(" --depth={d}", .{f.depth});
        try w.print("{s}\n", .{recursive});
    }
    try w.print("find . -exec touch -h -d @{d} {{}} +\n", .{checkout.mtime});

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
    // The runner's global config, with `safe.directory` (`actions.git_config_file`): a file://
    // source is the host's, nobody's to the job's root on a root runner.
    try extra.append(arena, .{ .name = "GIT_CONFIG_GLOBAL", .value = native_actions.git_config_path });
    // A commit fetched is the same tree every time, as Dagger's `git` keys it, so under step
    // caching it is a layer like a step's, keyed on its script (the URL and the commit), never
    // on the token in `extra`. A branch or tag moves, so its fetch always runs. The tags it reads
    // move too, with the commit staying: their digest is part of the key (`tagsDigest`).
    const env = try b.envStrings(extra.items);
    const submodule_tags = tagsInSubmodules(f.tags, co);
    const tags: ?[]const u8 = if (f.tags and checkout.isSha(f.want) and !submodule_tags)
        try b.tagsDigest(f.url, env)
    else
        "";
    const key = if (tags == null or !checkout.isSha(f.want) or submodule_tags)
        null
    else
        try b.keyFor(.step, try std.fmt.allocPrint(arena, "{s}\n# tags {s}", .{ aw.written(), tags.? }), &.{}, b.uid, b.gid);
    const claim = b.claimKey(key, "fetch") catch |e| switch (e) {
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
        env,
        &.{native_actions.git_config_file},
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

/// Whether the tags a checkout fetches include a submodule's (`fetch-depth: 0` or `fetch-tags`
/// with `submodules:`): they move with the commit staying, and `tagsDigest` lists only the top
/// repository's, which a submodule's URL (in `.gitmodules`, known only once fetched) is not part
/// of. Such a fetch is not replayed, as one of a branch is not. (A submodule's clone fetches its
/// tags whatever `fetch-tags` says, so those of a submodule checkout without tags go stale in a
/// replay: accepted, as gating every submodule checkout would cost its replay.)
fn tagsInSubmodules(tags: bool, co: job_mod.Checkout) bool {
    return tags and co.submodules;
}

test "a fetch with tags and submodules is never replayed, the tags of the submodules move" {
    var co: job_mod.Checkout = .{ .submodules = true };
    try std.testing.expect(tagsInSubmodules(true, co));
    try std.testing.expect(!tagsInSubmodules(false, co));
    co.submodules = false;
    try std.testing.expect(!tagsInSubmodules(true, co));
}

/// A digest of the tags `url`'s repository has and where they point, as `git fetch --tags` reads
/// them: a checkout of a commit is the same tree every time, but its tags are not, so a replay
/// keyed without them would keep the old ones. Null when they could not be listed: the fetch then
/// runs, and says why it cannot.
fn tagsDigest(b: *Backend, url: []const u8, env: []const []const u8) !?[]const u8 {
    var aw: std.Io.Writer.Allocating = .init(b.arena);
    try aw.writer.writeAll("tags=$(git ls-remote --tags -- ");
    try dagger.shellQuote(&aw.writer, try std.fmt.allocPrint(b.arena, "{s}.git", .{url}));
    try aw.writer.writeAll(") && printf '%s' \"$tags\" | sha256sum");
    var out: Captured = .{ .arena = b.arena };
    const ended = try b.exec(aw.written(), env, &.{native_actions.git_config_file}, b.uid, b.gid, out.output());
    defer b.dropLastLayer();
    if (ended.code != 0 or ended.failure.len > 0 or ended.killed) return null;
    const digest = std.mem.trim(u8, out.text.items, " \n");
    return if (digest.len == 0) null else digest;
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

pub const max_read = 16 * 1024 * 1024;

/// `hashFiles(args)` over the job's files as the next step would see them (`native/hash_files.zig`):
/// the layers as they are now, so what earlier steps wrote is there, read by the runner with no
/// mount, for the steps' user (`hashStep`). `ws` is the workspace.
pub fn hashFiles(
    b: *Backend,
    arena: Allocator,
    ws: []const u8,
    args: []const []const u8,
) Allocator.Error!expr.HashFiles.Result {
    // Topmost first, as `execIn`'s overlay stacks them.
    const n = b.layers.items.len;
    const layers = try b.gpa.alloc([]const u8, n + b.seed_layers.items.len + 1);
    defer b.gpa.free(layers);
    for (b.layers.items, 0..) |l, i| layers[n - 1 - i] = l.path;
    @memcpy(layers[n..][0..b.seed_layers.items.len], b.seed_layers.items);
    layers[layers.len - 1] = b.rootfs;
    var limits = b.hash_settings.limits(b.io);
    limits.cancel = b.cancel;
    const layer_ids = try b.gpa.alloc(Store.Ids, layers.len);
    defer b.gpa.free(layer_ids);
    const stack: hash_files.Stack = .{
        .layers = layers,
        .opaque_xattr = b.opaqueXattr(),
        .step = b.hashStep(layer_ids),
        .limits = limits,
    };
    // The call's own memory is freed when it returns; the job's arena gets the result only.
    return hash_files.hashFiles(b.gpa, arena, b.io, stack, ws, dagger.runner_home, args);
}

/// The supplementary groups of the steps' user, read once from the image, so hashFiles and the
/// steps' own processes have the one list. The engine read them at each exec; here a step that
/// edits /etc/group changes nothing for the steps after it. Only a job's own ids can be set, so a
/// gid past them is left out; a rootless runner's steps are root, and need none.
fn stepGroups(b: *const Backend) ![]const u32 {
    if (b.uid == 0 or b.how.userns != .mapped) return &.{};
    const arena = b.arena;
    const max_bytes = 10 << 20;
    const passwd = switch (try sandbox.readFollowingIn(arena, b.rootfs, "/etc/passwd", max_bytes)) {
        .text => |t| t,
        else => return &.{},
    };
    const group = switch (try sandbox.readFollowingIn(arena, b.rootfs, "/etc/group", max_bytes)) {
        .text => |t| t,
        else => return &.{},
    };
    return mappedGroups(arena, try images.supplementaryGroups(arena, passwd, group, b.user));
}

/// `groups` the job's ids reach, in order: `setgroups` fails a step for any other.
pub fn mappedGroups(arena: Allocator, groups: []const u32) ![]const u32 {
    const mapped = try arena.dupe(u32, groups);
    var n: usize = 0;
    for (groups) |g| if (g < ids_per_slot) {
        mapped[n] = g;
        n += 1;
    };
    return mapped[0..n];
}

test "a step's groups are those the job's ids reach, in order" {
    var a: std.heap.ArenaAllocator = .init(std.testing.allocator);
    defer a.deinit();
    const kept = try mappedGroups(a.allocator(), &.{ 4, 50, ids_per_slot - 1, ids_per_slot, 70000 });
    try std.testing.expectEqualSlices(u32, &.{ 4, 50, ids_per_slot - 1 }, kept);
}

/// The steps' user for `hashFiles`, with `layer_ids` filled for its layers, topmost first; null
/// when they run as root, which is every step of a rootless runner. A job's own upper has its
/// slot's host ids and is seen as it is; what is seen through the job's ids (`canonical`: stored
/// layers, a flattened one, then the seeds and the rootfs, the image's own) has the job's ids
/// (`sandbox.idmapLowers`). Rootless, no layer has any ids but the runner's own user's.
fn hashStep(b: *const Backend, layer_ids: []Store.Ids) ?hash_files.Step {
    if (b.uid == 0) return null;
    @memset(layer_ids, b.ids());
    if (b.how.userns == .mapped) {
        const n = b.layers.items.len;
        for (b.layers.items, 0..) |l, i| {
            if (!l.canonical) layer_ids[n - 1 - i] = b.slotIds();
        }
    }
    return .{ .uid = b.uid, .gid = b.gid, .groups = b.groups, .ids = layer_ids };
}

/// Overlay's attribute that marks a directory opaque: `trusted.` when the job's overlay is mounted
/// as the host's root, `user.` under `userxattr` (a rootless runner's).
fn opaqueXattr(b: *const Backend) [:0]const u8 {
    return if (b.how.userns == .mapped) "trusted.overlay.opaque" else "user.overlay.opaque";
}

/// Layer `i`'s path (P7's callers; P2's `Layer.path`).
pub fn layerPath(b: *Backend, i: usize) ![]const u8 {
    return b.layers.items[i].path;
}

/// `dagger.Transport` for the shared code: the native backend has no Dagger session, so a query
/// is a bug in what decided the job could run here (`unsupported`).
pub fn transport(b: *Backend) dagger.Transport {
    return .{ .ptr = b, .sendFn = send, .abortFn = abort, .warnFn = warn };
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

/// A stage of `dagger.Watch`'s ladder: `sig` to the running step. An exec only waiting for its
/// key's lock has nothing to warn, and stops as `abort` stops it.
fn warn(ptr: *anyopaque, sig: std.os.linux.SIG) dagger.Transport.Warned {
    const b: *Backend = @ptrCast(@alignCast(ptr));
    if (b.running.warn(b.io, sig)) return .warned;
    return if (abort(ptr)) .ended else .nothing;
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
    return b.execOn(&.{ "sh", "-c", script }, env, files, uid, gid, out, null);
}

/// `exec` of `argv`, in a Docker action's `container` when it has one (`docker_action.zig`):
/// the new layer is then where what it writes into the job's shared directories lands.
pub fn execOn(
    b: *Backend,
    argv: []const []const u8,
    env: []const []const u8,
    files: []const sandbox.Spec.File,
    uid: u32,
    gid: u32,
    out: sandbox.Output,
    container: ?sandbox.Spec.Container,
) !sandbox.Ended {
    return b.execIn(argv, env, files, uid, gid, out, container, true);
}

/// A Dockerfile's `RUN` in its `container` (`docker_action.zig`): what it writes goes to the
/// container's upper, the build's layer, and the job gets no layer (its overlay's upper is a
/// scratch one, which nothing writes, since the build shares nothing).
pub fn execBuild(
    b: *Backend,
    argv: []const []const u8,
    env: []const []const u8,
    uid: u32,
    gid: u32,
    out: sandbox.Output,
    container: sandbox.Spec.Container,
) !sandbox.Ended {
    return b.execIn(argv, env, &.{}, uid, gid, out, container, false);
}

fn execIn(
    b: *Backend,
    argv: []const []const u8,
    env: []const []const u8,
    files: []const sandbox.Spec.File,
    uid: u32,
    gid: u32,
    out: sandbox.Output,
    container: ?sandbox.Spec.Container,
    new_layer: bool,
) !sandbox.Ended {
    const arena = b.arena;
    if (b.layers.items.len >= b.flatten_at) b.flattenTimed() catch |e| return if (e == error.LayerNotShifted) e else .{
        .code = 1,
        .failure = try std.fmt.allocPrint(arena, "could not flatten the job's {d} layers " ++
            "into one: {s}", .{ b.layers.items.len, @errorName(e) }),
    };
    // A container with an owner has its own idmaps of the job's directory (`sandbox.jobView`).
    const owned = if (container) |c| c.owner != null else false;
    const idmapped = new_layer and !owned and b.upperIdmapped() and b.idmappedUpper();
    return b.runIn(argv, env, files, uid, gid, out, container, new_layer, idmapped);
}

/// `execIn` after its layers are in order: the step run, its upper written through an idmapped
/// mount when `idmapped` (`Spec.upper_canonical`), whose layer then has the canonical ids already.
fn runIn(
    b: *Backend,
    argv: []const []const u8,
    env: []const []const u8,
    files: []const sandbox.Spec.File,
    uid: u32,
    gid: u32,
    out: sandbox.Output,
    container: ?sandbox.Spec.Container,
    new_layer: bool,
    idmapped: bool,
) !sandbox.Ended {
    const arena = b.arena;
    const upper = if (new_layer) try b.layerName('L') else "BU";
    const upper_path = try std.fmt.allocPrint(arena, "{s}/{s}", .{ b.dir, upper });
    try std.Io.Dir.cwd().createDirPath(b.io, upper_path);
    const base_id = b.idBase();
    const netns = b.networkPath() catch return .{
        .code = 1,
        .failure = b.net_why orelse "the job's network could not be made",
    };
    // The upper's root is the overlay's `/`: the job's root's, as the image's `/` is, so a step
    // as root can make files there. Rootless, the runner's own user is the job's root already.
    if (b.how.userns == .mapped) {
        const p = try arena.dupeSentinel(u8, upper_path, 0);
        // Written through the job's ids, the root's own is 0 on disk, as a layer's is.
        const root_id: u32 = if (idmapped) 0 else base_id;
        _ = std.os.linux.chown(p, root_id, root_id);
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
    // Before the process exists: from then on a step may write to a tree, and no job is told of
    // the trees by a verdict again (`tool_trees.Epochs`). Every start with a volume mounted, a
    // step, an action's pre or post script, a Docker build or a set-up script alike.
    volumes.endEpochs(b.io, b.binds);
    const ended = try sandbox.run(arena, b.io, b.how.argv_prefix, .{
        .root = b.dir,
        .lowers = lowers,
        .upper = upper,
        .work = "W",
        .merged = "M",
        .workdir = b.workdir,
        .uid = uid,
        .gid = gid,
        .groups = if (container != null and container.?.owner != null)
            container.?.owner.?.groups
        else if (uid == b.uid and gid == b.gid) b.groups else &.{},
        .argv = argv,
        .env = env,
        .files = files,
        .binds = b.binds,
        .userns = b.how.userns,
        .id_base = base_id,
        .id_count = ids_per_slot,
        .netns = netns,
        .mount_points = mount_points,
        .cgroup = if (b.job_cgroup) |j| j.stepsDir() else null,
        .image_layers = @intCast(b.seed_layers.items.len + 1),
        .canonical = canonical,
        .upper_canonical = idmapped,
        .upper_userns = if (idmapped) (b.keepUserns() orelse "") else "",
        .volume_id_base = volumeIdBase(b.subid_base),
        .container = container,
        .container_opts = b.sandbox_opts,
    }, &b.running, out);
    b.timings.helper(arena, ended.helper, ended.spawned, ended.ended);
    if (new_layer) try b.layers.append(arena, .{ .name = upper, .path = upper_path, .canonical = idmapped });
    return ended;
}

/// The fewest entries (files, directories, anything) a step's layer must be expected to hold for
/// a job to start using the idmapped upper (`chooseUpper`). Once the job has its user namespace
/// kept (`keepUserns`) the idmapped upper is never slower than the shift, whatever the layer,
/// measured on the laptop (ReleaseSafe, under other agents' load: the mount phase and the shift
/// together, shifted against idmapped: 1 entry 751 against 609 us, 4 entries 2075 against 602, 21
/// entries 2080 against 792, 201 entries 12171 against 871). What it costs is making that
/// namespace, one helper spawn of about 2.4 ms for the job, which the shift's 30 us an entry pays
/// back at about 80 entries. So a job starts with the shift and starts using the idmapped upper at
/// the first step expected to make a layer that large.
pub const idmapped_min_entries_default = 80;

/// Whether the step about to run writes its upper idmapped rather than shifted afterwards
/// (`chooseUpper`), by whether its job has its namespace and what is known of its layer: its
/// step's last published size (`key_diff.readEntries`), else what the job's earlier steps made.
fn upperIdmapped(b: *Backend) bool {
    if (b.idmapped_min_entries == 0) return true;
    const have = b.upper_userns != null;
    const p = b.pending orelse return chooseUpper(b.idmapped_min_entries, false, have, null, b.earlier_entries);
    const s = b.store orelse return false;
    const last = if (p.label.len > 0) key_diff.readEntries(b.arena, b.io, s.root, &b.stepIdent(p.label)) else null;
    return chooseUpper(b.idmapped_min_entries, true, have, last, b.earlier_entries);
}

/// The choice itself. A step with no key (`keyed` false) is never published, so nothing is
/// shifted for it unless the stack is flattened: the shift costs it nothing, and the idmapped
/// upper something. A keyed step of a job that has its namespace (`have`) takes the idmapped
/// upper. Otherwise it starts one only for a layer expected to hold `min` entries: what its step's
/// last layer held, or for a step with no history (its first run) the largest layer the job's
/// earlier steps made, so a job that has made large layers goes on making them. A job's first
/// step, with nothing before it, is shifted.
fn chooseUpper(min: u64, keyed: bool, have: bool, last: ?u64, earlier: u64) bool {
    if (!keyed) return false;
    if (have) return true;
    return (last orelse earlier) >= min;
}

test "a step's upper is idmapped once its job has the namespace, or by its layer's last size" {
    // Never published: shifted, whatever came before.
    try std.testing.expect(!chooseUpper(80, false, true, 5000, 5000));
    // With the namespace: always.
    try std.testing.expect(chooseUpper(80, true, true, 0, 0));
    try std.testing.expect(chooseUpper(80, true, true, null, 0));
    // Without it: a known size decides, whatever the job did before.
    try std.testing.expect(chooseUpper(80, true, false, 80, 0));
    try std.testing.expect(!chooseUpper(80, true, false, 79, 5000));
    // First run: by the job's earlier layers; with none, shifted.
    try std.testing.expect(chooseUpper(80, true, false, null, 370));
    try std.testing.expect(!chooseUpper(80, true, false, null, 3));
    try std.testing.expect(!chooseUpper(80, true, false, null, 0));
}

/// The job's user namespace for its idmapped uppers kept in a file of the job's directory, made
/// once by a helper (`sandbox.usernsMain`) at the first step that needs it, so no step makes it:
/// the same map every step would make (`sandbox.upperUserns`, from the job's own ids), reachable
/// only through this job's directory, and unmounted with the job (`teardown`, `sweep`). Null when
/// the helper failed; the steps then make their own.
fn keepUserns(b: *Backend) ?[]const u8 {
    if (b.upper_userns_tried) return b.upper_userns;
    b.upper_userns_tried = true;
    const arena = b.arena;
    const path = "userns";
    const full = std.fmt.allocPrint(arena, "{s}/{s}", .{ b.dir, path }) catch return null;
    const first = std.fmt.allocPrint(arena, "{d}", .{b.idBase()}) catch return null;
    const count = std.fmt.allocPrint(arena, "{d}", .{ids_per_slot}) catch return null;
    const ran = std.process.run(arena, b.io, .{
        .argv = &.{ b.self_exe, sandbox.userns_command, full, first, count },
    }) catch |e| {
        std.log.warn("native: cannot start the user namespace's helper: {s}", .{@errorName(e)});
        return null;
    };
    if (ran.term != .exited or ran.term.exited != 0) {
        std.log.warn("native: the user namespace's helper failed: {s}", .{std.mem.trim(u8, ran.stderr, " \n")});
        detachNetns(arena, full);
        return null;
    }
    b.upper_userns = path;
    return path;
}

/// Whether this machine writes a step's upper through an idmapped mount, found once by running
/// one step that does and looking at what it left on disk, and remembered for the process (a
/// kernel and its filesystems do not change under it); null in `idmapped_upper` is the question
/// not yet asked. Where it does not work, or `Config.idmapped_upper` is off, or the runner is
/// rootless, the answer is no, and each layer is shifted when it is published or flattened.
var idmapped_upper_known: std.atomic.Value(u8) = .init(0); // 0: not asked yet
const idmapped_yes = 1;
const idmapped_no = 2;

fn idmappedUpper(b: *Backend) bool {
    if (b.how.userns != .mapped or !b.idmapped_upper) return false;
    switch (idmapped_upper_known.load(.acquire)) {
        idmapped_yes => return true,
        idmapped_no => return false,
        else => {},
    }
    const why = b.tryIdmappedUpper();
    idmapped_upper_known.store(if (why == null) idmapped_yes else idmapped_no, .release);
    if (why) |w| std.log.info("native: a step's upper is not idmapped on this machine ({s}); " ++
        "each layer is shifted after its step instead", .{w});
    return why == null;
}

/// The script `tryIdmappedUpper` runs: a file given to another user and a set-id one, a
/// directory, and a deletion that makes the overlay's whiteout (as host root, in its mounter's
/// own ids).
const idmapped_trial = "mkdir /idmapped-trial && echo x > /idmapped-trial/f && " ++
    "chown 1001:1002 /idmapped-trial/f && chmod 4755 /idmapped-trial/f && " ++
    "rm -f /etc/group";

/// One step with an idmapped upper on the job's own stack, its layer dropped again: null when it
/// ran and left the ids the job's own on disk, else why not. An upper the kernel did not idmap
/// (or idmapped another way) would have left the job's host ids.
fn tryIdmappedUpper(b: *Backend) ?[]const u8 {
    const arena = b.arena;
    var out: Captured = .{ .arena = arena };
    const ended = b.runIn(&.{ "sh", "-c", idmapped_trial }, &.{"PATH=/usr/bin:/bin"}, &.{}, 0, 0, out.output(), null, true, true) catch |e|
        return @errorName(e);
    const top = b.layers.pop() orelse return "no layer was made";
    defer removeTree(arena, b.io, top.path);
    if (ended.failure.len > 0) return ended.failure;
    if (ended.code != 0) return std.fmt.allocPrint(arena, "the trial step exited {d}: {s}", .{ ended.code, out.tailLines(4) }) catch "the trial step failed";
    const p = std.fmt.allocPrintSentinel(arena, "{s}/idmapped-trial/f", .{top.path}, 0) catch return "out of memory";
    var st: std.os.linux.Statx = undefined;
    if (std.os.linux.errno(std.os.linux.statx(std.os.linux.AT.FDCWD, p, std.os.linux.AT.SYMLINK_NOFOLLOW, .{ .UID = true, .GID = true, .MODE = true }, &st)) != .SUCCESS)
        return "the trial's file is missing";
    if (st.uid == 1001 and st.gid == 1002 and st.mode & 0o7777 == 0o4755) return null;
    return std.fmt.allocPrint(arena, "the trial's file has ids {d}:{d} mode {o} on disk", .{ st.uid, st.gid, st.mode & 0o7777 }) catch "the trial's ids are wrong";
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
/// or was not published, a Docker action's step, a JavaScript action's mount points): nothing
/// after such a layer is replayed or published, as under Dagger a new parent makes every later
/// key new, so what an image or a mount holds never needs to be in a key
/// (`Native.ops_keep_chained`). The env is the container's in its order, without the
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
    b.pending = null;
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
    // The same parts as components, to say what differs on a miss (`key_diff.zig`): digests, never
    // the content, and nothing the key does not hold.
    var cb: key_diff.Builder = .init(b.arena);
    if (b.layers.items.len > 0)
        try cb.add(key_diff.parent_name, &Store.hex(parent))
    else for (b.below_parts) |c| try cb.add(c.name, c.value);
    try cb.addDigest("script", script);
    for (b.env.items) |e| if (Store.stableEnv(e.name)) try envComponent(&cb, e.name, e.value);
    try cb.add("uid", try std.fmt.allocPrint(b.arena, "{d}", .{uid}));
    try cb.add("gid", try std.fmt.allocPrint(b.arena, "{d}", .{gid}));
    try cb.add("workdir", b.workdir);
    for (files) |f| {
        if (!f.keep) return null;
        h.field(f.path);
        h.field(f.contents);
        h.int(f.mode);
        try cb.addDigest(try std.fmt.allocPrint(b.arena, "file {s}", .{f.path}), f.contents);
    }
    // What a step may read is in its groups too. Hashed only if it has some, which leaves every
    // other key as it was; a layer stored before steps had them was made without, and misses.
    if (uid == b.uid and gid == b.gid and b.groups.len > 0) {
        h.int(b.groups.len);
        for (b.groups) |g| h.int(g);
        var groups: std.ArrayList(u8) = .empty;
        for (b.groups) |g| try groups.print(b.arena, "{d} ", .{g});
        try cb.addDigest("groups", groups.items);
    }
    const key = h.final();
    b.pending = .{ .key = key, .comps = try cb.finish() };
    return key;
}

/// One stable variable as components: a digest of its value (a tree check's value, a line for
/// each tree: the tree's path is the name, as it is what a reader knows it by).
fn envComponent(cb: *key_diff.Builder, name: []const u8, value: []const u8) !void {
    const label = if (std.mem.eql(u8, name, set_up.tool_trees_env))
        "tool tree "
    else if (std.mem.eql(u8, name, trees_check.full_env))
        "full tool tree "
    else
        return cb.addDigest(try std.fmt.allocPrint(cb.arena, "env {s}", .{name}), value);
    var lines = std.mem.tokenizeScalar(u8, value, '\n');
    while (lines.next()) |line| {
        const sp = std.mem.indexOfScalar(u8, line, ' ') orelse {
            try cb.addDigest(try std.fmt.allocPrint(cb.arena, "env {s}", .{name}), line);
            continue;
        };
        try cb.add(
            try std.fmt.allocPrint(cb.arena, "{s}{s}", .{ label, line[sp + 1 ..] }),
            try std.fmt.allocPrint(cb.arena, "sha:{s}", .{line[0..@min(sp, 16)]}),
        );
    }
}

/// A key's components, held until the key is claimed.
const Pending = struct {
    key: Store.Key,
    comps: []const key_diff.Component,
    /// Which step it is (`stepIdent`), set when the key is claimed.
    label: []const u8 = "",
};

/// Who step `label` ("base", "fetch", "step 3") is across runs, the id of its entry in the
/// store's index of steps (`key_diff.identity`): the scope is in it, so a fork's pull request never
/// reads or writes what the repository's own jobs do.
fn stepIdent(b: *const Backend, label: []const u8) [32]u8 {
    return key_diff.identity(&.{ b.ident[0], b.ident[1], b.ident[2], b.ident[3], b.ident[4], label });
}

/// What the store knew of this step when `key` was not in it, as a line for the step's log: the
/// first component that differs from the key the step had when last replayed or published, or why
/// there is none. Null when this is the step's first run, or when nothing is known. A step whose
/// own parts are as they were, but whose layer below is new, says so with the first such miss
/// of the job.
fn explainMiss(b: *Backend, c: Pending, label: []const u8) ?[]const u8 {
    const s = b.store orelse return null;
    const arena = b.arena;
    const was = key_diff.readIndex(arena, b.io, s.root, &b.stepIdent(label)) orelse return null;
    if (std.mem.eql(u8, was.key, &Store.hex(c.key)))
        return "Not replayed: its key is the same as last time, but the stored layer is gone " ++
            "(evicted, or made by a run that did not finish)";
    const ch = key_diff.firstChange(was.comps, c.comps) orelse return null;
    if (std.mem.eql(u8, ch.name, key_diff.parent_name)) {
        const cause = b.first_miss orelse return key_diff.describe(arena, ch) catch null;
        return std.fmt.allocPrint(arena, "Not replayed: an earlier step did not replay: {s}", .{
            cause["Not replayed: ".len..],
        }) catch null;
    }
    const line = key_diff.describe(arena, ch) catch return null;
    if (b.first_miss == null) b.first_miss = line;
    return line;
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
    const fp = Store.rootfsFingerprint(b.arena, b.io, b.rootfs, b.store_cfg.root) catch |e| {
        std.log.warn("native: the rootfs's fingerprint: {s}; the job's steps are not cached", .{
            @errorName(e),
        });
        b.store = null;
        return null;
    };
    // A root runner's job has a resolver of its own, in its own directory (`jobBinds`): keyed as
    // the host's, which it is made from, so jobs replay one another's layers.
    const binds = b.arena.dupe(sandbox.Spec.Bind, b.binds) catch {
        b.store = null;
        return null;
    };
    for (binds) |*bd| if (std.mem.eql(u8, bd.at, "/etc/resolv.conf")) {
        bd.host = "/etc/resolv.conf";
    };
    const in: Below = .{
        .format = Store.store_format,
        .scope = b.scope,
        .repository = b.repository,
        .fingerprint = &fp,
        .userns = @tagName(b.how.userns),
        .binds = binds,
        .seeds = b.seed_ids.items,
        .container_opts = b.opts_key,
    };
    b.below_parts = belowParts(b.arena, in) catch &.{};
    return belowKey(in, null);
}

/// `below`'s fields as components (`key_diff.zig`), for the base's miss to say which changed.
fn belowParts(arena: Allocator, in: Below) ![]const key_diff.Component {
    var cb: key_diff.Builder = .init(arena);
    try cb.add("base format", in.format);
    try cb.add("base scope", in.scope);
    try cb.add("base repository", in.repository);
    try cb.addDigest("base rootfs", in.fingerprint);
    try cb.add("base userns", in.userns);
    var binds: std.ArrayList(u8) = .empty;
    for (in.binds) |bd| try binds.print(arena, "{s}:{s}:{}:{}:{}\n", .{
        bd.host, bd.at, bd.read_only, bd.optional, bd.volume,
    });
    try cb.addDigest("base binds", binds.items);
    var layers: std.ArrayList(u8) = .empty;
    for (in.seeds) |l| try layers.print(arena, "{s}\n", .{l});
    try cb.addDigest("base zig cache seeds", layers.items);
    try cb.addDigest("base container options", in.container_opts);
    return cb.finish();
}

/// What `below` hashes, as values: the store's format and what it reads from the job.
pub const Below = struct {
    format: []const u8,
    scope: []const u8,
    repository: []const u8,
    fingerprint: []const u8,
    userns: []const u8,
    binds: []const sandbox.Spec.Bind,
    /// The Zig cache seeds' layers (`volumes.Seed`), by `volumes.seedId`: the path, which names the
    /// release, architecture and step user each was built for, and which build it is, as one
    /// evicted is built again and need not be the same tree.
    seeds: []const []const u8 = &.{},
    /// The job container's `--hostname`, `--shm-size` and `--tmpfs`, which the steps run under
    /// (`setUpSandboxOptions`); "" for none, which keys as before.
    container_opts: []const u8 = "",
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
    if (in.container_opts.len > 0) {
        h.field("container options");
        h.field(in.container_opts);
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
pub fn slotIds(b: *const Backend) Store.Ids {
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
    /// Why the key was not in the store, when the store can say (`explainMiss`).
    why: ?[]const u8 = null,

    fn release(c: Claim, io: std.Io) void {
        if (c.lock) |l| l.close(io);
    }
};

fn claimKey(
    b: *Backend,
    key: ?Store.Key,
    label: []const u8,
) error{ Stopped, OutOfMemory }!Claim {
    const k = key orelse return .{};
    const s = b.store.?;
    const arena = b.arena;
    // Components are those of this key or none (`keyFetched` claims keys `keyFor` did not make).
    if (b.pending) |*p| {
        if (std.mem.eql(u8, &p.key, &k)) p.label = label else b.pending = null;
    }
    const t = phases.now();
    defer _ = b.timings.since(arena, .claim, t);
    b.stop_wait.store(false, .release);
    b.waiting.store(true, .release);
    const lock = s.lockKey(arena, b.io, k, &b.stop_wait) catch |e| {
        b.waiting.store(false, .release);
        if (e == error.Stopped) return error.Stopped;
        // The task's cancel stops the step as `abort` does. std.Io delivers it once: re-armed, so
        // what runs next sees it too, instead of the job going on uncached.
        if (e == error.Canceled) {
            b.io.recancel();
            return error.Stopped;
        }
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
    }) orelse return .{
        .key = k,
        .lock = lock,
        .why = if (b.pending) |p| b.explainMiss(p, label) else null,
    };
    errdefer hit.layer.lock.close(b.io);
    errdefer lock.close(b.io);
    try b.layers.ensureUnusedCapacity(arena, 1);
    try b.held.ensureUnusedCapacity(arena, 1);
    try b.chain.ensureUnusedCapacity(arena, 1);
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
    b.chain.appendAssumeCapacity(hit.layer.lock);
    b.layers.appendAssumeCapacity(.{
        .name = name,
        .path = hit.layer.fs,
        .key = k,
        .canonical = b.how.userns == .mapped,
    });
    if (b.pending) |p| {
        b.remember(p);
        if (key_diff.readEntries(arena, b.io, s.root, &b.stepIdent(p.label))) |n|
            b.earlier_entries = @max(b.earlier_entries, n);
    }
    return .{ .key = k, .lock = lock, .hit = hit.rec };
}

/// What to tell the job once a deferred layer's sync failed mid-job: the steps after it ran over a
/// layer whose data may be lost, and this is otherwise seen only in the runner's log at the job's end.
fn settleWarning(b: *Backend) ?[]const u8 {
    const l = b.store_cfg.sync_log orelse return null;
    if (!l.settle_failed or l.settle_told) return null;
    l.settle_told = true;
    return "##[warning]Writing an earlier step's layer to the disk failed: that layer is not cached, " ++
        "and the steps that ran over it may have read data that was lost. The steps after this one are not published (they may still replay).";
}

/// Makes the key `p` the one its step is known by (`key_diff.writeIndex`).
fn remember(b: *Backend, p: Pending) void {
    const s = b.store orelse return;
    key_diff.writeIndex(b.arena, b.io, s.root, &b.stepIdent(p.label), &Store.hex(p.key), p.comps);
}

/// The stack's top layer, which an exec under `key` just left, given the canonical ids
/// (`canonicalize`, so any slot's job can use it) and moved into the store (`Store.publish`) with
/// its record, and the job's stack then links to it. Its parent is in the store (`keyFor`). A
/// failure to publish leaves the layer the job's own, and is logged: the job goes on, uncached from
/// here. One to shift its ids is the job's: the layer is then half one range's, half the other's.
fn publishTop(b: *Backend, key: Store.Key, kind: Store.Kind, rec_in: Store.Record) !void {
    const s = b.store orelse return;
    const arena = b.arena;
    var rec = rec_in;
    const pend: ?Pending = if (b.pending) |p| if (std.mem.eql(u8, &p.key, &key)) p else null else null;
    if (pend) |p| rec.components = key_diff.render(arena, p.comps) catch "";
    if (rec.log.len > Store.max_record_bytes) return;
    // Room first: once the layer has moved, the job must hold it and point at it.
    b.held.ensureUnusedCapacity(arena, 1) catch return;
    b.chain.ensureUnusedCapacity(arena, 1) catch return;
    const top = &b.layers.items[b.layers.items.len - 1];
    const t = phases.now();
    try b.canonicalize(top);
    _ = b.timings.since(arena, .unshift, t);
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
    const layer = s.publishTimed(arena, b.io, key, kind, top.path, rec, &b.timings) catch |e| {
        // A failed sync was logged with its errno, once, by the store.
        if (e != error.Sync) std.log.warn("native: cannot publish a layer to the store: {s}", .{@errorName(e)});
        cwd.deleteFile(b.io, link) catch {};
        // The key has an entry already (another job's, perhaps not yet durable, so this job could not
        // replay it): this job's own upper stays its own layer under the key, which is derived from
        // what made it, so its later steps are keyed and cached as if it were the stored one. Nothing
        // else sees it, and it goes with the job's directory.
        if (e == error.PublishLost) top.key = key;
        return;
    };
    b.held.appendAssumeCapacity(layer.lock);
    b.chain.appendAssumeCapacity(layer.lock);
    b.published = true;
    const canonical = top.canonical;
    top.* = .{ .name = name, .path = layer.fs, .key = key, .canonical = canonical };
    b.earlier_entries = @max(b.earlier_entries, layer.entries);
    if (pend) |p| {
        b.remember(p);
        key_diff.writeEntries(arena, b.io, s.root, &b.stepIdent(p.label), layer.entries);
    }
}

/// The stack's top layer, the job's own (not the store's), dropped and removed: an exec whose
/// layer nothing after it may see (`actions.readOwn`).
pub fn dropTop(b: *Backend) void {
    const top = b.layers.getLastOrNull() orelse return;
    if (top.key != null) return;
    _ = b.layers.pop();
    Store.removeTree(b.arena, b.io, top.path);
}

/// The stack's top layer, a tree git fetched at a commit (an action's, `actions.fetch`), keyed by
/// what it holds rather than by how it was made: `what` names the repository, where it is and the
/// commit, as Dagger's `git` keys a tree. Under step caching the store's layer under that key
/// takes its place (the same tree), or it is published under it, so the base and the steps above
/// it are keyed and replayed as above any other layer. Unkeyed, it would leave every later key
/// null, and every step of a job with an action uncached (finding 1 of the trial integration,
/// #275). Without the store, or with nothing keyed below it, the layer stays the job's own.
pub fn keyFetched(b: *Backend, what: []const u8) !void {
    if (b.store == null) return;
    const fetched = b.layers.pop() orelse return;
    const parent = if (b.layers.items.len > 0)
        b.layers.items[b.layers.items.len - 1].key
    else
        b.below();
    const p = parent orelse {
        b.layers.appendAssumeCapacity(fetched);
        return;
    };
    var h: Store.KeyHasher = .init(.step);
    h.core(p, what, &[_]job_mod.EnvVar{});
    const claim = b.claimKey(h.final(), "fetched") catch |e| {
        b.layers.appendAssumeCapacity(fetched);
        return e;
    };
    defer claim.release(b.io);
    if (claim.hit != null) {
        // The stored tree is linked on the stack in its place (`claimKey`): this one goes.
        Store.removeTree(b.arena, b.io, fetched.path);
        return;
    }
    b.layers.appendAssumeCapacity(fetched);
    if (claim.key) |k| try b.publishTop(k, .fetch, .{ .log = "", .fc = "" });
}

/// The job's stack merged into one layer (`Store.flatten`), before overlay's limits on layers and
/// on its options' length are reached. The merged layer stands for the stack's top: its key is
/// the top's, so the steps after it are keyed and published as before.
fn flattenTimed(b: *Backend) !void {
    const t = phases.now();
    defer _ = b.timings.since(b.arena, .flatten, t);
    return b.flatten();
}

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
    try Store.flatten(arena, b.io, paths, out, b.opaqueXattr());
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
    const img = try b.fetchRootfs(plan.job_image, creds, plan.provision, plan.as_runner, err_msg);
    // `options: --user` over the image's `USER`, as `docker create` has it. (Never with the
    // provisioned image: `container_options.unsupported` sends that job to Dagger.)
    const user = b.container_opts.user orelse img.user;
    if (!plan.as_runner and user.len > 0) {
        const user_ids = b.imageUser(user) catch |e| {
            // `docker create --user typo` fails on GitHub; Dagger would not read the option.
            b.job_fault = b.container_opts.user != null and
                (e == error.UnknownUser or e == error.UnknownGroup);
            err_msg.* = try std.fmt.allocPrint(arena, "the {s} {s}: {s}", .{
                if (b.container_opts.user != null) "container's --user" else "image's USER",
                user,
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

/// `image` pulled into the store or found there, and provisioned when `provision_it` (the default
/// image): `b.rootfs` is then what the job's steps start from. The part of `prepareRootfs` that
/// depends on nothing of a job, so `warm` makes it with no job.
fn fetchRootfs(
    b: *Backend,
    image: []const u8,
    creds: ?registry.Credentials,
    provision_it: bool,
    as_runner: bool,
    err_msg: *[]const u8,
) !oci.Image {
    const arena = b.arena;
    var why: []const u8 = "";
    var t = phases.now();
    if (provision_it) if (try b.pullProvisioned(as_runner)) |img| {
        _ = b.timings.since(arena, .image, t);
        return img;
    };
    const img = b.pull(image, creds, &why) catch |e| {
        err_msg.* = try std.fmt.allocPrint(arena, "could not pull {s} natively: {s}", .{
            image,
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
    t = b.timings.since(arena, .image, t);
    if (provision_it) b.rootfs = try b.provision(
        img,
        if (as_runner) set_up.provision_runner_script else set_up.provision_script,
        err_msg,
    );
    _ = b.timings.since(arena, .provision, t);
    return img;
}

/// How long the pre-provisioned image may take to pull before apt provisions instead: far less
/// than `pull_deadline`, since provisioning is the alternative and takes under a minute.
const provisioned_pull_deadline: std.Io.Duration = .fromSeconds(5 * 60);

/// The pre-provisioned default image (`provisioned.zig`) pulled into the store, or found there, as
/// what the job's steps start from: `b.rootfs` is then the image's own tree, under the store's
/// `oci/images/<key>/rootfs`, a path no locally provisioned rootfs (`provision`, under
/// `rootfs/<key>/rootfs`) shares, so `Store.rootfsFingerprint` and the step cache's keys never
/// take one for the other. Null when none is pinned or the operator turned it off, and when the
/// pull fails (the note says why): the caller pulls Ubuntu and provisions it with apt.
fn pullProvisioned(b: *Backend, as_runner: bool) !?oci.Image {
    const arena = b.arena;
    const ref = try provisioned.reference(arena, b.provisioned_image, b.provisioned_pins, .of(as_runner)) orelse
        return null;
    var why: []const u8 = "";
    const img = b.pullBefore(ref, null, provisioned_pull_deadline, &why) catch |e| {
        try b.notes.append(arena, try provisioned.fallbackNote(arena, ref, if (why.len > 0) why else @errorName(e)));
        return null;
    };
    b.image = img;
    b.image_env = img.env;
    b.rootfs = img.rootfs;
    try b.notes.append(arena, if (img.pulled) |p| try std.fmt.allocPrint(
        arena,
        "{s}, pulled natively in {d} ms ({d} KB fetched)",
        .{ try provisioned.usedNote(arena, ref), p.ms, p.bytes / 1024 },
    ) else try std.fmt.allocPrint(arena, "{s}, from the native store", .{try provisioned.usedNote(arena, ref)}));
    return img;
}

/// The job container's `options:`, read (`container_options.parse`; `unsupported` has already
/// refused what it does not carry out, so this is not expected to fail), with a note in "Set up
/// job" for what was honoured and for what is understood and has no effect here.
fn readContainerOptions(b: *Backend, ev: *Evaluator, err_msg: *[]const u8) !void {
    const jc = ev.job.container orelse return;
    const text = switch (jc.options orelse return) {
        .lit => |l| l,
        .expr => {
            err_msg.* = "the job container's `options:` is an expression";
            return error.BaseContainerFailed;
        },
    };
    var why: []const u8 = "";
    const o = container_options.parse(b.arena, text, &why) catch |e| {
        err_msg.* = if (why.len > 0) why else @errorName(e);
        return error.BaseContainerFailed;
    };
    b.container_opts = o;
    // A tmpfs and /dev/shm are charged to the memory cgroup of the job; with none, they would pin
    // host memory nobody accounts for (docs/native-backend.md, "Job container options").
    if (b.job_cgroup == null) if (container_options.withoutCgroup(o)) |reason| {
        err_msg.* = reason;
        return error.BaseContainerFailed;
    };
    var more: std.ArrayList(u8) = .empty;
    if (o.hostname) |h| try more.print(b.arena, ", `--hostname` {s}", .{h});
    if (o.add_hosts.len > 0) try more.print(b.arena, ", {d} `--add-host`", .{o.add_hosts.len});
    if (o.shm_size) |n| try more.print(b.arena, ", `--shm-size` {d} MiB", .{n >> 20});
    if (o.tmpfs.len > 0) try more.print(b.arena, ", {d} `--tmpfs`", .{o.tmpfs.len});
    if (o.memory) |n| try more.print(b.arena, ", `--memory` {d} MiB{s}", .{
        n >> 20,
        try b.limitMemory(n, err_msg),
    });
    try b.setUpSandboxOptions(o);
    try b.notes.append(b.arena, try std.fmt.allocPrint(b.arena, "Container options: {d} " ++
        "`--env`{s}{s}{s}; {d} understood and without effect natively (`--workdir`, " ++
        "`--health-*`, `--init`)", .{
        o.env.len,
        if (o.user != null) ", `--user` " else "",
        o.user orelse "",
        more.items,
        o.no_effect,
    }));
}

/// `--memory` as a limit of the job's cgroup, lowered when it is below the runner's own for a
/// job (never raised: the operator's limit is the most a job gets). The words that follow the
/// number in "Set up job". A job with no cgroup of its own cannot be held to one: it fails
/// rather than run without the limit it asked for.
fn limitMemory(b: *Backend, want: u64, err_msg: *[]const u8) ![]const u8 {
    const j = b.job_cgroup orelse {
        err_msg.* = "the job container's `--memory` needs the job's own cgroup, which this " ++
            "job has none of (RUNNER_NATIVE_CGROUP)";
        return error.BaseContainerFailed;
    };
    if (b.limits.memory_max) |have| if (want >= have) return try std.fmt.allocPrint(b.arena, " (the runner's limit of {d} MiB is lower, and holds)", .{have >> 20});
    j.lowerMemory(b.arena, want) catch {
        err_msg.* = "the job container's `--memory` could not be set on the job's cgroup";
        return error.BaseContainerFailed;
    };
    b.limits.memory_max = want;
    return "";
}

/// `--hostname`, `--add-host`, `--shm-size` and `--tmpfs` ready for the steps' sandboxes and the
/// job's hosts file; what changes a step's result is in `opts_key`, so the job's layers are not
/// replayed for a job that asked for something else.
fn setUpSandboxOptions(b: *Backend, o: container_options.Options) !void {
    const arena = b.arena;
    const tmpfs = try arena.alloc(sandbox.Spec.Tmpfs, o.tmpfs.len);
    var key: std.ArrayList(u8) = .empty;
    for (o.tmpfs, tmpfs) |t, *out| {
        out.* = .{ .path = t.target, .size = t.size, .mode = t.mode, .exec = t.exec, .read_only = t.read_only };
        try key.print(arena, "tmpfs {s} {d} {o} {} {};", .{ t.target, t.size, t.mode, t.exec, t.read_only });
    }
    if (o.hostname) |h| try key.print(arena, "hostname {s};", .{h});
    if (o.shm_size) |n| try key.print(arena, "shm {d};", .{n});
    b.sandbox_opts = .{ .hostname = o.hostname orelse "", .shm_size = o.shm_size orelse 0, .tmpfs = tmpfs };
    b.opts_key = key.items;
    var hosts: std.ArrayList(u8) = .empty;
    if (o.hostname) |h| try hosts.print(arena, "127.0.0.1\t{s}\n", .{h});
    for (o.add_hosts) |h| try hosts.print(arena, "{s}\t{s}\n", .{ h.ip, h.name });
    b.hosts_extra = hosts.items;
    try b.writeHosts("");
}

/// The job container's `ports:` published from the host (`publish.zig`): what the operator
/// allows (`RUNNER_NATIVE_PORT_ADDRESSES`, no host port below 1024, none for a job the runner
/// does not vouch for or a fork's pull request), each listened on by the relay in the host's
/// network and carried to the job's port on its loopback (`forward.zig`, `Spec.publish`), for
/// the job's life. "Set up job" says where each went, as `docker port` does. Anything refused, or
/// a port another process holds, fails the job naming it: on Dagger it would be ignored.
fn publishPorts(b: *Backend, ev: *Evaluator, err_msg: *[]const u8) !void {
    const arena = b.arena;
    const jc = ev.job.container orelse return;
    if (jc.ports.len == 0) return;
    var why: []const u8 = "";
    const ports = container_options.ports(arena, jc.ports, &why) catch |e| {
        err_msg.* = if (why.len > 0) why else @errorName(e);
        return error.BaseContainerFailed;
    };
    const scope = try set_up.packageCacheScope(arena, ev, ev.job.github.repository, b.caches.trusted);
    const trusted = b.vouched and std.mem.eql(u8, scope, "repo");
    const maps = publish.plan(arena, ports, .{
        .addresses = b.port_addresses,
        .range = b.port_range,
        .reserved = b.reserved_ports,
    }, trusted, &why) catch |e| {
        b.job_fault = true;
        err_msg.* = if (why.len > 0) why else @errorName(e);
        return error.BaseContainerFailed;
    };
    const netns = b.networkPath() catch |e| {
        b.job_fault = true;
        err_msg.* = b.net_why orelse @errorName(e);
        return error.BaseContainerFailed;
    };
    b.publisher = forward.start(arena, b.io, b.self_exe, .{
        .netns = netns,
        // The job's nobody: an id of its range, nothing on the host.
        .id = if (b.how.userns == .mapped) b.idBase() + 65534 else null,
        .cgroup = if (b.job_cgroup) |j| j.servicesDir() else null,
        .ports = maps,
        .publish = true,
        .reserved = b.reserved_ports,
        .limits = .{ .idle_ms = b.port_idle_ms },
        // Published beyond the host's loopback: no peer of the runner's jobs, nor of a bridge's.
        .guard = for (maps) |m| {
            if (m.address[0] != 127) break .{ .subnet = b.subnet.base, .prefix = b.subnet.prefix };
        } else null,
    }, &why) catch |e| {
        b.job_fault = true;
        err_msg.* = try std.fmt.allocPrint(arena, "the job container's ports could not be " ++
            "published: {s}", .{if (why.len > 0) why else @errorName(e)});
        return error.BaseContainerFailed;
    };
    const lines = try publish.report(arena, maps, b.publisher.?.ports);
    try b.notes.append(arena, try std.fmt.allocPrint(arena, "Container ports: {s}", .{
        try std.mem.join(arena, ", ", lines),
    }));
}

/// The job container's `volumes:` (`container_options.volumes`; `unsupported` has already
/// refused what it does not carry out). An anonymous one is a directory of the job's filesystem,
/// made in the base (`volume_dirs`, the shell that makes them after the work root): root's as
/// Docker makes a volume's mount point, what the image has there kept, and it lasts as long as
/// the job. A named one outlives the job as Docker's does: a directory of the store
/// (`volumes.openNamed`, scoped by the job's trust scope and repository), held shared for the
/// job and bound at its target in every step, read-only for `:ro`, with the cache volumes' ids,
/// nosuid and nodev. One the job made is seeded first from what the image has at its target, as
/// Docker copies it into a new volume (moby `daemon/create_unix.go`, `populateVolume`); one that
/// exists is never written over. A volume where the runner binds or makes something itself fails
/// the job, naming both: the bind would hide the volume's files, or the volume the bind's.
fn containerVolumes(b: *Backend, ev: *Evaluator, err_msg: *[]const u8) !void {
    const arena = b.arena;
    const jc = ev.job.container orelse return;
    if (jc.volumes.len == 0) return;
    var why: []const u8 = "";
    const found = container_options.volumes(arena, jc.volumes, &why) catch |e| {
        err_msg.* = if (why.len > 0) why else @errorName(e);
        return error.BaseContainerFailed;
    };
    for (found.list, 0..) |v, i| {
        const target = v.target;
        const taken = [_][]const u8{ ev.workspace, ev.temp };
        const mine = for (taken) |at| {
            if (container_options.under(target, at) or container_options.under(at, target)) break at;
        } else for (b.binds) |bind| {
            if (container_options.under(target, bind.at) or container_options.under(bind.at, target))
                break bind.at;
        } else null;
        if (mine) |at| {
            b.job_fault = true;
            err_msg.* = try std.fmt.allocPrint(arena, "the job container's volume at {s} overlaps " ++
                "{s}, which the runner mounts or makes itself", .{ target, at });
            return error.BaseContainerFailed;
        }
        // Nested volumes, where one of them is a mount that the other's mount point would be
        // made through: a host path inside any other volume or holding one, or a named volume
        // inside another named one. Such a mount point would be made, by the host's root,
        // through a bind of a directory a job can write (`sandbox.bindAll` makes them all first,
        // and finds every bind's target through no mount, so a link cannot do it either). An
        // anonymous volume with any but a host path nests as Docker's do: it is a directory of the
        // job's filesystem, or made in the base through the named volume's bind as the job would.
        for (found.list[0..i]) |other| {
            const has_host = v.host != null or other.host != null;
            const both_named = v.name != null and other.name != null;
            if (!has_host and !both_named) continue;
            if (!container_options.under(v.target, other.target) and
                !container_options.under(other.target, v.target)) continue;
            b.job_fault = true;
            err_msg.* = try std.fmt.allocPrint(arena, "the job container's volume at {s} is " ++
                "nested with the one at {s}: a host path may not be inside another volume, nor " ++
                "hold one, and a named volume may not be inside another named volume", .{ v.target, other.target });
            return error.BaseContainerFailed;
        }
    }
    var w: std.Io.Writer.Allocating = .init(arena);
    var anonymous: usize = 0;
    var new: usize = 0;
    const scope = try set_up.packageCacheScope(arena, ev, ev.job.github.repository, b.caches.trusted);
    const owner: ?u32 = if (b.how.userns == .mapped) volumeIdBase(b.subid_base) else null;
    for (found.list) |v| {
        // Bound after the named ones (`hostVolumes`), so that no filling runs with them.
        if (v.host != null) continue;
        const name = v.name orelse {
            if (anonymous == 0) try w.writer.writeAll("mkdir -p --");
            anonymous += 1;
            try w.writer.writeByte(' ');
            try dagger.shellQuote(&w.writer, v.target);
            continue;
        };
        // Kept between jobs, so what one job left is the next one's: never for a job the runner
        // does not vouch for, nor a fork's pull request on one that vouches for pull requests
        // (scope `untrusted`), whose volumes every other such job would share.
        if (!b.vouched or !std.mem.eql(u8, scope, "repo")) {
            b.job_fault = true;
            err_msg.* = try std.fmt.allocPrint(arena, "the job container's named volume `{s}` " ++
                "is kept between jobs, which a job the runner does not vouch for (a fork's pull " ++
                "request included) never gets: an anonymous volume (`- {s}`) lasts as long as " ++
                "the job", .{ name, v.target });
            return error.BaseContainerFailed;
        }
        const key = volumes.namedKey(arena, ev.job.github.repository, scope, name) catch |e| {
            err_msg.* = try std.fmt.allocPrint(arena, "the job container's volume `{s}` is kept " ++
                "per repository, and the job names none ({s})", .{ name, @errorName(e) });
            return error.BaseContainerFailed;
        };
        // Waiting for another job's filling of it no longer than a filling may take, and not
        // past the job's cancel.
        var vol = volumes.openNamedWaiting(arena, b.io, b.store_cfg.root, key, owner, .{
            .ms = b.volume_seed_limit_ms + 60 * 1000,
            .cancel = if (b.cancel) |c| &c.requested else null,
        }) catch |e| {
            err_msg.* = try std.fmt.allocPrint(arena, "could not open the job container's " ++
                "volume `{s}`: {s}", .{ name, switch (e) {
                error.VolumeBusy => "another job has been filling it for longer than a filling may take",
                error.Canceled => "the job was cancelled while another job filled it",
                else => @errorName(e),
            } });
            return error.BaseContainerFailed;
        };
        const bind: sandbox.Spec.Bind = .{
            .host = vol.dir,
            .volume_root = vol.root,
            .at = v.target,
            .read_only = v.read_only,
            .volume = true,
            .make = true,
        };
        if (vol.new) {
            if (b.seedVolume(bind)) |failure| {
                vol.discard(b.io);
                b.job_fault = true;
                err_msg.* = try std.fmt.allocPrint(arena, "could not fill the new volume `{s}` " ++
                    "from the image's {s}: {s}", .{ name, v.target, failure });
                return error.BaseContainerFailed;
            }
            vol.share();
            new += 1;
        }
        try b.cache_plan.held.append(arena, vol);
        b.binds = try std.mem.concat(arena, sandbox.Spec.Bind, &.{ b.binds, &.{bind} });
        b.named_volumes += 1;
    }
    if (anonymous > 0) b.volume_dirs = w.written();
    if (anonymous + b.named_volumes > 0)
        try b.notes.append(arena, try std.fmt.allocPrint(arena, "Container volumes: {d} made as " ++
            "directories of the job, which last as long as it; {d} named, kept between jobs in the " ++
            "native store ({s} scope, {d} new and filled from the image), which evicts one unused " ++
            "for long when it needs the room", .{ anonymous, b.named_volumes, scope, new }));
    try b.hostVolumes(ev, found.list, err_msg);
}

/// Stops a new named volume's filling (`seedVolume`) past `limit_ms` or at the job's cancel: it
/// holds the volume's lock alone, which every other job opening it waits for.
const SeedWatch = struct {
    done: std.atomic.Value(bool) = .init(false),
    fired: std.atomic.Value(bool) = .init(false),

    fn run(w: *SeedWatch, b: *Backend, limit_ms: u64) void {
        var waited: u64 = 0;
        while (!w.done.load(.acquire)) {
            const cancelled = if (b.cancel) |c| c.requested.load(.acquire) else false;
            if (waited >= limit_ms or cancelled) {
                w.fired.store(true, .release);
                // Again each turn until it ends: the helper may not have started yet.
                _ = b.running.kill(b.io);
            }
            b.io.sleep(.fromMilliseconds(100), .awake) catch return;
            waited += 100;
        }
    }
};

test "a volume's filling is stopped at the job's cancel, well before its time limit" {
    var a: std.heap.ArenaAllocator = .init(std.testing.allocator);
    defer a.deinit();
    const io = std.testing.io;
    var cancel: dagger.Cancel = .{};
    var b: Backend = .{
        .arena = a.allocator(),
        .io = io,
        .gpa = std.testing.allocator,
        .dir = "",
        .rootfs = "",
        .binds = &.{},
        .lock = undefined,
        .how = .{ .argv_prefix = &.{}, .userns = .mapped },
        .cancel = &cancel,
    };
    var dog: SeedWatch = .{};
    // An hour: only the cancel can be what stops it.
    var watch = try io.concurrent(SeedWatch.run, .{ &dog, &b, 60 * 60 * 1000 });
    defer {
        dog.done.store(true, .release);
        watch.await(io);
    }
    // Quiet while nothing is cancelled.
    try io.sleep(.fromMilliseconds(250), .awake);
    try std.testing.expect(!dog.fired.load(.acquire));
    cancel.requested.store(true, .release);
    for (0..300) |_| {
        if (dog.fired.load(.acquire)) break;
        try io.sleep(.fromMilliseconds(10), .awake);
    }
    try std.testing.expect(dog.fired.load(.acquire));
}

/// What the image has at `volume.at` copied into the new volume, as Docker fills one: the
/// directory's files, and its owner and mode (`cp -a`, run in the job's image as its root, so the
/// ids are the job's as every step sees them), in a sandbox whose layer is dropped. Nothing there,
/// or no directory (a symlink is not followed), leaves it empty. Null, or why it failed.
fn seedVolume(b: *Backend, volume: sandbox.Spec.Bind) ?[]const u8 {
    const arena = b.arena;
    const saved = b.binds;
    const workdir = b.workdir;
    defer {
        b.binds = saved;
        b.workdir = workdir;
    }
    const at = "/zig-runner-volume";
    var beside = volume;
    beside.at = at;
    beside.read_only = false;
    b.binds = std.mem.concat(arena, sandbox.Spec.Bind, &.{ saved, &.{beside} }) catch return "out of memory";
    b.workdir = "/";
    var w: std.Io.Writer.Allocating = .init(arena);
    w.writer.writeAll("t=") catch return "out of memory";
    dagger.shellQuote(&w.writer, volume.at) catch return "out of memory";
    w.writer.writeAll("\nif [ -d \"$t\" ] && [ ! -L \"$t\" ]; then cp -a -- \"$t\"/. " ++ at ++ "/; fi\n") catch
        return "out of memory";
    var out: Captured = .{ .arena = arena };
    // Bounded: the volume's lock is held alone meanwhile, and every other job that opens it
    // waits (`volumes.Wait`). Stopped past its time or at the job's cancel.
    var dog: SeedWatch = .{};
    var watch = b.io.concurrent(SeedWatch.run, .{ &dog, b, b.volume_seed_limit_ms }) catch
        return "cannot watch the filling's time on this machine";
    const ended = b.exec(b.test_volume_seed orelse w.written(), &.{"PATH=" ++ image_path}, &.{}, 0, 0, out.output()) catch |e| {
        dog.done.store(true, .release);
        watch.await(b.io);
        return @errorName(e);
    };
    dog.done.store(true, .release);
    watch.await(b.io);
    b.dropLastLayer();
    if (dog.fired.load(.acquire)) return std.fmt.allocPrint(arena, "stopped after {d} s{s}", .{
        b.volume_seed_limit_ms / 1000,
        if (b.cancel) |c| if (c.requested.load(.acquire)) " (the job was cancelled)" else "" else "",
    }) catch "stopped";
    if (ended.failure.len > 0) return ended.failure;
    if (ended.code != 0) return std.fmt.allocPrint(arena, "`cp -a` exited {d}{s}", .{
        ended.code,
        out.tail(),
    }) catch "`cp -a` failed";
    return null;
}

/// Whether the job container lists a host-path volume.
fn hasHostVolume(arena: Allocator, job: job_mod.Job) bool {
    const jc = job.container orelse return false;
    var why: []const u8 = "";
    const found = container_options.volumes(arena, jc.volumes, &why) catch return false;
    for (found.list) |v| if (v.host != null) return true;
    return false;
}

/// The job container's host-path volumes (`host_paths.zig`), each bound at its target in every
/// step (`Bind.host_path`: not recursive, nosuid, nodev, read-only for `:ro`, idmapped as a
/// cache volume where the filesystem can be), after the overlap check every volume had. Off by
/// default: a source the operator's `RUNNER_NATIVE_HOST_PATHS` does not allow, once its symlinks
/// are resolved now, fails the job naming the setting, as does any host path in a job the runner
/// does not vouch for, or a fork's pull request on one that does (scope `untrusted`): the host's
/// directories are the operator's, and a job they do not trust gets none. Failed, not sent to
/// Dagger: Dagger ignores a job container's `volumes:`, so the job would run without the
/// directory it asked for and the refusal would be a warning in "Set up job".
fn hostVolumes(b: *Backend, ev: *Evaluator, list: []const container_options.Volume, err_msg: *[]const u8) !void {
    const arena = b.arena;
    var n: usize = 0;
    var read_only: usize = 0;
    for (list) |v| {
        const source = v.host orelse continue;
        const raw = try std.fmt.allocPrint(arena, "{s}:{s}{s}", .{ source, v.target, if (v.read_only) ":ro" else "" });
        const scope = try set_up.packageCacheScope(arena, ev, ev.job.github.repository, b.caches.trusted);
        if (!b.vouched or !std.mem.eql(u8, scope, "repo")) {
            b.job_fault = true;
            err_msg.* = try std.fmt.allocPrint(arena, "the job container's volume `{s}` binds a " ++
                "host path, which a job the runner does not vouch for (a fork's pull request " ++
                "included) never gets, whatever " ++ host_paths.setting ++ " allows", .{raw});
            return error.BaseContainerFailed;
        }
        // A rootless runner's job root is the runner's own user on the host, unmapped: what it
        // wrote would be the runner's, and its own files would be the job's to change.
        if (b.how.userns != .mapped) {
            b.job_fault = true;
            err_msg.* = try std.fmt.allocPrint(arena, "the job container's volume `{s}` binds a " ++
                "host path, which needs a root runner (a rootless runner's jobs are its own " ++
                "user on the host), whatever " ++ host_paths.setting ++ " allows", .{raw});
            return error.BaseContainerFailed;
        }
        var why: []const u8 = "";
        const ok = try host_paths.resolve(arena, b.io, b.allowed_host_paths, source, &why, .{}) orelse {
            b.job_fault = true;
            err_msg.* = try std.fmt.allocPrint(arena, "the job container's volume `{s}` binds a " ++
                "host path that is not allowed: {s}", .{ raw, why });
            return error.BaseContainerFailed;
        };
        b.binds = try std.mem.concat(arena, sandbox.Spec.Bind, &.{ b.binds, &.{.{
            .host = ok.path,
            .at = v.target,
            .read_only = v.read_only,
            .host_path = true,
            .unmapped_ok = b.host_paths_unmapped,
            .make = true,
        }} });
        n += 1;
        read_only += @intFromBool(v.read_only);
    }
    if (n == 0) return;
    try b.notes.append(arena, try std.fmt.allocPrint(arena, "Container volumes: {d} host " ++
        "path(s) bound ({d} read-only), nosuid and nodev, allowed by " ++ host_paths.setting, .{ n, read_only }));
    try b.notes.append(arena, if (b.host_paths_unmapped) "Container volumes: a host path whose " ++
        "filesystem cannot be idmapped is bound with the host's ids (" ++ host_paths.unmapped_setting ++
        "=true): what the job writes there is its slot's ids" else "Container volumes: a host " ++
        "path whose filesystem cannot be idmapped fails the step (" ++ host_paths.unmapped_setting ++
        "=true binds it with the host's ids)");
    for (b.host_paths_closed) |e| try b.notes.append(arena, try std.fmt.allocPrint(arena, "Container " ++
        "volumes: {s} entry `{s}` is closed for this job: it is not the directory checked when " ++
        "the runner started", .{ host_paths.setting, e }));
}

/// Whether the job's image is musl-based: an `ld-musl-*` in its /lib, as the Dagger path asks
/// (`services.pullJobContainer`), for its JavaScript actions' runtime (`js.zig`). A /lib that is
/// a symlink (a merged /usr, glibc's) or missing is not musl; nothing is followed.
pub fn isMusl(b: *Backend) bool {
    return rootfsIsMusl(b.arena, b.io, b.rootfs);
}

fn rootfsIsMusl(arena: Allocator, io: std.Io, rootfs: []const u8) bool {
    const lib = std.fmt.allocPrint(arena, "{s}/lib", .{rootfs}) catch return false;
    var dir = std.Io.Dir.cwd().openDir(io, lib, .{ .iterate = true, .follow_symlinks = false }) catch
        return false;
    defer dir.close(io);
    var it = dir.iterate();
    while (it.next(io) catch null) |e| {
        if (std.mem.startsWith(u8, e.name, "ld-musl-")) return true;
    }
    return false;
}

test "a musl image is told by its /lib, never through a symlink" {
    var a: std.heap.ArenaAllocator = .init(std.testing.allocator);
    defer a.deinit();
    const arena = a.allocator();
    const io = std.testing.io;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    const root = try tmp.dir.realPathFileAlloc(io, ".", arena);
    try tmp.dir.createDirPath(io, "alpine/lib");
    try tmp.dir.writeFile(io, .{ .sub_path = "alpine/lib/ld-musl-x86_64.so.1", .data = "" });
    try tmp.dir.createDirPath(io, "debian/usr/lib");
    try tmp.dir.symLink(io, "usr/lib", "debian/lib", .{});
    // A /lib that leads to another tree's musl loader is not followed.
    try tmp.dir.createDirPath(io, "odd");
    try tmp.dir.symLink(io, "../alpine/lib", "odd/lib", .{});
    const p = struct {
        fn f(ar: Allocator, r: []const u8, name: []const u8) Allocator.Error![]const u8 {
            return std.fmt.allocPrint(ar, "{s}/{s}", .{ r, name });
        }
    }.f;
    try std.testing.expect(rootfsIsMusl(arena, io, try p(arena, root, "alpine")));
    try std.testing.expect(!rootfsIsMusl(arena, io, try p(arena, root, "debian")));
    try std.testing.expect(!rootfsIsMusl(arena, io, try p(arena, root, "odd")));
    try std.testing.expect(!rootfsIsMusl(arena, io, try p(arena, root, "missing")));
}

/// `image` pulled into the store, or found there (`oci/image.zig`), within `pull_deadline`.
fn pull(b: *Backend, image: []const u8, creds: ?registry.Credentials, why: *[]const u8) !oci.Image {
    return b.pullBefore(image, creds, pull_deadline, why);
}

/// `pull` within `deadline`.
fn pullBefore(
    b: *Backend,
    image: []const u8,
    creds: ?registry.Credentials,
    deadline: std.Io.Duration,
    why: *[]const u8,
) !oci.Image {
    const img = try pullWithin(b.arena, b.gpa, b.io, b.store_cfg.root, b.how.userns == .mapped, image, creds, deadline, why);
    errdefer img.lock.close(b.io);
    // Held to the job's end, as its layers are: eviction leaves it alone (`evict.zig`).
    try b.held.append(b.arena, img.lock);
    return img;
}

/// `pull` without a job (`docker_action.unsupported`, which decides the backend before the job
/// starts): into the store at `root`, with the image's owners when `owners` (a root runner). The
/// caller closes the image's lock (`oci.Image.lock`).
pub fn pullAt(
    arena: Allocator,
    gpa: Allocator,
    io: std.Io,
    root: []const u8,
    owners: bool,
    image: []const u8,
    creds: ?registry.Credentials,
    why: *[]const u8,
) !oci.Image {
    return pullWithin(arena, gpa, io, root, owners, image, creds, pull_deadline, why);
}

fn pullWithin(
    arena: Allocator,
    gpa: Allocator,
    io: std.Io,
    root: []const u8,
    owners: bool,
    image: []const u8,
    creds: ?registry.Credentials,
    deadline: std.Io.Duration,
    why: *[]const u8,
) !oci.Image {
    var local: std.http.Client = .{
        .allocator = gpa,
        .io = io,
        .write_buffer_size = http.write_buffer_size,
    };
    defer local.deinit();
    const store: ImageStore = .{ .root = root };
    const req: oci.Request = .{ .image = image, .creds = creds, .owners = owners };
    const r = try http.within(io, deadline, pullInto, .{
        arena, gpa, io, http.client(&local), store, req, why,
    });
    return (r orelse {
        why.* = try std.fmt.allocPrint(arena, "it took longer than {d} minutes", .{@divTrunc(deadline.toSeconds(), 60)});
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
    return images.fromPulled(b.arena, b.io, img.rootfs, img.digest, img.manifest) catch |e| {
        why.* = "its configuration cannot be read";
        return e;
    };
}

fn pullInto(
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
    b.held.append(arena, made.lock) catch |e| {
        made.lock.close(b.io);
        return e;
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
        const top = b.layers.items[b.layers.items.len - 1];
        const upper = top.path;
        // The step's layer is consumed; the job's other layers, if any, stay.
        defer {
            removeTree(arena, b.io, upper);
            _ = b.layers.pop();
        }
        if (ended.failure.len > 0 or ended.code != 0) {
            // Its last lines: apt's own last line ("dpkg returned an error code") says little.
            p.why = try std.fmt.allocPrint(arena, "{s}{s} (exit {d})", .{ ended.failure, out.tailLines(8), ended.code });
            return error.ProvisionFailed;
        }
        // On a root runner the layer belongs to the job's range of ids (unless its upper was written
        // through an idmapped mount, with the image's own already): back to the image's.
        const shift: u32 = if (b.how.userns == .mapped and !top.canonical) b.idBase() else 0;
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
pub fn plaintext(x: *Exec, id: []const u8) []const u8 {
    var it = x.secrets.ids.iterator();
    while (it.next()) |e| if (std.mem.eql(u8, e.value_ptr.*, id)) return e.key_ptr.*;
    return "";
}

/// A step's output fed to the job's log as Dagger's log stream feeds it: one span per exec.
pub const Live = struct {
    demux: *SpanDemux,
    arena: Allocator,
    /// Under step caching, the output as printed, for the store (`Store.Record.log`); null past
    /// `Store.max_record_bytes`, and the step is then not published.
    record: ?std.ArrayList(u8),

    pub fn output(l: *Live) sandbox.Output {
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
pub const Captured = struct {
    arena: Allocator,
    text: std.ArrayList(u8) = .empty,

    const keep = 4096;

    pub fn output(c: *Captured) sandbox.Output {
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

    pub fn tail(c: *const Captured) []const u8 {
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
const forward = @import("forward.zig");
const base_answer = @import("../dagger/testing.zig").base_answer;
const execAnswer = @import("../dagger/testing.zig").exec;

/// A native backend for tests, or `error.SkipZigTest` with the reason printed when this machine
/// cannot run one (a failure instead where `ZIG_RUNNER_REQUIRE_NATIVE=1`, as CI sets: there they
/// must run): a rootfs of a few directories with the host's /usr bound over it, in the
/// test's directory, and the runner binary the build copied for the tests (`ZIG_RUNNER_TEST_EXE`).
/// Rootless unless the tests run as root, where the job gets its range of ids and its network.
/// The host's /etc/pki for a test whose steps verify TLS on the host's rootfs (`testConfig`'s):
/// RHEL's /etc/ssl/certs and cert.pem are links into it. Only such a test asks for it, as a
/// container job's image has no /etc/pki to bind it onto.
fn withHostPki(arena: Allocator, tmp: *std.testing.TmpDir, cfg: *Config) !void {
    const io = std.testing.io;
    std.Io.Dir.cwd().access(io, "/etc/pki", .{}) catch return;
    try tmp.dir.createDirPath(io, "rootfs/etc/pki");
    cfg.binds = try std.mem.concat(arena, sandbox.Spec.Bind, &.{ cfg.binds, &.{.{
        .host = "/etc/pki",
        .at = "/etc/pki",
    }} });
}

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
    var cfg = try testConfigAt(arena, try d.realPathFileAlloc(io, ".", arena), exe);
    // As root, the root runner's path where this machine has it: under limits, in a tree of the
    // tests' own. They do not depend on it: nothing here takes more than it asks for by itself,
    // and the tests that reach limits have parents of their own (`testCgroup`).
    if (std.os.linux.geteuid() == 0 and cgroup.parent(arena, io, test_parent) == .dir)
        cfg.cgroup.parent = test_parent;
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

/// `testConfig`'s backend over the directory `root` it made, with the runner binary `exe`: for a
/// process of a test's own (`store_stress.zig`), whose jobs must key alike with the test's.
pub fn testConfigAt(arena: Allocator, root: []const u8, exe: []const u8) !Config {
    return .{
        .rootfs = try std.fmt.allocPrint(arena, "{s}/rootfs", .{root}),
        .store = try std.fmt.allocPrint(arena, "{s}/store", .{root}),
        .self_exe = exe,
        .vouched = true,
        .rootless = true,
        .check_store_parents = false,
        // Rootless tests have no cgroup to run in, and most machines none to delegate.
        .cgroup = .{ .parent = "none" },
        .binds = &.{
            .{ .host = "/usr", .at = "/usr" },
            .{ .host = "/etc/ld.so.cache", .at = "/etc/ld.so.cache" },
            // CA certificates, for the outbound test's HTTPS.
            .{ .host = "/etc/ssl", .at = "/etc/ssl" },
        },
    };
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

test "a native job's result comes back before its teardown, which holds the job's directory until it runs" {
    try requireRoot();
    var a: std.heap.ArenaAllocator = .init(std.testing.allocator);
    defer a.deinit();
    const arena = a.allocator();
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    const cfg = try testConfig(arena, &tmp);
    var env: std.process.Environ.Map = .init(arena);
    var w: std.Io.Writer.Allocating = .init(arena);
    var log: sink.LogSink = .{ .stdout = .{ .writer = &w.writer } };
    var res = try dagger.run(arena, std.testing.io, &env, .{
        .native = cfg,
        .step_user = .root,
        .gpa = std.testing.allocator,
        .defer_teardown = true,
    }, testJob(&.{testStep("echo reported-first")}), &log);
    try std.testing.expect(res.succeeded);
    // The result is in hand, and the job is still up: its directory is there, and no teardown
    // phase (down to the store's eviction) has been timed.
    const t = res.teardown orelse return error.TestUnexpectedResult;
    try std.testing.expect(res.native_phases == null);
    const jobs_path = try std.fmt.allocPrint(arena, "{s}/jobs", .{cfg.store});
    {
        var jobs = try std.Io.Dir.cwd().openDir(std.testing.io, jobs_path, .{ .iterate = true });
        defer jobs.close(std.testing.io);
        var it = jobs.iterate();
        try std.testing.expect(try it.next(std.testing.io) != null);
    }
    try std.testing.expect(!t.done);
    const timed = t.run() orelse return error.TestUnexpectedResult;
    try std.testing.expect(std.mem.indexOf(u8, timed, "collect=") != null);
    // Once: the second call changes nothing and returns the same phases.
    try std.testing.expectEqualStrings(timed, t.run().?);
    res.teardown = null;
    var jobs = try std.Io.Dir.cwd().openDir(std.testing.io, jobs_path, .{ .iterate = true });
    defer jobs.close(std.testing.io);
    var it = jobs.iterate();
    try std.testing.expect(try it.next(std.testing.io) == null);
}

test "a cancel stops a native step, and every process it started, well inside the ladder" {
    var a: std.heap.ArenaAllocator = .init(std.testing.allocator);
    defer a.deinit();
    const arena = a.allocator();
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    const cfg = try testConfig(arena, &tmp);

    var s1 = testStep("sleep 613.70 & sleep 613.70");
    s1.name = "long";
    var s2 = testStep("echo after");
    s2.condition = "always()";
    const r = try runCancelled(arena, cfg, testJob(&.{ s1, s2 }), .{ .when = "613.70" });
    try std.testing.expectEqual(dagger.Outcome.cancelled, r.res.steps[0].outcome);
    try std.testing.expectEqual(dagger.Outcome.success, r.res.steps[1].outcome);
    try std.testing.expect(r.res.cancelled);
    // The foreground `sleep` took SIGINT with it, the shell went too, and the backgrounded one,
    // which ignores SIGINT as a shell's background job does, went with the step's namespace: its
    // pipe closed, so the job went on.
    try std.testing.expect(r.took_ms < 5_000);
    try std.testing.expect(!processRuns("613.70"));
}

test "a cancel's SIGINT reaches a native step's foreground child, and the step's trap then runs" {
    var a: std.heap.ArenaAllocator = .init(std.testing.allocator);
    defer a.deinit();
    const arena = a.allocator();
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    const cfg = try testConfig(arena, &tmp);

    // A signal to the shell alone would wait for its `sleep`, as on GitHub, whose runner signals
    // only the step's entry process.
    const s1 = testStep("trap 'echo cleaned-up; echo int > got-int' INT\nsleep 613.71\n" ++
        "echo not\"\"-this");
    var s2 = testStep("cat got-int");
    s2.condition = "always()";
    const r = try runCancelled(arena, cfg, testJob(&.{ s1, s2 }), .{ .when = "613.71" });
    errdefer std.debug.print("{s}\n", .{r.text});
    try std.testing.expectEqual(dagger.Outcome.cancelled, r.res.steps[0].outcome);
    try std.testing.expectEqual(dagger.Outcome.success, r.res.steps[1].outcome);
    try expectLines(r.text, &.{
        "The job was cancelled: stopping the step with SIGINT, then SIGTERM in ",
        "cleaned-up",
        // The step's own log, as GitHub's runner ends it.
        "##[error]The operation was canceled.",
    });
    try std.testing.expect(std.mem.indexOf(u8, r.text, "not-this") == null);
    // It ended when it was done, not when the ladder was.
    try std.testing.expect(r.took_ms < 5_000);
    try std.testing.expect(!processRuns("613.71"));
}

test "a native step that takes no SIGINT hears SIGTERM 7500 ms on, and its end counts as cancelled" {
    var a: std.heap.ArenaAllocator = .init(std.testing.allocator);
    defer a.deinit();
    const arena = a.allocator();
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    const cfg = try testConfig(arena, &tmp);

    const s1 = testStep("trap '' INT\ntrap 'echo cleaned-up; echo term > got-term; exit 0' TERM\n" ++
        "sleep 613.72 &\nwait");
    var s2 = testStep("cat got-term");
    s2.condition = "always()";
    const r = try runCancelled(arena, cfg, testJob(&.{ s1, s2 }), .{ .when = "613.72" });
    errdefer std.debug.print("took {d} ms:\n{s}\n", .{ r.took_ms, r.text });
    // It exited 0, and is cancelled still (`ProcessInvoker.cs`: `ThrowIfCancellationRequested`).
    try std.testing.expectEqual(dagger.Outcome.cancelled, r.res.steps[0].outcome);
    try std.testing.expectEqual(dagger.Outcome.success, r.res.steps[1].outcome);
    try expectLines(r.text, &.{ "The step is still running: SIGTERM sent.", "cleaned-up" });
    try std.testing.expect(r.took_ms >= sigint_ms - 300);
    try std.testing.expect(r.took_ms < sigint_ms + 2_000);
    try std.testing.expect(!processRuns("613.72"));
}

test "a native step that ignores every signal is dead at the ladder's end, whatever it started" {
    var a: std.heap.ArenaAllocator = .init(std.testing.allocator);
    defer a.deinit();
    const arena = a.allocator();
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    const cfg = try testConfig(arena, &tmp);

    // A session of its own, a subshell, a plain background job: all ignoring what the shell does.
    // Each ends by itself if the kill fails, and the checks below then fail.
    const job = testJob(&.{testStep("trap '' INT TERM HUP\nsetsid sleep 613.73 &\n" ++
        "( sleep 613.73; : ) &\nsleep 613.73 &\nsleep 0.2\nfor i in $(seq 1 300); do sleep 0.1; " ++
        "done\necho out\"\"lived-the-ladder")});
    const r = try runCancelled(arena, cfg, job, .{
        .when = "613.73",
        .grace_ms = 3_000,
        .why = .runner_stopping,
    });
    errdefer std.debug.print("took {d} ms:\n{s}\n", .{ r.took_ms, r.text });
    try std.testing.expectEqual(dagger.Outcome.cancelled, r.res.steps[0].outcome);
    try expectLines(r.text, &.{
        // Less than the limit by when the watch saw the cancel.
        "The runner is stopping: stopping the step with SIGINT, then SIGTERM in ",
        "The step is still running: SIGTERM sent.",
        "The step did not stop: killing it.",
    });
    try std.testing.expect(std.mem.indexOf(u8, r.text, "outlived-the-ladder") == null);
    // The whole limit, and the ladder ended with it: a tick (200 ms) and the job's own end late.
    try std.testing.expect(r.took_ms >= 2_800);
    try std.testing.expect(r.took_ms < 6_000);
    try std.testing.expect(!processRuns("613.73"));
}

test "a native step that forks all through the ladder leaves nothing at its end" {
    var a: std.heap.ArenaAllocator = .init(std.testing.allocator);
    defer a.deinit();
    const arena = a.allocator();
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    const cfg = try testConfig(arena, &tmp);

    // Slowly enough to need no limit of its own: this test also runs with no cgroup.
    const job = testJob(&.{testStep("trap '' INT TERM\n" ++
        "for i in $(seq 1 300); do sleep 613.74 & sleep 0.1; done\necho out\"\"lived-the-ladder")});
    // No cancel limit near: only the ladder's own last stage can end it.
    const r = try runCancelled(arena, cfg, job, .{ .when = "613.74" });
    errdefer std.debug.print("took {d} ms:\n{s}\n", .{ r.took_ms, r.text });
    try std.testing.expectEqual(dagger.Outcome.cancelled, r.res.steps[0].outcome);
    try std.testing.expect(std.mem.indexOf(u8, r.text, "outlived-the-ladder") == null);
    try expectLines(r.text, &.{"The step did not stop: killing it."});
    try std.testing.expect(r.took_ms >= 9_800);
    try std.testing.expect(r.took_ms < 12_500);
    try std.testing.expect(!processRuns("613.74"));
}

test "a task's cancel stops a native step at once, and the job's own end still runs" {
    var a: std.heap.ArenaAllocator = .init(std.testing.allocator);
    defer a.deinit();
    const arena = a.allocator();
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    const cfg = try testConfig(arena, &tmp);
    const io = std.testing.io;

    const Job = struct {
        fn run(arena_: Allocator, cfg_: Config) anyerror!dagger.Result {
            var env: std.process.Environ.Map = .init(arena_);
            var w: std.Io.Writer.Allocating = .init(arena_);
            var log: sink.LogSink = .{ .stdout = .{ .writer = &w.writer } };
            // It ends by itself if the cancel does nothing, and the check below then fails.
            return dagger.run(arena_, io, &env, .{
                .native = cfg_,
                .step_user = .root,
                .gpa = std.testing.allocator,
            }, testJob(&.{testStep("sleep 12.75")}), &log);
        }
    };
    var job = try io.concurrent(Job.run, .{ arena, cfg });
    var cancelled = false;
    defer if (!cancelled) {
        _ = job.cancel(io) catch {};
    };
    try waitForProcess("12.75");
    const started = std.Io.Clock.awake.now(io).toMilliseconds();
    cancelled = true;
    _ = job.cancel(io) catch {};
    try std.testing.expect(std.Io.Clock.awake.now(io).toMilliseconds() - started < 8_000);
    try std.testing.expect(!processRuns("12.75"));
    // The job's layers went with it, its directory and locks (`deinit`).
    const jobs_path = try std.fmt.allocPrint(arena, "{s}/jobs", .{cfg.store});
    var jobs = try std.Io.Dir.cwd().openDir(io, jobs_path, .{ .iterate = true });
    defer jobs.close(io);
    var it = jobs.iterate();
    try std.testing.expect(try it.next(io) == null);
}

test "a task's cancel that lands in a sink's write of a native step's output is not lost" {
    var a: std.heap.ArenaAllocator = .init(std.testing.allocator);
    defer a.deinit();
    const arena = a.allocator();
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    const cfg = try testConfig(arena, &tmp);
    const io = std.testing.io;

    const Slow = struct {
        reached: std.atomic.Value(bool) = .init(false),

        /// A sink that waits, and sees nothing wrong in a cancel.
        fn chunk(ptr: *anyopaque, _: []const u8) void {
            const s: *@This() = @ptrCast(@alignCast(ptr));
            s.reached.store(true, .release);
            io.sleep(.fromSeconds(1), .awake) catch {};
        }

        fn run(s: *@This(), b: *Backend) anyerror!sandbox.Ended {
            // It ends by itself if the cancel is lost, and the check below then fails.
            return b.exec("echo first; sleep 12.79", &.{"PATH=/usr/bin:/bin"}, &.{}, 0, 0, .{
                .ptr = s,
                .chunkFn = chunk,
            });
        }
    };
    var b = try init(arena, io, std.testing.allocator, cfg);
    defer b.deinit();
    var slow: Slow = .{};
    var running = try io.concurrent(Slow.run, .{ &slow, &b });
    var cancelled = false;
    defer if (!cancelled) {
        _ = running.cancel(io) catch {};
    };
    for (0..3000) |_| {
        if (slow.reached.load(.acquire)) break;
        try io.sleep(.fromMilliseconds(10), .awake);
    }
    const started = std.Io.Clock.awake.now(io).toMilliseconds();
    cancelled = true;
    _ = running.cancel(io) catch {};
    try std.testing.expect(std.Io.Clock.awake.now(io).toMilliseconds() - started < 8_000);
}

/// `dagger.Watch`'s first stage, for the tests that wait it out.
const sigint_ms = 7_500;

/// How `runCancelled` cancels a job.
pub const CancelPlan = struct {
    /// A number on a `sleep` the job runs (`processRuns`): the cancel comes once it is running.
    when: []const u8,
    /// What the job's cancel limit leaves, from the cancel.
    grace_ms: i64 = 60_000,
    why: dagger.Cancel.Why = .github,
    /// The job uses the layer store, shared with later jobs.
    step_cache: bool = false,
};

/// `job` on the native backend, cancelled as `plan` says; `took_ms` runs from the cancel to the
/// job's end. Its `sleep`s are what the cancel waits for, so a slow machine still cancels a step
/// that has set its traps.
pub fn runCancelled(arena: Allocator, cfg: Config, job: job_mod.Job, plan: CancelPlan) !struct {
    res: dagger.Result,
    text: []const u8,
    took_ms: i64,
} {
    const io = std.testing.io;
    var cancel: dagger.Cancel = .{};
    var cancelled_at: std.atomic.Value(i64) = .init(0);
    var env: std.process.Environ.Map = .init(arena);
    var w: std.Io.Writer.Allocating = .init(arena);
    var log: sink.LogSink = .{ .stdout = .{ .writer = &w.writer } };
    var canceller = try io.concurrent(cancelOnce, .{ &cancel, plan, &cancelled_at });
    defer canceller.cancel(io);
    const res = try dagger.run(arena, io, &env, .{
        .native = cfg,
        .step_user = .root,
        .gpa = std.testing.allocator,
        .cancel = &cancel,
        .step_cache = plan.step_cache,
    }, job, &log);
    return .{
        .res = res,
        .text = w.written(),
        .took_ms = std.Io.Clock.awake.now(io).toMilliseconds() - cancelled_at.load(.acquire),
    };
}

fn cancelOnce(cancel: *dagger.Cancel, plan: CancelPlan, at: *std.atomic.Value(i64)) void {
    const io = std.testing.io;
    waitForProcess(plan.when) catch return;
    at.store(std.Io.Clock.awake.now(io).toMilliseconds(), .release);
    cancel.requestBecause(std.Io.Clock.real.now(io).toMilliseconds() + plan.grace_ms, plan.why);
}

/// Waits until `processRuns(number)`, for a minute at the most: whoever waits then fails on what
/// it expected, and does not hang.
fn waitForProcess(number: []const u8) !void {
    for (0..600) |_| {
        if (processRuns(number)) return;
        try std.testing.io.sleep(.fromMilliseconds(100), .awake);
    }
}

/// Whether a `sleep <number>` runs on this machine, seen from outside any namespace. The numbers
/// are the tests' own. Exactly that command line, or `sleep` behind a path or a shebang's
/// arguments (RHEL's single-binary coreutils shows `/usr/bin/coreutils --coreutils-prog-shebang=sleep
/// /usr/bin/sleep 613.7`): a step's `sh -c` holds its script's text too.
fn processRuns(number: []const u8) bool {
    const io = std.testing.io;
    var name_buf: [64]u8 = undefined;
    const want = std.fmt.bufPrint(&name_buf, "sleep\x00{s}\x00", .{number}) catch return false;
    var proc = std.Io.Dir.cwd().openDir(io, "/proc", .{ .iterate = true }) catch return false;
    defer proc.close(io);
    var it = proc.iterate();
    while (it.next(io) catch null) |e| {
        _ = std.fmt.parseInt(u32, e.name, 10) catch continue;
        var path_buf: [64]u8 = undefined;
        const path = std.fmt.bufPrint(&path_buf, "{s}/cmdline", .{e.name}) catch continue;
        var buf: [128]u8 = undefined;
        const line = proc.readFile(io, path, &buf) catch continue;
        if (!std.mem.endsWith(u8, line, want)) continue;
        const before = line.len - want.len;
        if (before == 0 or line[before - 1] == '/') return true;
    }
    return false;
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
    // Submodules are fetched natively (`fetchCheckout`), whether literal or an expression.
    for ([_]job_mod.Template{ .{ .lit = "true" }, .{ .lit = "recursive" }, .{ .expr = "inputs.s" } }) |v| {
        co.action = .{ .checkout = &.{.{ .name = "submodules", .value = v }} };
        try std.testing.expect(unsupported(io, testJob(&.{co}), root, ok) == null);
    }

    var uses = testStep("");
    uses.action = .{ .uses = .{ .owner = "actions", .name = "setup-node", .ref = "v4" } };
    // Decided once the action is fetched (`actions.preload`), not here.
    try std.testing.expect(unsupported(io, testJob(&.{uses}), root, ok) == null);

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
    // `container:` jobs and any image are pulled natively; a job container's ports and volumes
    // are not native yet, and its options only the ones `container_options.zig` carries out.
    var container = run_only;
    container.container = .{ .name = "", .image = .{ .lit = "node:22" } };
    try std.testing.expect(unsupported(io, container, root, ok) == null);
    // Ports are published natively by a root runner (`publishPorts`); a rootless runner's steps
    // share the host's network, and a range is not native anywhere.
    container.container.?.ports = &.{.{ .lit = "8080:80" }};
    if (std.os.linux.geteuid() == 0)
        try std.testing.expect(unsupported(io, container, root, ok) == null)
    else
        try expectReason("rootless", unsupported(io, container, root, ok));
    container.container.?.ports = &.{.{ .lit = "8000-8010:8000-8010" }};
    try expectReason("`8000-8010:8000-8010`", unsupported(io, container, root, ok));
    container.container.?.ports = &.{};
    // Volumes that are directories of the job are native, and so is a path of the host (allowed
    // or failed when the job starts, `hostVolumes`); a read-only anonymous one is not.
    container.container.?.volumes = &.{ .{ .lit = "/data" }, .{ .lit = "cache:/cache:ro" } };
    try std.testing.expect(unsupported(io, container, root, ok) == null);
    container.container.?.volumes = &.{.{ .lit = "/srv:/srv" }};
    try std.testing.expect(unsupported(io, container, root, ok) == null);
    container.container.?.volumes = &.{.{ .lit = "/data:ro" }};
    try expectReason("`/data:ro`", unsupported(io, container, root, ok));
    // A service mounts no volume natively, so it cannot share a named one.
    container.container.?.volumes = &.{.{ .lit = "shared:/shared" }};
    var with_volumes = container;
    with_volumes.services = &.{.{ .name = "db", .image = .{ .lit = "postgres:17" }, .volumes = &.{.{ .lit = "shared:/s" }} }};
    try expectReason("service", unsupported(io, with_volumes, root, ok));
    container.container.?.volumes = &.{};
    // An option the sandbox does not carry out is named, never dropped; the others are native.
    container.container.?.options = .{ .lit = "--cpus 1" };
    try expectReason("`--cpus`", unsupported(io, container, root, ok));
    container.container.?.options = .{ .lit = "--user 1001 -e A=1 --workdir /w --health-cmd true" };
    try std.testing.expect(unsupported(io, container, root, ok) == null);
    container.container.?.options = .{ .lit = "--hostname h --add-host a:10.0.0.1 --shm-size 1g " ++
        "--tmpfs /scratch --memory 1g --init" };
    try std.testing.expect(unsupported(io, container, root, ok) == null);
    // What would widen the sandbox is never native: each is named, and Dagger's drop of it said.
    for ([_][]const u8{ "--privileged", "--cap-add NET_ADMIN", "--security-opt apparmor=unconfined", "--device /dev/fuse", "--network host", "--pid host", "--ipc host", "--userns host" }) |flag| {
        container.container.?.options = .{ .lit = flag };
        const why = unsupported(io, container, root, ok);
        try expectReason(flag[0 .. std.mem.indexOfScalar(u8, flag, ' ') orelse flag.len], why);
        try expectReason("Dagger drops", why);
    }
    container.container.?.options = .{ .expr = "matrix.options" };
    try expectReason("expression", unsupported(io, container, root, ok));
    container.container.?.options = null;
    var custom = root;
    custom.image = "alpine:3";
    try std.testing.expect(unsupported(io, run_only, custom, ok) == null);
    custom.provision = false;
    try std.testing.expect(unsupported(io, run_only, custom, ok) == null);
    var nesting = root;
    nesting.nesting = true;
    const nesting_why = unsupported(io, run_only, nesting, ok);
    try expectReason("`dagger call` in a step", nesting_why);
    try expectReason("needs a Dagger engine", nesting_why);
    try expectReason("RUNNER_ENGINE not `none`", nesting_why);
    try expectReason("a pool that needs it keeps an engine", nesting_why);

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

    // `hashFiles()` is native: the runner reads the job's layers (`hash_files.zig`), in any
    // expression and in any case.
    var hashed = testStep("true");
    hashed.env = &.{.{ .name = "K", .value = .{ .expr = "HASHFILES('**/go.sum')" } }};
    try std.testing.expect(unsupported(io, testJob(&.{hashed}), root, ok) == null);
    var hashed_if = testStep("true");
    hashed_if.condition = "hashFiles('x') != ''";
    try std.testing.expect(unsupported(io, testJob(&.{hashed_if}), root, ok) == null);

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

test "a job sent to Dagger that cannot start it fails with the reason it was sent and what Dagger lacked" {
    var a: std.heap.ArenaAllocator = .init(std.testing.allocator);
    defer a.deinit();
    const arena = a.allocator();
    var env: std.process.Environ.Map = .init(arena);
    var w: std.Io.Writer.Allocating = .init(arena);
    var log: sink.LogSink = .{ .stdout = .{ .writer = &w.writer } };
    // No `dagger_cmd` that exists (a test's is /nonexistent/dagger), as in a stress test's workers.
    const res = try dagger.run(arena, std.testing.io, &env, .{
        .native = .{ .vouched = true, .rootless = true },
    }, testJob(&.{testStep("echo hi")}), &log);
    try std.testing.expect(!res.succeeded);
    const msg = res.engine_error orelse "";
    try std.testing.expect(std.mem.indexOf(u8, msg, "`/nonexistent/dagger`") != null);
    try std.testing.expect(std.mem.indexOf(u8, msg, "not found on PATH") != null);
    try std.testing.expect(std.mem.indexOf(u8, msg, ". This job runs on Dagger: the native " ++
        "store is not set up") != null);
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

/// A repository with a submodule that has a submodule: `o/r.git` holds `sub` (file `in-sub`), which
/// holds `deep` (file `in-deep`), all at file:// URLs under the returned root, which the job's
/// sandbox sees at the same path (`cfg.binds`). Null when git is missing.
fn submoduleRepos(arena: Allocator, cfg: *Config, tmp: *std.testing.TmpDir) !?struct {
    root: []const u8,
    sha: []const u8,
} {
    const io = std.testing.io;
    const root = try tmp.dir.realPathFileAlloc(io, ".", arena);
    const g = "git -c user.name=t -c user.email=t@t -c protocol.file.allow=always";
    const make = try std.fmt.allocPrint(arena, "set -e; cd '{[r]s}'; " ++
        "for n in deep sub r; do git init -q -b main --bare o/$n.git; git init -q -b main src-$n; done; " ++
        "cd src-deep; echo in-deep > in-deep; git add .; {[g]s} commit -q -m deep; " ++
        "git push -q ../o/deep.git HEAD:refs/heads/main; cd ../src-sub; echo in-sub > in-sub; " ++
        "{[g]s} submodule add -q file://{[r]s}/o/deep.git deep; git add .; " ++
        "{[g]s} commit -q -m sub; git push -q ../o/sub.git HEAD:refs/heads/main; cd ../src-r; " ++
        "echo in-r > in-r; {[g]s} submodule add -q file://{[r]s}/o/sub.git sub; git add .; " ++
        "{[g]s} commit -q -m r; git push -q ../o/r.git HEAD:refs/heads/main", .{
        .r = root,
        .g = g,
    });
    const made = std.process.run(arena, io, .{ .argv = &.{ "sh", "-c", make } }) catch return null;
    if (made.term != .exited or made.term.exited != 0) {
        std.debug.print("git could not make the repositories: {s}\n", .{made.stderr});
        return null;
    }
    const sha = std.mem.trim(u8, (try std.process.run(arena, io, .{
        .argv = &.{ "git", "-C", try std.fmt.allocPrint(arena, "{s}/src-r", .{root}), "rev-parse", "HEAD" },
    })).stdout, "\n");
    try tmp.dir.createDirPath(io, try std.fmt.allocPrint(arena, "rootfs/{s}", .{root}));
    cfg.binds = try std.mem.concat(arena, sandbox.Spec.Bind, &.{
        cfg.binds,
        &.{.{ .host = root, .at = root }},
    });
    return .{ .root = root, .sha = sha };
}

/// The job's env for a checkout from those repositories: the owner check off (they are the host's
/// root's, nobody in the job's namespace) and the file transport on for submodules (git refuses it
/// by default; GitHub's are HTTPS).
const file_repos_env = [_]job_mod.Input{.{
    .name = "GIT_CONFIG_PARAMETERS",
    .value = .{ .lit = "'safe.directory=*' 'protocol.file.allow=always'" },
}};

test "the native checkout's submodules: `true` the first level, `recursive` all, `false` none" {
    var a: std.heap.ArenaAllocator = .init(std.testing.allocator);
    defer a.deinit();
    const arena = a.allocator();
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    var cfg = try testConfig(arena, &tmp);
    const repos = (try submoduleRepos(arena, &cfg, &tmp)) orelse
        return skip(false, "git is not installed");

    // What actions/checkout leaves for each: the submodule's files and its own submodule's.
    const cases = [_]struct { input: ?[]const u8, sub: bool, deep: bool }{
        .{ .input = null, .sub = false, .deep = false },
        .{ .input = "false", .sub = false, .deep = false },
        .{ .input = "true", .sub = true, .deep = false },
        .{ .input = "recursive", .sub = true, .deep = true },
    };
    for (cases) |c| {
        var co = testStep("");
        co.name = "checkout";
        co.action = .{ .checkout = if (c.input) |v| &.{
            .{ .name = "submodules", .value = .{ .lit = v } },
        } else &.{} };
        const check = testStep("echo r=$(cat in-r) sub=$(test -f sub/in-sub && echo yes || " ++
            "echo no) deep=$(test -f sub/deep/in-deep && echo yes || echo no); " ++
            "echo mtime=$(stat -c %Y in-r)");
        var job = testJob(&.{ co, check });
        job.github.server_url = try std.fmt.allocPrint(arena, "file://{s}", .{repos.root});
        job.github.sha = repos.sha;
        job.env = &file_repos_env;
        var env: std.process.Environ.Map = .init(arena);
        var w: std.Io.Writer.Allocating = .init(arena);
        var log: sink.LogSink = .{ .stdout = .{ .writer = &w.writer } };
        const res = try dagger.run(arena, std.testing.io, &env, .{
            .native = cfg,
            .step_user = .root,
            .gpa = std.testing.allocator,
        }, job, &log);
        const text = w.written();
        const want = try std.fmt.allocPrint(arena, "r=in-r sub={s} deep={s}", .{
            if (c.sub) "yes" else "no",
            if (c.deep) "yes" else "no",
        });
        if (res.steps[0].outcome != .success or res.steps[1].outcome != .success or
            std.mem.indexOf(u8, text, want) == null)
        {
            std.debug.print("submodules {s}: wanted {s}; engine {s}\n{s}\n", .{
                c.input orelse "(unset)", want, res.engine_error orelse "-", text,
            });
            return error.TestUnexpectedResult;
        }
    }
}

test "native step cache: a checkout with submodules never replays one without, or with fewer" {
    var a: std.heap.ArenaAllocator = .init(std.testing.allocator);
    defer a.deinit();
    const arena = a.allocator();
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    var c = try cachedConfig(arena, &tmp);
    const repos = (try submoduleRepos(arena, &c.cfg, &tmp)) orelse
        return skip(false, "git is not installed");

    // The same commit three ways, each leaving something else: each runs its checkout once and
    // is replayed after that, never from another's layer.
    const inputs = [_][]const u8{ "false", "true", "recursive" };
    const seen = [_][]const u8{ "sub=no deep=no", "sub=yes deep=no", "sub=yes deep=yes" };
    for (inputs, seen, 0..) |input, want, i| {
        var co = testStep("");
        co.name = "checkout";
        co.action = .{ .checkout = &.{
            .{ .name = "ref", .value = .{ .lit = repos.sha } },
            .{ .name = "submodules", .value = .{ .lit = input } },
        } };
        const check = testStep("echo sub=$(test -f sub/in-sub && echo yes || echo no) " ++
            "deep=$(test -f sub/deep/in-deep && echo yes || echo no)");
        var job = testJob(&.{ co, check });
        job.github.server_url = try std.fmt.allocPrint(arena, "file://{s}", .{repos.root});
        job.env = &file_repos_env;
        const first = try runCached(arena, c.cfg, job, try std.fmt.allocPrint(arena, "a{d}", .{i}));
        try expectSucceeded(first);
        if (std.mem.indexOf(u8, first.text, want) == null) {
            std.debug.print("wanted {s} on the first run:\n{s}\n", .{ want, first.text });
            return error.TestUnexpectedResult;
        }
        try std.testing.expectEqual(@as(usize, 0), std.mem.count(u8, first.text, dagger.native_reused_note));
        const again = try runCached(arena, c.cfg, job, try std.fmt.allocPrint(arena, "b{d}", .{i}));
        try expectSucceeded(again);
        try std.testing.expectEqual(@as(usize, 2), std.mem.count(u8, again.text, dagger.native_reused_note));
        try std.testing.expect(std.mem.indexOf(u8, again.text, want) != null);
    }
}

test "native step cache: a checkout with submodules and tags is fetched again, not replayed" {
    var a: std.heap.ArenaAllocator = .init(std.testing.allocator);
    defer a.deinit();
    const arena = a.allocator();
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    var c = try cachedConfig(arena, &tmp);
    const repos = (try submoduleRepos(arena, &c.cfg, &tmp)) orelse
        return skip(false, "git is not installed");

    // A submodule's tags move with the commit staying, and the key has only the top repository's.
    var co = testStep("");
    co.name = "checkout";
    co.action = .{ .checkout = &.{
        .{ .name = "ref", .value = .{ .lit = repos.sha } },
        .{ .name = "submodules", .value = .{ .lit = "true" } },
        .{ .name = "fetch-tags", .value = .{ .lit = "true" } },
    } };
    var job = testJob(&.{ co, testStep("echo sub=$(test -f sub/in-sub && echo yes || echo no)") });
    job.github.server_url = try std.fmt.allocPrint(arena, "file://{s}", .{repos.root});
    job.env = &file_repos_env;
    try expectSucceeded(try runCached(arena, c.cfg, job, "a"));
    const again = try runCached(arena, c.cfg, job, "b");
    try expectSucceeded(again);
    try std.testing.expect(std.mem.indexOf(u8, again.text, "sub=yes") != null);
    try std.testing.expect(std.mem.count(u8, again.text, dagger.native_reused_note) < 2);
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

test "native step cache: a checkout of a commit with fetch-tags sees the tags as they are now" {
    var a: std.heap.ArenaAllocator = .init(std.testing.allocator);
    defer a.deinit();
    const arena = a.allocator();
    const io = std.testing.io;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    var c = try cachedConfig(arena, &tmp);
    const root = try tmp.dir.realPathFileAlloc(io, ".", arena);
    const git = try std.fmt.allocPrint(arena, "git -c user.name=t -c user.email=t@t -C '{s}/src'", .{root});
    const make = try std.fmt.allocPrint(arena, "set -e; cd '{s}'; git init -q --bare o/r.git; " ++
        "git init -q src; cd src; echo one > file; git add file; {s} commit -q -m one; " ++
        "{s} tag v1; {s} push -q ../o/r.git HEAD:refs/heads/main v1; " ++
        "echo two > file; {s} commit -qam two; {s} push -q ../o/r.git HEAD:refs/heads/main", .{
        root, git, git, git, git, git,
    });
    const made = std.process.run(arena, io, .{ .argv = &.{ "sh", "-c", make } }) catch
        return skip(false, "git is not installed");
    if (made.term != .exited or made.term.exited != 0)
        return skip(false, "git could not make a repository");
    const sha = std.mem.trim(u8, (try std.process.run(arena, io, .{
        .argv = &.{ "git", "-C", try std.fmt.allocPrint(arena, "{s}/src", .{root}), "rev-parse", "HEAD" },
    })).stdout, "\n");
    try tmp.dir.createDirPath(io, try std.fmt.allocPrint(arena, "rootfs/{s}", .{root}));
    c.cfg.binds = try std.mem.concat(arena, sandbox.Spec.Bind, &.{
        c.cfg.binds,
        &.{.{ .host = root, .at = root }},
    });

    var co = testStep("");
    co.name = "checkout";
    co.action = .{ .checkout = &.{
        .{ .name = "ref", .value = .{ .lit = sha } },
        .{ .name = "fetch-tags", .value = .{ .lit = "true" } },
    } };
    const check = testStep("echo tag-v1=$(git rev-parse --short v1)");
    var job = testJob(&.{ co, check });
    job.github.server_url = try std.fmt.allocPrint(arena, "file://{s}", .{root});
    job.env = &.{.{ .name = "GIT_CONFIG_PARAMETERS", .value = .{ .lit = "'safe.directory=*'" } }};
    const first = try runCached(arena, c.cfg, job, "j1");
    try expectSucceeded(first);

    // v1 moves to the second commit, as a release tag does, and the job runs again.
    const moved = try std.process.run(arena, io, .{ .argv = &.{
        "sh", "-c", try std.fmt.allocPrint(arena, "set -e; {s} tag -f v1 {s}; {s} push -q -f ../o/r.git v1", .{ git, sha, git }),
    } });
    try std.testing.expectEqual(@as(u8, 0), moved.term.exited);
    const second = try runCached(arena, c.cfg, job, "j2");
    try expectSucceeded(second);
    const now = try std.fmt.allocPrint(arena, "tag-v1={s}", .{sha[0..7]});
    if (std.mem.indexOf(u8, second.text, now) == null) {
        std.debug.print("the second run did not see v1 at {s}:\n{s}\n", .{ sha[0..7], second.text });
        return error.TestUnexpectedResult;
    }
    // With the tags as they were, the checkout and the step after it are replayed.
    const third = try runCached(arena, c.cfg, job, "j3");
    try expectSucceeded(third);
    try std.testing.expectEqual(@as(usize, 2), std.mem.count(u8, third.text, dagger.native_reused_note));
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
    // volume, in no layer, and no checked tree holds it (the check is off here), so its record is
    // not trusted.
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

test "native tool trees: a job's first step ends the epoch of the tool cache for those that have not checked yet" {
    var a: std.heap.ArenaAllocator = .init(std.testing.allocator);
    defer a.deinit();
    const arena = a.allocator();
    const io = std.testing.io;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    const c = try cachedConfig(arena, &tmp);
    const caches: volumes.Options = .{ .package_caches = true, .trusted = true, .tool_trees = true };
    const install = testJob(&.{testStep("mkdir -p $RUNNER_TOOL_CACHE/t/1/x64 && echo v1 > $RUNNER_TOOL_CACHE/t/1/x64/bin")});
    // The first job leaves a tree. Its own walk as the last out saw the files too new to be told
    // from a later write, so the walk is made again once they are old enough.
    _ = try runCachedJob(arena, c.cfg, install, caches, .{ .ran = "j1" });
    io.sleep(.fromMilliseconds(2_200), .awake) catch {};
    var last = try volumes.plan(arena, io, c.cfg.store, caches, "repo", install, dagger.default_image, false, false, null);
    const idle = last.idleToolCache(arena) orelse return error.TestUnexpectedResult;
    const lists = try trees_check.listsDir(arena, c.cfg.store, idle.dir);
    const kept = trees_check.walkIdle(arena, std.testing.allocator, io, idle.dir, lists, last.tool_cache.?, idle.left, trees_check.idle_limits, null);
    last.release(io);
    if (!kept) return error.SkipZigTest; // a filesystem that proves nothing at rest
    // A job that has opened the volume and not run anything is told it, as is one that opens after.
    var waiting = try volumes.plan(arena, io, c.cfg.store, caches, "repo", install, dagger.default_image, false, false, null);
    defer waiting.release(io);
    try std.testing.expect(waiting.tool_verdict != null);
    try std.testing.expect(waiting.verdictStands(io));
    // A whole job runs a step in the volume: from then on the waiting job's verdict is of the past.
    _ = try runCachedJob(arena, c.cfg, install, caches, .{ .ran = "j2" });
    try std.testing.expect(!waiting.verdictStands(io));
}

test "native tool trees: an installing step replays while its tree is held, not once changed" {
    var a: std.heap.ArenaAllocator = .init(std.testing.allocator);
    defer a.deinit();
    const arena = a.allocator();
    const io = std.testing.io;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    const c = try cachedConfig(arena, &tmp);
    const caches: volumes.Options = .{
        .package_caches = true,
        .trusted = true,
        .tool_trees = true,
    };
    // What install-zig.sh does: a tree TOOL/VERSION/NAME in the tool cache, on PATH, and the
    // digest it pins read from the variable "Set up job" sets. The step is the same text every job.
    const install = testJob(&.{
        testStep("echo x >> /shared/install; " ++
            "echo \"trees=[$ZIG_RUNNER_TOOL_TREES] full=[$ZIG_RUNNER_TOOL_TREES_FULL]\"; " ++
            "mkdir -p $RUNNER_TOOL_CACHE/t/1/x64 && echo v1 > $RUNNER_TOOL_CACHE/t/1/x64/bin && " ++
            "echo $RUNNER_TOOL_CACHE/t/1/x64 >> $GITHUB_PATH"),
        testStep("echo y >> /shared/after"),
    });
    // The first job finds no tree, and leaves one. The second sees it in "Set up job", so its
    // steps' keys are new (the variable is part of each), and the step finds the tree installed.
    const j1 = try runCachedJob(arena, c.cfg, install, caches, .{ .ran = "j1" });
    try expectLines(j1.text, &.{"trees=[] full=[]"});
    const j2 = try runCachedJob(arena, c.cfg, install, caches, .{ .ran = "j2" });
    try expectLines(j2.text, &.{
        "Tool cache: checked t/1/x64 (1 files, ",
        "/opt/hostedtoolcache/t/1/x64] full=[",
    });
    try std.testing.expectEqual(@as(usize, 2), runs(arena, c.shared, "install"));
    // The third has the same tree, so the install step replays, though it names a directory in
    // a volume that is in no layer (#229), and so does the step after it.
    const j3 = try runCachedJob(arena, c.cfg, install, caches, .{ .ran = "j3" });
    try expectLines(j3.text, &.{"/opt/hostedtoolcache/t/1/x64]"});
    try std.testing.expectEqual(@as(usize, 2), runs(arena, c.shared, "install"));
    try std.testing.expectEqual(@as(usize, 2), runs(arena, c.shared, "after"));
    // A tree another job changed (the volume's file, from the host) is not replayed against: the
    // digest, and with it every step's key, is new.
    const tools = try std.fmt.allocPrint(arena, "{s}/volumes/o/r/repo/toolcache", .{c.cfg.store});
    var dir = try std.Io.Dir.cwd().openDir(io, tools, .{ .iterate = true });
    defer dir.close(io);
    var it = dir.iterate();
    // Beside the volume's directory is its lock file.
    const image = while (try it.next(io)) |e| {
        if (e.kind == .directory) break e;
    } else return error.TestUnexpectedResult;
    const bin = try std.fmt.allocPrint(arena, "{s}/{s}/t/1/x64/bin", .{ tools, image.name });
    try std.Io.Dir.cwd().writeFile(io, .{ .sub_path = bin, .data = "v2\n" });
    _ = try runCachedJob(arena, c.cfg, install, caches, .{ .ran = "j4" });
    try std.testing.expectEqual(@as(usize, 3), runs(arena, c.shared, "install"));
    try std.testing.expectEqual(@as(usize, 3), runs(arena, c.shared, "after"));
    _ = try runCachedJob(arena, c.cfg, install, caches, .{ .ran = "j5" });
    try std.testing.expectEqual(@as(usize, 3), runs(arena, c.shared, "install"));
    // A link added to the tree is in no digest the install script pins, and in the other one:
    // the step runs again.
    const link = try std.fmt.allocPrint(arena, "{s}/{s}/t/1/x64/lnk", .{ tools, image.name });
    try std.Io.Dir.cwd().symLink(io, "bin", link, .{});
    _ = try runCachedJob(arena, c.cfg, install, caches, .{ .ran = "j5b" });
    try std.testing.expectEqual(@as(usize, 4), runs(arena, c.shared, "install"));
    _ = try runCachedJob(arena, c.cfg, install, caches, .{ .ran = "j5c" });
    try std.testing.expectEqual(@as(usize, 4), runs(arena, c.shared, "install"));
    // With the check off, as before: the step runs again every job.
    const off: volumes.Options = .{ .package_caches = true, .trusted = true };
    _ = try runCachedJob(arena, c.cfg, install, off, .{ .ran = "j6" });
    _ = try runCachedJob(arena, c.cfg, install, off, .{ .ran = "j7" });
    try std.testing.expectEqual(@as(usize, 6), runs(arena, c.shared, "install"));
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
        \\cp -aL /etc/pam.d rootfs/etc/
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
    var cfg = try testConfig(arena, &tmp);
    try withHostPki(arena, &tmp, &cfg);

    // Listeners on the host's 127.0.0.1 and on all its addresses (the bridge's among them), which
    // a step must not reach.
    // Below the kernel's ephemeral ports, so no outgoing connection on the host holds them.
    const loopback = try listen(17123, 0x7f000001);
    defer _ = std.os.linux.close(loopback);
    const any = try listen(17124, 0);
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
        \\print("host loopback", "reached" if reach("127.0.0.1", 17123) else "unreachable")
        \\print("host via bridge", "reached" if reach("{d}.{d}.{d}.{d}", 17124) else "unreachable")
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

test "root runner: a native job resolves through a nameserver only another interface reaches, and reaches nothing else there" {
    try requireRoot();
    var a: std.heap.ArenaAllocator = .init(std.testing.allocator);
    defer a.deinit();
    const arena = a.allocator();
    const io = std.testing.io;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    var cfg = try testConfig(arena, &tmp);
    const env = try std.testing.environ.createMap(arena);
    const required = std.mem.eql(u8, env.get("ZIG_RUNNER_REQUIRE_NATIVE") orelse "", "1");

    var dns = TestResolver.start(arena) catch |e| switch (e) {
        error.NoIp => return skip(required, "this machine has no `ip` (iproute2) for the resolver's network"),
        else => return e,
    };
    defer dns.stop(arena);

    // A host service on the resolver's network, at the host's own address there.
    // Below the kernel's ephemeral ports, so no outgoing connection on the host holds it.
    const host_side = try listen(17126, 0);
    defer _ = std.os.linux.close(host_side);

    // The host's resolver as Tailscale writes it, with systemd-resolved's stub first: the job
    // gets only the nameserver its network can reach, the search domain kept.
    const resolv = try std.fmt.allocPrint(arena, "{s}/host-resolv.conf", .{
        try tmp.dir.realPathFileAlloc(io, ".", arena),
    });
    try std.Io.Dir.cwd().writeFile(io, .{ .sub_path = resolv, .data = "# a host's\n" ++
        "nameserver 127.0.0.53\nnameserver 198.51.100.53\nnameserver fd7a:115c:a1e0::53\n" ++
        "search zr.test\noptions timeout:2 attempts:2\n" });
    cfg.test_resolv_conf = resolv;
    const script =
        \\cat /etc/resolv.conf
        \\getent hosts probe || echo "probe un""resolved"
        \\python3 - <<'EOF'
        \\import socket
        \\def reach(host, port):
        \\    try:
        \\        socket.create_connection((host, port), 3).close(); return True
        \\    except OSError: return False
        \\for name, host, port in (("dns53", "198.51.100.53", 53), ("dns54", "198.51.100.54", 53),
        \\        ("other port", "198.51.100.53", 8080), ("host side", "198.51.100.1", 17126)):
        \\    print(name, "reached" if reach(host, port) else "unreachable")
        \\EOF
    ;
    const first = try runNativeJob(arena, cfg, testJob(&.{testStep(script)}), .root);
    if (!first.res.succeeded) std.debug.print("{s}\n", .{first.text});
    try std.testing.expect(first.res.succeeded);
    try expectLines(first.text, &.{
        "nameserver 198.51.100.53",
        "search zr.test",
        "options timeout:2 attempts:2",
        "192.0.2.77",
        "probe.zr.test",
        "dns53 reached",
        "dns54 unreachable",
        "other port unreachable",
        "host side unreachable",
    });
    // Not in the script as written, which the log shows too.
    for ([_][]const u8{ "127.0.0.53", "fd7a:", "probe unresolved" }) |no|
        try std.testing.expect(std.mem.indexOf(u8, first.text, no) == null);

    // The host's resolver changes while the runner runs (Tailscale's address moving): the next
    // job resolves through the new one, and the old one is out of reach.
    try std.Io.Dir.cwd().writeFile(io, .{ .sub_path = resolv, .data = "nameserver 198.51.100.54\n" ++
        "search zr.test\n" });
    const second = try runNativeJob(arena, cfg, testJob(&.{testStep(script)}), .root);
    if (!second.res.succeeded) std.debug.print("{s}\n", .{second.text});
    try std.testing.expect(second.res.succeeded);
    try expectLines(second.text, &.{
        "nameserver 198.51.100.54",
        "192.0.2.77",
        "dns53 unreachable",
        "dns54 reached",
        "other port unreachable",
    });
}

/// The tests' rootfs (`testConfig`) without /etc/resolv.conf and /etc/hosts, as Alpine's is, and
/// a Docker action's image `zr-test/noetc:1` without them either: the tests' images directory.
fn withoutEtcFiles(arena: Allocator, tmp: *std.testing.TmpDir) ![]const u8 {
    const io = std.testing.io;
    const root = try tmp.dir.realPathFileAlloc(io, ".", arena);
    for ([_][]const u8{ "rootfs/etc/resolv.conf", "rootfs/etc/hosts" }) |f| try tmp.dir.deleteFile(io, f);
    const image_dir = try std.fmt.allocPrint(arena, "images/{s}", .{try images.key(arena, "zr-test/noetc:1")});
    for ([_][]const u8{ "etc/ssl", "usr", "tmp", "dev", "proc", "sys", "root" }) |p|
        try tmp.dir.createDirPath(io, try std.fmt.allocPrint(arena, "{s}/rootfs/{s}", .{ image_dir, p }));
    for ([_][2][]const u8{ .{ "usr/bin", "bin" }, .{ "usr/lib", "lib" }, .{ "usr/lib64", "lib64" } }) |l|
        try tmp.dir.symLink(io, l[0], try std.fmt.allocPrint(arena, "{s}/rootfs/{s}", .{ image_dir, l[1] }), .{});
    for ([_][2][]const u8{
        .{ "rootfs/etc/passwd", "root:x:0:0:root:/root:/bin/sh\n" },
        .{ "rootfs/etc/ld.so.cache", "" },
        .{ "config.json", "{\"config\":{\"Env\":[\"PATH=/usr/bin:/bin\"]}}" },
    }) |f| try tmp.dir.writeFile(io, .{
        .sub_path = try std.fmt.allocPrint(arena, "{s}/{s}", .{ image_dir, f[0] }),
        .data = f[1],
    });
    return std.fmt.allocPrint(arena, "{s}/images", .{root});
}

test "an image without /etc/resolv.conf or /etc/hosts gets the job's, in a step and a Docker action, and no layer keeps them" {
    var a: std.heap.ArenaAllocator = .init(std.testing.allocator);
    defer a.deinit();
    const arena = a.allocator();
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    var cfg = try testConfig(arena, &tmp);
    cfg.images = try withoutEtcFiles(arena, &tmp);
    const host = std.Io.Dir.cwd().readFileAlloc(std.testing.io, "/etc/hosts", arena, .limited(1 << 20)) catch "";
    if (std.mem.indexOf(u8, host, "localhost") == null) return error.SkipZigTest;
    // The step's own layer holds no mount point: it writes beside them, and the store's replay
    // of it would show one (`Store`); here the layer is looked at directly.
    const step = testStep("grep -c localhost /etc/hosts >/dev/null && echo step-hosts; " ++
        "test -e /etc/resolv.conf && echo step-resolv; echo x > /etc/written");
    var docker_step = testStep("");
    docker_step.action = .{ .docker = .{ .image = "zr-test/noetc:1", .inputs = &.{
        .{ .name = "entrypoint", .value = .{ .lit = "sh" } },
        .{ .name = "args", .value = .{ .lit = "-c \"grep -q localhost /etc/hosts && echo action-hosts; " ++
            "test -e /etc/resolv.conf && echo action-resolv\"" } },
    } } };
    var b = try init(arena, std.testing.io, std.testing.allocator, cfg);
    defer b.deinit();
    var out: Captured = .{ .arena = arena };
    const ended = try b.exec(step.action.script.script.lit, &.{"PATH=/usr/bin:/bin"}, &.{}, 0, 0, out.output());
    try std.testing.expectEqual(@as(i32, 0), ended.code);
    try expectLines(out.tailLines(20), &.{ "step-hosts", "step-resolv" });
    const upper = b.layers.items[b.layers.items.len - 1].path;
    var layer = try std.Io.Dir.cwd().openDir(std.testing.io, upper, .{});
    defer layer.close(std.testing.io);
    try layer.access(std.testing.io, "etc/written", .{});
    for ([_][]const u8{ "etc/resolv.conf", "etc/hosts" }) |f|
        try std.testing.expectError(error.FileNotFound, layer.access(std.testing.io, f, .{}));
    const r = try runNativeJob(arena, cfg, testJob(&.{docker_step}), .root);
    try expectLines(r.text, &.{ "action-hosts", "action-resolv" });
}

/// A resolver for the root tests, as Tailscale's MagicDNS is to razorbill: on no uplink, but on
/// an interface of its own (a veth to a network namespace of the test's, TEST-NET-2, the host at
/// 198.51.100.1), at 198.51.100.53 and .54, with a TCP port that is not DNS (8080). The host routes
/// there, but the jobs' rules forward nothing there but DNS to the nameservers the job's resolver
/// names. Over UDP and TCP, `git.zr.test` is 127.0.0.1 (a job's own loopback, where a fetch that
/// resolved finds nothing listening), every other name under zr.test 192.0.2.77, and any other
/// name NXDOMAIN. A UDP socket for each address, so each answer comes from the address it was
/// asked at. `error.NoIp` without iproute2's `ip`.
const TestResolver = struct {
    child: std.process.Child,

    const ns = "zrtest-dns";

    fn start(arena: Allocator) !TestResolver {
        const io = std.testing.io;
        _ = std.process.run(arena, io, .{ .argv = &.{ "ip", "netns", "del", ns } }) catch
            return error.NoIp;
        errdefer _ = std.process.run(arena, io, .{ .argv = &.{ "ip", "netns", "del", ns } }) catch {};
        try ip(arena, &.{ "netns", "add", ns });
        try ip(arena, &.{ "link", "add", "zrtdns0", "type", "veth", "peer", "name", "eth0", "netns", ns });
        try ip(arena, &.{ "addr", "add", "198.51.100.1/24", "dev", "zrtdns0" });
        try ip(arena, &.{ "link", "set", "zrtdns0", "up" });
        try ip(arena, &.{ "-n", ns, "addr", "add", "198.51.100.53/24", "dev", "eth0" });
        try ip(arena, &.{ "-n", ns, "addr", "add", "198.51.100.54/24", "dev", "eth0" });
        try ip(arena, &.{ "-n", ns, "link", "set", "eth0", "up" });
        try ip(arena, &.{ "-n", ns, "link", "set", "lo", "up" });
        const responder =
            \\import socket, struct, sys, threading
            \\def answer(q):
            \\    i, labels = 12, []
            \\    while q[i]:
            \\        labels.append(q[i + 1:i + 1 + q[i]].decode()); i += 1 + q[i]
            \\    qtype = struct.unpack(">H", q[i + 1:i + 3])[0]
            \\    name = ".".join(labels).lower()
            \\    rcode, an, ans = 3, 0, b""
            \\    if name == "zr.test" or name.endswith(".zr.test"):
            \\        rcode = 0
            \\        addr = [127, 0, 0, 1] if name == "git.zr.test" else [192, 0, 2, 77]
            \\        if qtype == 1:
            \\            an, ans = 1, b"\xc0\x0c" + struct.pack(">HHIH", 1, 1, 60, 4) + bytes(addr)
            \\    return q[:2] + struct.pack(">HHHHH", 0x8180 | rcode, 1, an, 0, 0) + q[12:i + 5] + ans
            \\def udp(s):
            \\    while True:
            \\        q, peer = s.recvfrom(512)
            \\        try: s.sendto(answer(q), peer)
            \\        except Exception: pass
            \\def tcp_one(c):
            \\    with c:
            \\        try:
            \\            n = struct.unpack(">H", c.recv(2))[0]; q = b""
            \\            while len(q) < n: q += c.recv(n - len(q))
            \\            r = answer(q); c.sendall(struct.pack(">H", len(r)) + r)
            \\        except Exception: pass
            \\def tcp(s, dns):
            \\    while True:
            \\        c, _ = s.accept()
            \\        if dns: threading.Thread(target=tcp_one, args=(c,), daemon=True).start()
            \\        else: c.close()
            \\def udp_on(addr):
            \\    u = socket.socket(socket.AF_INET, socket.SOCK_DGRAM); u.bind((addr, 53)); return u
            \\def listener(port):
            \\    s = socket.socket(); s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            \\    s.bind(("0.0.0.0", port)); s.listen(16); return s
            \\for addr in ("198.51.100.53", "198.51.100.54"):
            \\    threading.Thread(target=udp, args=(udp_on(addr),), daemon=True).start()
            \\threading.Thread(target=tcp, args=(listener(53), True), daemon=True).start()
            \\threading.Thread(target=tcp, args=(listener(8080), False), daemon=True).start()
            \\print("ready", flush=True)
            \\sys.stdin.read()
        ;
        var child = try std.process.spawn(io, .{
            .argv = &.{ "ip", "netns", "exec", ns, "python3", "-c", responder },
            .stdin = .pipe,
            .stdout = .pipe,
            .stderr = .inherit,
        });
        errdefer child.kill(io);
        var ready_buf: [64]u8 = undefined;
        var ready = child.stdout.?.readerStreaming(io, &ready_buf);
        const line = (try ready.interface.takeDelimiter('\n')) orelse return error.ResponderDidNotStart;
        try std.testing.expectEqualStrings("ready", line);
        return .{ .child = child };
    }

    fn stop(r: *TestResolver, arena: Allocator) void {
        r.child.kill(std.testing.io);
        _ = std.process.run(arena, std.testing.io, .{ .argv = &.{ "ip", "netns", "del", ns } }) catch {};
    }

    fn ip(arena: Allocator, args: []const []const u8) !void {
        const argv = try std.mem.concat(arena, []const u8, &.{ &.{"ip"}, args });
        const r = try std.process.run(arena, std.testing.io, .{ .argv = argv });
        if (r.term != .exited or r.term.exited != 0) {
            std.debug.print("ip {s}: {s}\n", .{ try std.mem.join(arena, " ", args), r.stderr });
            return error.IpFailed;
        }
    }
};

test "root runner: a native checkout and an action's fetch resolve through the job's resolver, as root and as the runner user, with a Zig seed below" {
    try requireRoot();
    var a: std.heap.ArenaAllocator = .init(std.testing.allocator);
    defer a.deinit();
    const arena = a.allocator();
    const io = std.testing.io;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    var cfg = try testConfig(arena, &tmp);
    const env = try std.testing.environ.createMap(arena);
    const required = std.mem.eql(u8, env.get("ZIG_RUNNER_REQUIRE_NATIVE") orelse "", "1");
    if (std.process.run(arena, io, .{ .argv = &.{ "git", "--version" } })) |_| {} else |_| return skip(required, "git is not installed");
    var dns = TestResolver.start(arena) catch |e| switch (e) {
        error.NoIp => return skip(required, "this machine has no `ip` (iproute2) for the resolver's network"),
        else => return e,
    };
    defer dns.stop(arena);
    const resolv = try std.fmt.allocPrint(arena, "{s}/host-resolv.conf", .{
        try tmp.dir.realPathFileAlloc(io, ".", arena),
    });
    try std.Io.Dir.cwd().writeFile(io, .{ .sub_path = resolv, .data = "nameserver 198.51.100.53\n" ++
        "search zr.test\noptions timeout:1 attempts:2\n" });
    cfg.test_resolv_conf = resolv;
    // As razorbill's toolcache job (runner-bench 41391500747) ran: a Zig seed below the job's
    // layers, the package caches bound, the steps as the runner user.
    cfg.test_seed_script = "mkdir -p /zig-seed/o/s && echo seeded > /zig-seed/o/s/f";
    try sudoRootfs(arena, try tmp.dir.realPathFileAlloc(io, ".", arena));
    const caches: volumes.Options = .{
        .package_caches = true,
        .trusted = true,
        .zig_seeds = &.{.{ .version = "0.0.1", .sha256 = "00" }},
    };

    // The job's image has no /etc/resolv.conf or /etc/hosts, as Alpine's has not, nor does the
    // Docker action's: the job's are bound all the same (`mount_points`).
    cfg.images = try withoutEtcFiles(arena, &tmp);

    const Run = struct {
        fn job(arena_: Allocator, cfg_: Config, j: job_mod.Job, caches_: volumes.Options, user: config.StepUser) ![]const u8 {
            var environ: std.process.Environ.Map = .init(arena_);
            var w: std.Io.Writer.Allocating = .init(arena_);
            var log: sink.LogSink = .{ .stdout = .{ .writer = &w.writer } };
            _ = try dagger.run(arena_, std.testing.io, &environ, .{
                .native = cfg_,
                .step_user = user,
                .gpa = std.testing.allocator,
                .package_caches = caches_.package_caches,
                .trusted = caches_.trusted,
                .zig_seeds = caches_.zig_seeds,
            }, j, &log);
            return w.written();
        }

        fn expectResolved(text: []const u8, what: []const u8) !void {
            for ([_][]const u8{ "Could not resolve host", "unresolved", "bad address" }) |no|
                if (std.mem.indexOf(u8, text, no) != null) {
                    std.debug.print("{s}: {s} in:\n{s}\n", .{ what, no, text });
                    return error.TestUnexpectedResult;
                };
        }
    };
    // The repository's server is `git.zr.test`, which only the test's resolver knows: a fetch
    // that resolved it fails to connect to the job's own loopback; one that did not says so.
    for ([_]config.StepUser{ .root, .runner }) |user| {
        const look = testStep("echo uid=$(id -u); ls -ln /etc/resolv.conf; cat /etc/resolv.conf # zig\n" ++
            "getent hosts git.zr.test || echo \"git.zr.test un\"\"resolved\"");
        var co = testStep("");
        co.name = "checkout";
        co.action = .{ .checkout = &.{.{ .name = "repository", .value = .{ .lit = "o/other" } }} };
        var job = testJob(&.{ look, co });
        job.github.server_url = "http://git.zr.test:9";
        const text = try Run.job(arena, cfg, job, caches, user);
        try expectLines(text, &.{
            "Zig global cache seeded from Zig 0.0.1",
            if (user == .root) "uid=0" else "uid=1001",
            "nameserver 198.51.100.53",
            "127.0.0.1",
            "could not fetch o/other",
            "git.zr.test port 9",
        });
        try Run.expectResolved(text, @tagName(user));
    }
    // An action's fetch, before the job ("Set up job" fails on an action it cannot fetch).
    var act = testStep("");
    act.action = .{ .uses = .{ .owner = "o", .name = "act", .ref = "v1" } };
    var act_job = testJob(&.{act});
    act_job.github.server_url = "http://git.zr.test:9";
    const act_text = try Run.job(arena, cfg, act_job, caches, .root);
    try expectLines(act_text, &.{ "Unable to resolve action `o/act@v1`", "git.zr.test port 9" });
    try Run.expectResolved(act_text, "the action's fetch");
    // A Docker action in an image without a resolver of its own.
    var docker_step = testStep("");
    docker_step.action = .{ .docker = .{ .image = "zr-test/noetc:1", .inputs = &.{
        .{ .name = "entrypoint", .value = .{ .lit = "sh" } },
        .{ .name = "args", .value = .{ .lit = "-c \"cat /etc/resolv.conf; getent hosts probe || echo docker un\"\"resolved\"\"" } },
    } } };
    const docker_text = try Run.job(arena, cfg, testJob(&.{docker_step}), .{}, .root);
    try expectLines(docker_text, &.{ "nameserver 198.51.100.53", "192.0.2.77", "probe.zr.test" });
    try Run.expectResolved(docker_text, "the Docker action");
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
    // The second job's set-up left the first's veth alone, and both are on the bridge: once each
    // job's network helper is done, as `init` only starts it.
    _ = try first.networkPath();
    _ = try second.networkPath();
    var sock = try net.Socket.open();
    defer sock.close();
    var buf: [16]u8 = undefined;
    try std.testing.expect(sock.index(net.hostLink(&buf, first.slot.?.n)) != null);
    try std.testing.expect(sock.index(net.hostLink(&buf, second.slot.?.n)) != null);
}

test "root runner: a job whose network helper fails starts, and its first use of the network fails, every time" {
    try requireRoot();
    var a: std.heap.ArenaAllocator = .init(std.testing.allocator);
    defer a.deinit();
    const arena = a.allocator();
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    var cfg = try testConfig(arena, &tmp);
    // `false` for the helper: it exits 1 and says nothing.
    cfg.self_exe = "/usr/bin/false";
    var b = try init(arena, std.testing.io, std.testing.allocator, cfg);
    defer b.deinit();
    try std.testing.expectError(error.JobNetworkFailed, b.networkPath());
    try std.testing.expect(std.mem.indexOf(u8, b.net_why.?, "making the job's network") != null);
    try std.testing.expectError(error.JobNetworkFailed, b.networkPath());
}

test "root runner: a job's veth goes with its namespace, and the next job of the slot never meets it" {
    // `deinit` deletes no veth: the namespace's mount goes and the kernel takes the veth down
    // after, in a batch. A job that comes up in the slot at once finds the host's end (named for
    // the slot) still there or not, and the helper `jobNetwork` starts removes it under the
    // slot's lock, so `addVeth`'s exclusive create never meets it.
    try requireRoot();
    var a: std.heap.ArenaAllocator = .init(std.testing.allocator);
    defer a.deinit();
    const arena = a.allocator();
    const io = std.testing.io;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    const cfg = try testConfig(arena, &tmp);
    var sock = try net.Socket.open();
    defer sock.close();
    var buf: [16]u8 = undefined;
    var slot: ?u32 = null;
    // Back to back, each in the slot the last let go, with no wait for the kernel.
    for (0..12) |_| {
        var b = try init(arena, io, std.testing.allocator, cfg);
        if (slot) |n| try std.testing.expectEqual(n, b.slot.?.n);
        slot = b.slot.?.n;
        // The helper runs beside the set-up: the veth is there once the first use waited for it.
        try std.testing.expect(try b.networkPath() != null);
        try std.testing.expect(sock.index(net.hostLink(&buf, slot.?)) != null);
        b.deinit();
    }
    // And left alone, the veth is gone soon after the last job: nothing deleted it by name.
    var waited: u32 = 0;
    while (sock.index(net.hostLink(&buf, slot.?)) != null and waited < 5000) : (waited += 10)
        io.sleep(.fromMilliseconds(10), .awake) catch {};
    try std.testing.expect(sock.index(net.hostLink(&buf, slot.?)) == null);
}

test "root runner: the network helper removes a dead job's veth of its slot before it makes its own" {
    try requireRoot();
    var a: std.heap.ArenaAllocator = .init(std.testing.allocator);
    defer a.deinit();
    const arena = a.allocator();
    const io = std.testing.io;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    const cfg = try testConfig(arena, &tmp);
    const root = try tmp.dir.realPathFileAlloc(io, ".", arena);
    const subnet = try std.fmt.allocPrint(arena, "{f}", .{cfg.subnet});
    // A slot no job of these tests takes. The first namespace stays mounted, so its veth stays,
    // as a dead job's does until the kernel is done with its namespace: the second helper finds it.
    const slot = try std.fmt.allocPrint(arena, "{d}", .{net.max_slots - 1});
    const runner_pid = try std.fmt.allocPrint(arena, "{d}", .{std.os.linux.getpid()});
    var sock = try net.Socket.open();
    defer sock.close();
    var buf: [16]u8 = undefined;
    // Both namespaces are let go at the end only: the first's veth is the dead job's until then.
    var paths: [2][]const u8 = undefined;
    defer for (paths) |p| if (p.len > 0) detachNetns(arena, p);
    @memset(&paths, "");
    for (&paths, 0..) |*path, i| {
        path.* = try std.fmt.allocPrint(arena, "{s}/netns-{d}", .{ root, i });
        const ran = try std.process.run(arena, io, .{ .argv = &.{ cfg.self_exe, net.command, path.*, slot, subnet, runner_pid } });
        try std.testing.expectEqual(std.process.Child.Term{ .exited = 0 }, ran.term);
        try std.testing.expectEqualStrings("", ran.stderr);
        try std.testing.expect(sock.index(net.hostLink(&buf, net.max_slots - 1)) != null);
    }
}

test "root runner: a network helper whose runner is not its parent makes and removes nothing" {
    try requireRoot();
    var a: std.heap.ArenaAllocator = .init(std.testing.allocator);
    defer a.deinit();
    const arena = a.allocator();
    const io = std.testing.io;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    const cfg = try testConfig(arena, &tmp);
    const root = try tmp.dir.realPathFileAlloc(io, ".", arena);
    const subnet = try std.fmt.allocPrint(arena, "{f}", .{cfg.subnet});
    const slot = try std.fmt.allocPrint(arena, "{d}", .{net.max_slots - 2});
    const path = try std.fmt.allocPrint(arena, "{s}/netns", .{root});
    defer detachNetns(arena, path);
    // Another pid than the helper's parent: as when its runner died and another job holds the slot.
    const other = try std.fmt.allocPrint(arena, "{d}", .{std.os.linux.getpid() + 1});
    const ran = try std.process.run(arena, io, .{ .argv = &.{ cfg.self_exe, net.command, path, slot, subnet, other } });
    try std.testing.expectEqual(std.process.Child.Term{ .exited = 1 }, ran.term);
    var sock = try net.Socket.open();
    defer sock.close();
    var buf: [16]u8 = undefined;
    try std.testing.expect(sock.index(net.hostLink(&buf, net.max_slots - 2)) == null);
}

test "root runner: a cancelled wait for the network helper still waits for it" {
    try requireRoot();
    var a: std.heap.ArenaAllocator = .init(std.testing.allocator);
    defer a.deinit();
    const arena = a.allocator();
    const io = std.testing.io;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    const cfg = try testConfig(arena, &tmp);
    var b = try init(arena, io, std.testing.allocator, cfg);
    defer b.deinit();
    const Wait = struct {
        fn run(bb: *Backend) void {
            _ = bb.networkPath() catch {};
        }
    };
    var waiting = try io.concurrent(Wait.run, .{&b});
    waiting.cancel(io);
    // The helper has ended, so its veth is there: the cancel did not drop it still running.
    var sock = try net.Socket.open();
    defer sock.close();
    var buf: [16]u8 = undefined;
    try std.testing.expect(b.net_helper == null);
    try std.testing.expect(sock.index(net.hostLink(&buf, b.slot.?.n)) != null);
}

test "native sweep: a job's directory its runner is removing is left to it; a dead runner's goes" {
    // Found by the store's stress test: a runner's removal took the lock file early, another
    // runner's sweep made a new one, found it free, and removed the directory alongside its
    // owner (`AccessDenied` from one of the two).
    var a: std.heap.ArenaAllocator = .init(std.testing.allocator);
    defer a.deinit();
    const arena = a.allocator();
    const io = std.testing.io;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    const store = try tmp.dir.realPathFileAlloc(io, ".", arena);
    for ([_][]const u8{ "jobs/live/W/x", "jobs/removing/W/x", "jobs/dead/W/x", "jobs/emptied" }) |d|
        try tmp.dir.createDirPath(io, d);
    // A live job holds its lock; one being removed holds it too, its file not yet gone (lock
    // last); a dead runner's is free.
    const live = try lockFile(arena, io, try std.fmt.allocPrint(arena, "{s}/jobs/live/lock", .{store}), false);
    defer live.close(io);
    const removing = try lockFile(arena, io, try std.fmt.allocPrint(arena, "{s}/jobs/removing/lock", .{store}), false);
    defer removing.close(io);
    try tmp.dir.writeFile(io, .{ .sub_path = "jobs/dead/lock", .data = "" });
    // Midway through `removeJobDir`: everything but the lock gone.
    try tmp.dir.deleteTree(io, "jobs/removing/W");
    sweep(arena, io, store, null);
    try tmp.dir.access(io, "jobs/live/W/x", .{});
    try tmp.dir.access(io, "jobs/removing/lock", .{});
    try std.testing.expectError(error.FileNotFound, tmp.dir.access(io, "jobs/dead", .{}));
    // An empty directory without a lock (a runner that died after removing it) goes; one whose
    // lock its runner removed while it still has files is not given a lock of the sweep's.
    try std.testing.expectError(error.FileNotFound, tmp.dir.access(io, "jobs/emptied", .{}));
    try tmp.dir.createDirPath(io, "jobs/unlocked/W");
    sweep(arena, io, store, null);
    try tmp.dir.access(io, "jobs/unlocked/W", .{});
    try std.testing.expectError(error.FileNotFound, tmp.dir.access(io, "jobs/unlocked/lock", .{}));
    // Its runner's removal ends with the lock, while held.
    removeJobDir(arena, io, try std.fmt.allocPrint(arena, "{s}/jobs/live", .{store}));
    try std.testing.expectError(error.FileNotFound, tmp.dir.access(io, "jobs/live", .{}));
}

test "native eviction under a real job: its directory has the mark, and no step can see it" {
    var a: std.heap.ArenaAllocator = .init(std.testing.allocator);
    defer a.deinit();
    const arena = a.allocator();
    const io = std.testing.io;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    const cfg = try testConfig(arena, &tmp);
    var b = try init(arena, io, std.testing.allocator, cfg);
    defer b.deinit();
    const mark = try std.fmt.allocPrint(arena, "{s}/{s}", .{ b.dir, evict.job_mark });
    try std.Io.Dir.cwd().access(io, mark, .{});
    var out: Captured = .{ .arena = arena };
    const step = try b.exec(
        try std.fmt.allocPrint(arena, "! test -e {s} && ! find / -xdev -name {s} | grep .", .{ mark, evict.job_mark }),
        &.{"PATH=/usr/bin:/bin"},
        &.{},
        0,
        0,
        out.output(),
    );
    try std.testing.expectEqual(@as(i32, 0), step.code);
}

test "native sweep: a crash that left only a job's mark leaves nothing" {
    var a: std.heap.ArenaAllocator = .init(std.testing.allocator);
    defer a.deinit();
    const arena = a.allocator();
    const io = std.testing.io;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    const store = try tmp.dir.realPathFileAlloc(io, ".", arena);
    try tmp.dir.createDirPath(io, "jobs/crashed");
    try tmp.dir.writeFile(io, .{ .sub_path = "jobs/crashed/" ++ evict.job_mark, .data = "" });
    sweep(arena, io, store, null);
    try std.testing.expectError(error.FileNotFound, tmp.dir.access(io, "jobs/crashed", .{}));
}

test "native sweep: a dead runner's directory goes where a listing does not say what is a directory" {
    var a: std.heap.ArenaAllocator = .init(std.testing.allocator);
    defer a.deinit();
    const arena = a.allocator();
    const io = std.testing.io;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    const store = try tmp.dir.realPathFileAlloc(io, ".", arena);
    try tmp.dir.createDirPath(io, "jobs/dead/W");
    try tmp.dir.writeFile(io, .{ .sub_path = "jobs/dead/lock", .data = "" });
    evict.test_unknown_kinds = true;
    defer evict.test_unknown_kinds = false;
    sweep(arena, io, store, null);
    try std.testing.expectError(error.FileNotFound, tmp.dir.access(io, "jobs/dead", .{}));
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
        .cgroup = .{ .parent = "none" },
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
    return testImageLayersWith(arena, true);
}

/// `testImageLayers`, with or without /etc/hosts and /etc/resolv.conf (Alpine's has neither).
fn testImageLayersWith(arena: Allocator, etc_files: bool) ![]const []const u8 {
    var t: oci_layer.TestTar = .{ .a = arena };
    for ([_][]const u8{ "usr/", "etc/", "etc/ssl/", "tmp/", "dev/", "proc/", "sys/", "root/", "home/", "home/app/" }) |d|
        try t.add(.{ .path = d, .kind = .directory, .mode = if (std.mem.eql(u8, d, "tmp/")) 0o1777 else 0o755 });
    for ([_][2][]const u8{ .{ "bin", "usr/bin" }, .{ "sbin", "usr/sbin" }, .{ "lib", "usr/lib" }, .{ "lib64", "usr/lib64" } }) |l|
        try t.add(.{ .path = l[0], .kind = .symlink, .link = l[1] });
    try t.add(.{ .path = "etc/passwd", .body = "root:x:0:0:root:/root:/bin/sh\napp:x:1002:1003::/home/app:/bin/sh\n" });
    try t.add(.{ .path = "etc/group", .body = "root:x:0:\napp:x:1003:\nstaff:x:50:\n" });
    for ([_][]const u8{ "etc/hosts", "etc/resolv.conf", "etc/ld.so.cache" }) |f| {
        if (etc_files or std.mem.eql(u8, f, "etc/ld.so.cache")) try t.add(.{ .path = f });
    }
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

    // Without its credentials, the native pull is refused, before any step: the job goes to
    // Dagger (here a scripted session, which pulls the image as it is given it), "Set up job"
    // saying why, and the memory gate, told of the job's native cgroup, measures it on the
    // engine again. Dagger's own failure would be the job's: nothing native is tried again.
    job.container.?.password = null;
    var slots: [1]admission.Admission.Slot = undefined;
    var pool: admission.Admission = .init(std.testing.io, .{}, &slots);
    pool.paths = .{ .meminfo = "/nonexistent", .pressure = "/nonexistent" };
    var gate: admission.Gate = .{ .pool = &pool };
    gate.leave(true);
    gate.assigned(admission.jobKey("o/r", "ci.yml", "refused natively"));
    var gated = cfg;
    gated.gate = &gate;
    const answers = [_][]const u8{
        "{\"data\":{\"container\":{\"from\":{\"zig_runtime_path\":\"/usr/bin:/bin\"," ++
            "\"withWorkdir\":{\"id\":\"C0\"}}}}}",
        "{\"data\":{\"container\":{\"from\":{\"entrypoint\":[]}}}}",
        "{\"data\":{\"container\":{\"from\":{\"imageRef\":\"img\"}}}}",
        "{\"data\":{\"container\":{\"from\":{\"directory\":{\"entries\":[]}}}}}",
        try execAnswer(arena, "C1", 0, "on dagger\\n"),
    };
    var fake: FakeSession = .{ .answers = &answers, .arena = arena };
    var w3: std.Io.Writer.Allocating = .init(arena);
    var log3: sink.LogSink = .{ .stdout = .{ .writer = &w3.writer } };
    const res3 = try dagger.run(arena, std.testing.io, &env, .{
        .native = gated,
        .step_user = .root,
        .gpa = std.testing.allocator,
        .test_session_argv = &.{ "sh", "-c", fake_child },
        .test_transport = fake.transport(),
    }, job, &log3);
    const text3 = w3.written();
    if (!res3.succeeded) std.debug.print("{s}\n", .{text3});
    try std.testing.expect(res3.succeeded);
    for ([_][]const u8{
        "This job runs on Dagger: the native set-up failed (could not pull 127.0.0.1:",
        "credentials",
        "Engine: Dagger",
        "on dagger",
    }) |e| if (std.mem.indexOf(u8, text3, e) == null) {
        std.debug.print("missing {s} in:\n{s}\n", .{ e, text3 });
        return error.TestUnexpectedResult;
    };
    try std.testing.expect(std.mem.indexOf(u8, text3, "Engine: native") == null);
    try std.testing.expect(!slots[0].native);
}

test "a container job's options on the native backend: --user and --env, the rest noted" {
    var a: std.heap.ArenaAllocator = .init(std.testing.allocator);
    defer a.deinit();
    const arena = a.allocator();
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    const cfg = try testConfig(arena, &tmp);

    // No `/__w` in the image, as in most: `app` cannot make it, so the base makes it as root and
    // hands it over (GitHub mounts it from the host, where it always exists).
    const layers = try testImageLayers(arena);
    const image_env = "\"PATH=/usr/bin:/bin\",\"BOTH=image\"";
    const img = try testregistry.testImage(arena, "test/opts", "1", layers, image_env, false);
    var server: testregistry.Server = .{ .routes = img.routes };
    try server.start();
    defer server.stop();

    // A rootless runner maps only root, so there the user is root; `app` needs a root runner.
    const as_root = std.os.linux.geteuid() == 0;
    const user = if (as_root) "app" else "root";
    var job = testJob(&.{testStep("echo uid=$(id -u) gid=$(id -g); echo A=$A BOTH=$BOTH; " ++
        "echo SPACED=$SPACED; echo home-is[$HOME]; pwd; touch /__w/_temp/mine && echo wrote")});
    job.container = .{
        .name = "",
        .image = .{ .lit = try server.image(arena, "test/opts:1") },
        .env = &.{.{ .name = "BOTH", .value = .{ .lit = "container" } }},
        // The image's /etc/passwd has `app` as 1002:1003. `--workdir` and `--health-*` are the
        // runner's, not the steps': `docker exec -w` and the services' health only.
        .options = .{ .lit = try std.fmt.allocPrint(arena, "--user {s} -e A=1 --env " ++
            "BOTH=options -e \"SPACED=two words\" -e HOME=/elsewhere --workdir /nowhere " ++
            "--health-cmd true --health-interval 5s", .{user}) },
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
        // `--user` over the image's USER (none here), `--env` over the container's `env:`.
        if (as_root) "uid=1002 gid=1003" else "uid=0 gid=0",
        // The container's `env:` is after the options on `docker create`: it wins.
        "A=1 BOTH=container",
        "SPACED=two words",
        "/__w/r/r",
        "wrote",
        try std.fmt.allocPrint(arena, "Container options: 3 `--env`, `--user` {s}; 4 understood " ++
            "and without effect natively", .{user}),
    };
    for (expect) |e| if (std.mem.indexOf(u8, text, e) == null) {
        std.debug.print("missing {s} in:\n{s}\n", .{ e, text });
        return error.TestUnexpectedResult;
    };
    // `-e HOME=` loses to GitHub's `HOME=/github/home`: never the option's value.
    try std.testing.expect(std.mem.indexOf(u8, text, "home-is[/elsewhere]") == null);
}

test "a container job's options on the native backend: hostname, add-host, shm-size and tmpfs" {
    var a: std.heap.ArenaAllocator = .init(std.testing.allocator);
    defer a.deinit();
    const arena = a.allocator();
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    const cfg = try testConfig(arena, &tmp);
    const layers = try testImageLayers(arena);
    const img = try testregistry.testImage(arena, "test/optsb", "1", layers, "\"PATH=/usr/bin:/bin\"", false);
    var server: testregistry.Server = .{ .routes = img.routes };
    try server.start();
    defer server.stop();

    // None of the tmpfs paths is in the image: Docker makes each. Every step has them, and what
    // a step writes to one is gone with its mount, not in the step's layer.
    var job = testJob(&.{
        testStep("echo hostname=$(cat /proc/sys/kernel/hostname)\n" ++
            "grep -E 'db.test|other.test|boxy' /etc/hosts\n" ++
            "grep -E ' (/dev/shm|/scratch|/fast) ' /proc/mounts\n" ++
            "echo hello > /scratch/f && echo scratch-wrote\n" ++
            "printf '#!/bin/sh\\necho ran-from-fast\\n' > /fast/p && chmod +x /fast/p && /fast/p\n" ++
            "printf '#!/bin/sh\\necho ran-from-scratch\\n' > /scratch/p && chmod +x /scratch/p\n" ++
            "/scratch/p 2>/dev/null || echo noexec-held"),
        testStep("cat /proc/sys/kernel/hostname; ls /scratch | wc -l"),
    });
    job.container = .{
        .name = "",
        .image = .{ .lit = try server.image(arena, "test/optsb:1") },
        .options = .{ .lit = "--hostname boxy.local --add-host db.test:10.1.2.3 " ++
            "--add-host=other.test=10.1.2.4 --shm-size 128m --init " ++
            "--tmpfs /scratch:size=1m --tmpfs /fast:exec,mode=0755,size=1m" },
    };
    const r = try runNativeJob(arena, cfg, job, .root);
    if (!r.res.succeeded) std.debug.print("{s}\n", .{r.text});
    try std.testing.expect(r.res.succeeded);
    try expectLines(r.text, &.{
        "Engine: native",
        "hostname=boxy.local",
        "10.1.2.3\tdb.test",
        "10.1.2.4\tother.test",
        "127.0.0.1\tboxy.local",
        "/dev/shm tmpfs rw,nosuid,nodev,noexec",
        "size=131072k",
        "/scratch tmpfs rw,nosuid,nodev,noexec",
        "size=1024k",
        "/fast tmpfs rw,nosuid,nodev,",
        "scratch-wrote",
        "ran-from-fast",
        "noexec-held",
        "`--hostname` boxy.local, 2 `--add-host`, `--shm-size` 128 MiB, 2 `--tmpfs`",
        "1 understood and without effect natively",
    });
    // (The script's own text, in the log's "Run" group, holds the word; its output would be a line.)
    try std.testing.expect(std.mem.indexOf(u8, r.text, "stdout] ran-from-scratch") == null);
    // Carried out here, so not reported as ignored, as on the Dagger path.
    try std.testing.expect(std.mem.indexOf(u8, r.text, "not supported here and ignored") == null);
}

test "a container job's --tmpfs through an image's link onto what the runner puts in place fails the step" {
    var a: std.heap.ArenaAllocator = .init(std.testing.allocator);
    defer a.deinit();
    const arena = a.allocator();
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    const cfg = try testConfig(arena, &tmp);
    var t: oci_layer.TestTar = .{ .a = arena };
    try t.add(.{ .path = "linked", .kind = .symlink, .link = "/etc" });
    try t.add(.{ .path = "linkroot", .kind = .symlink, .link = "/" });
    try t.add(.{ .path = "fine", .kind = .directory, .mode = 0o755 });
    const lay = try testImageLayers(arena);
    const layers = try arena.dupe([]const u8, &.{ lay[0], lay[1], try t.finish() });
    const img = try testregistry.testImage(arena, "test/optsl", "1", layers, "\"PATH=/usr/bin:/bin\"", false);
    var server: testregistry.Server = .{ .routes = img.routes };
    try server.start();
    defer server.stop();

    // The names are allowed (`/linked` and `/linkroot` are nothing the runner mounts); where the
    // links lead is not.
    for ([_][]const u8{ "/linked", "/linkroot" }) |p| {
        var job = testJob(&.{testStep("echo step-ran")});
        job.container = .{
            .name = "",
            .image = .{ .lit = try server.image(arena, "test/optsl:1") },
            .options = .{ .lit = try std.fmt.allocPrint(arena, "--tmpfs {s}:size=1m", .{p}) },
        };
        const r = try runNativeJob(arena, cfg, job, .root);
        try std.testing.expect(!r.res.succeeded);
        try std.testing.expect(std.mem.indexOf(u8, r.text, "step-ran") == null);
        // (The native set-up failed and the job went to Dagger, which this test has no engine for:
        // it has no log. Had the tmpfs been mounted, the step would have run.)
    }
    // A link to somewhere harmless is followed, as Docker does.
    var ok = testJob(&.{testStep("grep -c ' /fine tmpfs' /proc/mounts")});
    ok.container = .{
        .name = "",
        .image = .{ .lit = try server.image(arena, "test/optsl:1") },
        .options = .{ .lit = "--tmpfs /fine:size=1m" },
    };
    const good = try runNativeJob(arena, cfg, ok, .root);
    try std.testing.expect(good.res.succeeded);
}

test "root runner: a container job's --memory lowers the job's memory.max, and never raises it" {
    var a: std.heap.ArenaAllocator = .init(std.testing.allocator);
    defer a.deinit();
    const arena = a.allocator();
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    var cfg = try testConfig(arena, &tmp);
    const parent = try testCgroup(arena, &cfg);
    defer parent.remove(arena);
    cfg.cgroup.memory_max_mb = 256;
    const layers = try testImageLayers(arena);
    const img = try testregistry.testImage(arena, "test/optsm", "1", layers, "\"PATH=/usr/bin:/bin\"", false);
    var server: testregistry.Server = .{ .routes = img.routes };
    try server.start();
    defer server.stop();

    // The job's cgroup is the steps' parent: its limit, as the step sees the host's file.
    var step = testStep("cg=$(cut -d: -f3 /proc/self/cgroup | sed 's,/steps$,,')\n" ++
        "echo \"memory.max=$(cat /sys/fs/cgroup$cg/memory.max)\"");
    step.name = "limit";
    const image = try server.image(arena, "test/optsm:1");
    var job = testJob(&.{step});
    job.container = .{ .name = "", .image = .{ .lit = image }, .options = .{ .lit = "--memory 128m" } };
    const lowered = try runNativeJob(arena, cfg, job, .root);
    if (!lowered.res.succeeded) std.debug.print("{s}\n", .{lowered.text});
    try std.testing.expect(lowered.res.succeeded);
    try expectLines(lowered.text, &.{ "memory.max=134217728", "`--memory` 128 MiB" });

    // Above the runner's limit: the runner's holds, and "Set up job" says so.
    job.container = .{ .name = "", .image = .{ .lit = image }, .options = .{ .lit = "-m 4g" } };
    const capped = try runNativeJob(arena, cfg, job, .root);
    try std.testing.expect(capped.res.succeeded);
    try expectLines(capped.text, &.{ "memory.max=268435456", "the runner's limit of 256 MiB is lower" });
}

test "a container job's volumes on the native backend: directories of the job, there for every step" {
    var a: std.heap.ArenaAllocator = .init(std.testing.allocator);
    defer a.deinit();
    const arena = a.allocator();
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    const cfg = try testConfig(arena, &tmp);
    const layers = try testImageLayers(arena);
    const img = try testregistry.testImage(arena, "test/vols", "1", layers, "\"PATH=/usr/bin:/bin\"", false);
    var server: testregistry.Server = .{ .routes = img.routes };
    try server.start();
    defer server.stop();

    // None of these paths is in the image: Docker makes each volume's mount point, as root's, and
    // it is there from the first step on. What a step writes in one is there in the next.
    var job = testJob(&.{
        testStep("test -d /data && test -d /cache && test -d /var/lib/deep/er && " ++
            "echo made[$(ls -ldn /data | cut -d' ' -f3)] && echo hello > /cache/f && " ++
            "echo kept > /data/g"),
        testStep("echo cache=$(cat /cache/f) data=$(cat /data/g); ls /var/lib/deep"),
    });
    job.container = .{
        .name = "",
        .image = .{ .lit = try server.image(arena, "test/vols:1") },
        .volumes = &.{
            .{ .lit = "/data" },
            .{ .lit = "cache:/cache" },
            .{ .lit = "deep:/var/lib//deep/er:rw" },
        },
    };
    var env: std.process.Environ.Map = .init(arena);
    var w: std.Io.Writer.Allocating = .init(arena);
    var log: sink.LogSink = .{ .stdout = .{ .writer = &w.writer } };
    const res = try dagger.run(arena, std.testing.io, &env, .{
        .native = cfg,
        .step_user = .root,
        // Named volumes are kept between jobs, which only trusted jobs get.
        .trusted = true,
        .gpa = std.testing.allocator,
    }, job, &log);
    const text = w.written();
    if (!res.succeeded) std.debug.print("{s}\n", .{text});
    try std.testing.expect(res.succeeded);
    const expect = [_][]const u8{
        "Engine: native",
        "made[0]",
        "cache=hello data=kept",
        "Container volumes: 1 made as directories of the job, which last as long as it; 2 named, " ++
            "kept between jobs in the native store (repo scope, 2 new and filled from the image)",
    };
    for (expect) |e| if (std.mem.indexOf(u8, text, e) == null) {
        std.debug.print("missing {s} in:\n{s}\n", .{ e, text });
        return error.TestUnexpectedResult;
    };
    try std.testing.expect(std.mem.indexOf(u8, text, "runs on Dagger") == null);
}

test "a container job's volume where the runner mounts something fails the job, naming both" {
    var a: std.heap.ArenaAllocator = .init(std.testing.allocator);
    defer a.deinit();
    const arena = a.allocator();
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    const cfg = try testConfig(arena, &tmp);
    const layers = try testImageLayers(arena);
    const img = try testregistry.testImage(arena, "test/volclash", "1", layers, "\"PATH=/bin\"", false);
    var server: testregistry.Server = .{ .routes = img.routes };
    try server.start();
    defer server.stop();

    // /__w/r holds the workspace, /__w/r/r: a directory there would be the workspace's parent.
    var job = testJob(&.{testStep("echo ran")});
    job.container = .{
        .name = "",
        .image = .{ .lit = try server.image(arena, "test/volclash:1") },
        .volumes = &.{.{ .lit = "/__w/r" }},
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
    try std.testing.expect(!res.succeeded);
    const why = res.engine_error orelse text;
    try std.testing.expect(std.mem.indexOf(u8, why, "volume at /__w/r overlaps /__w/r/r") != null);
    try std.testing.expect(std.mem.indexOf(u8, text, "ran\n") == null);
}

const PortJob = struct {
    cfg: Config,
    job: job_mod.Job,
    ok: bool = false,
    text: []const u8 = "",
    why: []const u8 = "",
    arena: std.heap.ArenaAllocator = .init(std.testing.allocator),

    fn run(p: *PortJob) void {
        p.runOrFail() catch |e| {
            p.why = @errorName(e);
        };
    }

    fn runOrFail(p: *PortJob) !void {
        const arena = p.arena.allocator();
        var env: std.process.Environ.Map = .init(arena);
        var w: std.Io.Writer.Allocating = .init(arena);
        var log: sink.LogSink = .{ .stdout = .{ .writer = &w.writer } };
        const res = try dagger.run(arena, std.testing.io, &env, .{
            .native = p.cfg,
            .step_user = .root,
            .trusted = true,
            .gpa = std.testing.allocator,
        }, p.job, &log);
        p.ok = res.succeeded;
        p.text = w.written();
        p.why = res.engine_error orelse p.text;
    }
};

/// One job of `job` on `cfg`, trusted or not: whether it passed, what it printed, and why it
/// failed (its engine error, else its log).
fn runVolumeJob(arena: Allocator, cfg: Config, job: job_mod.Job, trusted: bool) !struct { ok: bool, text: []const u8, why: []const u8 } {
    var env: std.process.Environ.Map = .init(arena);
    var w: std.Io.Writer.Allocating = .init(arena);
    var log: sink.LogSink = .{ .stdout = .{ .writer = &w.writer } };
    const res = try dagger.run(arena, std.testing.io, &env, .{
        .native = cfg,
        .step_user = .root,
        .trusted = trusted,
        // On, as a runner has it: a job with a named volume or a host path turns it off.
        .step_cache = true,
        .gpa = std.testing.allocator,
    }, job, &log);
    const why = if (res.engine_error) |e| try std.mem.concat(arena, u8, &.{ e, "\n", w.written() }) else w.written();
    return .{ .ok = res.succeeded, .text = w.written(), .why = why };
}

fn expectAll(text: []const u8, want: []const []const u8) !void {
    for (want) |e| if (std.mem.indexOf(u8, text, e) == null) {
        std.debug.print("missing {s} in:\n{s}\n", .{ e, text });
        return error.TestUnexpectedResult;
    };
}

/// A TCP connection to `127.0.0.1:port` from the host, or null when refused.
fn connectLoopback(port: u16) ?std.os.linux.fd_t {
    const linux = std.os.linux;
    const rc = linux.socket(linux.AF.INET, linux.SOCK.STREAM | linux.SOCK.CLOEXEC, 0);
    const fd = std.math.cast(linux.fd_t, rc) orelse return null;
    var sa: linux.sockaddr.in = .{ .port = std.mem.nativeToBig(u16, port), .addr = std.mem.nativeToBig(u32, 0x7f000001) };
    if (linux.errno(linux.connect(fd, forward.asSockaddr(&sa), @sizeOf(linux.sockaddr.in))) != .SUCCESS) {
        _ = linux.close(fd);
        return null;
    }
    return fd;
}

/// A port of the host's loopback no one listens on now.
fn freePort() !u16 {
    const linux = std.os.linux;
    const rc = linux.socket(linux.AF.INET, linux.SOCK.STREAM | linux.SOCK.CLOEXEC, 0);
    const fd = std.math.cast(linux.fd_t, rc) orelse return error.SkipZigTest;
    defer _ = linux.close(fd);
    var sa: linux.sockaddr.in = .{ .port = 0, .addr = std.mem.nativeToBig(u32, 0x7f000001) };
    if (linux.errno(linux.bind(fd, forward.asSockaddr(&sa), @sizeOf(linux.sockaddr.in))) != .SUCCESS) return error.SkipZigTest;
    var len: linux.socklen_t = @sizeOf(linux.sockaddr.in);
    _ = linux.getsockname(fd, forward.asSockaddr(&sa), &len);
    return std.mem.bigToNative(u16, sa.port);
}

test "a container job's ports: published on the host, never another job's nor a bridge's, gone with the job; a taken port fails it; a bare one is the kernel's pick" {
    var a: std.heap.ArenaAllocator = .init(std.testing.allocator);
    defer a.deinit();
    const arena = a.allocator();
    const io = std.testing.io;
    const linux = std.os.linux;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    const cfg = try testConfig(arena, &tmp);
    // Rootless, a job has no network of its own to publish into: those go to Dagger.
    if (linux.geteuid() != 0) return error.SkipZigTest;
    const img = try testregistry.testImage(arena, "test/ports", "1", try testImageLayers(arena), "\"PATH=/usr/bin:/bin\"", false);
    var server: testregistry.Server = .{ .routes = img.routes };
    try server.start();
    defer server.stop();
    const image = try server.image(arena, "test/ports:1");
    const hp = try freePort();

    // The job's server, on its own 8080: "hello" to each connection, until one says "quit".
    const serve =
        \\python3 -c '
        \\import socket
        \\s = socket.socket(); s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        \\s.bind(("0.0.0.0", 8080)); s.listen(8); s.settimeout(120)
        \\while True:
        \\    c, _ = s.accept(); c.settimeout(10)
        \\    try:
        \\        c.sendall(b"hello\n"); d = c.recv(16)
        \\    except Exception:
        \\        d = b""
        \\    c.close()
        \\    if d.startswith(b"quit"): break
        \\print("served-" + str(2 + 3))
        \\'
    ;
    // With no cgroup of its own, whose removal would end the relay too: the ports go with the
    // relay's stop alone.
    var lone = cfg;
    lone.cgroup = .{ .parent = "none" };
    // On every address of the host, so what keeps other jobs out is the runner's table (`input`
    // drops their packets to the bridge's address) and the relay's guard, not the address.
    lone.port_addresses = &.{.{ 0, 0, 0, 0 }};
    // `hp` is the kernel's pick, from its ephemeral range.
    lone.port_range = .{ .lo = 1024, .hi = 65535 };
    var serving: PortJob = .{ .cfg = lone, .job = testJob(&.{testStep(serve)}) };
    defer serving.arena.deinit();
    serving.job.container = .{
        .name = "",
        .image = .{ .lit = image },
        .ports = &.{ .{ .lit = try std.fmt.allocPrint(arena, "{d}:8080", .{hp}) }, .{ .lit = "9090" } },
    };
    const t = try std.Thread.spawn(.{}, PortJob.run, .{&serving});
    var joined = false;
    defer if (!joined) t.join();
    // Published once the relay listens: a connection is taken (and closed while the job's
    // server is not up yet).
    var tries: u32 = 0;
    while (connectLoopback(hp) == null) : (tries += 1) {
        if (tries > 1200) return error.TestUnexpectedResult;
        io.sleep(.fromMilliseconds(100), .awake) catch {};
    }

    // Another job reaches it neither at its own 127.0.0.1 nor at the host's address on the bridge.
    const gw = cfg.subnet.gateway();
    const probe_script = try std.fmt.allocPrint(arena,
        \\python3 -c '
        \\import socket
        \\for name, host in (("gw", "{d}.{d}.{d}.{d}"), ("lo", "127.0.0.1")):
        \\    s = socket.socket(); s.settimeout(3)
        \\    try:
        \\        s.connect((host, {d})); r = "connected"
        \\    except Exception:
        \\        r = "refused"
        \\    print("other-" + name + "=" + r)
        \\'
    , .{ gw[0], gw[1], gw[2], gw[3], hp });
    var other: PortJob = .{ .cfg = cfg, .job = testJob(&.{testStep(probe_script)}) };
    defer other.arena.deinit();
    other.job.container = .{ .name = "", .image = .{ .lit = image } };
    other.run();
    if (!other.ok) std.debug.print("{s}\n", .{other.text});
    try std.testing.expect(other.ok);
    try expectAll(other.text, &.{ "other-gw=refused", "other-lo=refused" });

    // A container on another bridge of the host's (Docker's, the engine's), which the runner's
    // table does not see: the relay refuses it by its address.
    const bridge_script = try std.fmt.allocPrint(arena,
        \\set -e
        \\ip link add zrtbr0 type bridge; ip addr add 172.31.250.1/24 dev zrtbr0; ip link set zrtbr0 up
        \\ip netns add zrtpeer; ip link add zrtv0 type veth peer name zrtv1 netns zrtpeer
        \\ip link set zrtv0 master zrtbr0 up
        \\ip -n zrtpeer addr add 172.31.250.2/24 dev zrtv1; ip -n zrtpeer link set zrtv1 up; ip -n zrtpeer link set lo up
        \\ip netns exec zrtpeer python3 -c '
        \\import socket
        \\s = socket.socket(); s.settimeout(3)
        \\try:
        \\    s.connect(("172.31.250.1", {d})); d = s.recv(16); r = "hello" if d.startswith(b"hello") else "closed"
        \\except Exception as e:
        \\    r = "refused"
        \\print("bridge=" + r)
        \\'
    , .{hp});
    const bridged = std.process.run(arena, io, .{ .argv = &.{ "sh", "-c", bridge_script } }) catch |e| {
        std.debug.print("the bridge peer could not be made: {s}\n", .{@errorName(e)});
        return e;
    };
    _ = std.process.run(arena, io, .{ .argv = &.{ "sh", "-c", "ip netns del zrtpeer; ip link del zrtbr0" } }) catch {};
    if (std.mem.indexOf(u8, bridged.stdout, "bridge=") == null) std.debug.print("{s}{s}\n", .{ bridged.stdout, bridged.stderr });
    // Accepted by the host's socket and closed by the relay at once, or not let in at all.
    try std.testing.expect(std.mem.indexOf(u8, bridged.stdout, "bridge=hello") == null);
    try std.testing.expect(std.mem.indexOf(u8, bridged.stdout, "bridge=") != null);

    // The host reaches the job's server through it.
    var hello = false;
    tries = 0;
    while (!hello and tries < 600) : (tries += 1) {
        const fd = connectLoopback(hp) orelse break;
        defer _ = linux.close(fd);
        var buf: [16]u8 = undefined;
        var fds = [_]linux.pollfd{.{ .fd = fd, .events = linux.POLL.IN, .revents = 0 }};
        if (linux.poll(&fds, 1, 2000) == 1) {
            const n = linux.read(fd, &buf, buf.len);
            if (linux.errno(n) == .SUCCESS and std.mem.startsWith(u8, buf[0..n], "hello")) {
                hello = true;
                _ = linux.write(fd, "quit\n", 5);
                break;
            }
        }
        io.sleep(.fromMilliseconds(100), .awake) catch {};
    }
    try std.testing.expect(hello);
    t.join();
    joined = true;
    if (!serving.ok) std.debug.print("{s}\n", .{serving.text});
    try std.testing.expect(serving.ok);
    try expectAll(serving.text, &.{
        "served-5",
        try std.fmt.allocPrint(arena, "Container ports: 8080/tcp -> 0.0.0.0:{d}, 9090/tcp -> 0.0.0.0:", .{hp}),
    });
    // The bare port got a port of its own, said as Docker says it.
    const said = "9090/tcp -> 0.0.0.0:";
    const at = std.mem.indexOf(u8, serving.text, said).? + said.len;
    var end = at;
    while (end < serving.text.len and std.ascii.isDigit(serving.text[end])) end += 1;
    const picked = try std.fmt.parseInt(u16, serving.text[at..end], 10);
    try std.testing.expect(picked != 0 and picked != 9090);
    // Gone with the job.
    try std.testing.expect(connectLoopback(hp) == null);

    // A port another process holds fails the job, naming it; nothing runs.
    const holder = std.math.cast(linux.fd_t, linux.socket(linux.AF.INET, linux.SOCK.STREAM | linux.SOCK.CLOEXEC, 0)).?;
    defer _ = linux.close(holder);
    var sa: linux.sockaddr.in = .{ .port = std.mem.nativeToBig(u16, hp), .addr = std.mem.nativeToBig(u32, 0x7f000001) };
    // The connections above may leave the port in TIME_WAIT; a listener still refuses a second.
    const one: i32 = 1;
    _ = linux.setsockopt(holder, linux.SOL.SOCKET, linux.SO.REUSEADDR, std.mem.asBytes(&one), 4);
    try std.testing.expectEqual(linux.E.SUCCESS, linux.errno(linux.bind(holder, forward.asSockaddr(&sa), @sizeOf(linux.sockaddr.in))));
    try std.testing.expectEqual(linux.E.SUCCESS, linux.errno(linux.listen(holder, 1)));
    var taken_cfg = cfg;
    taken_cfg.port_range = lone.port_range;
    var taken: PortJob = .{ .cfg = taken_cfg, .job = testJob(&.{testStep("echo ran-$((1+1))")}) };
    defer taken.arena.deinit();
    taken.job.container = .{
        .name = "",
        .image = .{ .lit = image },
        .ports = &.{.{ .lit = try std.fmt.allocPrint(arena, "{d}:8080", .{hp}) }},
    };
    taken.run();
    try std.testing.expect(!taken.ok);
    try expectAll(taken.why, &.{try std.fmt.allocPrint(arena, "publish 127.0.0.1:{d}/tcp", .{hp})});
    try std.testing.expect(std.mem.indexOf(u8, taken.text, "ran-2") == null);
}

/// Mounts a filesystem of `fstype` at `path` (made first) with `flags`, for the root tests of host
/// paths: an allowed directory must be on a `nosuid,nodev` mount, and the work directory is not.
fn testMount(arena: Allocator, path: []const u8, fstype: [*:0]const u8, flags: u32) !void {
    const z = try arena.dupeSentinel(u8, path, 0);
    try std.testing.expectEqual(std.os.linux.E.SUCCESS, std.os.linux.errno(std.os.linux.mount(fstype, z, fstype, flags, 0)));
}

fn testUnmount(arena: Allocator, path: []const u8) void {
    const z = arena.dupeSentinel(u8, path, 0) catch return;
    _ = std.os.linux.umount2(z, std.os.linux.MNT.DETACH);
}

fn testHostPaths(arena: Allocator, raw: []const u8) ![]const host_paths.Entry {
    var r: host_paths.Refusal = .{};
    return host_paths.parse(arena, std.testing.io, raw, &.{}, &r, .{}) catch |e| {
        std.debug.print("{s}: {s}\n", .{ r.entry, r.why });
        return e;
    };
}

fn testExists(arena: Allocator, path: []const u8) bool {
    const z = arena.dupeSentinel(u8, path, 0) catch return false;
    var st: std.os.linux.Statx = undefined;
    return std.os.linux.errno(std.os.linux.statx(std.os.linux.AT.FDCWD, z, std.os.linux.AT.SYMLINK_NOFOLLOW, .{ .TYPE = true }, &st)) == .SUCCESS;
}

test "a container job's host-path volumes: only where the operator allows, nosuid and nodev, :ro read-only" {
    var a: std.heap.ArenaAllocator = .init(std.testing.allocator);
    defer a.deinit();
    const arena = a.allocator();
    const io = std.testing.io;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    var cfg = try testConfig(arena, &tmp);
    const root = try tmp.dir.realPathFileAlloc(io, ".", arena);
    const layers = try testImageLayers(arena);
    const img = try testregistry.testImage(arena, "test/hostvol", "1", layers, "\"PATH=/usr/bin:/bin\"", false);
    var server: testregistry.Server = .{ .routes = img.routes };
    try server.start();
    defer server.stop();
    const image = try server.image(arena, "test/hostvol:1");
    const host = try std.fmt.allocPrint(arena, "{s}/host", .{root});
    try tmp.dir.createDirPath(io, "host");

    if (std.os.linux.geteuid() != 0) {
        // Rootless: the job's root is the runner's own user on the host, so no host path,
        // whatever the list says.
        var r: host_paths.Refusal = .{};
        cfg.host_paths = try host_paths.parse(arena, io, host, &.{}, &r, .{ .mount_flags = false });
        var job = testJob(&.{testStep("echo ran-$((1+1))")});
        job.container = .{ .name = "", .image = .{ .lit = image }, .volumes = &.{.{ .lit = try std.fmt.allocPrint(arena, "{s}:/x", .{host}) }} };
        const refused = try runVolumeJob(arena, cfg, job, true);
        try std.testing.expect(!refused.ok);
        try expectAll(refused.why, &.{ "needs a root runner", "RUNNER_NATIVE_HOST_PATHS" });
        try std.testing.expect(std.mem.indexOf(u8, refused.text, "ran-2") == null);
        return;
    }

    // What an operator does: the allowed tree on a nosuid,nodev mount.
    try testMount(arena, host, "tmpfs", std.os.linux.MS.NOSUID | std.os.linux.MS.NODEV);
    defer testUnmount(arena, host);
    for ([_][]const u8{ "host/allowed/data/sub", "host/allowed/plain", "host/outside" }) |d| try tmp.dir.createDirPath(io, d);
    try tmp.dir.writeFile(io, .{ .sub_path = "host/allowed/data/from-host", .data = "host file\n" });
    try tmp.dir.writeFile(io, .{ .sub_path = "host/outside/secret", .data = "not yours\n" });
    // A link inside the allowed directory to one outside it.
    try tmp.dir.symLink(io, "../outside", "host/allowed/escape", .{});
    const allowed = try std.fmt.allocPrint(arena, "{s}/allowed", .{host});
    cfg.host_paths = try testHostPaths(arena, allowed);
    const data = try std.fmt.allocPrint(arena, "{s}/data", .{allowed});
    // A directory below the allowed one on a mount of its own without nosuid and nodev.
    const plain = try std.fmt.allocPrint(arena, "{s}/plain", .{allowed});
    try testMount(arena, plain, "tmpfs", 0);
    defer testUnmount(arena, plain);
    // What an operator does for a directory jobs write to: give it to the volumes' range, which a
    // root runner's jobs see as their root (its files stay root's, so nobody's to the job).
    const base_id = volumeIdBase(cfg.subid_base);
    const data_z = try arena.dupeSentinel(u8, data, 0);
    try std.testing.expectEqual(std.os.linux.E.SUCCESS, std.os.linux.errno(std.os.linux.lchown(data_z, base_id, base_id)));

    // Allowed: the host's files there, what the job writes on the host, a second bind of it
    // read-only, both nosuid and nodev, and neither remounted otherwise by the job. Nothing
    // expected is in the script's text (the log echoes it).
    const mounts = "while read -r _ _ _ _ at opts _; do case $at in /data) echo data-opts:$opts;; " ++
        "/ro) echo ro-opts:$opts;; esac; done < /proc/self/mountinfo";
    var job = testJob(&.{testStep("sed 's/^/seen:/' /data/from-host; echo owner[$(stat -c %u /data/from-host)]; " ++
        "echo job > /data/from-job && echo wrote-$((2+3)); r=wrote; touch /ro/x 2>/dev/null || " ++
        "r=refused; echo ro-$r; sed 's/^/ro-seen:/' /ro/from-job; " ++
        "for m in 'remount,rw /ro' 'remount,bind,rw /ro' 'remount,bind,suid,dev /data'; do " ++
        "mount -o $m 2>&1 && echo remount-yes-$((6*7)):$m || echo remount-no-$((40+2)); done; " ++ mounts)});
    job.container = .{
        .name = "",
        .image = .{ .lit = image },
        .volumes = &.{
            .{ .lit = try std.fmt.allocPrint(arena, "{s}:/data", .{data}) },
            .{ .lit = try std.fmt.allocPrint(arena, "{s}/:/ro:ro", .{data}) },
        },
    };
    const ok = try runVolumeJob(arena, cfg, job, true);
    if (!ok.ok) std.debug.print("{s}\n", .{ok.text});
    try std.testing.expect(ok.ok);
    try expectAll(ok.text, &.{
        "Engine: native",
        "seen:host file",
        // Host ids are nobody to a root runner's job.
        "owner[65534]",
        "wrote-5",
        "ro-refused",
        "ro-seen:job",
        "data-opts:rw,nosuid,nodev",
        "ro-opts:ro,nosuid,nodev",
        "2 host path(s) bound (1 read-only), nosuid and nodev, allowed by RUNNER_NATIVE_HOST_PATHS",
        "cannot be idmapped fails the step (RUNNER_NATIVE_HOST_PATHS_UNMAPPED=true",
        "Step cache: off for this job, as it mounts named volumes or binds host paths",
    });
    // Each remount was refused, and the mounts are as they were.
    try std.testing.expect(std.mem.indexOf(u8, ok.text, "remount-yes-42") == null);
    try std.testing.expectEqual(@as(usize, 3), std.mem.count(u8, ok.text, "remount-no-42"));
    // On the host: written, owned by the volumes' range (the job's root seen through the
    // idmapped mount), no host user's.
    const from_job = try std.fmt.allocPrintSentinel(arena, "{s}/from-job", .{data}, 0);
    var st: std.os.linux.Statx = undefined;
    try std.testing.expectEqual(std.os.linux.E.SUCCESS, std.os.linux.errno(std.os.linux.statx(
        std.os.linux.AT.FDCWD,
        from_job,
        0,
        .{ .UID = true },
        &st,
    )));
    try std.testing.expectEqual(base_id, st.uid);

    // Refused, failing the job and naming the setting: outside the list, a link out of it (both
    // saying the same, nothing of where the link points), a mount below the list without nosuid
    // and nodev, a host path nested with another volume, and any host path in a job the runner
    // does not vouch for: a fork's pull request (scope `untrusted`), and one whose ref the
    // runner's trusted refs do not vouch for (`Config.vouched` false, as `configFor` makes it).
    job.steps = &.{testStep("echo ran-$((1+1))")};
    const not_allowed = "is not a directory under one RUNNER_NATIVE_HOST_PATHS allows";
    const Case = struct {
        volumes: []const []const u8,
        trusted: bool = true,
        vouched: bool = true,
        says: []const u8,
        setting: bool = true,
        /// What the refusal must not tell the job.
        hides: ?[]const u8 = null,
    };
    const outside = try std.fmt.allocPrint(arena, "{s}/outside:/x", .{host});
    const escape = try std.fmt.allocPrint(arena, "{s}/escape:/x", .{allowed});
    const at_x = try std.fmt.allocPrint(arena, "{s}:/x", .{data});
    const cases = [_]Case{
        .{ .volumes = &.{outside}, .says = not_allowed },
        .{ .volumes = &.{escape}, .says = not_allowed, .hides = "outside" },
        .{ .volumes = &.{try std.fmt.allocPrint(arena, "{s}:/x", .{plain})}, .says = "without nosuid and nodev" },
        .{ .volumes = &.{ at_x, try std.fmt.allocPrint(arena, "{s}/sub:/x/y", .{data}) }, .says = "nested", .setting = false },
        .{ .volumes = &.{ "/x/y", at_x }, .says = "nested", .setting = false },
        .{ .volumes = &.{at_x}, .trusted = false, .says = "does not vouch for" },
        .{ .volumes = &.{at_x}, .vouched = false, .says = "does not vouch for" },
    };
    for (cases) |c| {
        var vols: std.ArrayList(job_mod.Template) = .empty;
        for (c.volumes) |v| try vols.append(arena, .{ .lit = v });
        job.container.?.volumes = vols.items;
        var case_cfg = cfg;
        case_cfg.vouched = c.vouched;
        if (!c.vouched) {
            // As `configFor` decides it: a job the runner does not vouch for runs natively only
            // under per-job limits (else on Dagger, which binds no host path either).
            case_cfg.job_limits = jobLimits(arena, io, case_cfg.cgroup);
            if (!case_cfg.job_limits) {
                std.debug.print("skipped the unvouched case: no cgroup for per-job limits\n", .{});
                continue;
            }
        }
        const refused = try runVolumeJob(arena, case_cfg, job, c.trusted);
        try std.testing.expect(!refused.ok);
        try expectAll(refused.why, &.{c.says});
        if (c.setting) try expectAll(refused.why, &.{"RUNNER_NATIVE_HOST_PATHS"});
        try std.testing.expect(std.mem.indexOf(u8, refused.why, "ran-2") == null);
        try std.testing.expect(std.mem.indexOf(u8, refused.why, "runs on Dagger") == null);
        if (c.hides) |h| try std.testing.expect(std.mem.indexOf(u8, refused.why, h) == null);
    }
    // None allowed: off, saying so.
    var off_cfg = cfg;
    off_cfg.host_paths = &.{};
    job.container.?.volumes = &.{.{ .lit = at_x }};
    const off = try runVolumeJob(arena, off_cfg, job, true);
    try std.testing.expect(!off.ok);
    try expectAll(off.why, &.{"host paths are off: RUNNER_NATIVE_HOST_PATHS allows none"});
}

test "a container job's host path inside another bind through the image's symlink fails, making nothing on the host" {
    var a: std.heap.ArenaAllocator = .init(std.testing.allocator);
    defer a.deinit();
    const arena = a.allocator();
    const io = std.testing.io;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    var cfg = try testConfig(arena, &tmp);
    if (std.os.linux.geteuid() != 0) return error.SkipZigTest;
    const root = try tmp.dir.realPathFileAlloc(io, ".", arena);
    const host = try std.fmt.allocPrint(arena, "{s}/host", .{root});
    try tmp.dir.createDirPath(io, "host");
    try testMount(arena, host, "tmpfs", std.os.linux.MS.NOSUID | std.os.linux.MS.NODEV);
    defer testUnmount(arena, host);
    for ([_][]const u8{ "host/one", "host/two" }) |d| try tmp.dir.createDirPath(io, d);
    cfg.host_paths = try testHostPaths(arena, host);
    // The image's /y is a link to /x: `/y/z` is not below `/x` as written, and is once resolved.
    var t: oci_layer.TestTar = .{ .a = arena };
    try t.add(.{ .path = "x/", .kind = .directory, .mode = 0o755 });
    try t.add(.{ .path = "y", .kind = .symlink, .link = "/x" });
    const layers = try std.mem.concat(arena, []const u8, &.{ try testImageLayers(arena), &.{try t.finish()} });
    const img = try testregistry.testImage(arena, "test/hostlink", "1", layers, "\"PATH=/usr/bin:/bin\"", false);
    var server: testregistry.Server = .{ .routes = img.routes };
    try server.start();
    defer server.stop();
    var job = testJob(&.{testStep("echo ran-$((1+1))")});
    job.container = .{
        .name = "",
        .image = .{ .lit = try server.image(arena, "test/hostlink:1") },
        .volumes = &.{
            .{ .lit = try std.fmt.allocPrint(arena, "{s}/one:/x", .{host}) },
            .{ .lit = try std.fmt.allocPrint(arena, "{s}/two:/y/z", .{host}) },
        },
    };
    const refused = try runVolumeJob(arena, cfg, job, true);
    try std.testing.expect(!refused.ok);
    try expectAll(refused.why, &.{"the volume at /y/z lies inside another mount of the job"});
    try std.testing.expect(std.mem.indexOf(u8, refused.why, "ran-2") == null);
    // Failed, not sent to Dagger, which would run the job without its volumes.
    try std.testing.expect(std.mem.indexOf(u8, refused.why, "runs on Dagger") == null);
    // And the host's root made no mount point in the first host path on the job's behalf.
    try std.testing.expect(!testExists(arena, try std.fmt.allocPrint(arena, "{s}/one/z", .{host})));
}

test "a container job's host path on a filesystem that cannot be idmapped: refused unless the operator allows it" {
    var a: std.heap.ArenaAllocator = .init(std.testing.allocator);
    defer a.deinit();
    const arena = a.allocator();
    const io = std.testing.io;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    var cfg = try testConfig(arena, &tmp);
    if (std.os.linux.geteuid() != 0) return error.SkipZigTest;
    const root = try tmp.dir.realPathFileAlloc(io, ".", arena);
    // ramfs takes no idmapping (no FS_ALLOW_IDMAP): the kernel refuses with EINVAL, as for NFS.
    const host = try std.fmt.allocPrint(arena, "{s}/ramfs", .{root});
    try tmp.dir.createDirPath(io, "ramfs");
    try testMount(arena, host, "ramfs", std.os.linux.MS.NOSUID | std.os.linux.MS.NODEV);
    defer testUnmount(arena, host);
    // Writable by every slot's ids: unmapped, the job's root is its slot's host id.
    try std.testing.expectEqual(std.os.linux.E.SUCCESS, std.os.linux.errno(std.os.linux.chmod(try arena.dupeSentinel(u8, host, 0), 0o1777)));
    cfg.host_paths = try testHostPaths(arena, host);
    const img = try testregistry.testImage(arena, "test/hostram", "1", try testImageLayers(arena), "\"PATH=/usr/bin:/bin\"", false);
    var server: testregistry.Server = .{ .routes = img.routes };
    try server.start();
    defer server.stop();
    var job = testJob(&.{testStep("echo job > /r/from-job && echo wrote-$((2+3))")});
    job.container = .{
        .name = "",
        .image = .{ .lit = try server.image(arena, "test/hostram:1") },
        .volumes = &.{.{ .lit = try std.fmt.allocPrint(arena, "{s}:/r", .{host}) }},
    };
    const refused = try runVolumeJob(arena, cfg, job, true);
    try std.testing.expect(!refused.ok);
    try expectAll(refused.why, &.{ "cannot idmap", "RUNNER_NATIVE_HOST_PATHS_UNMAPPED=true" });
    try std.testing.expect(std.mem.indexOf(u8, refused.why, "runs on Dagger") == null);
    try std.testing.expect(std.mem.indexOf(u8, refused.why, "wrote-5") == null);
    try std.testing.expect(!testExists(arena, try std.fmt.allocPrint(arena, "{s}/from-job", .{host})));

    cfg.host_paths_unmapped = true;
    const ok = try runVolumeJob(arena, cfg, job, true);
    if (!ok.ok) std.debug.print("{s}\n", .{ok.why});
    try std.testing.expect(ok.ok);
    try expectAll(ok.text, &.{ "wrote-5", "bound with the host's ids (RUNNER_NATIVE_HOST_PATHS_UNMAPPED=true)" });
    // Owned by the job's slot's ids, never a host user's (nor the volumes' range: not mapped).
    const from_job = try std.fmt.allocPrintSentinel(arena, "{s}/from-job", .{host}, 0);
    var st: std.os.linux.Statx = undefined;
    try std.testing.expectEqual(std.os.linux.E.SUCCESS, std.os.linux.errno(std.os.linux.statx(std.os.linux.AT.FDCWD, from_job, 0, .{ .UID = true }, &st)));
    try std.testing.expect(st.uid >= cfg.subid_base and st.uid < volumeIdBase(cfg.subid_base));
}

test "a container job's named volumes: kept between jobs, filled from the image once, apart by scope and repository, :ro read-only" {
    var a: std.heap.ArenaAllocator = .init(std.testing.allocator);
    defer a.deinit();
    const arena = a.allocator();
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    const cfg = try testConfig(arena, &tmp);
    var extra: oci_layer.TestTar = .{ .a = arena };
    try extra.add(.{ .path = "srv/", .kind = .directory, .mode = 0o755 });
    try extra.add(.{ .path = "srv/seed/", .kind = .directory, .mode = 0o750, .uid = 1002, .gid = 1003 });
    try extra.add(.{ .path = "srv/seed/from-image", .body = "image\n" });
    try extra.add(.{ .path = "srv/ro/", .kind = .directory, .mode = 0o755 });
    try extra.add(.{ .path = "srv/ro/readme", .body = "read me\n" });
    const layers = try std.mem.concat(arena, []const u8, &.{ try testImageLayers(arena), &.{try extra.finish()} });
    const img = try testregistry.testImage(arena, "test/named", "1", layers, "\"PATH=/usr/bin:/bin\"", false);
    var server: testregistry.Server = .{ .routes = img.routes };
    try server.start();
    defer server.stop();
    const image = try server.image(arena, "test/named:1");
    const as_root = std.os.linux.geteuid() == 0;

    const mounts = "while read -r _ _ _ _ at opts _; do case $at in /srv/seed) echo seed-opts:$opts;; " ++
        "/srv/ro) echo ro-opts:$opts;; esac; done < /proc/self/mountinfo";
    var job = testJob(&.{
        // Nothing expected below is in the script's text, which the log echoes.
        testStep("sed 's/^/seeded:/' /srv/seed/from-image /srv/ro/readme; " ++
            "echo owner[$(stat -c %u:%g:%a /srv/seed)]; " ++
            "echo one > /srv/seed/kept && rm /srv/seed/from-image && echo wrote-$((2+3)); " ++
            "r=wrote; touch /srv/ro/x 2>/dev/null || r=refused; echo ro-$r; " ++
            // Nor can the job remount either otherwise.
            "for m in 'remount,rw /srv/ro' 'remount,bind,rw /srv/ro' 'remount,bind,suid,dev /srv/seed'; do " ++
            "mount -o $m 2>&1 && echo remount-yes-$((6*7)):$m || echo remount-no-$((40+2)); done; " ++ mounts),
        testStep("echo next-step[$(cat /srv/seed/kept)]"),
    });
    job.container = .{
        .name = "",
        .image = .{ .lit = image },
        .volumes = &.{ .{ .lit = "data:/srv/seed" }, .{ .lit = "docs:/srv/ro:ro" } },
    };
    const first = try runVolumeJob(arena, cfg, job, true);
    if (!first.ok) std.debug.print("{s}\n", .{first.text});
    try std.testing.expect(first.ok);
    try expectAll(first.text, &.{
        "Engine: native",
        // A new volume holds what the image has at its target, its owner and mode too.
        "seeded:image",
        "seeded:read me",
        if (as_root) "owner[1002:1003:750]" else "Engine: native",
        "wrote-5",
        "ro-refused",
        "seed-opts:rw,nosuid,nodev",
        "ro-opts:ro,nosuid,nodev",
        "next-step[one]",
        "2 named, kept between jobs in the native store (repo scope, 2 new and filled from the image)",
        "Step cache: off for this job",
    });
    // Each remount refused, and the mounts (read after) as they were.
    try std.testing.expect(std.mem.indexOf(u8, first.text, "remount-yes-42") == null);
    try std.testing.expectEqual(@as(usize, 3), std.mem.count(u8, first.text, "remount-no-42"));

    // The next job of the repository finds the volume as the last left it: not filled again.
    job.steps = &.{testStep("echo kept[$(cat /srv/seed/kept)]; f=no; test -e /srv/seed/from-image && " ++
        "f=yes; echo filled-again=$f; ls /srv/ro")};
    const second = try runVolumeJob(arena, cfg, job, true);
    if (!second.ok) std.debug.print("{s}\n", .{second.text});
    try std.testing.expect(second.ok);
    try expectAll(second.text, &.{ "kept[one]", "filled-again=no", "readme", "(repo scope, 0 new" });

    // An untrusted job gets no named volume at all, failing and saying so: a fork's pull request
    // (scope `untrusted`), and a job whose ref the runner's trusted refs do not vouch for
    // (`Config.vouched` false, as `configFor` makes it; native only under per-job limits).
    job.steps = &.{testStep("k=apart; test -e /srv/seed/kept && k=leaked; echo kept-$k; " ++
        "sed 's/^/seeded:/' /srv/seed/from-image")};
    const untrusted = try runVolumeJob(arena, cfg, job, false);
    try std.testing.expect(!untrusted.ok);
    try expectAll(untrusted.why, &.{ "named volume `data` is kept between jobs, which a job the runner does not vouch for", "anonymous volume (`- /srv/seed`)" });
    try std.testing.expect(std.mem.indexOf(u8, untrusted.why, "kept-") == null);
    try std.testing.expect(std.mem.indexOf(u8, untrusted.why, "runs on Dagger") == null);
    var unvouched = cfg;
    unvouched.vouched = false;
    unvouched.job_limits = jobLimits(arena, std.testing.io, unvouched.cgroup);
    if (unvouched.job_limits) {
        const refused = try runVolumeJob(arena, unvouched, job, true);
        try std.testing.expect(!refused.ok);
        try expectAll(refused.why, &.{"which a job the runner does not vouch for"});
        try std.testing.expect(std.mem.indexOf(u8, refused.why, "kept-") == null);
    } else std.debug.print("skipped the unvouched case: no cgroup for per-job limits\n", .{});
    // Neither left a volume of its own in the store.
    const store_named = try std.fmt.allocPrint(arena, "{s}/volumes/o/r/untrusted", .{cfg.store});
    try std.testing.expectError(error.FileNotFound, std.Io.Dir.cwd().access(std.testing.io, store_named, .{}));
    // A trusted job of another repository never sees it: a new volume, filled from its image.
    job.github.repository = "o/other";
    const other = try runVolumeJob(arena, cfg, job, true);
    if (!other.ok) std.debug.print("{s}\n", .{other.text});
    try std.testing.expect(other.ok);
    try expectAll(other.text, &.{ "kept-apart", "seeded:image", "(repo scope, 2 new" });

    // A filling that does not end (an image's `cp` that hangs) is stopped at its limit, failing
    // the job, and the volume is removed so the next job fills it: no other job waits on it for
    // good.
    var slow = cfg;
    slow.test_volume_seed = "sleep 60";
    slow.test_volume_seed_limit_ms = 1000;
    job.github.repository = "o/slow";
    job.steps = &.{testStep("echo ran-$((1+1))")};
    const started = std.Io.Clock.awake.now(std.testing.io).toMilliseconds();
    const stuck = try runVolumeJob(arena, slow, job, true);
    const took_ms = std.Io.Clock.awake.now(std.testing.io).toMilliseconds() - started;
    try std.testing.expect(!stuck.ok);
    try expectAll(stuck.why, &.{ "could not fill the new volume `data`", "stopped after 1 s" });
    try std.testing.expect(std.mem.indexOf(u8, stuck.why, "ran-2") == null);
    try std.testing.expect(took_ms < 30_000);
    const after = try runVolumeJob(arena, cfg, job, true);
    if (!after.ok) std.debug.print("{s}\n", .{after.text});
    try std.testing.expect(after.ok);
    try expectAll(after.text, &.{"(repo scope, 2 new"});
}

test "a container job's named volume and host path together: both bound, nesting across kinds refused" {
    var a: std.heap.ArenaAllocator = .init(std.testing.allocator);
    defer a.deinit();
    const arena = a.allocator();
    const io = std.testing.io;
    // Host paths need a root runner (a rootless one refuses them, tested above).
    if (std.os.linux.geteuid() != 0) return error.SkipZigTest;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    var cfg = try testConfig(arena, &tmp);
    const root = try tmp.dir.realPathFileAlloc(io, ".", arena);
    var extra: oci_layer.TestTar = .{ .a = arena };
    try extra.add(.{ .path = "srv/", .kind = .directory, .mode = 0o755 });
    try extra.add(.{ .path = "srv/seed/", .kind = .directory, .mode = 0o755 });
    try extra.add(.{ .path = "srv/seed/from-image", .body = "image\n" });
    const layers = try std.mem.concat(arena, []const u8, &.{ try testImageLayers(arena), &.{try extra.finish()} });
    const img = try testregistry.testImage(arena, "test/bothvol", "1", layers, "\"PATH=/usr/bin:/bin\"", false);
    var server: testregistry.Server = .{ .routes = img.routes };
    try server.start();
    defer server.stop();
    const image = try server.image(arena, "test/bothvol:1");
    const host = try std.fmt.allocPrint(arena, "{s}/host", .{root});
    try tmp.dir.createDirPath(io, "host");
    try testMount(arena, host, "tmpfs", std.os.linux.MS.NOSUID | std.os.linux.MS.NODEV);
    defer testUnmount(arena, host);
    try tmp.dir.createDirPath(io, "host/data");
    try tmp.dir.writeFile(io, .{ .sub_path = "host/data/from-host", .data = "host file\n" });
    cfg.host_paths = try testHostPaths(arena, host);
    const data = try std.fmt.allocPrint(arena, "{s}/data", .{host});
    const base_id = volumeIdBase(cfg.subid_base);
    try std.testing.expectEqual(std.os.linux.E.SUCCESS, std.os.linux.errno(std.os.linux.lchown(try arena.dupeSentinel(u8, data, 0), base_id, base_id)));

    // Side by side: the named volume filled from the image and kept, the host path the host's,
    // both nosuid and nodev, and the job's step cache off. Nothing expected is in the script.
    const mounts = "while read -r _ _ _ _ at opts _; do case $at in /srv/seed) echo named-opts:$opts;; " ++
        "/h) echo host-opts:$opts;; esac; done < /proc/self/mountinfo";
    var job = testJob(&.{testStep("sed 's/^/named:/' /srv/seed/from-image; sed 's/^/host:/' /h/from-host; " ++
        "echo one > /srv/seed/kept && echo job > /h/from-job && echo wrote-$((2+3)); " ++
        "k=no; test -e /h/kept && k=yes; echo crossed-$k; " ++ mounts)});
    const both = [_]job_mod.Template{ .{ .lit = "data:/srv/seed" }, .{ .lit = try std.fmt.allocPrint(arena, "{s}:/h", .{data}) } };
    job.container = .{ .name = "", .image = .{ .lit = image }, .volumes = &both };
    const ok = try runVolumeJob(arena, cfg, job, true);
    if (!ok.ok) std.debug.print("{s}\n", .{ok.why});
    try std.testing.expect(ok.ok);
    try expectAll(ok.text, &.{
        "Engine: native",
        "named:image",
        "host:host file",
        "wrote-5",
        "crossed-no",
        "named-opts:rw,nosuid,nodev",
        "host-opts:rw,nosuid,nodev",
        "1 named, kept between jobs in the native store (repo scope, 1 new and filled from the image)",
        "1 host path(s) bound (0 read-only), nosuid and nodev, allowed by RUNNER_NATIVE_HOST_PATHS",
        "Step cache: off for this job, as it mounts named volumes or binds host paths",
    });
    const from_job = try std.fmt.allocPrintSentinel(arena, "{s}/from-job", .{data}, 0);
    var st: std.os.linux.Statx = undefined;
    try std.testing.expectEqual(std.os.linux.E.SUCCESS, std.os.linux.errno(std.os.linux.statx(std.os.linux.AT.FDCWD, from_job, 0, .{ .UID = true }, &st)));
    try std.testing.expectEqual(base_id, st.uid);
    job.steps = &.{testStep("echo kept[$(cat /srv/seed/kept)]")};
    const again = try runVolumeJob(arena, cfg, job, true);
    if (!again.ok) std.debug.print("{s}\n", .{again.why});
    try std.testing.expect(again.ok);
    try expectAll(again.text, &.{ "kept[one]", "(repo scope, 0 new" });

    // Nested across kinds, as written: a host path inside a named volume, a named volume inside a
    // host path, and a named volume inside another; each fails before any named volume is opened.
    job.steps = &.{testStep("echo ran-$((1+1))")};
    job.github.repository = "o/nest";
    const host_in_named = try std.fmt.allocPrint(arena, "{s}:/srv/seed/h", .{data});
    const at_h = try std.fmt.allocPrint(arena, "{s}:/h", .{data});
    const nested = [_][2][]const u8{
        .{ "data:/srv/seed", host_in_named },
        .{ host_in_named, "data:/srv/seed" },
        .{ at_h, "data:/h/n" },
        .{ "data:/n", "more:/n/m" },
    };
    for (nested) |pair| {
        job.container.?.volumes = &.{ .{ .lit = pair[0] }, .{ .lit = pair[1] } };
        const refused = try runVolumeJob(arena, cfg, job, true);
        try std.testing.expect(!refused.ok);
        try expectAll(refused.why, &.{"is nested with the one at"});
        try std.testing.expect(std.mem.indexOf(u8, refused.why, "ran-2") == null);
        try std.testing.expect(std.mem.indexOf(u8, refused.why, "runs on Dagger") == null);
    }
    const store_nest = try std.fmt.allocPrint(arena, "{s}/volumes/o/nest", .{cfg.store});
    try std.testing.expectError(error.FileNotFound, std.Io.Dir.cwd().access(io, store_nest, .{}));
    // An anonymous volume holding a named one nests as Docker's do.
    job.container.?.volumes = &.{ .{ .lit = "/anon" }, .{ .lit = "inner:/anon/n" } };
    const anon = try runVolumeJob(arena, cfg, job, true);
    if (!anon.ok) std.debug.print("{s}\n", .{anon.why});
    try std.testing.expect(anon.ok);
    try expectAll(anon.text, &.{"ran-2"});
}

test "a container job's ports, host path and named volume together: each carried out, the port serves both" {
    var a: std.heap.ArenaAllocator = .init(std.testing.allocator);
    defer a.deinit();
    const arena = a.allocator();
    const io = std.testing.io;
    const linux = std.os.linux;
    // Ports and host paths need a root runner.
    if (linux.geteuid() != 0) return error.SkipZigTest;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    var cfg = try testConfig(arena, &tmp);
    const root = try tmp.dir.realPathFileAlloc(io, ".", arena);
    var extra: oci_layer.TestTar = .{ .a = arena };
    try extra.add(.{ .path = "srv/", .kind = .directory, .mode = 0o755 });
    try extra.add(.{ .path = "srv/seed/", .kind = .directory, .mode = 0o755 });
    try extra.add(.{ .path = "srv/seed/from-image", .body = "image\n" });
    const layers = try std.mem.concat(arena, []const u8, &.{ try testImageLayers(arena), &.{try extra.finish()} });
    const img = try testregistry.testImage(arena, "test/allthree", "1", layers, "\"PATH=/usr/bin:/bin\"", false);
    var server: testregistry.Server = .{ .routes = img.routes };
    try server.start();
    defer server.stop();
    const host = try std.fmt.allocPrint(arena, "{s}/host", .{root});
    try tmp.dir.createDirPath(io, "host");
    try testMount(arena, host, "tmpfs", linux.MS.NOSUID | linux.MS.NODEV);
    defer testUnmount(arena, host);
    try tmp.dir.createDirPath(io, "host/data");
    try tmp.dir.writeFile(io, .{ .sub_path = "host/data/from-host", .data = "host file\n" });
    cfg.host_paths = try testHostPaths(arena, host);
    cfg.port_range = .{ .lo = 1024, .hi = 65535 };
    const hp = try freePort();

    // The job's server sends what the host path and the named volume hold, until one says "quit".
    const serve =
        \\python3 -c '
        \\import socket
        \\body = open("/h/from-host", "rb").read() + open("/srv/seed/from-image", "rb").read()
        \\s = socket.socket(); s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        \\s.bind(("0.0.0.0", 8080)); s.listen(8); s.settimeout(120)
        \\while True:
        \\    c, _ = s.accept(); c.settimeout(10)
        \\    try:
        \\        c.sendall(body); d = c.recv(16)
        \\    except Exception:
        \\        d = b""
        \\    c.close()
        \\    if d.startswith(b"quit"): break
        \\print("served-" + str(2 + 3))
        \\'
    ;
    var job: PortJob = .{ .cfg = cfg, .job = testJob(&.{testStep(serve)}) };
    defer job.arena.deinit();
    const vols = [_]job_mod.Template{ .{ .lit = "data:/srv/seed" }, .{ .lit = try std.fmt.allocPrint(arena, "{s}/data:/h:ro", .{host}) } };
    job.job.container = .{
        .name = "",
        .image = .{ .lit = try server.image(arena, "test/allthree:1") },
        .volumes = &vols,
        .ports = &.{.{ .lit = try std.fmt.allocPrint(arena, "{d}:8080", .{hp}) }},
    };
    const t = try std.Thread.spawn(.{}, PortJob.run, .{&job});
    var got = false;
    var tries: u32 = 0;
    while (!got and tries < 1200) : (tries += 1) {
        if (connectLoopback(hp)) |fd| {
            defer _ = linux.close(fd);
            var buf: [64]u8 = undefined;
            var fds = [_]linux.pollfd{.{ .fd = fd, .events = linux.POLL.IN, .revents = 0 }};
            if (linux.poll(&fds, 1, 2000) == 1) {
                const n = linux.read(fd, &buf, buf.len);
                if (linux.errno(n) == .SUCCESS and std.mem.eql(u8, buf[0..n], "host file\nimage\n")) {
                    got = true;
                    _ = linux.write(fd, "quit\n", 5);
                }
            }
        }
        io.sleep(.fromMilliseconds(100), .awake) catch {};
    }
    t.join();
    if (!job.ok) std.debug.print("{s}\n", .{job.why});
    try std.testing.expect(got);
    try std.testing.expect(job.ok);
    try expectAll(job.text, &.{
        "Engine: native",
        "served-5",
        try std.fmt.allocPrint(arena, "Container ports: 8080/tcp -> 127.0.0.1:{d}", .{hp}),
        "1 named, kept between jobs in the native store (repo scope, 1 new and filled from the image)",
        "1 host path(s) bound (1 read-only), nosuid and nodev",
    });
    try std.testing.expect(connectLoopback(hp) == null);
}

test "the base hands a work root to the user, and the tool cache only when it is not theirs" {
    var a: std.heap.ArenaAllocator = .init(std.testing.allocator);
    defer a.deinit();
    const arena = a.allocator();
    const none = try ownedBy(arena, 1002, 1003, "", true);
    try std.testing.expectEqualStrings(" && chown -R 1002:1003 /__w", none);
    const with = try ownedBy(arena, 1002, 1003, " /opt/hostedtoolcache", false);
    const head = " && chown -R 1002:1003 /home/runner/work && { [ ";
    try std.testing.expect(std.mem.startsWith(u8, with, head));
    const tail = "= 1002:1003 ] || chown -R 1002:1003 /opt/hostedtoolcache; }";
    try std.testing.expect(std.mem.indexOf(u8, with, tail) != null);
}

test "a container job's --user the image does not know fails the job, never runs it as root" {
    var a: std.heap.ArenaAllocator = .init(std.testing.allocator);
    defer a.deinit();
    const arena = a.allocator();
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    const cfg = try testConfig(arena, &tmp);
    const layers = try testImageLayers(arena);
    const img = try testregistry.testImage(arena, "test/typo", "1", layers, "\"PATH=/bin\"", false);
    var server: testregistry.Server = .{ .routes = img.routes };
    try server.start();
    defer server.stop();

    var job = testJob(&.{testStep("echo ran as $(id -u)")});
    job.container = .{
        .name = "",
        .image = .{ .lit = try server.image(arena, "test/typo:1") },
        .options = .{ .lit = "--user typo" },
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
    try std.testing.expect(!res.succeeded);
    const reason = "--user typo: not in its /etc/passwd";
    // The job's failure (`engine_error`), not a step's output.
    try std.testing.expect(std.mem.indexOf(u8, res.engine_error orelse "", reason) != null);
    try std.testing.expect(std.mem.indexOf(u8, text, "ran as") == null);
    try std.testing.expect(std.mem.indexOf(u8, text, "runs on Dagger") == null);
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

test "native pre-provisioned image: pulled as the rootfs; nothing pinned, a stale pin or the setting leaves it to apt; a failed pull says why" {
    var a: std.heap.ArenaAllocator = .init(std.testing.allocator);
    defer a.deinit();
    const arena = a.allocator();
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    var cfg = try testConfig(arena, &tmp);
    const fp = try arena.dupe(u8, &provisioned.fingerprint(.root));
    const tag = try std.fmt.allocPrint(arena, "{s}-root", .{fp});
    const img = try testregistry.testImage(arena, "test/base", tag, try testImageLayers(arena), "\"PATH=/usr/bin:/bin\"", false);
    var server: testregistry.Server = .{ .routes = img.routes };
    try server.start();
    defer server.stop();
    const repository = try server.image(arena, "test/base");
    const pins: provisioned.Pins = .{
        .root = .{ .fingerprint = fp, .digest = img.index },
        .runner = .{ .fingerprint = "", .digest = "" },
        .repository = repository,
    };

    // Pinned and current: its own tree is the rootfs, in the store's image area, a path no
    // locally provisioned rootfs has, so the step cache's keys cannot take one for the other.
    cfg.provisioned_pins = pins;
    {
        var b = try init(arena, std.testing.io, std.testing.allocator, cfg);
        defer b.deinit();
        var err_msg: []const u8 = "";
        const got = try b.fetchRootfs(dagger.default_image, null, true, false, &err_msg);
        try std.testing.expect(std.mem.indexOf(u8, b.rootfs, "/oci/images/") != null);
        try std.testing.expectEqualStrings(got.rootfs, b.rootfs);
        try std.testing.expectEqualStrings("from the image\n", try std.Io.Dir.cwd().readFileAlloc(std.testing.io, try std.fmt.allocPrint(arena, "{s}/etc/marker", .{b.rootfs}), arena, .limited(64)));
        const note = b.notes.getLast();
        try std.testing.expect(std.mem.indexOf(u8, note, "Provisioned image: ") != null);
        try std.testing.expect(std.mem.indexOf(u8, note, "@" ++ "sha256:") != null);
        try std.testing.expect(std.mem.indexOf(u8, note, "Provisioned natively") == null);
    }

    // Not pinned for the runner variant, a pin made for another script, and the setting off:
    // nothing is pulled, and nothing is said.
    const stale: provisioned.Pins = .{
        .root = .{ .fingerprint = "000000000000", .digest = img.index },
        .runner = pins.runner,
        .repository = repository,
    };
    const before = server.requests.load(.acquire);
    for ([_]struct { pins: provisioned.Pins, on: bool, as_runner: bool }{
        .{ .pins = pins, .on = true, .as_runner = true },
        .{ .pins = stale, .on = true, .as_runner = false },
        .{ .pins = pins, .on = false, .as_runner = false },
    }) |case| {
        cfg.provisioned_pins = case.pins;
        cfg.provisioned_image = case.on;
        var b = try init(arena, std.testing.io, std.testing.allocator, cfg);
        defer b.deinit();
        try std.testing.expect(try b.pullProvisioned(case.as_runner) == null);
        for (b.notes.items) |n| try std.testing.expect(std.mem.indexOf(u8, n, "Provisioned image") == null);
    }
    try std.testing.expectEqual(before, server.requests.load(.acquire));

    // A registry that cannot be reached: no image, and the note says what could not be pulled,
    // for the caller to provision with apt.
    // (Not the digest the store has: an image it holds is found without asking the registry.)
    const unseen = "sha256:cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc";
    cfg.provisioned_pins = .{
        .root = .{ .fingerprint = fp, .digest = unseen },
        .runner = pins.runner,
        .repository = "127.0.0.1:1/test/base",
    };
    cfg.provisioned_image = true;
    var gone = try init(arena, std.testing.io, std.testing.allocator, cfg);
    defer gone.deinit();
    try std.testing.expect(try gone.pullProvisioned(false) == null);
    const said = gone.notes.getLast();
    try std.testing.expect(std.mem.indexOf(u8, said, "Provisioned image: could not pull 127.0.0.1:1/test/base:") != null);
    try std.testing.expect(std.mem.indexOf(u8, said, "provisioning with apt-get instead") != null);
}

/// A runner's job ends, again and again, while the test's job runs: what it holds must stay.
const Evictor = struct {
    s: Store,
    stop: std.atomic.Value(bool) = .init(false),

    fn hostile(root: []const u8) Evictor {
        return .{ .s = .{ .root = root, .max_bytes = 1, .limits = .{
            .volumes_max_bytes = 1,
            .images_max_bytes = 1,
            .min_free_pct = 0,
            .idle_s = 0,
            .recent_s = 0,
            .remeasure_s = 0,
        } } };
    }

    fn run(e: *Evictor) void {
        while (!e.stop.load(.acquire)) {
            var a: std.heap.ArenaAllocator = .init(std.heap.page_allocator);
            defer a.deinit();
            e.s.collect(a.allocator(), std.testing.io);
            std.testing.io.sleep(.fromMilliseconds(5), .awake) catch {};
        }
    }

    fn end(e: *Evictor, t: std.Thread) void {
        e.stop.store(true, .release);
        t.join();
    }
};

test "native eviction under a real job: its rootfs and image are its overlay's lowers, and stay" {
    var a: std.heap.ArenaAllocator = .init(std.testing.allocator);
    defer a.deinit();
    const arena = a.allocator();
    const io = std.testing.io;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    const cfg = try testConfig(arena, &tmp);
    const img = try testregistry.testImage(arena, "test/prov", "1", try testImageLayers(arena), "\"PATH=/usr/bin:/bin\"", false);
    var server: testregistry.Server = .{ .routes = img.routes };
    try server.start();
    defer server.stop();

    var evictor: Evictor = .hostile(cfg.store);
    var b = try init(arena, io, std.testing.allocator, cfg);
    var ended = false;
    defer if (!ended) b.deinit();
    var why: []const u8 = "";
    const pulled = try b.pull(try server.image(arena, "test/prov:1"), null, &why);
    var err_msg: []const u8 = "";
    const rootfs = try b.provision(pulled, "mkdir -p /opt/tool && echo new > /opt/tool/f", &err_msg);
    const t: std.Thread = try .spawn(.{}, Evictor.run, .{&evictor});
    {
        defer evictor.end(t);
        b.rootfs = rootfs;
        var out: Captured = .{ .arena = arena };
        const step = try b.exec(
            \\for i in 1 2 3 4 5 6 7 8 9 10; do
            \\  [ "$(cat /opt/tool/f)" = new ] && [ "$(cat /etc/marker)" = "from the image" ] || exit 9
            \\  sleep 0.1
            \\done
        , &.{"PATH=" ++ image_path}, &.{}, 0, 0, out.output());
        try std.testing.expectEqual(@as(i32, 0), step.code);
    }
    try std.Io.Dir.cwd().access(io, rootfs, .{});
    try std.Io.Dir.cwd().access(io, pulled.rootfs, .{});
    // Let go, both can go: they were kept by the job's locks, and nothing else.
    b.deinit();
    ended = true;
    var after: Evictor = .hostile(cfg.store);
    for (0..8) |_| after.s.collect(arena, io);
    try std.testing.expectError(error.FileNotFound, std.Io.Dir.cwd().access(io, rootfs, .{}));
    try std.testing.expectError(error.FileNotFound, std.Io.Dir.cwd().access(io, pulled.rootfs, .{}));
}

test "native eviction under a real job: a seed and a volume stay until it ends, and a seed built again is a new key" {
    var a: std.heap.ArenaAllocator = .init(std.testing.allocator);
    defer a.deinit();
    const arena = a.allocator();
    const io = std.testing.io;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    var cfg = try testConfig(arena, &tmp);
    cfg.test_seed_script = "mkdir -p /zig-seed/o/s && echo seeded > /zig-seed/o/s/f";
    const caches: volumes.Options = .{
        .package_caches = true,
        .trusted = true,
        .zig_seeds = &.{.{ .version = "0.0.1", .sha256 = "00" }},
    };
    const job = testJob(&.{testStep(
        \\echo mine > /root/.npm/f # npm zig build
        \\for i in 1 2 3 4 5 6 7 8 9 10; do
        \\  [ "$(cat /root/.cache/zig/o/s/f)" = seeded ] && [ "$(cat /root/.npm/f)" = mine ] || exit 9
        \\  sleep 0.1
        \\done
        \\echo whole-to-the-end
    )});
    var evictor: Evictor = .hostile(cfg.store);
    const t: std.Thread = try .spawn(.{}, Evictor.run, .{&evictor});
    const first = first: {
        defer evictor.end(t);
        break :first try runCachedJob(arena, cfg, job, caches, .{});
    };
    try expectLines(first.text, &.{ "whole-to-the-end", "Zig global cache seeded from Zig 0.0.1" });
    // Let go, it can go: the job's lock was what kept it.
    var after: Evictor = .hostile(cfg.store);
    for (0..8) |_| after.s.collect(arena, io);
    const dir = try std.fmt.allocPrint(arena, "{s}/seeds", .{cfg.store});
    try std.testing.expectError(error.NoSeed, seedIn(arena, io, dir));
    // Built again, the job's layer on the old one is not replayed over it.
    const second = try runCachedJob(arena, cfg, job, caches, .{});
    try expectLines(second.text, &.{"whole-to-the-end"});
}

test "the native pre-warm makes the Zig seed a job then finds, and a second warm finds it made" {
    var a: std.heap.ArenaAllocator = .init(std.testing.allocator);
    defer a.deinit();
    const arena = a.allocator();
    const io = std.testing.io;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    var cfg = try testConfig(arena, &tmp);
    cfg.test_seed_script = "mkdir -p /zig-seed/o/s && echo seeded > /zig-seed/o/s/f";
    const zig_seeds: []const config.ZigSeed = &.{.{ .version = "0.0.1", .sha256 = "00" }};
    const plan: Warm = .{ .image = dagger.default_image, .provision = true, .as_runner = false, .seeds = zig_seeds };

    var err_msg: []const u8 = "";
    {
        var b = try init(arena, io, std.testing.allocator, cfg);
        defer b.deinit();
        const first = try b.warm(plan, &err_msg);
        try std.testing.expectEqual(@as(u32, 1), first.seeds_built);
        try std.testing.expectEqual(@as(u32, 0), first.seeds_found);
        try std.testing.expect(first.seed_failure == null);
    }
    {
        var b = try init(arena, io, std.testing.allocator, cfg);
        defer b.deinit();
        const second = try b.warm(plan, &err_msg);
        try std.testing.expectEqual(@as(u32, 0), second.seeds_built);
        try std.testing.expectEqual(@as(u32, 1), second.seeds_found);
    }

    // The job's own build would fail: what it runs on is the pre-warm's seed.
    var job_cfg = cfg;
    job_cfg.test_seed_script = "exit 1";
    const caches: volumes.Options = .{ .package_caches = true, .trusted = true, .zig_seeds = zig_seeds };
    const job = testJob(&.{testStep(
        \\[ "$(cat /root/.cache/zig/o/s/f)" = seeded ] || exit 9 # zig build
        \\echo found-the-warm-seed
    )});
    const ran = try runCachedJob(arena, job_cfg, job, caches, .{});
    try expectLines(ran.text, &.{ "found-the-warm-seed", "Zig global cache seeded from Zig 0.0.1" });

    // A seed that cannot be made is said and left to the job; the image is still warm.
    var broken = cfg;
    broken.test_seed_script = "exit 1";
    var b = try init(arena, io, std.testing.allocator, broken);
    defer b.deinit();
    const other: Warm = .{
        .image = dagger.default_image,
        .provision = true,
        .as_runner = false,
        .seeds = &.{.{ .version = "0.0.2", .sha256 = "00" }},
    };
    const failed_warm = try b.warm(other, &err_msg);
    try std.testing.expectEqual(@as(u32, 0), failed_warm.seeds_built);
    try std.testing.expect(failed_warm.seed_failure != null);
}

/// The one seed under `dir`.
fn seedIn(arena: Allocator, io: std.Io, dir: []const u8) ![]const u8 {
    var d = try std.Io.Dir.cwd().openDir(io, dir, .{ .iterate = true });
    defer d.close(io);
    var it = d.iterate();
    while (try it.next(io)) |e| if (e.kind == .directory and e.name[0] != '.')
        return std.fmt.allocPrint(arena, "{s}/{s}", .{ dir, e.name });
    return error.NoSeed;
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
    // What a job's end evicted is deleted after it returns (`reaper`).
    reaper.drain(std.testing.io);
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

test "native step cache: a miss says which part of the key changed, from the step's last run" {
    var a: std.heap.ArenaAllocator = .init(std.testing.allocator);
    defer a.deinit();
    const arena = a.allocator();
    const io = std.testing.io;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    const c = try cachedConfig(arena, &tmp);
    const first = testJob(&.{ testStep("echo one"), testStep("echo two") });
    const j1 = try runCached(arena, c.cfg, first, "j1");
    try expectSucceeded(j1);
    // The first run of a step has nothing to compare with.
    try std.testing.expect(std.mem.indexOf(u8, j1.text, "Not replayed") == null);

    // Every layer has its key's components, and none holds a script's text or a value.
    var layers = try std.Io.Dir.cwd().openDir(io, try std.fmt.allocPrint(arena, "{s}/layers", .{c.cfg.store}), .{ .iterate = true });
    defer layers.close(io);
    var n: usize = 0;
    var it = layers.iterate();
    while (try it.next(io)) |e| {
        const text = try layers.readFileAlloc(io, try std.fmt.allocPrint(arena, "{s}/components", .{e.name}), arena, .limited(64 * 1024));
        try std.testing.expect(std.mem.indexOf(u8, text, "script\tsha:") != null);
        try std.testing.expect(std.mem.indexOf(u8, text, "echo") == null);
        n += 1;
    }
    try std.testing.expectEqual(@as(usize, 3), n);

    // Same job: replayed, so nothing to explain.
    const same = try runCached(arena, c.cfg, first, "j2");
    try std.testing.expect(std.mem.indexOf(u8, same.text, "Not replayed") == null);

    // A second step with another script: its own script is named. The first one replays.
    const edited = testJob(&.{ testStep("echo one"), testStep("echo three") });
    const j3 = try runCached(arena, c.cfg, edited, "j3");
    try expectSucceeded(j3);
    try std.testing.expectEqual(@as(usize, 1), std.mem.count(u8, j3.text, "Not replayed: the step's script changed ("));
    try std.testing.expectEqual(@as(usize, 1), std.mem.count(u8, j3.text, "Not replayed"));

    // The first step changed: the second misses only because of it, and says so.
    const earlier = testJob(&.{ testStep("echo zero"), testStep("echo three") });
    const j4 = try runCached(arena, c.cfg, earlier, "j4");
    try expectSucceeded(j4);
    try std.testing.expectEqual(@as(usize, 2), std.mem.count(u8, j4.text, "Not replayed"));
    try std.testing.expect(std.mem.indexOf(u8, j4.text, "Not replayed: an earlier step did not replay: the step's script changed (") != null);
}

test "native step cache: a step's identity holds its scope, so trusted and untrusted jobs never share a record" {
    var b: Backend = undefined;
    b.ident = .{ "repo", "o/r", "ci", "build", "build" };
    const trusted = b.stepIdent("step 2");
    b.ident[0] = "untrusted";
    try std.testing.expect(!std.mem.eql(u8, &trusted, &b.stepIdent("step 2")));
    b.ident[0] = "repo";
    try std.testing.expectEqualSlices(u8, &trusted, &b.stepIdent("step 2"));
    try std.testing.expect(!std.mem.eql(u8, &trusted, &b.stepIdent("step 3")));
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

test "nothing is keyed above a layer with no key: what a Docker action or a mount left is in no key" {
    var a: std.heap.ArenaAllocator = .init(std.testing.allocator);
    defer a.deinit();
    const arena = a.allocator();
    var b: Backend = undefined;
    b.store = .{ .root = "/nowhere" };
    b.arena = arena;
    b.pending = null;
    b.env = .empty;
    b.workdir = "/w";
    b.layers = .empty;
    const stored: Store.Key = @splat(7);
    try b.layers.append(arena, .{ .name = "l0", .path = "/l0", .key = stored });
    try std.testing.expect(try b.keyFor(.step, "true", &.{}, 0, 0) != null);
    // What `execIn` leaves for a Docker action's step, a JavaScript action's mount points (bound in
    // every later step from then on) or an always-run step.
    try b.layers.append(arena, .{ .name = "L1", .path = "/L1" });
    try std.testing.expect(try b.keyFor(.step, "true", &.{}, 0, 0) == null);
    // A fetched tree on it stays the job's own: `claimKey` is never reached.
    try b.layers.append(arena, .{ .name = "L2", .path = "/L2" });
    try b.keyFetched("an action's tree");
    try std.testing.expectEqual(@as(usize, 3), b.layers.items.len);
    try std.testing.expect(b.layers.items[2].key == null);
    try std.testing.expect(try b.keyFor(.step, "true", &.{}, 0, 0) == null);
}

test "native step cache: nothing after a Docker action is replayed or kept, nor can its image be stale" {
    var a: std.heap.ArenaAllocator = .init(std.testing.allocator);
    defer a.deinit();
    const arena = a.allocator();
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    var c = try cachedConfig(arena, &tmp);
    const image = "zr-test/tool:1";
    c.cfg.images = try @import("docker_action.zig").testImage(arena, &tmp, image, "{\"config\":{\"Env\":[\"PATH=/usr/bin:/bin\"]}}");
    var docker_step = testStep("");
    docker_step.action = .{ .docker = .{ .image = image, .inputs = &.{
        .{ .name = "entrypoint", .value = .{ .lit = "sh" } },
        .{ .name = "args", .value = .{ .lit = "-c \"cat /image-marker > from-image\"" } },
    } } };
    const job = testJob(&.{
        testStep("echo x >> /shared/before"),
        docker_step,
        testStep("echo x >> /shared/after; cat from-image"),
    });
    const first = try runCached(arena, c.cfg, job, "j1");
    try expectSucceeded(first);
    try expectLines(first.text, &.{"in the image"});
    // The tag now names another image: the step after it sees what the new one gave.
    const marker = try std.fmt.allocPrint(arena, "images/{s}/rootfs/image-marker", .{try images.key(arena, image)});
    try tmp.dir.writeFile(std.testing.io, .{ .sub_path = marker, .data = "moved under its tag\n" });
    const second = try runCached(arena, c.cfg, job, "j2");
    try expectSucceeded(second);
    try expectLines(second.text, &.{"moved under its tag"});
    try std.testing.expectEqual(@as(usize, 1), runs(arena, c.shared, "before"));
    try std.testing.expectEqual(@as(usize, 2), runs(arena, c.shared, "after"));
    // The base and the step before the action.
    try std.testing.expectEqual(@as(usize, 2), try storeLayers(arena, c.cfg.store));
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
    var c = try cachedConfig(arena, &tmp);
    // Synced before it is published: a layer left pending is the publishing job's alone, and the
    // job waiting for the key would run the step again (`Store.defer_sync`).
    c.cfg.defer_sync = false;
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

/// The files in `shared` whose names start with `prefix`: one for each run of a step that makes one.
fn madeBy(io: std.Io, shared: []const u8, prefix: []const u8) usize {
    var dir = std.Io.Dir.cwd().openDir(io, shared, .{ .iterate = true }) catch return 0;
    defer dir.close(io);
    var n: usize = 0;
    var it = dir.iterate();
    while (it.next(io) catch null) |e| n += @intFromBool(std.mem.startsWith(u8, e.name, prefix));
    return n;
}

test "native step cache: with the deferred sync, a job that lost a key to another's pending layer keeps caching its later steps" {
    var a: std.heap.ArenaAllocator = .init(std.testing.allocator);
    defer a.deinit();
    const arena = a.allocator();
    const io = std.testing.io;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    const c = try cachedConfig(arena, &tmp);
    // The first step is the same in both jobs, and the other waits for its key: the first job's layer
    // is pending when it gets the lock, so it runs the step too, and its publish loses. Its second
    // step is then keyed over its own layer, and a third run replays both from the store.
    const job = testJob(&.{ testStep("sleep 1; mktemp /shared/first.XXXXXX"), testStep("mktemp /shared/second.XXXXXX") });
    const Other = struct {
        fn run(cfg: Config, j: job_mod.Job, ok: *bool) void {
            var b: std.heap.ArenaAllocator = .init(std.testing.allocator);
            const r = runCached(b.allocator(), cfg, j, "j2") catch {
                b.deinit();
                return;
            };
            ok.* = r.res.succeeded;
            b.deinit();
        }
    };
    var other_ok = false;
    var other = try io.concurrent(Other.run, .{ c.cfg, job, &other_ok });
    const mine = try runCached(arena, c.cfg, job, "j1");
    other.await(io);
    try expectSucceeded(mine);
    try std.testing.expect(other_ok);
    const before_first = madeBy(io, c.shared, "first.");
    const before_second = madeBy(io, c.shared, "second.");
    try std.testing.expect(before_first >= 1 and before_first <= 2);
    try std.testing.expect(before_second >= 1 and before_second <= 2);
    // Both jobs ended, so every layer is durable and a later job replays everything.
    const third = try runCached(arena, c.cfg, job, "j3");
    try expectSucceeded(third);
    try std.testing.expectEqual(before_first, madeBy(io, c.shared, "first."));
    try std.testing.expectEqual(before_second, madeBy(io, c.shared, "second."));
    try std.testing.expect(std.mem.count(u8, third.text, dagger.native_reused_note) >= 2);
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
    // RHEL's `id` is a script for its single-binary coreutils, which the kernel gives no
    // privilege by its mode: there the binary itself is copied, and told which program to be.
    var head: [2]u8 = undefined;
    const single = std.mem.eql(u8, std.Io.Dir.cwd().readFile(io, "/usr/bin/id", &head) catch "", "#!");
    const suid_src = if (single) "/usr/bin/coreutils" else "/usr/bin/id";
    const suid_id = if (single) "/w/suid --coreutils-prog=id -u" else "/w/suid -u";
    const make = testStep(try std.fmt.allocPrint(arena, "echo x >> /shared/made; /opt/sudo -n mkdir -p /w && " ++
        "/opt/sudo -n chown 1001:1001 /w && echo mine > /w/mine && " ++
        "/opt/sudo -n cp {s} /w/suid && /opt/sudo -n chmod 4755 /w/suid", .{suid_src}));
    // Run as the runner user, the set-uid file works through the stored layer (euid 0), and
    // that 0 is the second job's root: its own range of host ids.
    const look = testStep(try std.fmt.allocPrint(arena, "stat -c 'seen %n %u:%g %a' /w/mine /w/suid; " ++
        "echo suid-euid=$({s}); " ++
        "head -n1 /proc/self/uid_map | tr -s ' ' | sed 's/^ //; s/^/map /'; " ++
        "echo more >> /w/mine && stat -c 'copied up %u:%g' /w/mine", .{suid_id}));
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

/// The steps of the idmapped-upper tests: one that leaves a tree of every kind of entry, owners,
/// set-id bits, links, and (where the tools are there) an ACL and a file capability; one that
/// deletes and changes in it, so overlay copies up and makes a whiteout; and one that says what a
/// later job sees, its lines starting `seen`. A job cannot make what its ids do not reach.
const idmapped_steps = [_][]const u8{
    "mkdir -p /w/d/e && echo a > /w/a && echo b > /w/d/e/b && chown 1001:1001 /w/d /w/a && " ++
        "chown 1002:1003 /w/d/e/b && chmod 4755 /w/a && chmod 2755 /w/d && ln -s /w/a /w/link && " ++
        "ln /w/d/e/b /w/hard && mkfifo /w/fifo && " ++
        "if command -v setfacl >/dev/null; then setfacl -m u:1001:rw,g:1002:r /w/d/e/b && " ++
        "setfacl -d -m g:1002:rx /w/d; fi && " ++
        "if command -v setcap >/dev/null; then cp /bin/true /w/cap && setcap cap_net_raw+ep /w/cap; fi",
    "rm /w/d/e/b /w/hard && chown 1002:1002 /w/a && chmod 4755 /w/a && chmod 600 /w/fifo && mkdir /w/d/new && echo c > /w/d/new/c && " ++
        "rm -rf /w/d/e && mkdir /w/d/e && echo d > /w/d/e/y",
    "! chown 70000:70000 /w/a && ! mknod /w/null c 1 3 && echo refused-ids-and-devices",
};

const idmapped_look =
    "stat -c 'seen %n %u:%g %a %F' /w /w/a /w/d /w/d/e/y /w/d/new/c /w/link /w/fifo; " ++
    "test ! -e /w/d/e/b && test ! -e /w/hard && echo seen b-and-hard-are-gone; " ++
    "if command -v getfacl >/dev/null; then getfacl -p /w/d | sed 's/^/seen acl /'; fi; " ++
    "if command -v getcap >/dev/null; then getcap /w/cap | sed 's/^/seen cap /'; fi; " ++
    "echo more >> /w/d/e/y && stat -c 'seen copied-up %u:%g' /w/d/e/y";

/// The `seen` lines of a job's log, in order.
fn seenLines(arena: Allocator, text: []const u8) ![]const u8 {
    var out: std.ArrayList(u8) = .empty;
    var it = std.mem.splitScalar(u8, text, '\n');
    while (it.next()) |l| if (std.mem.indexOf(u8, l, "seen ")) |at| {
        try out.appendSlice(arena, l[at..]);
        try out.append(arena, '\n');
    };
    return out.items;
}

/// A store's layers: each key with its tree's digest as the job's own ids see it.
fn layerDigests(arena: Allocator, store: []const u8) !std.StringArrayHashMapUnmanaged(Store.Key) {
    var out: std.StringArrayHashMapUnmanaged(Store.Key) = .empty;
    const layers = try std.fmt.allocPrint(arena, "{s}/layers", .{store});
    var dir = try std.Io.Dir.cwd().openDir(std.testing.io, layers, .{ .iterate = true });
    defer dir.close(std.testing.io);
    var it = dir.iterate();
    while (try it.next(std.testing.io)) |e| {
        const fs = try std.fmt.allocPrint(arena, "{s}/{s}/fs", .{ layers, e.name });
        const canonical_ids: Store.Ids = .{ .base = 0, .count = ids_per_slot };
        try out.put(arena, try arena.dupe(u8, e.name), try Store.treeDigest(arena, std.testing.io, fs, .content, canonical_ids));
    }
    return out;
}

/// The owner on disk of the whiteout (a character device 0/0) of `name` in some layer of `store`,
/// or null when none has one.
fn whiteoutOwner(arena: Allocator, store: []const u8, name: []const u8) !?u32 {
    const layers = try std.fmt.allocPrint(arena, "{s}/layers", .{store});
    var dir = try std.Io.Dir.cwd().openDir(std.testing.io, layers, .{ .iterate = true });
    defer dir.close(std.testing.io);
    var it = dir.iterate();
    while (try it.next(std.testing.io)) |e| {
        const p = try std.fmt.allocPrintSentinel(arena, "{s}/{s}/fs/{s}", .{ layers, e.name, name }, 0);
        var st: std.os.linux.Statx = undefined;
        if (std.os.linux.errno(std.os.linux.statx(std.os.linux.AT.FDCWD, p, std.os.linux.AT.SYMLINK_NOFOLLOW, .{ .UID = true, .TYPE = true }, &st)) != .SUCCESS) continue;
        if (st.mode & std.os.linux.S.IFMT == std.os.linux.S.IFCHR) return st.uid;
    }
    return null;
}

test "root runner: an idmapped upper leaves the layers the shift does, and each reads the other's store" {
    try requireRoot();
    var a: std.heap.ArenaAllocator = .init(std.testing.allocator);
    defer a.deinit();
    const arena = a.allocator();
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    // One directory of rootfs and binds, so the keys are alike, and a store for each way.
    var idmapped = try cachedConfig(arena, &tmp);
    var shifted = idmapped;
    try tmp.dir.createDirPath(std.testing.io, "store-shifted");
    shifted.cfg.store = try std.fmt.allocPrint(arena, "{s}/store-shifted", .{try tmp.dir.realPathFileAlloc(std.testing.io, ".", arena)});
    idmapped.cfg.idmapped_upper = true;
    idmapped.cfg.idmapped_min_entries = 0;
    shifted.cfg.idmapped_upper = false;
    var steps: [idmapped_steps.len]job_mod.Step = undefined;
    for (idmapped_steps, &steps) |s, *o| o.* = testStep(s);
    const make = testJob(&steps);
    const first = try runCached(arena, idmapped.cfg, make, "j1");
    try expectSucceeded(first);
    try expectLines(first.text, &.{"refused-ids-and-devices"});
    // Where this kernel or filesystem does not take it, the answer is the shift's: nothing to compare.
    if (idmapped_upper_known.load(.acquire) != idmapped_yes) {
        std.debug.print("idmapped upper test skipped: this machine does not take it\n", .{});
        return error.SkipZigTest;
    }
    // The same ran marker, which a layer holds.
    const second = try runCached(arena, shifted.cfg, make, "j1");
    try expectSucceeded(second);
    try expectLines(second.text, &.{"refused-ids-and-devices"});

    // The same layers, key by key, with the same digests: owners, modes, links, ACLs, capabilities.
    const via_idmap = try layerDigests(arena, idmapped.cfg.store);
    const via_shift = try layerDigests(arena, shifted.cfg.store);
    try std.testing.expectEqual(via_shift.count(), via_idmap.count());
    try std.testing.expect(via_idmap.count() >= 3);
    for (via_shift.keys(), via_shift.values()) |k, d| {
        const other = via_idmap.get(k) orelse return error.TestUnexpectedResult;
        try std.testing.expectEqualSlices(u8, &d, &other);
    }
    // On disk what differs is the whiteout's owner, the overlay's own mounter: the id nothing
    // owns, where the shift gives the overflow id; both digest as the overflow id.
    try std.testing.expectEqual(@as(?u32, std.math.maxInt(u32) - 1), try whiteoutOwner(arena, idmapped.cfg.store, "w/hard"));
    try std.testing.expectEqual(@as(?u32, 65534), try whiteoutOwner(arena, shifted.cfg.store, "w/hard"));

    // Each path replays the other's layers, and a step after them sees what it would after its own.
    var steps_look: [idmapped_steps.len + 1]job_mod.Step = undefined;
    for (idmapped_steps, steps_look[0..idmapped_steps.len]) |s, *o| o.* = testStep(s);
    steps_look[idmapped_steps.len] = testStep(idmapped_look);
    const look = testJob(&steps_look);
    var shift_reads = shifted.cfg;
    shift_reads.store = idmapped.cfg.store;
    var idmap_reads = idmapped.cfg;
    idmap_reads.store = shifted.cfg.store;
    const own = try runCached(arena, idmapped.cfg, look, "j3");
    const reads_idmapped = try runCached(arena, shift_reads, look, "j4");
    const reads_shifted = try runCached(arena, idmap_reads, look, "j5");
    for ([_]CachedRun{ own, reads_idmapped, reads_shifted }) |r| try expectSucceeded(r);
    const seen = try seenLines(arena, own.text);
    try expectLines(seen, &.{ "seen /w/a 1002:1002 4755", "seen /w/d 1001:1001 2755", "seen b-and-hard-are-gone", "seen copied-up 0:1001" });
    try std.testing.expectEqualStrings(seen, try seenLines(arena, reads_idmapped.text));
    try std.testing.expectEqualStrings(seen, try seenLines(arena, reads_shifted.text));
    // Replayed, not run again: the other store's layers were taken.
    for ([_]CachedRun{ reads_idmapped, reads_shifted }) |r| {
        try std.testing.expect(std.mem.count(u8, r.text, dagger.native_reused_note) >= 1);
    }
}

/// The owners on disk of every whiteout of `name` in the layers of `store`.
fn whiteoutOwners(arena: Allocator, store: []const u8, name: []const u8) ![]const u32 {
    var out: std.ArrayList(u32) = .empty;
    const layers = try std.fmt.allocPrint(arena, "{s}/layers", .{store});
    var dir = try std.Io.Dir.cwd().openDir(std.testing.io, layers, .{ .iterate = true });
    defer dir.close(std.testing.io);
    var it = dir.iterate();
    while (try it.next(std.testing.io)) |e| {
        const p = try std.fmt.allocPrintSentinel(arena, "{s}/{s}/fs/{s}", .{ layers, e.name, name }, 0);
        var st: std.os.linux.Statx = undefined;
        if (std.os.linux.errno(std.os.linux.statx(std.os.linux.AT.FDCWD, p, std.os.linux.AT.SYMLINK_NOFOLLOW, .{ .UID = true, .TYPE = true }, &st)) != .SUCCESS) continue;
        if (st.mode & std.os.linux.S.IFMT == std.os.linux.S.IFCHR) try out.append(arena, st.uid);
    }
    return out.items;
}

test "root runner: a step with a large layer takes the idmapped upper once its size is known, a small one the shift" {
    try requireRoot();
    var a: std.heap.ArenaAllocator = .init(std.testing.allocator);
    defer a.deinit();
    const arena = a.allocator();
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    const c = try cachedConfig(arena, &tmp);
    // Large: a hundred and twenty files and a deletion (an overlay whiteout, whose owner says how the upper was
    // written: 65534 shifted, the id nothing owns idmapped). The second run changes the script, so
    // the step runs again, knowing its last layer's size.
    var big1 = testStep("mkdir /w && for i in $(seq 120); do echo $i > /w/f$i; done; rm /etc/group");
    var big2 = testStep("mkdir /w && for i in $(seq 120); do echo $i > /w/f$i; done; rm /etc/group; : again");
    const r1 = try runCached(arena, c.cfg, testJob(@as(*const [1]job_mod.Step, &big1)), "j1");
    try expectSucceeded(r1);
    if (idmapped_upper_known.load(.acquire) == idmapped_no) return error.SkipZigTest;
    const r2 = try runCached(arena, c.cfg, testJob(@as(*const [1]job_mod.Step, &big2)), "j2");
    try expectSucceeded(r2);
    const owners = try whiteoutOwners(arena, c.cfg.store, "etc/group");
    try std.testing.expectEqual(@as(usize, 2), owners.len);
    try std.testing.expect(std.mem.indexOfScalar(u32, owners, 65534) != null);
    try std.testing.expect(std.mem.indexOfScalar(u32, owners, std.math.maxInt(u32) - 1) != null);
    // A small step stays shifted, run again (in a store of its own: a step is known by its place
    // in the job, which the big one's job shares).
    var small_cfg = c.cfg;
    try tmp.dir.createDirPath(std.testing.io, "store-small");
    small_cfg.store = try std.fmt.allocPrint(arena, "{s}/store-small", .{try tmp.dir.realPathFileAlloc(std.testing.io, ".", arena)});
    var small1 = testStep("echo a > /s; rm /etc/passwd");
    var small2 = testStep("echo a > /s; rm /etc/passwd; : again");
    try expectSucceeded(try runCached(arena, small_cfg, testJob(@as(*const [1]job_mod.Step, &small1)), "j3"));
    try expectSucceeded(try runCached(arena, small_cfg, testJob(@as(*const [1]job_mod.Step, &small2)), "j4"));
    const small = try whiteoutOwners(arena, small_cfg.store, "etc/passwd");
    try std.testing.expectEqual(@as(usize, 2), small.len);
    for (small) |o| try std.testing.expectEqual(@as(u32, 65534), o);
}

test "root runner: the kept user namespace for the idmapped uppers maps the job's ids and the host's root, and goes with its mount" {
    try requireRoot();
    var a: std.heap.ArenaAllocator = .init(std.testing.allocator);
    defer a.deinit();
    const arena = a.allocator();
    const io = std.testing.io;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    const c = try cachedConfig(arena, &tmp);
    const file = try std.fmt.allocPrint(arena, "{s}/userns", .{try tmp.dir.realPathFileAlloc(io, ".", arena)});
    const made = try std.process.run(arena, io, .{ .argv = &.{ c.cfg.self_exe, sandbox.userns_command, file, "1900065536", "65536" } });
    try std.testing.expect(made.term == .exited and made.term.exited == 0);
    // Seen from inside: the job's ids from 0, and the host's root as the id nothing owns.
    const seen = try std.process.run(arena, io, .{ .argv = &.{ "nsenter", try std.fmt.allocPrint(arena, "--user={s}", .{file}), "--no-fork", "cat", "/proc/self/uid_map", "/proc/self/gid_map" } });
    try std.testing.expect(seen.term == .exited and seen.term.exited == 0);
    const rows = std.mem.count(u8, seen.stdout, "         0 1900065536      65536") + std.mem.count(u8, seen.stdout, "4294967294          0          1");
    try std.testing.expectEqual(@as(usize, 4), rows);
    // Unmounted, the file is just a file again.
    _ = std.os.linux.umount2(try arena.dupeSentinel(u8, file, 0), std.os.linux.MNT.DETACH);
    const after = try std.process.run(arena, io, .{ .argv = &.{ "nsenter", try std.fmt.allocPrint(arena, "--user={s}", .{file}), "--no-fork", "true" } });
    try std.testing.expect(!(after.term == .exited and after.term.exited == 0));
}

test "root runner: a step whose kept user namespace is unmounted makes its own and runs; a planted file at its path stops the helper" {
    try requireRoot();
    var a: std.heap.ArenaAllocator = .init(std.testing.allocator);
    defer a.deinit();
    const arena = a.allocator();
    const io = std.testing.io;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    const cfg = try testConfig(arena, &tmp);
    var b = try init(arena, io, std.testing.allocator, cfg);
    defer b.deinit();
    b.idmapped_min_entries = 0;
    if (!b.idmappedUpper()) return error.SkipZigTest;
    var out: Captured = .{ .arena = arena };
    const first = try b.exec("echo one > /f", &.{"PATH=/usr/bin"}, &.{}, 0, 0, out.output());
    try std.testing.expect(first.failure.len == 0 and first.code == 0);
    try std.testing.expect(b.upper_userns != null);
    // Unmounted from outside: the file is a plain one, and the next step makes its own namespace.
    const kept = try std.fmt.allocPrintSentinel(arena, "{s}/userns", .{b.dir}, 0);
    try std.testing.expectEqual(std.os.linux.E.SUCCESS, std.os.linux.errno(std.os.linux.umount2(kept, std.os.linux.MNT.DETACH)));
    var out2: Captured = .{ .arena = arena };
    const second = try b.exec("echo two > /g", &.{"PATH=/usr/bin"}, &.{}, 0, 0, out2.output());
    try std.testing.expect(second.failure.len == 0 and second.code == 0);
    // A file already at the path: the helper fails rather than mount over it.
    const planted = try std.fmt.allocPrint(arena, "{s}/planted", .{b.dir});
    try std.Io.Dir.cwd().writeFile(io, .{ .sub_path = planted, .data = "x" });
    const refused = try std.process.run(arena, io, .{ .argv = &.{ b.self_exe, sandbox.userns_command, planted, "1900065536", "65536" } });
    try std.testing.expect(!(refused.term == .exited and refused.term.exited == 0));
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

test "native phases: where a cached job's time goes, cold and replayed" {
    // A measurement, not a check: ZIG_RUNNER_NATIVE_PHASES=<runs> runs it, each run a cold job
    // in a store of its own then the same job replayed. It prints each job's phases as the
    // runner logs them, for .github/scripts/native-phases.sh (`zig build test ... 2>&1 |
    // native-phases.sh`). ZIG_RUNNER_NATIVE_PHASES_DIR puts the stores there (a slow disk's
    // mount) instead of the tests' temporary directory.
    var a: std.heap.ArenaAllocator = .init(std.testing.allocator);
    defer a.deinit();
    const arena = a.allocator();
    var env = try std.testing.environ.createMap(arena);
    const runs_text = env.get("ZIG_RUNNER_NATIVE_PHASES") orelse return error.SkipZigTest;
    const n = std.fmt.parseInt(u32, runs_text, 10) catch return error.SkipZigTest;
    // A small file, 32 MiB in one, 3000 empty files, and nothing.
    const steps = [_]job_mod.Step{
        testStep("echo small > /tmp/small"),
        testStep("head -c 33554432 /dev/urandom > /tmp/big.bin"),
        testStep("mkdir -p /tmp/many && cd /tmp/many && seq 1 3000 | xargs touch"),
        testStep("true"),
    };
    for (0..n) |i| {
        var tmp = std.testing.tmpDir(.{});
        defer tmp.cleanup();
        var c = try cachedConfig(arena, &tmp);
        if (env.get("ZIG_RUNNER_NATIVE_PHASES_DIR")) |dir| {
            const store = try std.fmt.allocPrint(arena, "{s}/store-{d}", .{ dir, i });
            Store.removeTree(arena, std.testing.io, store);
            c.cfg.store = store;
        }
        defer if (env.get("ZIG_RUNNER_NATIVE_PHASES_DIR") != null)
            Store.removeTree(arena, std.testing.io, c.cfg.store);
        for ([_][]const u8{ "cold", "replayed" }) |how| {
            const r = try runCached(arena, c.cfg, testJob(&steps), how);
            try expectSucceeded(r);
            std.debug.print("job {d} '{s}': native phases (ms): {s}\n", .{
                i,
                how,
                r.res.native_phases orelse "",
            });
        }
    }
}

test "native phases: where the set-up goes when jobs start together" {
    // A measurement, not a check: ZIG_RUNNER_NATIVE_BURST=<jobs> starts that many jobs at once on
    // one store, as a burst of a workflow's jobs does, and prints each job's phases as the runner
    // logs them (`.github/scripts/native-phases.sh`). As root, so that each job has its own
    // cgroup, slot and network.
    var a: std.heap.ArenaAllocator = .init(std.testing.allocator);
    defer a.deinit();
    const arena = a.allocator();
    var env = try std.testing.environ.createMap(arena);
    const n_text = env.get("ZIG_RUNNER_NATIVE_BURST") orelse return error.SkipZigTest;
    const n = std.fmt.parseInt(u32, n_text, 10) catch return error.SkipZigTest;
    try requireRoot();
    const io = std.testing.io;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    const cfg = try testConfig(arena, &tmp);
    const Run = struct {
        fn one(cfg_: Config, out: *[]const u8) void {
            var ar: std.heap.ArenaAllocator = .init(std.heap.page_allocator);
            const r = runNativeJob(ar.allocator(), cfg_, testJob(&.{testStep("true")}), .root) catch return;
            out.* = std.heap.page_allocator.dupe(u8, r.res.native_phases orelse "") catch "";
        }
    };
    const rounds = 3;
    for (0..rounds) |round| {
        const lines = try arena.alloc([]const u8, n);
        @memset(lines, "");
        const futures = try arena.alloc(std.Io.Future(void), n);
        for (futures, lines) |*f, *l| f.* = try io.concurrent(Run.one, .{ cfg, l });
        for (futures) |*f| f.await(io);
        for (lines) |l| std.debug.print("job {d} 'burst {d}': native phases (ms): {s}\n", .{ round, n, l });
    }
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
        .tool_trees = caches.tool_trees,
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

/// A fork's pull request for `job`: its head repository is another's, so its cache scope is
/// `untrusted` whatever the runner vouches for (`set_up.packageCacheScope`).
fn asFork(arena: Allocator, job: job_mod.Job) !job_mod.Job {
    const ctx =
        \\{"github":{"t":2,"d":[{"k":"repository","v":"o/r"},{"k":"event","v":{"t":2,"d":[
    ++
        \\{"k":"pull_request","v":{"t":2,"d":[{"k":"head","v":
    ++
        \\{"t":2,"d":[{"k":"repo","v":{"t":2,"d":[{"k":"full_name","v":
    ++ "\"someone/r\"}]}}]}" ++ "}]}}]}}]}}";
    var out = job;
    out.context_data = try std.json.parseFromSliceLeaky(std.json.Value, arena, ctx, .{});
    return out;
}

/// A tree's digest over its content, modes, owners and links (`Store.treeDigest`): what a write
/// anywhere in it would change. Compared before and after a hostile job.
fn treeSum(arena: Allocator, path: []const u8) !Store.Key {
    return Store.treeDigest(arena, std.testing.io, path, .content, .host);
}

/// The names in the store's `layers/`, each with its tree's digest.
const LayerSums = struct {
    names: []const []const u8,
    sums: []const Store.Key,

    fn of(arena: Allocator, store: []const u8) !LayerSums {
        const path = try std.fmt.allocPrint(arena, "{s}/layers", .{store});
        var dir = try std.Io.Dir.cwd().openDir(std.testing.io, path, .{ .iterate = true });
        defer dir.close(std.testing.io);
        var names: std.ArrayList([]const u8) = .empty;
        var sums: std.ArrayList(Store.Key) = .empty;
        var it = dir.iterate();
        while (try it.next(std.testing.io)) |e| {
            if (e.kind != .directory) continue;
            try names.append(arena, try arena.dupe(u8, e.name));
            try sums.append(arena, try treeSum(arena, try std.fmt.allocPrint(arena, "{s}/{s}", .{ path, e.name })));
        }
        return .{ .names = names.items, .sums = sums.items };
    }

    /// Every layer of `before` is still there, as it was: a job may add layers, never change one.
    fn expectKept(before: LayerSums, after: LayerSums) !void {
        for (before.names, before.sums) |n, sum| {
            const at = for (after.names, 0..) |m, i| {
                if (std.mem.eql(u8, n, m)) break i;
            } else {
                std.debug.print("layer {s} is gone\n", .{n});
                return error.TestUnexpectedResult;
            };
            if (!std.mem.eql(u8, &sum, &after.sums[at])) {
                std.debug.print("layer {s} changed\n", .{n});
                return error.TestUnexpectedResult;
            }
        }
    }
};

/// A tree as it is now: its digest, and one line per entry (path, kind, size) to say what changed
/// when the digest did.
const TreeSum = struct {
    path: []const u8,
    sum: Store.Key,
    listing: []const u8,

    fn of(arena: Allocator, path: []const u8) !TreeSum {
        const io = std.testing.io;
        var dir = try std.Io.Dir.cwd().openDir(io, path, .{ .iterate = true });
        defer dir.close(io);
        var walker = try dir.walk(arena);
        defer walker.deinit();
        var out: std.Io.Writer.Allocating = .init(arena);
        while (try walker.next(io)) |e| {
            const st = e.dir.statFile(io, e.basename, .{ .follow_symlinks = false }) catch null;
            try out.writer.print("{s} {s} {d}\n", .{ e.path, @tagName(e.kind), if (st) |s| s.size else 0 });
        }
        return .{ .path = path, .sum = try treeSum(arena, path), .listing = out.written() };
    }

    /// The tree at `before.path` is what `before` saw.
    fn expectSame(before: TreeSum, arena: Allocator) !void {
        const now = try of(arena, before.path);
        if (std.mem.eql(u8, &before.sum, &now.sum)) return;
        std.debug.print("{s} changed.\nbefore:\n{s}now:\n{s}", .{ before.path, before.listing, now.listing });
        return error.TestUnexpectedResult;
    }
};

fn readTrimmed(arena: Allocator, path: []const u8) ![]const u8 {
    const text = try std.Io.Dir.cwd().readFileAlloc(std.testing.io, path, arena, .limited(4096));
    return std.mem.trim(u8, text, "\n");
}

/// What makes a job untrusted in `expectUntrustedLeavesTrustedAlone`.
const Untrusted = enum {
    /// A fork's pull request on a runner that vouches for pull requests: scope `untrusted`.
    fork,
    /// A job the runner does not vouch for (`Config.vouched` false), which runs natively only on a
    /// root runner under per-job limits (`untrustedRefusal`).
    unvouched,
};

/// The trust boundary of the native backend, end to end (docs/native-backend.md, "Trust scopes"):
/// a trusted job of a repository fills every place the repository's jobs share, an untrusted job
/// of the same repository then does everything a hostile one can to reach them, and nothing a
/// trusted job reads or replays has changed. Every shared place is listed in the pull request
/// that added this, with what keeps it apart.
fn expectUntrustedLeavesTrustedAlone(arena: Allocator, kind: Untrusted) !void {
    const io = std.testing.io;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    var c = try cachedConfig(arena, &tmp);
    // The seed's build, without a Zig release to download: a file where Zig's cache would be.
    c.cfg.test_seed_script = "mkdir -p /zig-seed/o/s && echo seeded > /zig-seed/o/s/f";
    const caches: volumes.Options = .{
        .package_caches = true,
        .trusted = true,
        .zig_local_cache = true,
        .zig_local_cache_max_mb = 1,
        .zig_seeds = &.{.{ .version = "0.0.1", .sha256 = "00" }},
    };
    var hostile_cfg = c.cfg;
    var hostile_caches = caches;
    var parent: ?TestCgroup = null;
    if (kind == .unvouched) {
        if (std.os.linux.geteuid() != 0) {
            std.debug.print("skipped the unvouched case: it needs a root runner\n", .{});
            return error.SkipZigTest;
        }
        hostile_cfg.vouched = false;
        hostile_caches.trusted = false;
        parent = try testCgroup(arena, &hostile_cfg);
        hostile_cfg.job_limits = jobLimits(arena, io, hostile_cfg.cgroup);
        if (!hostile_cfg.job_limits) {
            std.debug.print("skipped the unvouched case: no cgroup for per-job limits\n", .{});
            return error.SkipZigTest;
        }
    }
    defer if (parent) |p| p.remove(arena);
    const store = c.cfg.store;
    const gate_file = try std.fmt.allocPrint(arena, "{s}/memory-gate-test", .{store});
    try std.Io.Dir.cwd().writeFile(io, .{ .sub_path = gate_file, .data = "learned job sizes\n" });

    // The trusted job fills the volumes the repository's jobs share, with a secret each.
    // Who runs a step, told by a file the keys do not hold (`/shared` is bound at `Config.binds`,
    // and its contents are in no key): the same steps, written by different jobs, say who ran.
    const who_trusted = "run-by-the-trusted-job";
    const who_hostile = "run-by-the-hostile-job";
    const who_file = try std.fmt.allocPrint(arena, "{s}/who", .{c.shared});
    try std.Io.Dir.cwd().writeFile(io, .{ .sub_path = who_file, .data = who_trusted ++ "\n" });
    const seed_job = testJob(&.{testStep("echo secret > /root/.npm/trusted-secret # npm\n" ++
        "echo secret > $RUNNER_TOOL_CACHE/trusted-secret\n" ++
        "echo secret > /root/.cache/zig/p/trusted-secret # zig\n" ++
        "echo secret > $ZIG_LOCAL_CACHE_DIR/trusted-secret")});
    const seeded = try runCachedJob(arena, c.cfg, seed_job, caches, .{ .ran = "t0" });
    try expectSucceeded(seeded);

    const volumes_dir = try std.fmt.allocPrint(arena, "{s}/volumes/o/r/repo", .{store});
    const seeds_dir = try std.fmt.allocPrint(arena, "{s}/seeds", .{store});
    // Each volume's tree; the runner's own bookkeeping beside them (`.lock`, `.size`) is its own.
    var before_volumes: std.ArrayList(TreeSum) = .empty;
    for ([_][]const u8{ "npm", "zig-packages", "zig-local", "zig-builtin", "node-compile-cache" }) |name|
        try before_volumes.append(arena, try TreeSum.of(arena, try std.fmt.allocPrint(arena, "{s}/{s}", .{ volumes_dir, name })));
    // The tool cache is a volume per image.
    const tool_dir = try std.fmt.allocPrint(arena, "{s}/toolcache", .{volumes_dir});
    var tools = try std.Io.Dir.cwd().openDir(io, tool_dir, .{ .iterate = true });
    defer tools.close(io);
    var tool_it = tools.iterate();
    while (try tool_it.next(io)) |e| {
        if (e.kind != .directory) continue;
        try before_volumes.append(arena, try TreeSum.of(arena, try std.fmt.allocPrint(arena, "{s}/{s}", .{ tool_dir, e.name })));
    }
    try std.testing.expect(before_volumes.items.len >= 6);
    const before_rootfs = try TreeSum.of(arena, c.cfg.rootfs);
    const before_seeds = try TreeSum.of(arena, seeds_dir);
    const before_layers = try LayerSums.of(arena, store);
    try std.testing.expectEqualStrings("secret", try readTrimmed(arena, try std.fmt.allocPrint(arena, "{s}/npm/trusted-secret", .{volumes_dir})));

    // What a hostile step tries, with the steps after it that publish layers a trusted job could
    // look up (`/shared` counts how often each really ran). The same steps run as the trusted job's
    // later: a stored layer that was found by their key would replay without running them.
    const attack = try std.fmt.allocPrint(arena,
        \\cat /shared/who > /root/.npm/head # npm
        \\cat /shared/who > $RUNNER_TOOL_CACHE/head
        \\cat /shared/who > /root/.cache/zig/p/head # zig
        \\cat /shared/who > /root/.cache/zig/o/s/f
        \\cat /shared/who >> /etc/passwd
        \\ln -s /etc/passwd /root/.npm/link-abs
        \\ln -s ../../repo/npm /root/.npm/link-up
        \\ln /etc/passwd /tmp/hardlink && cat /shared/who >> /tmp/hardlink
        \\n=$(find / -path /proc -prune -o -path /sys -prune -o -path /usr -prune -o -name trusted-secret -print 2>/dev/null | wc -l)
        \\echo found-$n-secrets
        \\for p in {0s}/volumes/o/r/repo/npm/head {0s}/memory-gate-test {0s}/layers/head /run/zig-runner/head; do
        \\  if {{ echo x > $p; }} 2>/dev/null; then echo wrote-to-host; fi
        \\  if [ -e $p ]; then echo sees-host; fi
        \\done
        \\if [ -e /run/zig-runner ]; then echo sees-run-dir; fi
        \\echo trusted-mounts-$(grep -c '/volumes/o/r/repo' /proc/self/mountinfo)
        \\echo gate-mounts-$(grep -c 'memory-gate' /proc/self/mountinfo)
        \\if ln /usr/bin/env /root/.npm/host-hardlink 2>/dev/null; then echo linked-host-file; fi
        \\if echo x >> /usr/bin/env 2>/dev/null; then echo wrote-host-binary; fi
        \\echo attack-done-$((2+3))
    , .{store});
    var hostile = testJob(&.{
        testStep(attack),
        testStep("echo x >> /shared/b1; mkdir -p /tmp/k; echo layer > /tmp/k/f"),
        testStep("echo x >> /shared/b2; cat /tmp/k/f"),
    });
    if (kind == .fork) hostile = try asFork(arena, hostile);
    try std.Io.Dir.cwd().writeFile(io, .{ .sub_path = who_file, .data = who_hostile ++ "\n" });
    const first = try runCachedJob(arena, hostile_cfg, hostile, hostile_caches, .{ .ran = "h1" });
    if (!first.res.succeeded) std.debug.print("{s}\n", .{first.text});
    try expectSucceeded(first);
    try expectLines(first.text, &.{
        "found-0-secrets",
        "trusted-mounts-0",
        "gate-mounts-0",
        "attack-done-5",
    });
    try std.testing.expectEqual(@as(usize, 0), std.mem.count(u8, first.text, "stdout] wrote-"));
    try std.testing.expectEqual(@as(usize, 0), std.mem.count(u8, first.text, "stdout] sees-"));
    try std.testing.expectEqual(@as(usize, 0), std.mem.count(u8, first.text, "stdout] linked-"));
    try std.testing.expectEqual(@as(usize, 0), std.mem.count(u8, first.text, "stdout] sees-run"));
    try std.testing.expectEqual(@as(usize, 1), runs(arena, c.shared, "b1"));

    // The job did write, into volumes of its own scope: the attack reached what it could reach.
    const hostile_volumes = try std.fmt.allocPrint(arena, "{s}/volumes/o/r/untrusted", .{store});
    try std.testing.expectEqualStrings(who_hostile, try readTrimmed(arena, try std.fmt.allocPrint(arena, "{s}/npm/head", .{hostile_volumes})));

    // Nothing a trusted job shares has changed: its volumes, the rootfs and the Zig seed every
    // job starts from, the layers it published, and the runner's own state.
    for (before_volumes.items) |v| try v.expectSame(arena);
    try before_rootfs.expectSame(arena);
    try before_seeds.expectSame(arena);
    try before_layers.expectKept(try LayerSums.of(arena, store));
    try std.testing.expectEqualStrings("learned job sizes", try readTrimmed(arena, gate_file));

    // The control: the hostile job's own run again replays its layers (so they were published and
    // the next check means something).
    const again = try runCachedJob(arena, hostile_cfg, hostile, hostile_caches, .{ .ran = "h2" });
    try expectSucceeded(again);
    try std.testing.expectEqual(@as(usize, 1), runs(arena, c.shared, "b1"));
    try std.testing.expect(std.mem.count(u8, again.text, dagger.native_reused_note) >= 2);

    // The same steps as a trusted job: nothing replays, whatever the hostile job published. Each
    // step runs, and writes its own commit into the trusted volumes.
    var same = hostile;
    same.context_data = .null;
    try std.Io.Dir.cwd().writeFile(io, .{ .sub_path = who_file, .data = who_trusted ++ "\n" });
    const trusted = try runCachedJob(arena, c.cfg, same, caches, .{ .ran = "t1" });
    try expectSucceeded(trusted);
    try std.testing.expectEqual(@as(usize, 2), runs(arena, c.shared, "b1"));
    try std.testing.expectEqual(@as(usize, 2), runs(arena, c.shared, "b2"));
    try std.testing.expectEqual(@as(usize, 0), std.mem.count(u8, trusted.text, dagger.native_reused_note));
    try std.testing.expectEqualStrings(who_trusted, try readTrimmed(arena, try std.fmt.allocPrint(arena, "{s}/npm/head", .{volumes_dir})));
    try std.testing.expectEqualStrings("secret", try readTrimmed(arena, try std.fmt.allocPrint(arena, "{s}/npm/trusted-secret", .{volumes_dir})));
    // And what the hostile job planted in its own scope is still its own.
    try std.testing.expectEqualStrings(who_hostile, try readTrimmed(arena, try std.fmt.allocPrint(arena, "{s}/npm/head", .{hostile_volumes})));
    // With no cache volume in the job, their paths are not in the key and the trust scope alone
    // keeps the two apart: the same steps are replayed for their own side, never the other's.
    var plain = testJob(&.{
        testStep("echo x >> /shared/c1; mkdir -p /tmp/p; echo plain > /tmp/p/f"),
        testStep("echo x >> /shared/c2; cat /tmp/p/f"),
    });
    if (kind == .fork) plain = try asFork(arena, plain);
    const no_caches: volumes.Options = .{ .trusted = hostile_caches.trusted };
    try expectSucceeded(try runCachedJob(arena, hostile_cfg, plain, no_caches, .{ .ran = "p1" }));
    try expectSucceeded(try runCachedJob(arena, hostile_cfg, plain, no_caches, .{ .ran = "p2" }));
    try std.testing.expectEqual(@as(usize, 1), runs(arena, c.shared, "c1"));
    plain.context_data = .null;
    const plain_trusted = try runCachedJob(arena, c.cfg, plain, .{ .trusted = true }, .{ .ran = "p3" });
    try expectSucceeded(plain_trusted);
    try std.testing.expectEqual(@as(usize, 2), runs(arena, c.shared, "c1"));
    try std.testing.expectEqual(@as(usize, 2), runs(arena, c.shared, "c2"));
    try std.testing.expectEqual(@as(usize, 0), std.mem.count(u8, plain_trusted.text, dagger.native_reused_note));

    // A trusted job that reads the caches finds the trusted ones only.
    const reader = testJob(&.{testStep("cat /root/.npm/head # npm\ncat $RUNNER_TOOL_CACHE/head\n" ++
        "cat /root/.npm/trusted-secret")});
    const read = try runCachedJob(arena, c.cfg, reader, caches, .{});
    try expectSucceeded(read);
    try expectLines(read.text, &.{ "stdout] " ++ who_trusted, "stdout] secret" });
    try std.testing.expect(std.mem.indexOf(u8, read.text, who_hostile) == null);
}

test "native trust: a fork's pull request on a runner that vouches for pull requests reaches nothing a trusted job reads or replays" {
    var a: std.heap.ArenaAllocator = .init(std.testing.allocator);
    defer a.deinit();
    try expectUntrustedLeavesTrustedAlone(a.allocator(), .fork);
}

test "root runner: a job the runner does not vouch for reaches nothing a trusted job reads or replays" {
    var a: std.heap.ArenaAllocator = .init(std.testing.allocator);
    defer a.deinit();
    try expectUntrustedLeavesTrustedAlone(a.allocator(), .unvouched);
}

test "native trust: every key a job's layers are stored under differs by trust scope and by repository" {
    var a: std.heap.ArenaAllocator = .init(std.testing.allocator);
    defer a.deinit();
    const arena = a.allocator();
    const io = std.testing.io;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    const trusted_in: Below = .{
        .format = Store.store_format,
        .scope = "repo",
        .repository = "o/r",
        .fingerprint = "the same rootfs",
        .userns = "mapped",
        .binds = &.{},
    };
    var fork_in = trusted_in;
    fork_in.scope = "untrusted";
    var other_in = trusted_in;
    other_in.repository = "o/other";
    const trusted_base = belowKey(trusted_in, null);
    const fork_base = belowKey(fork_in, null);
    const other_base = belowKey(other_in, null);
    try std.testing.expect(!std.mem.eql(u8, &trusted_base, &fork_base));
    try std.testing.expect(!std.mem.eql(u8, &trusted_base, &other_base));
    try std.testing.expect(!std.mem.eql(u8, &fork_base, &other_base));

    // A step, an action's fetched tree and the steps above them are keyed from their parent, so
    // the same script above different bases is never the same key.
    const script = "echo same script";
    var keys: [3]Store.Key = undefined;
    for ([_]Store.Key{ trusted_base, fork_base, other_base }, &keys) |parent, *k| {
        var h: Store.KeyHasher = .init(.step);
        h.core(parent, script, &[_]job_mod.EnvVar{});
        var above: Store.KeyHasher = .init(.step);
        above.core(h.final(), "the next step", &[_]job_mod.EnvVar{});
        k.* = above.final();
    }
    try std.testing.expect(!std.mem.eql(u8, &keys[0], &keys[1]));
    try std.testing.expect(!std.mem.eql(u8, &keys[0], &keys[2]));

    // A Dockerfile build's layer, from one builder key.
    var builder: Store.Key = undefined;
    @memset(&builder, 0x5a);
    const build_trusted = @import("layers.zig").layerKey(Store.store_format, "repo", "mapped", builder, null);
    const build_fork = @import("layers.zig").layerKey(Store.store_format, "untrusted", "mapped", builder, null);
    try std.testing.expect(!std.mem.eql(u8, &build_trusted, &build_fork));

    // In a real store: what the untrusted job publishes, the trusted job's key does not find.
    const root = try tmp.dir.realPathFileAlloc(io, ".", arena);
    const store: Store = .{ .root = try std.fmt.allocPrint(arena, "{s}/store", .{root}) };
    try Store.prepare(arena, io, store.root, .{ .check_parents = false });
    try tmp.dir.createDirPath(io, "up/d");
    try tmp.dir.writeFile(io, .{ .sub_path = "up/d/f", .data = "planted by the fork" });
    var never: std.atomic.Value(bool) = .init(false);
    const lock = try store.lockKey(arena, io, keys[1], &never);
    defer lock.close(io);
    const layer = try store.publish(arena, io, keys[1], .fetch, try std.fmt.allocPrint(arena, "{s}/up", .{root}), .{ .log = "", .fc = "" });
    layer.lock.close(io);
    try std.testing.expect(try store.open(arena, io, keys[0]) == null);
    try std.testing.expect(try store.open(arena, io, keys[2]) == null);
    const hit = (try store.open(arena, io, keys[1])).?;
    hit.layer.lock.close(io);
}

/// The tests' tree as root, for the tests that reach no limit (`testConfig`).
const test_parent = cgroup.mount_point ++ "/zig-runner-test";

/// A test's own cgroup parent: a new one as root, since all jobs' limits are on the parent and
/// tests of them give it different numbers, or `ZIG_RUNNER_TEST_CGROUP` (`self` under `systemd-run
/// --user --scope -p Delegate=yes`) rootless. Without one the test is skipped (failed where
/// `ZIG_RUNNER_REQUIRE_NATIVE=1`) before it can run anything: in a container whose root holds
/// processes no parent can be made (#367).
const TestCgroup = struct {
    /// Where the jobs' cgroups go.
    dir: []const u8,
    /// What was made for this test, and `remove` removes; null for a delegated `self`.
    top: ?[]const u8,

    fn remove(t: TestCgroup, arena: Allocator) void {
        const top = t.top orelse return;
        (cgroup.Job{ .dir = t.dir }).remove(arena, std.testing.io);
        (cgroup.Job{ .dir = top }).remove(arena, std.testing.io);
    }
};

fn testCgroup(arena: Allocator, cfg: *Config) !TestCgroup {
    const io = std.testing.io;
    var env = try std.testing.environ.createMap(arena);
    const own = std.os.linux.geteuid() == 0;
    if (own) {
        var raw: [8]u8 = undefined;
        io.random(&raw);
        const name = std.fmt.bytesToHex(raw, .lower);
        cfg.cgroup.parent = try std.fmt.allocPrint(arena, "{s}-{s}", .{ test_parent, &name });
    } else if (env.get("ZIG_RUNNER_TEST_CGROUP")) |p| {
        cfg.cgroup.parent = p;
    } else {
        std.debug.print("native backend test skipped: it needs root, or a delegated cgroup " ++
            "(ZIG_RUNNER_TEST_CGROUP=self)\n", .{});
        return error.SkipZigTest;
    }
    switch (cgroup.parent(arena, io, cfg.cgroup.parent)) {
        .dir => |d| return .{
            .dir = try arena.dupe(u8, d),
            .top = if (own) cfg.cgroup.parent else null,
        },
        .none => |why| {
            if (own) (cgroup.Job{ .dir = cfg.cgroup.parent }).remove(arena, io);
            const required = std.mem.eql(u8, env.get("ZIG_RUNNER_REQUIRE_NATIVE") orelse "", "1");
            return skip(required, why);
        },
    }
}

/// A step that takes `mb` of memory, 8 MiB at a time, and then ends by itself, saying so: the
/// tests' runaway, which never relies on a limit to protect the host. Its exit status follows
/// `exit=`, since bash's `-e` would end the step at it; without python3 it says `no-python`. Both
/// sayings are put together as they run, as a step's log shows its script too.
fn hogStep(comptime mb: u32) job_mod.Step {
    return testStep("command -v python3 >/dev/null || { echo no\"\"-python; exit 0; }\n" ++
        "python3 -c 'x = []\nfor _ in range(" ++ std.fmt.comptimePrint("{d}", .{mb / 8}) ++
        "): x.append(b\"x\" * (8 << 20))\nprint(\"no limit\", \"stopped it\")\n" ++
        "raise SystemExit(3)' || echo exit=$?");
}

/// A step that forks a binary tree of `depth` levels of processes, 2^(`depth` + 1) - 1 at the most
/// and each spinning for 20 s at the most, and ends it after 2 s: a fork bomb with an end of its
/// own. In a process group of its own (`set -m`), of builtins only (nothing else can fork while
/// it holds every process), then killed, and waited out until no process of the group is left,
/// so the step's own end (`scripts.stepScriptFc`'s epilogue, whose `sh` must fork) finds its
/// processes free again. Left running, the bomb still held them there: the wrapper's `sh` could
/// not fork, and the step failed with exit 2 (#265's CI, once).
fn bombStep(comptime depth: u32) job_mod.Step {
    return testStep("set -m\n" ++
        "( set +m\n" ++
        "bomb() {\n" ++
        "  if [ \"$1\" -gt 0 ]; then bomb $(($1 - 1)) & bomb $(($1 - 1)) & fi\n" ++
        "  until [ $SECONDS -ge 20 ]; do :; done\n" ++
        "}\n" ++
        "bomb " ++ std.fmt.comptimePrint("{d}", .{depth}) ++ " ) &\n" ++
        "pg=$!\nset +m\n" ++
        "end=$((SECONDS + 2)); while [ $SECONDS -lt $end ]; do :; done\n" ++
        "kill -9 -- -$pg\n" ++
        "while kill -0 -- -$pg 2>/dev/null; do :; done\n" ++
        "echo after-the-bomb");
}

test "root runner: a native step's fork bomb that ignores signals goes at the ladder's end" {
    var a: std.heap.ArenaAllocator = .init(std.testing.allocator);
    defer a.deinit();
    const arena = a.allocator();
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    var cfg = try testConfig(arena, &tmp);
    const parent = try testCgroup(arena, &cfg);
    defer parent.remove(arena);
    // It fills the job's limit, so no process can be forked to warn the step: the warnings go
    // unsent, the ladder goes on, and its end needs no fork.
    cfg.cgroup.memory_max_mb = 256;
    cfg.cgroup.pids_max = 64;
    // Of builtins, as `bombStep`, and with an end of its own, should the kill fail.
    const job = testJob(&.{testStep("trap '' INT TERM\nsleep 613.75 &\n" ++
        "bomb() {\n" ++
        "  if [ \"$1\" -gt 0 ]; then bomb $(($1 - 1)) & bomb $(($1 - 1)) & fi\n" ++
        "  until [ $SECONDS -ge 20 ]; do :; done\n" ++
        "}\n" ++
        "bomb 9\n" ++
        "echo out\"\"lived-the-ladder")});
    const r = try runCancelled(arena, cfg, job, .{ .when = "613.75", .grace_ms = 2_000 });
    errdefer std.debug.print("took {d} ms:\n{s}\n", .{ r.took_ms, r.text });
    try std.testing.expectEqual(dagger.Outcome.cancelled, r.res.steps[0].outcome);
    try std.testing.expect(std.mem.indexOf(u8, r.text, "outlived-the-ladder") == null);
    try std.testing.expect(r.took_ms >= 1_800);
    try std.testing.expect(r.took_ms < 6_000);
    try std.testing.expect(!processRuns("613.75"));
}

test "the tests' runaway and fork bomb end by themselves, with no limit on them" {
    // Small, as nothing here holds them but themselves: #367's `while True` under a cgroup that
    // could not be made ran until the machine's global OOM.
    var a: std.heap.ArenaAllocator = .init(std.testing.allocator);
    defer a.deinit();
    const arena = a.allocator();
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    var cfg = try testConfig(arena, &tmp);
    cfg.cgroup.parent = "none";
    const r = try runNativeJob(arena, cfg, testJob(&.{ hogStep(64), bombStep(3) }), .root);
    if (std.mem.indexOf(u8, r.text, "no-python") != null) return error.SkipZigTest;
    try expectLines(r.text, &.{ "no limit stopped it", "exit=3", "after-the-bomb" });
    try std.testing.expect(r.res.succeeded);
}

test "a native job that cannot be bounded is refused, unless the operator accepts it" {
    var a: std.heap.ArenaAllocator = .init(std.testing.allocator);
    defer a.deinit();
    const arena = a.allocator();
    const io = std.testing.io;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    try tmp.dir.createDirPath(io, "refused/store");
    try tmp.dir.createDirPath(io, "refused/rootfs");
    const root = try tmp.dir.realPathFileAlloc(io, "refused", arena);
    // No parent, on any machine, as a rootless runner without delegation has none. Refused before
    // any sandbox, so this part needs none.
    const no_parent = cgroup.mount_point ++ "/../not-a-cgroup";
    const refused: Config = .{
        .rootfs = try std.fmt.allocPrint(arena, "{s}/rootfs", .{root}),
        .store = try std.fmt.allocPrint(arena, "{s}/store", .{root}),
        .self_exe = "/bin/true",
        .vouched = true,
        .check_store_parents = false,
        .cgroup = .{ .parent = no_parent },
    };
    var why: []const u8 = "";
    try std.testing.expectError(
        error.NoJobLimits,
        initWhy(arena, io, std.testing.allocator, refused, &why),
    );
    // It says why not, and what accepts the risk.
    for ([_][]const u8{
        "would have no cgroup",
        "is not a cgroup's path",
        "RUNNER_NATIVE_CGROUP=none",
    }) |w| try std.testing.expect(std.mem.indexOf(u8, why, w) != null);

    // Said by the operator, it runs, saying plainly what that means.
    var cfg = try testConfig(arena, &tmp);
    cfg.cgroup.parent = "none";
    const accepted = try runNativeJob(arena, cfg, testJob(&.{testStep("echo ran")}), .root);
    try std.testing.expect(accepted.res.succeeded);
    try expectLines(accepted.text, &.{
        "ran",
        "this job runs UNBOUNDED (RUNNER_NATIVE_CGROUP=none): it has no memory or process limit",
    });

    // A machine that cannot make a job's cgroup can still run the probe: the refusal is the
    // job's, with its reason, not a probe's error for every job.
    probe_cache = .{};
    defer probe_cache = .{};
    cfg.cgroup.parent = no_parent;
    try std.testing.expect(usable(arena, io, std.testing.allocator, cfg) == null);
}

test "root runner: a native job's runaway is OOM-killed in its own cgroup, a fork bomb stops at pids.max" {
    var a: std.heap.ArenaAllocator = .init(std.testing.allocator);
    defer a.deinit();
    const arena = a.allocator();
    const io = std.testing.io;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    var cfg = try testConfig(arena, &tmp);
    const parent = try testCgroup(arena, &cfg);
    defer parent.remove(arena);
    var runaway = cfg;
    // Room for the step's shell and the helper: the kernel kills the largest process first, but
    // a limit near their own size takes them too (seen on the root pass at 64 MB).
    runaway.cgroup.memory_max_mb = 256;
    runaway.cgroup.pids_max = 64;

    // The runaway job holds more and more memory, and a fork bomb after it; its neighbour, at
    // the same time, holds 200 MB under the default limit and must not notice.
    // Each ends by itself if its limit fails, and the checks below then fail.
    const hog = hogStep(1024);
    var bomb = bombStep(9);
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
    try std.testing.expect(std.mem.indexOf(u8, texts[0], "no limit stopped it") == null);
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

test "root runner: an OOM kill takes every process of a step's cgroup, and the job goes on" {
    var a: std.heap.ArenaAllocator = .init(std.testing.allocator);
    defer a.deinit();
    const arena = a.allocator();
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    var cfg = try testConfig(arena, &tmp);
    const parent = try testCgroup(arena, &cfg);
    defer parent.remove(arena);
    // Room for the step's shell and the helper, as the runaway test's.
    cfg.cgroup.memory_max_mb = 256;

    // Where the steps run, as the step sees it: the cgroup file is the host's, read-only.
    var which = testStep("cg=$(cut -d: -f3 /proc/self/cgroup)\necho \"cgroup=$cg\"\n" ++
        "echo \"oom.group=$(cat /sys/fs/cgroup$cg/memory.oom.group)\"");
    which.name = "which";
    // Without the group kill the kernel ends the hog, the largest, and the shell carries on
    // after it (`survived`); with it the shell and the sleep beside it go too. It ends by itself
    // if the limit fails: `no limit stopped it`.
    var oom = testStep("command -v python3 >/dev/null || { echo no\"\"-python; exit 0; }\n" ++
        "sleep 60 &\npython3 -c 'x = []\nfor _ in range(128): x.append(b\"x\" * (8 << 20))\n" ++
        "print(\"no limit\", \"stopped it\")\nraise SystemExit(3)' || echo exit=$?\n" ++
        "echo survived\"\"-the-oom");
    oom.name = "oom";
    var after = testStep("echo after-the-oom");
    after.name = "after";
    after.condition = "always()";
    const r = try runNativeJob(arena, cfg, testJob(&.{ which, oom, after }), .root);
    std.debug.print("oom group job:\n{s}\n", .{r.text});
    try expectLines(r.text, &.{
        "The job reached its memory limit (256 MB, RUNNER_NATIVE_MEMORY_MAX_MB): the kernel " ++
            "killed ",
        "after-the-oom",
    });
    try std.testing.expect(std.mem.indexOf(u8, r.text, "survived-the-oom") == null);
    try std.testing.expect(std.mem.indexOf(u8, r.text, "no limit stopped it") == null);
    try std.testing.expect(r.res.steps[1].outcome != .success);
    try std.testing.expectEqual(dagger.Outcome.success, r.res.steps[2].outcome);
    // The steps' cgroup is the one with the flag; services get another (`cgroup.Job.split`).
    try expectLines(r.text, &.{ "oom.group=1", "/steps" });
}

test "root runner: a step's processes, and their children, get oom_score_adj 500 or the env's" {
    var a: std.heap.ArenaAllocator = .init(std.testing.allocator);
    defer a.deinit();
    const arena = a.allocator();
    const io = std.testing.io;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    const cfg = try testConfig(arena, &tmp);
    // The runner's own, which a step is never given less than.
    var buf: [16]u8 = undefined;
    const own = std.fmt.parseInt(i32, std.mem.trim(u8, try std.Io.Dir.cwd().readFile(
        io,
        "/proc/self/oom_score_adj",
        &buf,
    ), "\n"), 10) catch return error.TestUnexpectedResult;

    // `cat` is a child of the shell, and `sh -c` a grandchild's parent: all inherit it.
    const show = "echo \"adj=$(cat /proc/self/oom_score_adj)\"\n" ++
        "sh -c 'echo \"child=$(cat /proc/self/oom_score_adj)\"'";
    const adj_env = "PIPELINE_JOB_OOMSCOREADJ";
    var plain = testStep(show);
    plain.name = "plain";
    var set = testStep(show);
    set.name = "set";
    set.env = &.{.{ .name = adj_env, .value = .{ .lit = "700" } }};
    var invalid = testStep(show);
    invalid.name = "invalid";
    invalid.env = &.{.{ .name = adj_env, .value = .{ .lit = "lots" } }};
    var low = testStep(show);
    low.name = "low";
    low.env = &.{.{ .name = adj_env, .value = .{ .lit = "-1000" } }};
    const r = try runNativeJob(arena, cfg, testJob(&.{ plain, set, invalid, low }), .root);
    std.debug.print("oom_score_adj job:\n{s}\n", .{r.text});
    try std.testing.expect(r.res.succeeded);
    const want = [_]i32{ @max(500, own), @max(700, own), @max(500, own), own };
    var at: usize = 0;
    for (want) |w| for ([_][]const u8{ "adj=", "child=" }) |key| {
        const line = try std.fmt.allocPrint(arena, "{s}{d}\n", .{ key, w });
        const found = std.mem.indexOfPos(u8, r.text, at, line) orelse {
            std.debug.print("missing {s} after {d} in:\n{s}\n", .{ line, at, r.text });
            return error.TestUnexpectedResult;
        };
        at = found + line.len;
    };
}

test "root runner: native gate accuracy, each job's own cgroup against the engine-wide reading" {
    var a: std.heap.ArenaAllocator = .init(std.testing.allocator);
    defer a.deinit();
    const arena = a.allocator();
    const io = std.testing.io;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    var cfg = try testConfig(arena, &tmp);
    const test_cgroup = try testCgroup(arena, &cfg);
    defer test_cgroup.remove(arena);
    const parent = test_cgroup.dir;
    // The jobs' parent stands for the engine's cgroup: one cgroup for every job, as the engine
    // is, read as the gate reads the engine's (which needs a cap to be read at all). The first
    // job replaces this cap with all jobs' limit, which serves as well.
    const cap = try std.fmt.allocPrintSentinel(arena, "{s}/memory.max", .{parent}, 0);
    const fd = std.os.linux.open(cap, .{ .ACCMODE = .WRONLY, .CLOEXEC = true }, 0);
    if (std.os.linux.errno(fd) != .SUCCESS) return skip(true, "the cgroup parent's memory.max");
    _ = std.os.linux.write(@intCast(fd), "68719476736", 11);
    _ = std.os.linux.close(@intCast(fd));

    // Two jobs as on razorbill's soak: the second starts while the first holds its memory.
    const mb = 300;
    var slots: [4]admission.Admission.Slot = undefined;
    var pool: admission.Admission = .init(io, .{ .margin_percent = 0 }, &slots);
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

test "root runner: a native job's cgroup gets memory.high from what the gate reserves for it" {
    var a: std.heap.ArenaAllocator = .init(std.testing.allocator);
    defer a.deinit();
    const arena = a.allocator();
    const io = std.testing.io;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    var cfg = try testConfig(arena, &tmp);
    const parent = try testCgroup(arena, &cfg);
    defer parent.remove(arena);
    // On a machine with no swap at all it has no use (`cgroup.canSwap`), and the test below has it.
    const can = cgroup.canSwap(.{ .swap = true }, io);
    if (!can) return error.SkipZigTest;
    cfg.cgroup.swap = true;
    var slots: [1]admission.Admission.Slot = undefined;
    var pool: admission.Admission = .init(io, .{ .margin_percent = 0 }, &slots);
    pool.paths = .{ .meminfo = "/nonexistent", .pressure = "/nonexistent" };
    pool.native = true;
    var gate: admission.Gate = .{ .pool = &pool };
    var gated = cfg;
    gated.gate = &gate;
    const key = admission.jobKey("o/r", "ci.yml", "memory.high");
    const job = testJob(&.{testStep("echo small job")});

    // Not learned yet: `native_per_job_mb` (256 MB), twice that and 512 MB of headroom, as the
    // kernel holds it (read back from the job's cgroup), beside its memory.max.
    gate.leave(true);
    gate.assigned(key);
    const first = try runNativeJob(arena, gated, job, .root);
    if (!first.res.succeeded) std.debug.print("{s}\n", .{first.text});
    try std.testing.expect(first.res.succeeded);
    try std.testing.expectEqual(@as(?u32, 1024), slots[0].high_mb);
    try expectLines(first.text, &.{
        "with memory.max ",
        "Native steps: all native jobs under ",
        "Native steps: memory.high 1.0 GB, from what the memory gate reserves for the job",
    });
    // All jobs' limits are on the parent.
    const all = cgroup.Limits.of(io, cfg.cgroup, parent.dir);
    // The kernel rounds it down to a page.
    const held = admission.readCgroupBytes(io, parent.dir, "memory.max").?;
    try std.testing.expect(held <= all.memory_total.? and all.memory_total.? - held < 1 << 16);
    var pids_buf: [32]u8 = undefined;
    const pids = try std.Io.Dir.cwd().readFile(
        io,
        try std.fmt.allocPrint(arena, "{s}/pids.max", .{parent.dir}),
        &pids_buf,
    );
    const pids_held = try std.fmt.parseInt(u32, std.mem.trim(u8, pids, "\n"), 10);
    try std.testing.expectEqual(all.pids_total.?, pids_held);
    const learned = gate.ended() orelse return error.TestUnexpectedResult;
    try std.testing.expect(learned.native and learned.alone);
    // The job's own few MB (its shell and helper), or the 64 MB floor.
    try std.testing.expect(learned.estimate_mb < 128);

    // Learned: its next memory.high is from what it took, 640 MB at the floor.
    gate.leave(true);
    gate.assigned(key);
    const second = try runNativeJob(arena, gated, job, .root);
    try std.testing.expect(second.res.succeeded);
    const high = admission.nativeHighMb(learned.estimate_mb);
    try std.testing.expectEqual(@as(?u32, high), slots[0].high_mb);
    try expectLines(second.text, &.{
        try std.fmt.allocPrint(arena, "Native steps: memory.high {d} MB, from ", .{high}),
    });
    _ = gate.ended();
}

test "root runner: with no swap a job past what the gate reserves is not held there" {
    // It stops dead at a `memory.high` it cannot reclaim: nothing kills it, and it holds its runner
    // until the job's timeout. `timeout` ends it here if it comes to that.
    var a: std.heap.ArenaAllocator = .init(std.testing.allocator);
    defer a.deinit();
    const arena = a.allocator();
    const io = std.testing.io;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    var cfg = try testConfig(arena, &tmp);
    const parent = try testCgroup(arena, &cfg);
    defer parent.remove(arena);
    cfg.cgroup.memory_max_mb = 1536;
    var slots: [1]admission.Admission.Slot = undefined;
    var pool: admission.Admission = .init(io, .{ .margin_percent = 0 }, &slots);
    pool.paths = .{ .meminfo = "/nonexistent", .pressure = "/nonexistent" };
    pool.native = true;
    var gate: admission.Gate = .{ .pool = &pool };
    cfg.gate = &gate;
    var sampling = try io.concurrent(admission.Admission.sample, .{&pool});
    defer sampling.cancel(io);
    gate.leave(true);
    gate.assigned(admission.jobKey("o/r", "ci.yml", "past its high"));
    // 1.1 GiB, over the 1 GB a job not learned yet would get, under its `memory.max`, and held for
    // the gate to see.
    const step = testStep("timeout 60 python3 -c 'import time; x = b\"x\" * (1100 << 20); " ++
        "print(\"held\", len(x) >> 20, flush=True); time.sleep(4)' || echo exit=$?");
    const r = try runNativeJob(arena, cfg, testJob(&.{step}), .root);
    if (!r.res.succeeded) std.debug.print("{s}\n", .{r.text});
    try expectLines(r.text, &.{ "held 1100", "Native steps: no memory.high: with no swap" });
    try std.testing.expectEqual(@as(?u32, null), slots[0].high_mb);
    // Seen at what it took, with nothing held down.
    const learned = gate.ended() orelse return error.TestUnexpectedResult;
    try std.testing.expect(learned.seen_mb >= 1100);
}

test "the error line says which limit an OOM kill came from" {
    var a: std.heap.ArenaAllocator = .init(std.testing.allocator);
    defer a.deinit();
    const arena = a.allocator();
    const limits: cgroup.Limits = .{
        .memory_max = 256 << 20,
        .pids_max = 64,
        .memory_total = 512 << 20,
    };
    const job = try oomLine(arena, .job, limits, 1);
    try std.testing.expect(std.mem.startsWith(u8, job, "The job reached its memory limit (256 "));
    const all = try oomLine(arena, .all, limits, 2);
    try std.testing.expect(std.mem.startsWith(u8, all, "All native jobs together reached their " ++
        "memory limit (512 MB, "));
    const above = try oomLine(arena, .above, limits, 1);
    try std.testing.expect(std.mem.startsWith(u8, above, "The machine ran out of memory"));
    try std.testing.expect(std.mem.indexOf(u8, above, "RUNNER_NATIVE") == null);
}

test "root runner: a named parent keeps the operator's limit, and a job's limits go below it" {
    var a: std.heap.ArenaAllocator = .init(std.testing.allocator);
    defer a.deinit();
    const arena = a.allocator();
    const io = std.testing.io;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    var cfg = try testConfig(arena, &tmp);
    const parent = try testCgroup(arena, &cfg);
    defer parent.remove(arena);
    if (parent.top == null) return error.SkipZigTest;
    // The operator's: a slice's `MemoryMax=4G`.
    const cap = try std.fmt.allocPrint(arena, "{s}/memory.max", .{parent.top.?});
    try std.Io.Dir.cwd().writeFile(io, .{ .sub_path = cap, .data = "4294967296" });
    const r = try runNativeJob(arena, cfg, testJob(&.{testStep("echo small job")}), .root);
    try std.testing.expect(r.res.succeeded);
    // Its limit and its swap are as they were, ours in the `jobs` child, figured from its 4 GiB.
    const top = parent.top.?;
    try std.testing.expectEqual(@as(?u64, 4 << 30), admission.readCgroupBytes(io, top, "memory.max"));
    try std.testing.expectEqual(null, admission.readCgroupBytes(io, top, "memory.swap.max"));
    try std.testing.expect(std.mem.endsWith(u8, parent.dir, "/jobs"));
    try std.testing.expect(admission.readCgroupBytes(io, parent.dir, "memory.max").? <= 2 << 30);
}

test "root runner: a job the runner does not vouch for does not run where no total can hold" {
    var a: std.heap.ArenaAllocator = .init(std.testing.allocator);
    defer a.deinit();
    const arena = a.allocator();
    const io = std.testing.io;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    var cfg = try testConfig(arena, &tmp);
    const parent = try testCgroup(arena, &cfg);
    defer parent.remove(arena);
    // A pool set to no limit, whose job holds 50 MB, so that a total of 1 MB would end it.
    var open = cfg;
    open.cgroup.memory_total_mb = 0;
    open.cgroup.memory_max_mb = 0;
    const Run = struct {
        fn one(arena_: Allocator, cfg_: Config, out: *?dagger.Result) void {
            const script = "python3 -c 'import time; x = b\"x\" * (50 << 20); time.sleep(6)'";
            const r = runNativeJob(arena_, cfg_, testJob(&.{testStep(script)}), .root) catch return;
            out.* = r.res;
        }
    };
    var ran: ?dagger.Result = null;
    var other_arena: std.heap.ArenaAllocator = .init(std.testing.allocator);
    defer other_arena.deinit();
    var holding = try io.concurrent(Run.one, .{ other_arena.allocator(), open, &ran });
    try io.sleep(.fromSeconds(3), .awake);
    var strict = cfg;
    strict.vouched = false;
    strict.cgroup.memory_total_mb = 1;
    var why: []const u8 = "";
    const refused = initWhy(arena, io, std.testing.allocator, strict, &why);
    holding.await(io);
    try std.testing.expectError(error.NoJobLimits, refused);
    try std.testing.expect(std.mem.indexOf(u8, why, "does not vouch for") != null);
    // And the job it would have put at risk ran through.
    try std.testing.expect(ran != null and ran.?.succeeded);
}

test "root runner: all native jobs together stay under the limit on their parent" {
    var a: std.heap.ArenaAllocator = .init(std.testing.allocator);
    defer a.deinit();
    const arena = a.allocator();
    const io = std.testing.io;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    var cfg = try testConfig(arena, &tmp);
    const parent = try testCgroup(arena, &cfg);
    defer parent.remove(arena);
    // Each job within its own limit, two of them not within all jobs': 600 MB of 400 at the
    // most, and neither asks for more whatever the limit does.
    cfg.cgroup.memory_max_mb = 350;
    cfg.cgroup.memory_total_mb = 400;
    const Run = struct {
        fn one(arena_: Allocator, cfg_: Config, out: *[]const u8) void {
            const r = runNativeJob(arena_, cfg_, testJob(&.{testStep("python3 -c 'import time; " ++
                "x = b\"x\" * (300 << 20); print(\"held\", flush=True); time.sleep(8)' || " ++
                "echo exit=$?")}), .root) catch return;
            out.* = r.text;
        }
    };
    var texts: [2][]const u8 = .{ "", "" };
    var arenas: [2]std.heap.ArenaAllocator = .{
        .init(std.testing.allocator),
        .init(std.testing.allocator),
    };
    defer for (&arenas) |*x| x.deinit();
    var first = try io.concurrent(Run.one, .{ arenas[0].allocator(), cfg, &texts[0] });
    try io.sleep(.fromSeconds(3), .awake);
    Run.one(arenas[1].allocator(), cfg, &texts[1]);
    first.await(io);
    for (texts) |t| try expectLines(t, &.{
        "with memory.max 350 MB",
        "share memory.max 400 MB and pids.max 32768",
    });
    // The kernel kills the larger of the two, either one, and the log says which limit it was.
    const said = "All native jobs together reached their memory limit (400 MB, " ++
        "RUNNER_NATIVE_MEMORY_TOTAL_MB)";
    try std.testing.expect(std.mem.indexOf(u8, texts[0], said) != null or
        std.mem.indexOf(u8, texts[1], said) != null);
    if (admission.readCgroupBytes(io, parent.dir, "memory.peak")) |peak|
        try std.testing.expect(peak <= 400 << 20);
}

test "root runner: a test's cgroup parent is its own, so runs side by side keep their limits" {
    var a: std.heap.ArenaAllocator = .init(std.testing.allocator);
    defer a.deinit();
    const arena = a.allocator();
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    var one = try testConfig(arena, &tmp);
    var other = one;
    if (std.os.linux.geteuid() != 0) return error.SkipZigTest;
    const p1 = try testCgroup(arena, &one);
    defer p1.remove(arena);
    const p2 = try testCgroup(arena, &other);
    defer p2.remove(arena);
    try std.testing.expect(!std.mem.eql(u8, p1.dir, p2.dir));
    one.cgroup.memory_total_mb = 256;
    other.cgroup.memory_total_mb = 512;
    const io = std.testing.io;
    const l1 = cgroup.Limits.compute(one.cgroup, null);
    const j1 = try cgroup.Job.make(arena, io, p1.dir, "one", l1);
    defer j1.remove(arena, io);
    const l2 = cgroup.Limits.compute(other.cgroup, null);
    const j2 = try cgroup.Job.make(arena, io, p2.dir, "two", l2);
    defer j2.remove(arena, io);
    const held = [_]?u64{
        admission.readCgroupBytes(io, p1.dir, "memory.max"),
        admission.readCgroupBytes(io, p2.dir, "memory.max"),
    };
    try std.testing.expectEqual(@as(?u64, 256 << 20), held[0]);
    try std.testing.expectEqual(@as(?u64, 512 << 20), held[1]);
}

test "a runner whose binary a deployment replaced runs native jobs on the binary it started from" {
    // razorbill, 2026-11-02: zig-runner-deploy renamed v0.24.2 over /usr/local/bin/zig-runner
    // while zig-runner@bench.service, not among its UNITS, kept running v0.24.1. The runner read
    // its own path from /proc/self/exe for each job, "/usr/local/bin/zig-runner (deleted)", and
    // every job's helper failed to start: "could not make the job's sandbox: FileNotFound".
    var a: std.heap.ArenaAllocator = .init(std.testing.allocator);
    defer a.deinit();
    const arena = a.allocator();
    const io = std.testing.io;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    var cfg = try testConfig(arena, &tmp);
    const cwd = std.Io.Dir.cwd();
    // The runner, installed from the tests' binary, running (a helper waiting for its spec on
    // stdin stands in for the runner's own process: it is the same binary).
    try tmp.dir.createDirPath(io, "bin");
    const installed = try std.fmt.allocPrint(arena, "{s}/bin/zig-runner", .{
        try tmp.dir.realPathFileAlloc(io, ".", arena),
    });
    try std.Io.Dir.copyFileAbsolute(cfg.self_exe, installed, io, .{});
    var runner = try std.process.spawn(io, .{
        .argv = &.{ installed, forward.command },
        .stdin = .pipe,
        .stdout = .ignore,
        .stderr = .ignore,
    });
    defer runner.kill(io);
    // Deployed over, as zig-runner-deploy puts a release: written beside it, renamed over it.
    const next = try std.fmt.allocPrint(arena, "{s}.new", .{installed});
    try cwd.writeFile(io, .{ .sub_path = next, .data = "#!/bin/sh\nexit 3\n" });
    try cwd.rename(next, cwd, installed, io);

    // What /proc/<pid>/exe names now is no file at all: razorbill's FileNotFound.
    const pid = runner.id.?;
    const link = try std.fmt.allocPrint(arena, "/proc/{d}/exe", .{pid});
    var buf: [std.fs.max_path_bytes]u8 = undefined;
    const named = try arena.dupe(u8, buf[0..try std.Io.Dir.readLinkAbsolute(io, link, &buf)]);
    try std.testing.expectEqualStrings(try std.fmt.allocPrint(arena, "{s} (deleted)", .{installed}), named);
    try std.testing.expectError(error.FileNotFound, std.process.spawn(io, .{ .argv = &.{ named, "x" } }));

    // The runner's helpers run the binary it started from, and "Set up job" says why.
    const exe = exeOf(arena, io, pid);
    try std.testing.expectEqualStrings(link, exe.path);
    try std.testing.expectEqualStrings(installed, exe.replaced);
    cfg.self_exe = exe.path;
    cfg.self_exe_replaced = exe.replaced;
    const job = testJob(&.{testStep("echo ran-natively")});
    // Started under `unshare` (Ubuntu's restricted user namespaces), the helper cannot be that
    // binary: the job goes to Dagger, saying why, before anything native is tried.
    if (usernsHere(io) == .inherited) {
        const why = unsupported(io, job, .{}, cfg) orelse return error.TestUnexpectedResult;
        try std.testing.expect(std.mem.indexOf(u8, why, "binary was replaced since it started") != null);
        return;
    }
    const r = try runNativeJob(arena, cfg, job, .root);
    if (!r.res.succeeded) std.debug.print("{s}\n", .{r.text});
    try std.testing.expect(r.res.succeeded);
    try expectLines(r.text, &.{
        "ran-natively",
        try std.fmt.allocPrint(arena, "Native steps: {s} was replaced since this runner started", .{installed}),
    });
    try std.testing.expect(std.mem.indexOf(u8, r.text, "This job runs on Dagger") == null);

    // As the runner had it, on a root runner, whose set-up starts the job's network helper: the
    // set-up says which helper it could not start, and from where.
    if (std.os.linux.geteuid() == 0) {
        var stale = cfg;
        stale.self_exe = named;
        stale.self_exe_replaced = "";
        var why: []const u8 = "";
        try std.testing.expectError(error.FileNotFound, initWhy(arena, io, std.testing.allocator, stale, &why));
        try std.testing.expectEqualStrings(try std.fmt.allocPrint(arena, "starting the job's " ++
            "network helper {s}: FileNotFound", .{named}), why);
    }
    // An unchanged binary is named by its own path.
    const self = exeOf(arena, io, std.os.linux.getpid());
    try std.testing.expect(self.replaced.len == 0 and std.mem.startsWith(u8, self.path, "/") and
        !std.mem.startsWith(u8, self.path, "/proc/"));
}

test "a native set-up that fails says what it did and on which path" {
    var a: std.heap.ArenaAllocator = .init(std.testing.allocator);
    defer a.deinit();
    const arena = a.allocator();
    const io = std.testing.io;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    var cfg = try testConfig(arena, &tmp);
    // A store whose jobs directory is a file: nothing of the job's can be made in it.
    const store = try std.fmt.allocPrint(arena, "{s}/blocked", .{try tmp.dir.realPathFileAlloc(io, ".", arena)});
    for ([_][]const u8{ "layers", "keys" }) |d|
        try tmp.dir.createDirPath(io, try std.fmt.allocPrint(arena, "blocked/{s}", .{d}));
    try tmp.dir.writeFile(io, .{ .sub_path = "blocked/jobs", .data = "" });
    cfg.store = store;
    var why: []const u8 = "";
    if (initWhy(arena, io, std.testing.allocator, cfg, &why)) |made| {
        var b = made;
        b.deinit();
        return error.TestUnexpectedResult;
    } else |_| {}
    const expect = try std.fmt.allocPrint(arena, "preparing the native store {s}: ", .{store});
    if (!std.mem.startsWith(u8, why, expect)) {
        std.debug.print("why: {s}\n", .{why});
        return error.TestUnexpectedResult;
    }
}

/// GitHub's `hashFiles()` of files with these contents, in this order.
fn hashOfFiles(contents: []const []const u8) [64]u8 {
    var all = Sha256.init(.{});
    for (contents) |c| {
        var d: [32]u8 = undefined;
        Sha256.hash(c, &d, .{});
        all.update(&d);
    }
    return std.fmt.bytesToHex(all.finalResult(), .lower);
}

/// The steps of `hashFiles()`'s tests: one writes the files (`lock` is the first one's text), the
/// others read them where an expression can: a script, `env:`, `if:`, a name, the job's outputs.
/// Step 4 deletes a file written below it (a whiteout) and makes a link; step 5 reads the tree
/// again, and hashes it as the step's own overlay sees it (the oracle) as well.
fn hashingJob(arena: Allocator, lock: []const u8) !job_mod.Job {
    const s1 = testStep(try std.fmt.allocPrint(arena, "echo x >> /shared/s1; printf '{s}' > lock.txt; " ++
        "mkdir -p sub; printf two > sub/lock.txt", .{lock}));
    var s2 = testStep("");
    s2.action.script.script = .{ .expr = "format('echo x >> /shared/s2; echo key={0}.', hashFiles('**/lock.txt'))" };
    var s3 = testStep("echo x >> /shared/s3; echo env=$K.");
    s3.env = &.{.{ .name = "K", .value = .{ .expr = "hashFiles('**/lock.txt', '!sub/**')" } }};
    s3.condition = "hashFiles('**/lock.txt') != ''";
    s3.name_expr = "format('named-{0}', hashFiles('sub/lock.txt'))";
    const s4 = testStep("echo x >> /shared/s4; printf changed > lock.txt; rm sub/lock.txt; " ++
        "mkdir sub2; printf z > sub2/a; ln -s sub2 dl");
    var s5 = testStep("echo x >> /shared/s5; echo key2=$KEY2. follow=$FOLLOW. link=$LINK. gone=$GONE. all=$ALL.\n" ++
        "echo oracle=$(python3 -c \"import hashlib,os\n" ++
        "h=hashlib.sha256()\n" ++
        "def walk(d):\n" ++
        "  for n in sorted(os.listdir(d)):\n" ++
        "    p=d+'/'+n\n" ++
        "    if os.path.isdir(p):\n" ++
        "      if not os.path.islink(p): walk(p)\n" ++
        "    else: h.update(hashlib.sha256(open(p,'rb').read()).digest())\n" ++
        "walk('.')\n" ++
        "print(h.hexdigest())\")");
    s5.env = &.{
        .{ .name = "KEY2", .value = .{ .expr = "hashFiles('**/lock.txt')" } },
        .{ .name = "FOLLOW", .value = .{ .expr = "hashFiles('--follow-symbolic-links', 'dl/**')" } },
        .{ .name = "LINK", .value = .{ .expr = "hashFiles('dl')" } },
        .{ .name = "GONE", .value = .{ .expr = "hashFiles('sub/lock.txt')" } },
        .{ .name = "ALL", .value = .{ .expr = "hashFiles('**')" } },
    };
    var s6 = testStep("echo x >> /shared/s6; echo ran-if");
    s6.condition = "hashFiles('sub/lock.txt') == '' && hashFiles('dl/*') == ''";
    var job = testJob(try arena.dupe(job_mod.Step, &.{ s1, s2, s3, s4, s5, s6 }));
    job.outputs = &.{.{ .name = "key", .value = .{ .expr = "hashFiles('**/lock.txt')" } }};
    return job;
}

test "native hashFiles: steps read the files the steps before them left, replayed or run, and a changed file is not served a stale replay" {
    var a: std.heap.ArenaAllocator = .init(std.testing.allocator);
    defer a.deinit();
    const arena = a.allocator();
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    const c = try cachedConfig(arena, &tmp);

    const one = hashOfFiles(&.{ "one", "two" });
    const first_only = hashOfFiles(&.{"one"});
    const sub_only = hashOfFiles(&.{"two"});
    const upper = hashOfFiles(&.{ "ONE", "two" });
    const changed = hashOfFiles(&.{"changed"});
    // What step 5 sees: lock.txt as step 4 wrote it, sub/lock.txt gone, `dl` (to a directory) not
    // a file, `sub2/a` through it when links are followed, and the whole tree as the oracle walks.
    const whole = hashOfFiles(&.{ "changed", "z" });
    const via_link = hashOfFiles(&.{"z"});

    const first = try runCached(arena, c.cfg, try hashingJob(arena, "one"), "j1");
    try expectSucceeded(first);
    try expectLines(first.text, &.{
        try std.fmt.allocPrint(arena, "key={s}.", .{&one}),
        try std.fmt.allocPrint(arena, "env={s}.", .{&first_only}),
        try std.fmt.allocPrint(arena, "key2={s}. follow={s}. link=. gone=. all={s}.", .{ &changed, &via_link, &whole }),
        // The overlay a step sees, walked and hashed in the step: the runner's merge of the layers
        // gave the same files, in the same order, with the same hash.
        try std.fmt.allocPrint(arena, "oracle={s}", .{&whole}),
        "ran-if",
    });
    try std.testing.expectEqualStrings(try std.fmt.allocPrint(arena, "named-{s}", .{&sub_only}), first.res.steps[2].name);
    // The job's outputs are read once the last step has run.
    try std.testing.expectEqualStrings(&changed, first.res.outputs[0].value);

    // The same job again: every step replayed, the hash read from the layers the store gave back,
    // and the replayed log the live one.
    const second = try runCached(arena, c.cfg, try hashingJob(arena, "one"), "j2");
    try expectSucceeded(second);
    for ([_][]const u8{ "s1", "s2", "s3", "s4", "s5", "s6" }) |name|
        try std.testing.expectEqual(@as(usize, 1), runs(arena, c.shared, name));
    try std.testing.expectEqual(@as(usize, 6), std.mem.count(u8, second.text, dagger.native_reused_note));
    try std.testing.expectEqualStrings(&changed, second.res.outputs[0].value);
    try std.testing.expectEqualStrings(try std.fmt.allocPrint(arena, "named-{s}", .{&sub_only}), second.res.steps[2].name);
    const live = try replayableLines(arena, first.text);
    const replayed = try replayableLines(arena, second.text);
    try std.testing.expectEqual(live.len, replayed.len);
    for (live, replayed) |l, r| try std.testing.expectEqualStrings(l, r);

    // Another first file: the steps that read it print its hash and run again, none is served the
    // earlier job's output (whose `key=` has the other hash).
    const third = try runCached(arena, c.cfg, try hashingJob(arena, "ONE"), "j3");
    try expectSucceeded(third);
    for ([_][]const u8{ "s1", "s2", "s3", "s4", "s5", "s6" }) |name|
        try std.testing.expectEqual(@as(usize, 2), runs(arena, c.shared, name));
    try expectLines(third.text, &.{try std.fmt.allocPrint(arena, "key={s}.", .{&upper})});
    try std.testing.expect(std.mem.indexOf(u8, third.text, &one) == null);
}

test "native hashFiles: no match is an empty string, a pattern with `..` fails the step, as on Dagger" {
    var a: std.heap.ArenaAllocator = .init(std.testing.allocator);
    defer a.deinit();
    const arena = a.allocator();
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    const cfg = try testConfig(arena, &tmp);
    var none = testStep("");
    none.action.script.script = .{ .expr = "format('echo none-{0}. {1}.', hashFiles('**/missing.lock'), hashFiles('/elsewhere/x', '!a'))" };
    var dots = testStep("echo not-reached");
    dots.action.script.script = .{ .expr = "format('echo {0}', hashFiles('sub/../lock.txt'))" };
    const r = try runNativeJob(arena, cfg, testJob(&.{ none, dots }), .root);
    try std.testing.expectEqual(dagger.Outcome.success, r.res.steps[0].outcome);
    try expectLines(r.text, &.{"none-. ."});
    try std.testing.expectEqual(dagger.Outcome.failure, r.res.steps[1].outcome);
    try expectLines(r.text, &.{"could not evaluate the script: hashFiles(sub/../lock.txt) failed"});
    try std.testing.expect(std.mem.indexOf(u8, r.text, "not-reached") == null);
}

test "native hashFiles: a link a step planted out of the job's tree does not read the host's files" {
    var a: std.heap.ArenaAllocator = .init(std.testing.allocator);
    defer a.deinit();
    const arena = a.allocator();
    const io = std.testing.io;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    const cfg = try testConfig(arena, &tmp);
    try tmp.dir.createDirPath(io, "host-dir");
    try tmp.dir.writeFile(io, .{ .sub_path = "host-dir/secret.txt", .data = "host secret" });
    const root = try tmp.dir.realPathFileAlloc(io, ".", arena);
    const host_dir = try std.fmt.allocPrint(arena, "{s}/host-dir", .{root});
    // The host's directory under the workspace, by an absolute link and by one of `..` (as many as
    // reach the host's root, if the job's were it).
    const plant = try std.fmt.allocPrint(arena, "printf ok > ok.txt; ln -s {s} abs-dir; " ++
        "ln -s {s}/secret.txt abs-file; ln -s ../../../../../../../../../../../../../../../..{s} rel-dir; " ++
        "true", .{ host_dir, host_dir, host_dir });
    var follow = testStep("");
    follow.action.script.script = .{ .expr = "format('echo follow={0}.', hashFiles('--follow-symbolic-links', '**'))" };
    var plain = testStep("");
    plain.action.script.script = .{ .expr = "format('echo plain={0}.', hashFiles('abs-file'))" };
    const r = try runNativeJob(arena, cfg, testJob(&.{ testStep(plant), follow, plain }), .root);
    const ok = hashOfFiles(&.{"ok"});
    // Followed, the links lead to nothing in the job's tree: only `ok.txt` is hashed. Not followed,
    // a link to a file that is not there fails the call, rather than hash the host's file.
    try expectLines(r.text, &.{try std.fmt.allocPrint(arena, "follow={s}.", .{&ok})});
    try std.testing.expectEqual(dagger.Outcome.failure, r.res.steps[2].outcome);
    try std.testing.expect(std.mem.indexOf(u8, r.text, "plain=") == null);
    var dir = try tmp.dir.openDir(io, "host-dir", .{ .iterate = true });
    defer dir.close(io);
    var it = dir.iterate();
    while (try it.next(io)) |e| try std.testing.expectEqualStrings("secret.txt", e.name);
}

test "hashFiles reads for the steps' user, by each layer's ids, and for root checks nothing" {
    var a: std.heap.ArenaAllocator = .init(std.testing.allocator);
    defer a.deinit();
    const arena = a.allocator();
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
    try b.layers.append(arena, .{ .name = "old", .path = "old", .canonical = true });
    try b.layers.append(arena, .{ .name = "new", .path = "new" });
    var seen: [4]Store.Ids = undefined;

    // Root sees all of it, on a root runner...
    try std.testing.expect(b.hashStep(&seen) == null);
    // ...as a rootless one's steps, which can be no one else, do, in a namespace of their own or
    // in one they were started in.
    for ([_]sandbox.Userns{ .self, .inherited }) |rootless| {
        b.how.userns = rootless;
        try std.testing.expect(b.hashStep(&seen) == null);
    }

    // The runner user on a root runner: the job's upper in the slot's ids, the stored layer and
    // the image's below it in the job's.
    b.how.userns = .mapped;
    b.uid = 1001;
    b.gid = 1001;
    b.user = dagger.runner_user;
    const step = b.hashStep(&seen).?;
    try std.testing.expectEqual(@as(u32, 1001), step.uid);
    try std.testing.expectEqual(b.slotIds(), seen[0]);
    for (seen[1..]) |lower| try std.testing.expectEqual(b.ids(), lower);

    // No layer of a rootless runner has a slot's ids, whoever it were asked for.
    for ([_]sandbox.Userns{ .self, .inherited }) |rootless| {
        b.how.userns = rootless;
        _ = b.hashStep(&seen).?;
        for (seen) |any| try std.testing.expectEqual(b.ids(), any);
    }
}

/// A job that plants links to what its user may not read, in a rootfs that has such files, then
/// asks for each in a step of its own. `hashFiles()` failing fails a step, and these run anyway.
fn deniedJob(arena: Allocator) !job_mod.Job {
    const plant = testStep("ln -s /etc/shadow s; ln -s /opt/shut/f behind; ln -s /opt/shut/none absent; " ++
        "ln -s /opt/shut/sub dir-behind; ln -s /opt/grouped grouped; ln -s /opt opt-dir; " ++
        "printf mine > mine; chmod 600 mine; mkdir own; printf x > own/f; chmod 000 own");
    const asks = [_][]const u8{
        "'s'",
        "'behind'",
        "'absent'",
        "'dir-behind'",
        "'own/f'",
        "'--follow-symbolic-links', 'dir-behind/**'",
        "'opt-dir'",
        "'mine'",
        "'grouped'",
    };
    const steps = try arena.alloc(job_mod.Step, asks.len + 2);
    steps[0] = plant;
    steps[asks.len + 1] = testStep("echo read-by-group=$(cat grouped).");
    steps[asks.len + 1].condition = "always()";
    for (asks, steps[1 .. asks.len + 1], 0..) |ask, *st, i| {
        st.* = testStep("");
        st.condition = "always()";
        st.action.script.script = .{ .expr = try std.fmt.allocPrint(
            arena,
            "format('echo got{d}={{0}}.', hashFiles({s}))",
            .{ i, ask },
        ) };
    }
    return testJob(steps);
}

/// What `deniedJob` must leave: a step's failure for each file its user may not reach, in the words
/// of Dagger's `sha256sum` and `realpath`, and the hashes of those it may.
fn expectDenied(arena: Allocator, r: anytype) !void {
    const ws = "/home/runner/work/r/r";
    try expectLines(r.text, &.{
        "hashFiles(s) failed: sha256sum: s: Permission denied",
        "hashFiles(behind) failed: sha256sum: behind: Permission denied",
        // What is not there behind the directory reads as what is.
        "hashFiles(absent) failed: sha256sum: absent: Permission denied",
        "failed: sha256sum: dir-behind: Permission denied",
        // The user's own file, in the user's own directory, whose search it took away.
        "hashFiles(own/f) failed: sha256sum: own/f: Permission denied",
        "failed: realpath: " ++ ws ++ "/dir-behind: Permission denied",
        // A link to a directory the user can reach is skipped.
        "got6=.",
        try std.fmt.allocPrint(arena, "got7={s}.", .{&hashOfFiles(&.{"mine"})}),
        // By a supplementary group of /etc/group, which the step has too.
        try std.fmt.allocPrint(arena, "got8={s}.", .{&hashOfFiles(&.{"grouped"})}),
        "read-by-group=grouped.",
    });
    const steps = r.res.steps;
    for (steps[1..7]) |st| try std.testing.expectEqual(dagger.Outcome.failure, st.outcome);
    // The content of nothing refused reached the job.
    for ([_][]const u8{ "root:secret", "behind the door", "x" }) |content| {
        const hash = hashOfFiles(&.{content});
        try std.testing.expect(std.mem.indexOf(u8, r.text, &hash) == null);
    }
}

/// `deniedJob`'s rootfs, under `root`: what a provisioned image gives the runner user, and files
/// of the job's root that it may not read.
fn deniedRootfs(arena: Allocator, root: []const u8) !void {
    const setup = try std.fmt.allocPrint(arena,
        \\set -e
        \\cd '{s}'
        \\mkdir -p rootfs/opt/shut/sub rootfs/github rootfs/home/runner
        \\chown 1001:1001 rootfs/github rootfs/home/runner
        \\chmod 1777 rootfs/tmp
        \\printf 'root:secret' > rootfs/etc/shadow
        \\chmod 0640 rootfs/etc/shadow
        \\printf 'behind the door' > rootfs/opt/shut/f
        \\chmod 0755 rootfs/opt
        \\chmod 0700 rootfs/opt/shut
        \\printf grouped > rootfs/opt/grouped
        \\chown 0:50 rootfs/opt/grouped
        \\chmod 0640 rootfs/opt/grouped
        \\printf 'root:x:0:\nrunner:x:1001:\nstaff:x:50:runner\n' > rootfs/etc/group
    , .{root});
    const made = try std.process.run(arena, std.testing.io, .{ .argv = &.{ "sh", "-c", setup } });
    try std.testing.expect(made.term == .exited and made.term.exited == 0);
}

test "native hashFiles: a step's user hashes only what it could read, as Dagger's `sha256sum` did" {
    try requireRoot();
    var a: std.heap.ArenaAllocator = .init(std.testing.allocator);
    defer a.deinit();
    const arena = a.allocator();
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    const cfg = try testConfig(arena, &tmp);
    try deniedRootfs(arena, try tmp.dir.realPathFileAlloc(std.testing.io, ".", arena));
    // The job's upper in its slot's host ids: each step sees it unmapped.
    const r = try runNativeJob(arena, cfg, try deniedJob(arena), .runner);
    try expectDenied(arena, r);
}

test "native hashFiles: a stored layer's ids are the job's, whichever slot left them" {
    try requireRoot();
    var a: std.heap.ArenaAllocator = .init(std.testing.allocator);
    defer a.deinit();
    const arena = a.allocator();
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    const c = try cachedConfig(arena, &tmp);
    try deniedRootfs(arena, try tmp.dir.realPathFileAlloc(std.testing.io, ".", arena));
    // A step that wrote a file only its user may read, kept in the store with the canonical ids,
    // and a step after it, replayed or not, whose hash of it is the user's.
    const write = testStep("echo x >> /shared/w; printf mine > mine; chmod 600 mine");
    var read = testStep("");
    read.action.script.script = .{ .expr = "format('echo x >> /shared/r; echo got={0}.', hashFiles('mine'))" };
    const job = testJob(&.{ write, read });
    const want = try std.fmt.allocPrint(arena, "got={s}.", .{&hashOfFiles(&.{"mine"})});
    const first = try runCachedAs(arena, c.cfg, job, "j1", .runner);
    try expectSucceeded(first);
    try expectLines(first.text, &.{want});
    const again = try runCachedAs(arena, c.cfg, job, "j2", .runner);
    try expectSucceeded(again);
    try expectLines(again.text, &.{want});
    try std.testing.expectEqual(@as(usize, 1), runs(arena, c.shared, "w"));
}

test "native hashFiles: a job container's --user is whom it reads for, its groups by its form" {
    try requireRoot();
    var a: std.heap.ArenaAllocator = .init(std.testing.allocator);
    defer a.deinit();
    const arena = a.allocator();
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    const cfg = try testConfig(arena, &tmp);
    // `app` (1002:1003 in the image) is in `staff` here, and only `staff` may read the file.
    var extra: oci_layer.TestTar = .{ .a = arena };
    try extra.add(.{ .path = "__w/", .kind = .directory, .mode = 0o777 });
    try extra.add(.{ .path = "etc/group", .body = "root:x:0:\napp:x:1003:\nstaff:x:50:app\n" });
    try extra.add(.{ .path = "etc/grouped", .body = "grouped", .mode = 0o640, .gid = 50 });
    const layers = try std.mem.concat(arena, []const u8, &.{
        try testImageLayers(arena),
        &.{try extra.finish()},
    });
    const img = try testregistry.testImage(arena, "test/user", "1", layers, "\"PATH=/usr/bin:/bin\"", false);
    var server: testregistry.Server = .{ .routes = img.routes };
    try server.start();
    defer server.stop();

    var read = testStep("");
    read.action.script.script = .{ .expr = "format('echo got={0}.', hashFiles('l'))" };
    // Stored once for the member: the same ids without the group must not replay what it read.
    var reader = testStep("echo read=$(cat /etc/grouped 2>/dev/null).");
    reader.condition = "always()";
    const steps = [_]job_mod.Step{ testStep("ln -s /etc/grouped l"), read, reader };
    // By name, the user's groups count; with its ids alone, as BuildKit gives them, they do not.
    for ([_][]const u8{ "--user app", "--user 1002:1003" }, [_]bool{ true, false }) |options, member| {
        var job = testJob(&steps);
        job.container = .{
            .name = "",
            .image = .{ .lit = try server.image(arena, "test/user:1") },
            .options = .{ .lit = options },
        };
        const r = try runNativeJob(arena, cfg, job, .root);
        try expectLines(r.text, &.{if (member)
            try std.fmt.allocPrint(arena, "got={s}.", .{&hashOfFiles(&.{"grouped"})})
        else
            "hashFiles(l) failed: sha256sum: l: Permission denied"});
        try expectLines(r.text, &.{if (member) "read=grouped." else "read=."});
    }
}

test "native hashFiles: a root step's hash does not look at the file's mode" {
    var a: std.heap.ArenaAllocator = .init(std.testing.allocator);
    defer a.deinit();
    const arena = a.allocator();
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    const cfg = try testConfig(arena, &tmp);
    const plant = testStep("mkdir d; printf r > d/f; chmod 600 d/f; chmod 700 d");
    var read = testStep("");
    read.action.script.script = .{ .expr = "format('echo got={0}.', hashFiles('d/f'))" };
    const r = try runNativeJob(arena, cfg, testJob(&.{ plant, read }), .root);
    try expectLines(r.text, &.{try std.fmt.allocPrint(arena, "got={s}.", .{&hashOfFiles(&.{"r"})})});
}

/// Two steps whose text is the same in every job: the first writes the file from its env, the
/// second reads its hash through its own env. Only `content` differs between jobs.
fn envJob(arena: Allocator, content: []const u8) !job_mod.Job {
    var write = testStep("echo x >> /shared/w; printf '%s' \"$SEED\" > seed.txt");
    write.env = try arena.dupe(job_mod.Input, &.{.{ .name = "SEED", .value = .{ .lit = content } }});
    var read = testStep("echo x >> /shared/r; echo read=$K.");
    read.env = &.{.{ .name = "K", .value = .{ .expr = "hashFiles('seed.txt')" } }};
    return testJob(try arena.dupe(job_mod.Step, &.{ write, read }));
}

test "native hashFiles: a change only in a step's env, or in the file that gives it the hash, is not replayed from the old job" {
    var a: std.heap.ArenaAllocator = .init(std.testing.allocator);
    defer a.deinit();
    const arena = a.allocator();
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    const c = try cachedConfig(arena, &tmp);
    const one = hashOfFiles(&.{"one"});
    const two = hashOfFiles(&.{"two"});

    const first = try runCached(arena, c.cfg, try envJob(arena, "one"), "j1");
    try expectSucceeded(first);
    try expectLines(first.text, &.{try std.fmt.allocPrint(arena, "read={s}.", .{&one})});
    const again = try runCached(arena, c.cfg, try envJob(arena, "one"), "j2");
    try expectSucceeded(again);
    try std.testing.expectEqual(@as(usize, 1), runs(arena, c.shared, "w"));
    try std.testing.expectEqual(@as(usize, 1), runs(arena, c.shared, "r"));
    // Neither step's text changes, only the writer's env: the writer runs again, the reader's hash
    // is of the new file, and it runs again too. A replay of either would print `one`'s hash.
    const other = try runCached(arena, c.cfg, try envJob(arena, "two"), "j3");
    try expectSucceeded(other);
    try std.testing.expectEqual(@as(usize, 2), runs(arena, c.shared, "w"));
    try std.testing.expectEqual(@as(usize, 2), runs(arena, c.shared, "r"));
    try expectLines(other.text, &.{try std.fmt.allocPrint(arena, "read={s}.", .{&two})});
    try std.testing.expect(std.mem.indexOf(u8, other.text, &one) == null);
    // And the first job's own steps are still kept: `one` replays again.
    const back = try runCached(arena, c.cfg, try envJob(arena, "one"), "j4");
    try expectSucceeded(back);
    try std.testing.expectEqual(@as(usize, 2), runs(arena, c.shared, "w"));
    try expectLines(back.text, &.{try std.fmt.allocPrint(arena, "read={s}.", .{&one})});
}

test "a refused sandbox names the AppArmor profile when Ubuntu's restriction is on" {
    var a: std.heap.ArenaAllocator = .init(std.testing.allocator);
    defer a.deinit();
    const arena = a.allocator();
    const exe = "/usr/local/bin/zig-runner";
    const hint = try usernsHint(arena, "1\n", false, exe);
    try std.testing.expect(std.mem.indexOf(u8, hint, "apparmor_restrict_unprivileged_userns") != null);
    try std.testing.expect(std.mem.indexOf(u8, hint, "deploy/apparmor/usr.local.bin.zig-runner") != null);
    try std.testing.expect(std.mem.indexOf(u8, hint, "apparmor_parser -r") != null);
    try std.testing.expect(std.mem.indexOf(u8, hint, exe) != null);
    // Not the cause: sysctl off, unreadable (not Ubuntu), or a root runner, which needs no profile.
    try std.testing.expectEqualStrings("", try usernsHint(arena, "0\n", false, exe));
    try std.testing.expectEqualStrings("", try usernsHint(arena, "", false, exe));
    try std.testing.expectEqualStrings("", try usernsHint(arena, "1\n", true, exe));
}

test "host paths: the runner's own files refused, and each job held to the list checked at the start" {
    var a: std.heap.ArenaAllocator = .init(std.testing.allocator);
    defer a.deinit();
    const arena = a.allocator();
    const io = std.testing.io;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    const root = try tmp.dir.realPathFileAlloc(io, ".", arena);
    for ([_][]const u8{ "keys", "store", "data" }) |d| try tmp.dir.createDirPath(io, d);
    try tmp.dir.writeFile(io, .{ .sub_path = "keys/app.pem", .data = "" });
    var env: std.process.Environ.Map = .init(arena);
    try env.put("GH_SCOPE", "o/r");
    try env.put("GH_APP_ID", "1");
    try env.put("GH_APP_PRIVATE_KEY_FILE", try std.fmt.allocPrint(arena, "{s}/keys/app.pem", .{root}));
    try env.put("RUNNER_BACKEND", "native");
    try env.put("RUNNER_NATIVE_STORE", try std.fmt.allocPrint(arena, "{s}/store", .{root}));
    var cfg = try config.Config.load(&env, &.{"runner"});
    // The App key's directory, and the one holding the runner's own executable.
    const exe = exeOf(arena, io, std.os.linux.getpid()).path;
    for ([_][]const u8{ try std.fmt.allocPrint(arena, "{s}/keys", .{root}), std.fs.path.dirname(exe).? }) |entry| {
        cfg.native_host_paths = entry;
        var r: host_paths.Refusal = .{};
        try std.testing.expectError(error.Refused, hostPathsOf(arena, io, &env, &cfg, &r));
        if (std.mem.indexOf(u8, r.why, "runner's own") == null) {
            std.debug.print("{s}: {s}\n", .{ entry, r.why });
            return error.TestUnexpectedResult;
        }
    }

    // A job is held to the list `main` checked: none when it was never checked, and an entry
    // whose directory changed since is closed, not resolved again to where it points now.
    const data = try std.fmt.allocPrint(arena, "{s}/data", .{root});
    cfg.native_host_paths = data;
    cfg.native_host_allowed = null;
    const unchecked = (try configFor(arena, io, &env, &cfg, true)).?;
    try std.testing.expectEqual(@as(usize, 0), unchecked.host_paths.len);
    var r: host_paths.Refusal = .{};
    cfg.native_host_allowed = try host_paths.parse(arena, io, data, &.{}, &r, .{ .mount_flags = false });
    try tmp.dir.rename("data", tmp.dir, "data-was", io);
    try tmp.dir.createDirPath(io, "data");
    const replaced = (try configFor(arena, io, &env, &cfg, true)).?;
    try std.testing.expectEqual(@as(usize, 0), replaced.host_paths.len);
    try std.testing.expectEqual(@as(usize, 1), replaced.host_paths_closed.len);
}
