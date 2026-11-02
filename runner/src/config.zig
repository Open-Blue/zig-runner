//! Runner configuration (SPEC §2). Environment variables, overridden by flags.
const std = @import("std");
const builtin = @import("builtin");
const zig_release = @import("zig_release.zig");
const pg = @import("pg.zig");
const engine = @import("engine.zig");
const admission = @import("admission.zig");
const trust = @import("trust.zig");
const app = @import("github/app.zig");
const NativeBackend = @import("native/Backend.zig");
const native_net = @import("native/net.zig");
const NativeStore = @import("native/Store.zig");
const native_cgroup = @import("native/cgroup.zig");

pub const Scope = union(enum) {
    repo: struct { owner: []const u8, name: []const u8 },
    org: []const u8,

    pub fn parse(s: []const u8) error{InvalidScope}!Scope {
        if (std.mem.startsWith(u8, s, "org:")) {
            const name = s["org:".len..];
            if (name.len == 0) return error.InvalidScope;
            return .{ .org = name };
        }
        const slash = std.mem.indexOfScalar(u8, s, '/') orelse return error.InvalidScope;
        const owner = s[0..slash];
        const name = s[slash + 1 ..];
        if (owner.len == 0 or name.len == 0 or std.mem.indexOfScalar(u8, name, '/') != null)
            return error.InvalidScope;
        return .{ .repo = .{ .owner = owner, .name = name } };
    }
};

pub const JsRuntime = enum { bun, node };
/// Who steps run as in the default image: `runner` (uid 1001, passwordless sudo), as on GitHub's
/// hosted runners, or root.
pub const StepUser = enum { runner, root };
/// How jobs reach the Dagger engine: directly (`engine.zig`), or through a `dagger run` child.
pub const EngineMode = enum { direct, cli };
/// What runs a job's steps: the Dagger engine, or the runner itself where it can
/// (docs/native-backend.md), each job it cannot run going to Dagger.
pub const StepBackend = enum { dagger, native };
/// The Zig release a Zig global-cache seed is built with (`RUNNER_ZIG_SEED=<version>=<sha256>`):
/// its version and the sha256 of its tarball for the engine host's architecture, from
/// https://ziglang.org/download/index.json.
pub const ZigSeed = struct { version: []const u8, sha256: []const u8 };
/// A GitHub App the runner authenticates as to manage its registrations, in place of `GH_TOKEN`
/// (`github/app.zig`): `GH_APP_ID`, `GH_APP_PRIVATE_KEY_FILE` or `GH_APP_PRIVATE_KEY`, and
/// optionally `GH_APP_INSTALLATION_ID`.
pub const GhApp = struct {
    /// The App's ID or its Client ID: GitHub takes either as the JWT's issuer.
    id: []const u8,
    key: union(enum) { file: []const u8, pem: []const u8 },
    /// Found from the scope (`GET /repos/{owner}/{repo}/installation`, `/orgs/{org}/installation`)
    /// when unset.
    installation_id: ?u64 = null,
};

/// A Zig version's characters only: it goes into a URL and a shell script.
pub fn validZigVersion(v: []const u8) bool {
    if (v.len == 0 or v.len > 64) return false;
    for (v) |ch| {
        if (!std.ascii.isAlphanumeric(ch) and std.mem.indexOfScalar(u8, ".+-", ch) == null)
            return false;
    }
    return true;
}

pub const Config = struct {
    /// "" with a GitHub App (`gh_app`).
    gh_token: []const u8,
    scope: Scope,
    /// A GitHub App to manage registrations as, instead of `gh_token`; the two exclude each other.
    gh_app: ?GhApp = null,
    /// The App's installation tokens, set up by `main` from `gh_app`. Every runner-management call
    /// takes its token from here when set (`jitconfig`).
    app_auth: ?*app.Auth = null,
    labels: []const u8 = "self-hosted,linux,zig",
    runner_group_id: u64 = 1,
    name_prefix: []const u8 = "zig",
    /// Absent means "log to stdout only" (StdoutSink).
    database_url: ?[]const u8 = null,
    dagger_cmd: []const u8 = "dagger",
    /// Base image for jobs. The default (pinned by digest; its bare name means the same) gets git,
    /// curl and CA certificates installed (cached by Dagger); a custom image is used as is.
    image: []const u8 = @import("dagger.zig").default_image,
    log_flush_lines: u32 = 200,
    log_flush_ms: u32 = 500,
    /// What runs JavaScript actions (`runs.using: node*`). Bun by default; Node for exact Node
    /// behaviour.
    js_runtime: JsRuntime = .bun,
    engine: EngineMode = .direct,
    /// The engine container `direct` sessions run `buildctl dial-stdio` in.
    engine_container: []const u8 = "dagger-engine-v0.21.10",
    /// The engine's own listener (`tcp://host:port`, `unix:///path`) for `direct` sessions, reached
    /// without the Docker API; empty to go through `engine_container`.
    engine_host: []const u8 = "",
    /// Seconds a step's query may go on with nothing at all heard from the engine (no health
    /// check, no answer, no log line) before its session is aborted and the step failed
    /// (`engine.Session.watch`, #100). 0 turns it off. Ten minutes: a swapping engine answers
    /// late, not that late.
    engine_silence_timeout_secs: u32 = 600,
    /// The Docker API socket (from DOCKER_HOST when it is `unix://`).
    docker_socket: []const u8 = "/var/run/docker.sock",
    /// Give each step's commands access to the job's Dagger engine
    /// (`experimentalPrivilegedNesting`), so `dagger call` inside a job works, as
    /// dagger/dagger-for-github expects, and only in jobs the runner vouches for. That access is
    /// enough to run privileged containers and open any cache volume by its key, so a job with it
    /// controls the runner's host: off unless a pool that needs it turns it on.
    dagger_nesting: bool = false,
    /// Mount persistent Dagger cache volumes at package managers' cache directories in every job.
    package_caches: bool = true,
    /// Check the tool cache's trees in "Set up job", before any step can write there, from lists
    /// kept in a volume no step mounts, and hand steps their digests (ZIG_RUNNER_TOOL_TREES), so a
    /// script that pins a tree's digest (install-zig.sh) need not read the tree again: 10-19 s of
    /// razorbill's Install Zig under load. Only in jobs without `dagger_nesting`, whose steps
    /// cannot reach the lists' volume (`set_up.verifyToolTrees`).
    tool_trees: bool = true,
    /// Reuse a step's result from an earlier run when its inputs are unchanged (steps that use
    /// secrets always run). A workflow can opt out with `ZIG_RUNNER_STEP_CACHE: false` in its env.
    step_cache: bool = true,
    /// Who steps run as in the default image (`RUNNER_STEP_USER`).
    step_user: StepUser = .runner,
    /// What runs steps (`RUNNER_BACKEND`): Dagger, or the native backend with Dagger for the jobs
    /// it cannot run yet.
    backend: StepBackend = .dagger,
    /// The native backend's rootfs, the default image provisioned, used instead of pulling and
    /// provisioning it natively (`RUNNER_NATIVE_ROOTFS`; "" to pull it), and where jobs' layers,
    /// pulled images and provisioned rootfs go (`RUNNER_NATIVE_STORE`; "" for the default,
    /// `nativeStore`).
    native_rootfs: []const u8 = "",
    native_store: []const u8 = "",
    /// Native steps on a runner that is not root (`RUNNER_NATIVE_ROOTLESS`), with only root
    /// mapped inside (`Backend.Config.rootless`); off, such a runner sends every job to Dagger.
    native_rootless: bool = false,
    /// The first host id of the native jobs' ranges on a root runner
    /// (`RUNNER_NATIVE_SUBID_BASE`, `Backend.Config.subid_base`): at least
    /// `NativeBackend.min_subid_base`.
    native_subid_base: u32 = NativeBackend.default_subid_base,
    /// The native jobs' network on a root runner (`RUNNER_NATIVE_SUBNET`, `net.Subnet.parse`).
    native_subnet: []const u8 = native_net.Subnet.default_text,
    /// Past this many MiB, the native step store's least recently used layers go
    /// (`RUNNER_NATIVE_STORE_MAX_MB`, `native/Store.zig`).
    native_store_max_mb: u64 = NativeStore.default_max_bytes / (1024 * 1024),
    /// Where native jobs' cgroups go (`RUNNER_NATIVE_CGROUP`: "", `self`, `none` or a cgroup's
    /// path), and each job's limits (`RUNNER_NATIVE_MEMORY_MAX_MB`, null for three quarters of
    /// the machine's memory and 0 for none; `RUNNER_NATIVE_PIDS_MAX`, 0 for none). See
    /// `native/cgroup.zig`.
    native_cgroup: []const u8 = "",
    native_memory_max_mb: ?u32 = null,
    native_pids_max: u32 = native_cgroup.default_pids_max,

    /// Experimental: key the steps after one that always runs on what it produced rather than on
    /// the step itself (see `dagger.Options.output_keys`).
    output_keys: bool = false,
    /// Give a step that did not name a run-specific value (`GITHUB_SHA`, `GITHUB_RUN_ID`, the
    /// actor, the refs) a constant instead of the real one, so that a step which reads one
    /// indirectly cannot be replayed with an earlier run's value. On by default, and a deliberate
    /// divergence from GitHub's runner: see SPEC "Where this runner differs from GitHub's".
    enforce_volatile: bool = true,
    /// Where a job's log is spooled while it runs, so the copy the upload reads is not held in
    /// memory for the length of the job (see `sink.Spool` and docs/RELATED.md, "Streaming a step's
    /// output"). The files go in the runner's own directory under it, `zig-runner-<uid>`, mode 0700
    /// (`SpoolDir`). Empty keeps the lines in memory, as before. A directory the runner cannot use
    /// is reported once and then ignored, because logging must never fail a job.
    log_spool_dir: []const u8 = "/tmp",
    /// Put uv's project environment inside its cache volume, so uv can hardlink into it instead of
    /// copying every file (28.6 s against 0.2 s on a Raspberry Pi; see SPEC §6 "Package caches").
    /// The workspace gets a `.venv` symlink to it, so paths into `.venv` still work. Only in jobs
    /// whose steps are not cached (`step_cache` off, or the job opted out): a replayed `uv sync`
    /// writes nothing into the volume, so later steps would run against whatever environment
    /// another commit's job left there (#70). With step caching the environment stays in the
    /// workspace, part of each step's cached result.
    uv_env_in_cache: bool = true,
    /// Keep Zig's local cache (`.zig-cache`) between jobs, in a cache volume of its own: about 1.2 s
    /// off every `zig build test` of zig-runner itself, and 4-6 s when the previous build of the
    /// repository had the same source. Off by default: Zig never removes anything from that cache,
    /// so it grows by about 50 MB for every source version built, until the engine collects it.
    zig_local_cache: bool = false,
    /// With `zig_local_cache`, the size in MB past which Zig's local cache starts over, whole, in a
    /// new generation of its volume (`set_up.zig`, `zig_local_roll_script`): Zig grows it by about
    /// 111 MB for every commit built, and a Zig cache must never lose part of itself. 0 lets it
    /// grow, in the volume's root as before.
    zig_local_cache_max_mb: u32 = 4096,
    /// Seed Zig jobs' global cache with what every `zig build` compiles before it reads any
    /// project: the build runner, 104 s on one core and about 1 GB on the laptop (`set_up.zig`,
    /// "The Zig cache seed"). The Zig releases to seed, comma-separated, at most three
    /// (`zig_release.zig`): each tarball's minisign signature is checked against Zig's pinned key
    /// when the runner starts, and one that does not verify is not seeded. By default the Zig the
    /// runner itself is built with; empty seeds nothing.
    zig_seed_versions: []const u8 = builtin.zig_version_string,
    /// An explicit seed, `<version>=<sha256>`, used instead of `zig_seed_versions`: the digest is
    /// the operator's pin, so no signature is checked.
    zig_seed: ?ZigSeed = null,
    /// The seeds jobs get: `zig_seed`, or the verified `zig_seed_versions` (`zig_release.resolve`,
    /// set by `main`).
    zig_seeds: []const ZigSeed = &.{},
    /// The `zig_seed_versions` that did not verify (`zig_release.resolve`), for "Set up job".
    zig_seeds_unverified: []const []const u8 = &.{},
    /// Where the seeds live once the runner runs jobs: the configured ones, and the tool caches'
    /// Zig versions as they are found and verified (set by `main`; null with `zig_seed`).
    zig_seed_registry: ?*zig_release.Registry = null,
    /// Build the default image's provisioned base container, and the Zig cache seed, in the
    /// background when the runner starts and when the engine comes back after a restart (its
    /// cache may be wiped then), so the first job does not spend 27-40 s, and the seed's 104 s,
    /// in "Set up job" (`loop.Warmer`). Direct engines only (not `RUNNER_ENGINE=cli`).
    prewarm: bool = true,
    /// Output keys cost two walks of the job's filesystem, whatever the step changed: 25 s on a
    /// large checkout against 1 s on a small one (STUDY.md §3.6). When a job spends longer than
    /// this on them, later jobs for that repository skip them until the runner restarts. 0 never
    /// skips.
    output_keys_max_ms: u32 = 10_000,
    /// With output keys: days a stored output may go unused before it is removed.
    output_keys_days: u32 = 7,
    /// Refs a job must come from to run here, comma-separated, a trailing `*` matching any rest
    /// (`refs/heads/main,refs/tags/v*`): the run's ref and its workflow file's. Empty runs no job;
    /// `*` trusts every ref, only on a machine untrusted workflows may reach (see `trust.zig`).
    trusted_refs: []const u8 = "",
    /// The events a job may come from, as `trusted_refs`: `*` trusts every event, empty none.
    trusted_events: []const u8 = "push,workflow_dispatch",
    dry_run: bool = false,
    /// Stop after one job (or one failed attempt), as an ephemeral runner process. Off by default:
    /// the runner registers again after each job.
    once: bool = false,
    /// Runners in this process, each serving jobs one after another, concurrently with the others.
    runners: u32 = 1,
    /// Ask for a job only while the machine has the memory for it (`admission.zig`, #126).
    admission: bool = true,
    admission_limits: admission.Limits = .{},
    /// The engine container's cgroup directory, whose memory cap the gate holds on too
    /// (`admission.Engine`, #142). Empty: found from `engine_host`'s unix socket; `none`: not
    /// looked for.
    engine_cgroup: []const u8 = "",
    /// Seconds a running job may go on after a stop signal before the runner cancels it, as GitHub
    /// cancels one: its step stopped, `if: always()` steps and post scripts still run, the job
    /// reported cancelled. The deploy agent restarts the runner on every release and expects jobs
    /// to finish, but a stop must not wait on a stuck one (#127). 0 cancels at once. The service's
    /// `TimeoutStopSec` leaves room for this and the cancel (`stop_cancel_ms` in loop/job.zig).
    stop_grace_secs: u32 = 600,
    /// Connect to the configured database, report what is there, and exit (no GitHub credentials
    /// needed).
    db_check: bool = false,
    /// Dev: run a saved acquirejob response through the executor without contacting GitHub.
    exec_job: ?[]const u8 = null,
    /// Register one runner, print the shape of its config, delete it, exit.
    inspect: bool = false,

    pub const Error = error{
        MissingGhToken,
        GhTokenAndApp,
        MissingGhAppId,
        MissingGhAppKey,
        GhAppKeyTwice,
        InvalidGhAppId,
        MissingGhScope,
        InvalidScope,
        InvalidNumber,
        InvalidJsRuntime,
        InvalidStepUser,
        InvalidBackend,
        InvalidNativeRootfs,
        InvalidNativeSubnet,
        InvalidNativeSubidBase,
        InvalidNativeCgroup,
        InvalidEngine,
        InvalidBool,
        InvalidZigSeed,
        UnknownFlag,
        MissingFlagValue,
        ProdTrustsNoRef,
    };

    /// What to tell the operator for an error whose name does not say how to fix it.
    pub fn explain(e: Error) ?[]const u8 {
        return switch (e) {
            error.ProdTrustsNoRef => "RUNNER_LABELS includes prod, but RUNNER_TRUSTED_REFS is " ++
                "not set, so this runner would fail every job. Set it to the refs prod may run " ++
                "(RUNNER_TRUSTED_REFS=refs/heads/main,refs/tags/v*), or to * to trust every ref " ++
                "(README, \"Environments\").",
            error.InvalidNativeRootfs => "RUNNER_NATIVE_ROOTFS is a directory's absolute path: " ++
                "overlay takes it as a layer from the job's directory.",
            error.InvalidNativeSubnet => "RUNNER_NATIVE_SUBNET is an IPv4 network a.b.c.d/p " ++
                "with no host bits set and a prefix of 8 to 23 bits (room for every job's " ++
                "address), by default " ++ native_net.Subnet.default_text ++ ".",
            error.InvalidNativeSubidBase => "RUNNER_NATIVE_SUBID_BASE is at least 100000, " ++
                "above every id a host's users and groups have.",
            error.InvalidNativeCgroup => "RUNNER_NATIVE_CGROUP is `self` (the runner's own " ++
                "cgroup, delegated to it), `none`, or a cgroup's path under /sys/fs/cgroup.",
            error.MissingGhToken => "No GitHub credentials: set GH_TOKEN, or a GitHub App with " ++
                "GH_APP_ID and GH_APP_PRIVATE_KEY_FILE (or GH_APP_PRIVATE_KEY) " ++
                "(deploy/runner.env.example).",
            error.GhTokenAndApp => "Both GH_TOKEN and a GitHub App (GH_APP_*) are set: the " ++
                "runner uses one or the other. Remove GH_TOKEN to use the App.",
            error.MissingGhAppId => "GH_APP_* is set but GH_APP_ID is not: set it to the App's " ++
                "ID or Client ID.",
            error.MissingGhAppKey => "GH_APP_ID is set but no private key: set " ++
                "GH_APP_PRIVATE_KEY_FILE to the App's PEM file, or GH_APP_PRIVATE_KEY to the PEM.",
            error.GhAppKeyTwice => "GH_APP_PRIVATE_KEY_FILE and GH_APP_PRIVATE_KEY are both " ++
                "set: give the key one way.",
            error.InvalidGhAppId => "GH_APP_ID is the App's ID (digits) or its Client ID " ++
                "(letters and digits, Iv23...).",
            error.InvalidZigSeed => "RUNNER_ZIG_SEED is <version>=<sha256>: a Zig version and " ++
                "the sha256 of its Linux tarball for this machine's architecture, from " ++
                "https://ziglang.org/download/index.json.",
            else => null,
        };
    }

    /// Values are borrowed from `environ` / `args`, which must outlive the Config.
    pub fn load(environ: *const std.process.Environ.Map, args: []const [:0]const u8) Error!Config {
        var creds: Credentials = .{
            .token = nonEmpty(environ.get("GH_TOKEN")),
            .scope = environ.get("GH_SCOPE"),
        };
        var c: Config = .{ .gh_token = "", .scope = undefined };
        try c.fromEnviron(environ);

        var i: usize = 1; // args[0] is the program name
        while (i < args.len) : (i += 1) {
            const arg: []const u8 = args[i];
            if (c.modeFlag(arg)) continue;
            if (!std.mem.startsWith(u8, arg, "--")) return error.UnknownFlag;
            var key = arg[2..];
            var val: []const u8 = undefined;
            if (std.mem.indexOfScalar(u8, key, '=')) |eq| {
                val = key[eq + 1 ..];
                key = key[0..eq];
            } else {
                i += 1;
                if (i >= args.len) return error.MissingFlagValue;
                val = args[i];
            }
            try c.applyFlag(key, val, &creds);
        }
        if (c.native_rootfs.len > 0 and !std.fs.path.isAbsolutePosix(c.native_rootfs))
            return error.InvalidNativeRootfs;
        _ = try native_net.Subnet.parse(c.native_subnet);
        if (c.native_subid_base < NativeBackend.min_subid_base) return error.InvalidNativeSubidBase;
        if (c.native_cgroup.len > 0 and !std.mem.eql(u8, c.native_cgroup, "self") and
            !std.mem.eql(u8, c.native_cgroup, "none") and !native_cgroup.within(c.native_cgroup))
            return error.InvalidNativeCgroup;

        if (c.exec_job != null or c.db_check) {
            // Offline mode: no GitHub credentials needed.
            c.gh_token = creds.token orelse "";
            c.scope = .{ .org = "offline" };
            return c;
        }
        // A runner that says it is prod and trusts nothing is a configuration slip (a lost
        // `EnvironmentFile` line, a typo), not a choice: say so now, not in every job's log (#105).
        if (trust.prodLabel(c.labels) and trust.none(c.trusted_refs)) return error.ProdTrustsNoRef;
        c.gh_app = try ghApp(environ);
        if (c.gh_app != null and creds.token != null) return error.GhTokenAndApp;
        if (c.gh_app == null) c.gh_token = creds.token orelse return error.MissingGhToken;
        c.scope = try Scope.parse(creds.scope orelse return error.MissingGhScope);
        return c;
    }

    /// The GitHub App from `GH_APP_*`, or null when none of them is set. Empty counts as unset,
    /// as the example env file leaves the variables it does not use empty (`GH_TOKEN=`).
    fn ghApp(environ: *const std.process.Environ.Map) Error!?GhApp {
        const id = nonEmpty(environ.get("GH_APP_ID"));
        const file = nonEmpty(environ.get("GH_APP_PRIVATE_KEY_FILE"));
        const pem = nonEmpty(environ.get("GH_APP_PRIVATE_KEY"));
        const installation = nonEmpty(environ.get("GH_APP_INSTALLATION_ID"));
        if (id == null and file == null and pem == null and installation == null) return null;
        const app_id = id orelse return error.MissingGhAppId;
        // It goes into the JWT's JSON as it is.
        for (app_id) |ch| if (!std.ascii.isAlphanumeric(ch)) return error.InvalidGhAppId;
        if (file != null and pem != null) return error.GhAppKeyTwice;
        return .{
            .id = app_id,
            .key = if (file) |f| .{ .file = f } else .{
                .pem = pem orelse return error.MissingGhAppKey,
            },
            .installation_id = if (installation) |v| try num(u64, v) else null,
        };
    }

    fn nonEmpty(v: ?[]const u8) ?[]const u8 {
        const s = v orelse return null;
        return if (s.len == 0) null else s;
    }

    /// `GH_TOKEN` and `GH_SCOPE` as given, by variable or flag, before they are required — a mode
    /// that runs offline needs neither.
    const Credentials = struct { token: ?[]const u8, scope: ?[]const u8 };

    /// Every setting the environment can give (SPEC.md §2's table).
    fn fromEnviron(c: *Config, environ: *const std.process.Environ.Map) Error!void {
        if (environ.get("RUNNER_LABELS")) |v| c.labels = v;
        if (environ.get("RUNNER_GROUP_ID")) |v| c.runner_group_id = try num(u64, v);
        if (environ.get("RUNNER_NAME_PREFIX")) |v| c.name_prefix = v;
        if (environ.get("DATABASE_URL")) |v| c.database_url = v;
        if (environ.get("DAGGER_CMD")) |v| c.dagger_cmd = v;
        if (environ.get("RUNNER_IMAGE")) |v| c.image = v;
        if (environ.get("LOG_FLUSH_LINES")) |v| c.log_flush_lines = try num(u32, v);
        if (environ.get("LOG_FLUSH_MS")) |v| c.log_flush_ms = try num(u32, v);
        if (environ.get("RUNNER_JS_RUNTIME")) |v| c.js_runtime = try jsRuntime(v);
        if (environ.get("RUNNER_ENGINE")) |v| c.engine = try engineMode(v);
        if (environ.get("RUNNER_ENGINE_CONTAINER")) |v| c.engine_container = v;
        if (environ.get("RUNNER_ENGINE_HOST")) |v| c.engine_host = v;
        if (environ.get("RUNNER_ENGINE_SILENCE_TIMEOUT")) |v|
            c.engine_silence_timeout_secs = try secs(v);
        if (environ.get("DOCKER_HOST")) |v| if (std.mem.startsWith(u8, v, "unix://")) {
            c.docker_socket = v["unix://".len..];
        };
        if (environ.get("RUNNER_DAGGER_NESTING")) |v| c.dagger_nesting = try boolean(v);
        if (environ.get("RUNNER_PACKAGE_CACHES")) |v| c.package_caches = try boolean(v);
        if (environ.get("RUNNER_TOOL_TREES")) |v| c.tool_trees = try boolean(v);
        if (environ.get("RUNNER_STEP_CACHE")) |v| c.step_cache = try boolean(v);
        if (environ.get("RUNNER_STEP_USER")) |v| c.step_user = try stepUser(v);
        if (environ.get("RUNNER_BACKEND")) |v| c.backend = try stepBackend(v);
        if (environ.get("RUNNER_NATIVE_ROOTFS")) |v| c.native_rootfs = v;
        if (environ.get("RUNNER_NATIVE_STORE")) |v| c.native_store = v;
        if (environ.get("RUNNER_NATIVE_ROOTLESS")) |v| c.native_rootless = try boolean(v);
        if (environ.get("RUNNER_NATIVE_SUBID_BASE")) |v| c.native_subid_base = try num(u32, v);
        if (environ.get("RUNNER_NATIVE_SUBNET")) |v| c.native_subnet = v;
        if (environ.get("RUNNER_NATIVE_STORE_MAX_MB")) |v| c.native_store_max_mb = try num(u64, v);
        if (environ.get("RUNNER_NATIVE_CGROUP")) |v| c.native_cgroup = v;
        if (environ.get("RUNNER_NATIVE_MEMORY_MAX_MB")) |v| c.native_memory_max_mb = try num(u32, v);
        if (environ.get("RUNNER_NATIVE_PIDS_MAX")) |v| c.native_pids_max = try num(u32, v);

        if (environ.get("RUNNER_OUTPUT_KEYS")) |v| c.output_keys = try boolean(v);
        if (environ.get("RUNNER_ENFORCE_VOLATILE")) |v| c.enforce_volatile = try boolean(v);
        if (environ.get("RUNNER_LOG_SPOOL_DIR")) |v| c.log_spool_dir = v;
        if (environ.get("RUNNER_UV_ENV_IN_CACHE")) |v| c.uv_env_in_cache = try boolean(v);
        if (environ.get("RUNNER_ZIG_LOCAL_CACHE")) |v| c.zig_local_cache = try boolean(v);
        if (environ.get("RUNNER_ZIG_LOCAL_CACHE_MAX_MB")) |v|
            c.zig_local_cache_max_mb = try num(u32, v);
        if (environ.get("RUNNER_ZIG_SEED")) |v| c.zig_seed = try zigSeed(v);
        if (environ.get("RUNNER_ZIG_SEED_VERSIONS")) |v| c.zig_seed_versions = v;
        if (environ.get("RUNNER_PREWARM")) |v| c.prewarm = try boolean(v);
        if (environ.get("RUNNER_OUTPUT_KEYS_MAX_MS")) |v| c.output_keys_max_ms = try millis(v);
        if (environ.get("RUNNER_OUTPUT_KEYS_DAYS")) |v| c.output_keys_days = try count(v);
        if (environ.get("RUNNER_ONCE")) |v| c.once = try boolean(v);
        if (environ.get("RUNNER_COUNT")) |v| c.runners = try count(v);
        if (environ.get("RUNNER_ADMISSION")) |v| c.admission = try boolean(v);
        const l = &c.admission_limits;
        if (environ.get("RUNNER_MIN_MEM_AVAILABLE_MB")) |v| l.min_available_mb = try num(u32, v);
        if (environ.get("RUNNER_MEM_PER_JOB_MB")) |v| l.per_job_mb = try num(u32, v);
        if (environ.get("RUNNER_MAX_MEM_PRESSURE")) |v| l.max_pressure = try percent(v);
        if (environ.get("RUNNER_MAX_SWAP_GROWTH_MB")) |v| l.max_swap_growth_mb = try num(u32, v);
        if (environ.get("RUNNER_MIN_ENGINE_HEADROOM_MB")) |v|
            l.min_engine_headroom_mb = try num(u32, v);
        if (environ.get("RUNNER_ENGINE_CGROUP")) |v| c.engine_cgroup = v;
        if (environ.get("RUNNER_STOP_GRACE_SECS")) |v| c.stop_grace_secs = try secs(v);
        if (environ.get("RUNNER_TRUSTED_REFS")) |v| c.trusted_refs = v;
        if (environ.get("RUNNER_TRUSTED_EVENTS")) |v| c.trusted_events = v;
    }

    /// The flags that take no value and choose what the process does. True when `arg` was one.
    fn modeFlag(c: *Config, arg: []const u8) bool {
        if (std.mem.eql(u8, arg, "--db-check")) c.db_check = true //
        else if (std.mem.eql(u8, arg, "--dry-run")) c.dry_run = true //
        else if (std.mem.eql(u8, arg, "--inspect")) c.inspect = true //
        else if (std.mem.eql(u8, arg, "--once")) c.once = true //
        else return false;
        return true;
    }

    /// One `--key value` flag (SPEC.md §2's flag list); flags override the environment.
    fn applyFlag(c: *Config, key: []const u8, val: []const u8, creds: *Credentials) Error!void {
        const eq = struct {
            fn f(a: []const u8, b: []const u8) bool {
                return std.mem.eql(u8, a, b);
            }
        }.f;
        const l = &c.admission_limits;
        if (eq(key, "token")) creds.token = val //
        else if (eq(key, "scope")) creds.scope = val //
        else if (eq(key, "exec-job")) c.exec_job = val //
        else if (eq(key, "labels")) c.labels = val //
        else if (eq(key, "group-id")) c.runner_group_id = try num(u64, val) //
        else if (eq(key, "name-prefix")) c.name_prefix = val //
        else if (eq(key, "database-url")) c.database_url = val //
        else if (eq(key, "dagger-cmd")) c.dagger_cmd = val //
        else if (eq(key, "image")) c.image = val //
        else if (eq(key, "log-flush-lines")) c.log_flush_lines = try num(u32, val) //
        else if (eq(key, "log-flush-ms")) c.log_flush_ms = try num(u32, val) //
        else if (eq(key, "js-runtime")) c.js_runtime = try jsRuntime(val) //
        else if (eq(key, "engine")) c.engine = try engineMode(val) //
        else if (eq(key, "engine-host")) c.engine_host = val //
        else if (eq(key, "engine-silence-timeout")) c.engine_silence_timeout_secs = try secs(val) //
        else if (eq(key, "dagger-nesting")) c.dagger_nesting = try boolean(val) //
        else if (eq(key, "package-caches")) c.package_caches = try boolean(val) //
        else if (eq(key, "tool-trees")) c.tool_trees = try boolean(val) //
        else if (eq(key, "step-cache")) c.step_cache = try boolean(val) //
        else if (eq(key, "step-user")) c.step_user = try stepUser(val) //
        else if (eq(key, "backend")) c.backend = try stepBackend(val) //
        else if (eq(key, "native-rootfs")) c.native_rootfs = val //
        else if (eq(key, "native-store")) c.native_store = val //
        else if (eq(key, "native-rootless")) c.native_rootless = try boolean(val) //
        else if (eq(key, "native-subid-base")) c.native_subid_base = try num(u32, val) //
        else if (eq(key, "native-subnet")) c.native_subnet = val //
        else if (eq(key, "native-store-max-mb")) c.native_store_max_mb = try num(u64, val) //
        else if (eq(key, "native-cgroup")) c.native_cgroup = val //
        else if (eq(key, "native-memory-max-mb")) c.native_memory_max_mb = try num(u32, val) //
        else if (eq(key, "native-pids-max")) c.native_pids_max = try num(u32, val) //

        else if (eq(key, "uv-env-in-cache")) c.uv_env_in_cache = try boolean(val) //
        else if (eq(key, "zig-local-cache")) c.zig_local_cache = try boolean(val) //
        else if (eq(key, "zig-local-cache-max-mb")) c.zig_local_cache_max_mb = try num(u32, val) //
        else if (eq(key, "zig-seed")) c.zig_seed = try zigSeed(val) //
        else if (eq(key, "zig-seed-versions")) c.zig_seed_versions = val //
        else if (eq(key, "prewarm")) c.prewarm = try boolean(val) //
        else if (eq(key, "output-keys-max-ms")) c.output_keys_max_ms = try millis(val) //
        else if (eq(key, "log-spool-dir")) c.log_spool_dir = val //
        else if (eq(key, "enforce-volatile")) c.enforce_volatile = try boolean(val) //
        else if (eq(key, "output-keys")) c.output_keys = try boolean(val) //
        else if (eq(key, "output-keys-days")) c.output_keys_days = try count(val) //
        else if (eq(key, "runners")) c.runners = try count(val) //
        else if (eq(key, "admission")) c.admission = try boolean(val) //
        else if (eq(key, "min-mem-available-mb")) l.min_available_mb = try num(u32, val) //
        else if (eq(key, "mem-per-job-mb")) l.per_job_mb = try num(u32, val) //
        else if (eq(key, "max-mem-pressure")) l.max_pressure = try percent(val) //
        else if (eq(key, "max-swap-growth-mb")) l.max_swap_growth_mb = try num(u32, val) //
        else if (eq(key, "min-engine-headroom-mb")) l.min_engine_headroom_mb = try num(u32, val) //
        else if (eq(key, "engine-cgroup")) c.engine_cgroup = val //
        else if (eq(key, "stop-grace-secs")) c.stop_grace_secs = try secs(val) //
        else if (eq(key, "trusted-refs")) c.trusted_refs = val //
        else if (eq(key, "trusted-events")) c.trusted_events = val //
        else return error.UnknownFlag;
    }

    /// Where logs and run state go: `DATABASE_URL` / `--database-url`, else the standard PG*
    /// variables. Null means the runner logs to stdout only (StdoutSink).
    pub fn pgConfig(
        c: *const Config,
        arena: std.mem.Allocator,
        environ: *const std.process.Environ.Map,
    ) pg.ParseError!?pg.Config {
        if (c.database_url) |u| return try pg.parseUrl(arena, u);
        return pg.fromEnv(environ);
    }

    /// Secrets that must never appear in output (SPEC §9).
    pub fn secrets(c: *const Config, buf: *[2][]const u8) []const []const u8 {
        buf[0] = c.gh_token;
        var n: usize = 1;
        if (c.database_url) |u| {
            buf[1] = u;
            n = 2;
        }
        return buf[0..n];
    }

    fn engineMode(s: []const u8) error{InvalidEngine}!EngineMode {
        return std.meta.stringToEnum(EngineMode, s) orelse error.InvalidEngine;
    }

    fn stepUser(s: []const u8) error{InvalidStepUser}!StepUser {
        return std.meta.stringToEnum(StepUser, s) orelse error.InvalidStepUser;
    }

    fn stepBackend(s: []const u8) error{InvalidBackend}!StepBackend {
        return std.meta.stringToEnum(StepBackend, s) orelse error.InvalidBackend;
    }

    /// Where the native backend keeps jobs' layers: `native_store`, else under /var/lib for root
    /// and the user's cache directory otherwise.
    pub fn nativeStore(
        c: *const Config,
        arena: std.mem.Allocator,
        environ: *const std.process.Environ.Map,
    ) ![]const u8 {
        if (c.native_store.len > 0) return c.native_store;
        if (std.os.linux.geteuid() == 0) return "/var/lib/zig-runner/native";
        if (environ.get("XDG_CACHE_HOME")) |d| if (d.len > 0)
            return std.fmt.allocPrint(arena, "{s}/zig-runner/native", .{d});
        const home = environ.get("HOME") orelse "/tmp";
        return std.fmt.allocPrint(arena, "{s}/.cache/zig-runner/native", .{home});
    }

    /// `<version>=<sha256>`, or empty for none. Both go into a URL and a shell script, so only a
    /// version's characters and 64 lowercase hex digits pass.
    fn zigSeed(s: []const u8) error{InvalidZigSeed}!?ZigSeed {
        if (s.len == 0) return null;
        const at = std.mem.indexOfScalar(u8, s, '=') orelse return error.InvalidZigSeed;
        const version = s[0..at];
        const sha256 = s[at + 1 ..];
        if (!validZigVersion(version) or sha256.len != 64) return error.InvalidZigSeed;
        for (sha256) |ch| {
            if (!std.ascii.isDigit(ch) and !(ch >= 'a' and ch <= 'f')) return error.InvalidZigSeed;
        }
        return .{ .version = version, .sha256 = sha256 };
    }

    fn jsRuntime(s: []const u8) error{InvalidJsRuntime}!JsRuntime {
        return std.meta.stringToEnum(JsRuntime, s) orelse error.InvalidJsRuntime;
    }

    fn num(comptime T: type, s: []const u8) error{InvalidNumber}!T {
        return std.fmt.parseInt(T, s, 10) catch error.InvalidNumber;
    }

    /// How jobs reach the engine, for `dagger.Options.engine`: null means a `dagger run` child.
    pub fn engineEndpoint(c: *const Config) ?engine.Endpoint {
        return switch (c.engine) {
            .direct => .{
                .host = c.engine_host,
                .docker_socket = c.docker_socket,
                .container = c.engine_container,
                .silence_timeout = if (c.engine_silence_timeout_secs == 0)
                    null
                else
                    .fromSeconds(c.engine_silence_timeout_secs),
            },
            .cli => null,
        };
    }

    const max_millis = std.time.ms_per_hour;
    const max_count = 1024;

    /// Milliseconds, up to an hour; 0 turns the limit off.
    fn millis(s: []const u8) error{InvalidNumber}!u32 {
        const n = try num(u32, s);
        if (n > max_millis) return error.InvalidNumber;
        return n;
    }

    /// Seconds, up to a day.
    fn secs(s: []const u8) error{InvalidNumber}!u32 {
        const n = try num(u32, s);
        if (n > std.time.s_per_day) return error.InvalidNumber;
        return n;
    }

    /// A count (of runners, of days): 1 to 1024.
    fn count(s: []const u8) error{InvalidNumber}!u32 {
        const n = try num(u32, s);
        if (n < 1 or n > max_count) return error.InvalidNumber;
        return n;
    }

    /// A percentage, 0 to 100; 0 turns the limit off.
    fn percent(s: []const u8) error{InvalidNumber}!u32 {
        const n = try num(u32, s);
        if (n > 100) return error.InvalidNumber;
        return n;
    }

    fn boolean(s: []const u8) error{InvalidBool}!bool {
        if (std.ascii.eqlIgnoreCase(s, "true") or std.mem.eql(u8, s, "1")) return true;
        if (std.ascii.eqlIgnoreCase(s, "false") or std.mem.eql(u8, s, "0")) return false;
        return error.InvalidBool;
    }
};

test "scope parsing" {
    const r = try Scope.parse("octo/repo");
    try std.testing.expectEqualStrings("octo", r.repo.owner);
    try std.testing.expectEqualStrings("repo", r.repo.name);
    try std.testing.expectEqualStrings("acme", (try Scope.parse("org:acme")).org);
    try std.testing.expectError(error.InvalidScope, Scope.parse("nope"));
    try std.testing.expectError(error.InvalidScope, Scope.parse("org:"));
    try std.testing.expectError(error.InvalidScope, Scope.parse("a/b/c"));
}

test "load: env then flag override" {
    var env: std.process.Environ.Map = .init(std.testing.allocator);
    defer env.deinit();
    try env.put("GH_TOKEN", "t");
    try env.put("GH_SCOPE", "o/r");
    try env.put("LOG_FLUSH_MS", "10");
    const args = [_][:0]const u8{ "runner", "--labels=a,b", "--log-flush-ms", "20", "--dry-run" };
    const c = try Config.load(&env, &args);
    try std.testing.expectEqualStrings("a,b", c.labels);
    try std.testing.expectEqual(@as(u32, 20), c.log_flush_ms);
    try std.testing.expect(c.dry_run);
}

test "load: missing token" {
    var env: std.process.Environ.Map = .init(std.testing.allocator);
    defer env.deinit();
    try env.put("GH_SCOPE", "o/r");
    try std.testing.expectError(error.MissingGhToken, Config.load(&env, &.{"runner"}));
}

test "RUNNER_ENGINE, RUNNER_ENGINE_CONTAINER and DOCKER_HOST" {
    var env: std.process.Environ.Map = .init(std.testing.allocator);
    defer env.deinit();
    try env.put("GH_TOKEN", "t");
    try env.put("GH_SCOPE", "o/r");
    const d = try Config.load(&env, &.{"runner"});
    try std.testing.expectEqual(EngineMode.direct, d.engine);
    try std.testing.expectEqualStrings("/var/run/docker.sock", d.docker_socket);
    try env.put("DOCKER_HOST", "unix:///run/user/1000/docker.sock");
    try env.put("RUNNER_ENGINE_CONTAINER", "dagger-engine-custom");
    const c = try Config.load(&env, &.{ "runner", "--engine=cli" });
    try std.testing.expectEqual(EngineMode.cli, c.engine);
    try std.testing.expectEqualStrings("/run/user/1000/docker.sock", c.docker_socket);
    try std.testing.expectEqualStrings("dagger-engine-custom", c.engine_container);
    try std.testing.expectError(error.InvalidEngine, Config.load(&env, &.{ "runner", "--engine=go" }));
    try env.put("RUNNER_ENGINE_HOST", "tcp://dagger-engine:1234");
    try std.testing.expectEqualStrings("tcp://dagger-engine:1234", (try Config.load(&env, &.{"runner"})).engineEndpoint().?.host);
}

test "--runners and RUNNER_COUNT" {
    var env: std.process.Environ.Map = .init(std.testing.allocator);
    defer env.deinit();
    try env.put("GH_TOKEN", "t");
    try env.put("GH_SCOPE", "o/r");
    try std.testing.expectEqual(@as(u32, 1), (try Config.load(&env, &.{"runner"})).runners);
    try env.put("RUNNER_COUNT", "8");
    try std.testing.expectEqual(@as(u32, 8), (try Config.load(&env, &.{"runner"})).runners);
    try std.testing.expectEqual(@as(u32, 20), (try Config.load(&env, &.{ "runner", "--runners=20" })).runners);
    try std.testing.expectError(error.InvalidNumber, Config.load(&env, &.{ "runner", "--runners", "0" }));
    try std.testing.expect((try Config.load(&env, &.{ "runner", "--once" })).once);
}

test "--db-check needs no GitHub credentials" {
    var env: std.process.Environ.Map = .init(std.testing.allocator);
    defer env.deinit();
    const c = try Config.load(&env, &.{ "runner", "--db-check" });
    try std.testing.expect(c.db_check);
}

test "JavaScript actions run on Bun unless Node is asked for" {
    var env: std.process.Environ.Map = .init(std.testing.allocator);
    defer env.deinit();
    try env.put("GH_TOKEN", "t");
    try env.put("GH_SCOPE", "o/r");
    try std.testing.expectEqual(JsRuntime.bun, (try Config.load(&env, &.{"runner"})).js_runtime);
    try env.put("RUNNER_JS_RUNTIME", "node");
    try std.testing.expectEqual(JsRuntime.node, (try Config.load(&env, &.{"runner"})).js_runtime);
    try std.testing.expectEqual(JsRuntime.bun, (try Config.load(&env, &.{ "runner", "--js-runtime=bun" })).js_runtime);
    try env.put("RUNNER_JS_RUNTIME", "deno");
    try std.testing.expectError(error.InvalidJsRuntime, Config.load(&env, &.{"runner"}));
}

test "the output-keys limit: milliseconds, and 0 turns it off" {
    var env: std.process.Environ.Map = .init(std.testing.allocator);
    defer env.deinit();
    try env.put("GH_TOKEN", "t");
    try env.put("GH_SCOPE", "o/r");
    try std.testing.expect((try Config.load(&env, &.{"runner"})).enforce_volatile);
    try env.put("RUNNER_ENFORCE_VOLATILE", "false");
    try std.testing.expect(!(try Config.load(&env, &.{"runner"})).enforce_volatile);
    try std.testing.expect((try Config.load(&env, &.{ "runner", "--enforce-volatile=true" })).enforce_volatile);
    try std.testing.expectEqual(@as(u32, 10_000), (try Config.load(&env, &.{"runner"})).output_keys_max_ms);
    try env.put("RUNNER_OUTPUT_KEYS_MAX_MS", "0");
    try std.testing.expectEqual(@as(u32, 0), (try Config.load(&env, &.{"runner"})).output_keys_max_ms);
    try env.put("RUNNER_OUTPUT_KEYS_MAX_MS", "4000000"); // over an hour
    try std.testing.expectError(error.InvalidNumber, Config.load(&env, &.{"runner"}));
    // The variable is read before the flags, so a bad one fails whatever the flags say; with a good
    // one, the flag wins.
    try env.put("RUNNER_OUTPUT_KEYS_MAX_MS", "9000");
    try std.testing.expectEqual(@as(u32, 2500), (try Config.load(&env, &.{ "runner", "--output-keys-max-ms=2500" })).output_keys_max_ms);
}

test "the stop grace: ten minutes by default, in seconds, 0 for none, at most a day" {
    var env: std.process.Environ.Map = .init(std.testing.allocator);
    defer env.deinit();
    try env.put("GH_TOKEN", "t");
    try env.put("GH_SCOPE", "o/r");
    try std.testing.expectEqual(@as(u32, 600), (try Config.load(&env, &.{"runner"})).stop_grace_secs);
    try env.put("RUNNER_STOP_GRACE_SECS", "0");
    try std.testing.expectEqual(@as(u32, 0), (try Config.load(&env, &.{"runner"})).stop_grace_secs);
    try std.testing.expectEqual(@as(u32, 90), (try Config.load(&env, &.{ "runner", "--stop-grace-secs=90" })).stop_grace_secs);
    try env.put("RUNNER_STOP_GRACE_SECS", "86401");
    try std.testing.expectError(error.InvalidNumber, Config.load(&env, &.{"runner"}));
}

test "the engine silence timeout: ten minutes by default, in seconds, 0 turns it off" {
    var env: std.process.Environ.Map = .init(std.testing.allocator);
    defer env.deinit();
    try env.put("GH_TOKEN", "t");
    try env.put("GH_SCOPE", "o/r");
    var c = try Config.load(&env, &.{"runner"});
    try std.testing.expectEqual(@as(u32, 600), c.engine_silence_timeout_secs);
    const limit = c.engineEndpoint().?.silence_timeout.?;
    try std.testing.expectEqual(@as(i64, 600_000), limit.toMilliseconds());
    try env.put("RUNNER_ENGINE_SILENCE_TIMEOUT", "0");
    c = try Config.load(&env, &.{"runner"});
    try std.testing.expect(c.engineEndpoint().?.silence_timeout == null);
    c = try Config.load(&env, &.{ "runner", "--engine-silence-timeout=1200" });
    try std.testing.expectEqual(@as(u32, 1200), c.engine_silence_timeout_secs);
    try env.put("RUNNER_ENGINE_SILENCE_TIMEOUT", "86401");
    try std.testing.expectError(error.InvalidNumber, Config.load(&env, &.{"runner"}));
}

test "dagger nesting is off by default and can be turned on" {
    var env: std.process.Environ.Map = .init(std.testing.allocator);
    defer env.deinit();
    try env.put("GH_TOKEN", "t");
    try env.put("GH_SCOPE", "o/r");
    try std.testing.expect(!(try Config.load(&env, &.{"runner"})).dagger_nesting);
    try env.put("RUNNER_DAGGER_NESTING", "true");
    try std.testing.expect((try Config.load(&env, &.{"runner"})).dagger_nesting);
    try std.testing.expect(!(try Config.load(&env, &.{ "runner", "--dagger-nesting=false" })).dagger_nesting);
    try env.put("RUNNER_DAGGER_NESTING", "maybe");
    try std.testing.expectError(error.InvalidBool, Config.load(&env, &.{"runner"}));
}

test "the native jobs' cgroups and limits: defaults, settings, and parents that are refused" {
    var env: std.process.Environ.Map = .init(std.testing.allocator);
    defer env.deinit();
    try env.put("GH_TOKEN", "t");
    try env.put("GH_SCOPE", "o/r");
    const c = try Config.load(&env, &.{"runner"});
    try std.testing.expectEqualStrings("", c.native_cgroup);
    try std.testing.expectEqual(@as(?u32, null), c.native_memory_max_mb);
    try std.testing.expectEqual(native_cgroup.default_pids_max, c.native_pids_max);
    try env.put("RUNNER_NATIVE_CGROUP", "self");
    try env.put("RUNNER_NATIVE_MEMORY_MAX_MB", "0");
    try env.put("RUNNER_NATIVE_PIDS_MAX", "512");
    const set = try Config.load(&env, &.{"runner"});
    try std.testing.expectEqualStrings("self", set.native_cgroup);
    try std.testing.expectEqual(@as(?u32, 0), set.native_memory_max_mb);
    try std.testing.expectEqual(@as(u32, 512), set.native_pids_max);
    try std.testing.expectEqualStrings("/sys/fs/cgroup/zr.slice", (try Config.load(&env, &.{
        "runner",
        "--native-cgroup=/sys/fs/cgroup/zr.slice",
    })).native_cgroup);
    for ([_][]const u8{ "/tmp/x", "/sys/fs/cgroup/../x", "/sys/fs/cgroup", "selfish" }) |bad| {
        try env.put("RUNNER_NATIVE_CGROUP", bad);
        try std.testing.expectError(error.InvalidNativeCgroup, Config.load(&env, &.{"runner"}));
    }
}

test "the native subnet and ids: defaults, and values that are refused" {
    var env: std.process.Environ.Map = .init(std.testing.allocator);
    defer env.deinit();
    try env.put("GH_TOKEN", "t");
    try env.put("GH_SCOPE", "o/r");
    const c = try Config.load(&env, &.{"runner"});
    try std.testing.expectEqualStrings("10.211.0.0/16", c.native_subnet);
    try std.testing.expectEqual(NativeBackend.default_subid_base, c.native_subid_base);
    try env.put("RUNNER_NATIVE_SUBNET", "10.88.0.0/24");
    try std.testing.expectError(error.InvalidNativeSubnet, Config.load(&env, &.{"runner"}));
    try std.testing.expectEqualStrings("172.30.0.0/20", (try Config.load(&env, &.{
        "runner",
        "--native-subnet=172.30.0.0/20",
    })).native_subnet);
    _ = env.swapRemove("RUNNER_NATIVE_SUBNET");
    try env.put("RUNNER_NATIVE_SUBID_BASE", "99999");
    try std.testing.expectError(error.InvalidNativeSubidBase, Config.load(&env, &.{"runner"}));
    try env.put("RUNNER_NATIVE_SUBID_BASE", "100000");
    try std.testing.expectEqual(@as(u32, 100000), (try Config.load(&env, &.{"runner"})).native_subid_base);
}

test "the pre-warm is on by default and can be turned off" {
    var env: std.process.Environ.Map = .init(std.testing.allocator);
    defer env.deinit();
    try env.put("GH_TOKEN", "t");
    try env.put("GH_SCOPE", "o/r");
    try std.testing.expect((try Config.load(&env, &.{"runner"})).prewarm);
    try std.testing.expect(!(try Config.load(&env, &.{ "runner", "--prewarm=false" })).prewarm);
    try env.put("RUNNER_PREWARM", "false");
    try std.testing.expect(!(try Config.load(&env, &.{"runner"})).prewarm);
    try env.put("RUNNER_PREWARM", "maybe");
    try std.testing.expectError(error.InvalidBool, Config.load(&env, &.{"runner"}));
}

test "package caches are on by default and can be turned off" {
    var env: std.process.Environ.Map = .init(std.testing.allocator);
    defer env.deinit();
    try env.put("GH_TOKEN", "t");
    try env.put("GH_SCOPE", "o/r");
    try std.testing.expect((try Config.load(&env, &.{"runner"})).package_caches);
    try std.testing.expect(!(try Config.load(&env, &.{ "runner", "--package-caches=false" })).package_caches);
    try env.put("RUNNER_PACKAGE_CACHES", "0");
    try std.testing.expect(!(try Config.load(&env, &.{"runner"})).package_caches);
}

test "Zig seeding is on by default, for the runner's own Zig; RUNNER_ZIG_SEED_VERSIONS picks others or none" {
    var env: std.process.Environ.Map = .init(std.testing.allocator);
    defer env.deinit();
    try env.put("GH_TOKEN", "t");
    try env.put("GH_SCOPE", "o/r");
    try std.testing.expectEqualStrings(builtin.zig_version_string, (try Config.load(&env, &.{"runner"})).zig_seed_versions);
    try env.put("RUNNER_ZIG_SEED_VERSIONS", "0.17.0,0.16.0");
    try std.testing.expectEqualStrings("0.17.0,0.16.0", (try Config.load(&env, &.{"runner"})).zig_seed_versions);
    try std.testing.expectEqualStrings("", (try Config.load(&env, &.{ "runner", "--zig-seed-versions=" })).zig_seed_versions);
}

test "RUNNER_ZIG_SEED, the explicit override, names a version and a sha256" {
    var env: std.process.Environ.Map = .init(std.testing.allocator);
    defer env.deinit();
    try env.put("GH_TOKEN", "t");
    try env.put("GH_SCOPE", "o/r");
    try std.testing.expect((try Config.load(&env, &.{"runner"})).zig_seed == null);
    const sum = "1cbe9df9f27e6b78d14ccbca43b6703a404ef79ef1c463de901d7f088d4e2026";
    try env.put("RUNNER_ZIG_SEED", "0.17.0=" ++ sum);
    const seed = (try Config.load(&env, &.{"runner"})).zig_seed.?;
    try std.testing.expectEqualStrings("0.17.0", seed.version);
    try std.testing.expectEqualStrings(sum, seed.sha256);
    try std.testing.expect((try Config.load(&env, &.{ "runner", "--zig-seed=" })).zig_seed == null);
    // Both end up in a shell script and a URL: nothing but a version and hex gets through.
    for ([_][]const u8{
        "0.17.0",
        "=" ++ sum,
        "0.17.0=" ++ sum[1..],
        "0.17.0=" ++ sum[1..] ++ "G",
        "0.17.0;rm=" ++ sum,
        "0.17.0 =" ++ sum,
    }) |bad| {
        try env.put("RUNNER_ZIG_SEED", bad);
        try std.testing.expectError(error.InvalidZigSeed, Config.load(&env, &.{"runner"}));
    }
}

test "Zig's local cache is kept only when asked for, and uv's setting is read" {
    var env: std.process.Environ.Map = .init(std.testing.allocator);
    defer env.deinit();
    try env.put("GH_TOKEN", "t");
    try env.put("GH_SCOPE", "o/r");
    try std.testing.expect(!(try Config.load(&env, &.{"runner"})).zig_local_cache);
    try std.testing.expect((try Config.load(&env, &.{ "runner", "--zig-local-cache=true" })).zig_local_cache);
    try env.put("RUNNER_ZIG_LOCAL_CACHE", "1");
    try std.testing.expect((try Config.load(&env, &.{"runner"})).zig_local_cache);
    try std.testing.expectEqual(@as(u32, 4096), (try Config.load(&env, &.{"runner"})).zig_local_cache_max_mb);
    try env.put("RUNNER_ZIG_LOCAL_CACHE_MAX_MB", "0");
    try std.testing.expectEqual(@as(u32, 0), (try Config.load(&env, &.{"runner"})).zig_local_cache_max_mb);
    try env.put("RUNNER_UV_ENV_IN_CACHE", "false");
    try std.testing.expect(!(try Config.load(&env, &.{"runner"})).uv_env_in_cache);
}

test "the tool cache's trees are checked in Set up job unless turned off" {
    var env: std.process.Environ.Map = .init(std.testing.allocator);
    defer env.deinit();
    try env.put("GH_TOKEN", "t");
    try env.put("GH_SCOPE", "o/r");
    try std.testing.expect((try Config.load(&env, &.{"runner"})).tool_trees);
    try std.testing.expect(!(try Config.load(&env, &.{ "runner", "--tool-trees=false" })).tool_trees);
    try env.put("RUNNER_TOOL_TREES", "0");
    try std.testing.expect(!(try Config.load(&env, &.{"runner"})).tool_trees);
}

test "step caching is on by default and can be turned off" {
    var env: std.process.Environ.Map = .init(std.testing.allocator);
    defer env.deinit();
    try env.put("GH_TOKEN", "t");
    try env.put("GH_SCOPE", "o/r");
    try std.testing.expect((try Config.load(&env, &.{"runner"})).step_cache);
    try std.testing.expect(!(try Config.load(&env, &.{ "runner", "--step-cache=false" })).step_cache);
    try env.put("RUNNER_STEP_CACHE", "false");
    try std.testing.expect(!(try Config.load(&env, &.{"runner"})).step_cache);
}

test "RUNNER_TRUSTED_REFS and RUNNER_TRUSTED_EVENTS" {
    var env: std.process.Environ.Map = .init(std.testing.allocator);
    defer env.deinit();
    try env.put("GH_TOKEN", "t");
    try env.put("GH_SCOPE", "o/r");
    const unset = try Config.load(&env, &.{"runner"});
    try std.testing.expectEqualStrings("", unset.trusted_refs);
    try std.testing.expectEqualStrings("push,workflow_dispatch", unset.trusted_events);
    try env.put("RUNNER_TRUSTED_REFS", "refs/heads/main,refs/tags/v*");
    try env.put("RUNNER_TRUSTED_EVENTS", "push");
    const set = try Config.load(&env, &.{"runner"});
    try std.testing.expectEqualStrings("refs/heads/main,refs/tags/v*", set.trusted_refs);
    try std.testing.expectEqualStrings("push", set.trusted_events);
    const flag = try Config.load(&env, &.{ "runner", "--trusted-refs", "refs/heads/main" });
    try std.testing.expectEqualStrings("refs/heads/main", flag.trusted_refs);
    // Empty is kept as empty, which trusts no ref (`trust.refusal`); `*` is every ref.
    try env.put("RUNNER_TRUSTED_REFS", "");
    try env.put("RUNNER_TRUSTED_EVENTS", "");
    const empty = try Config.load(&env, &.{"runner"});
    try std.testing.expectEqualStrings("", empty.trusted_refs);
    try std.testing.expectEqualStrings("", empty.trusted_events);
    try env.put("RUNNER_TRUSTED_REFS", "*");
    try env.put("RUNNER_TRUSTED_EVENTS", "*");
    const all = try Config.load(&env, &.{"runner"});
    try std.testing.expectEqualStrings("*", all.trusted_refs);
    try std.testing.expectEqualStrings("*", all.trusted_events);
}

test "a prod runner with no trusted refs refuses to start; with * or a list it starts" {
    var env: std.process.Environ.Map = .init(std.testing.allocator);
    defer env.deinit();
    try env.put("GH_TOKEN", "t");
    try env.put("GH_SCOPE", "o/r");
    try env.put("RUNNER_LABELS", "self-hosted,linux,zig,prod");
    const refused = error.ProdTrustsNoRef;
    try std.testing.expectError(refused, Config.load(&env, &.{"runner"}));
    try std.testing.expect(Config.explain(refused) != null);
    try env.put("RUNNER_TRUSTED_REFS", " , ");
    try std.testing.expectError(refused, Config.load(&env, &.{"runner"}));
    // A flag can leave it empty too.
    const flag = [_][:0]const u8{ "runner", "--trusted-refs=" };
    try env.put("RUNNER_TRUSTED_REFS", "refs/heads/main");
    try std.testing.expectError(refused, Config.load(&env, &flag));
    _ = try Config.load(&env, &.{"runner"});
    try env.put("RUNNER_TRUSTED_REFS", "*");
    _ = try Config.load(&env, &.{"runner"});
    // Not prod: no refs is allowed (every job fails, and the log says why).
    try env.put("RUNNER_TRUSTED_REFS", "");
    try env.put("RUNNER_LABELS", "self-hosted,linux,zig,pre-prod");
    _ = try Config.load(&env, &.{"runner"});
}

test "the memory gate is on by default, with limits from the environment or flags" {
    var env: std.process.Environ.Map = .init(std.testing.allocator);
    defer env.deinit();
    try env.put("GH_TOKEN", "t");
    try env.put("GH_SCOPE", "o/r");
    const d = try Config.load(&env, &.{"runner"});
    try std.testing.expect(d.admission);
    try std.testing.expectEqual(admission.Limits{}, d.admission_limits);
    try env.put("RUNNER_MIN_MEM_AVAILABLE_MB", "2048");
    try env.put("RUNNER_MEM_PER_JOB_MB", "0");
    try env.put("RUNNER_MAX_MEM_PRESSURE", "20");
    try env.put("RUNNER_MAX_SWAP_GROWTH_MB", "128");
    try env.put("RUNNER_MIN_ENGINE_HEADROOM_MB", "512");
    const scope = "/sys/fs/cgroup/system.slice/docker-e.scope";
    try env.put("RUNNER_ENGINE_CGROUP", scope);
    const set = try Config.load(&env, &.{ "runner", "--max-mem-pressure=5" });
    try std.testing.expectEqual(admission.Limits{
        .min_available_mb = 2048,
        .per_job_mb = 0,
        .max_pressure = 5,
        .max_swap_growth_mb = 128,
        .min_engine_headroom_mb = 512,
    }, set.admission_limits);
    try std.testing.expectEqualStrings(scope, set.engine_cgroup);
    const flags = try Config.load(&env, &.{
        "runner", "--engine-cgroup=none", "--min-engine-headroom-mb=0",
    });
    try std.testing.expectEqualStrings("none", flags.engine_cgroup);
    try std.testing.expectEqual(@as(u32, 0), flags.admission_limits.min_engine_headroom_mb);
    try std.testing.expectError(error.InvalidNumber, Config.load(&env, &.{ "runner", "--max-mem-pressure=101" }));
    try env.put("RUNNER_ADMISSION", "false");
    try std.testing.expect(!(try Config.load(&env, &.{"runner"})).admission);
    try std.testing.expect((try Config.load(&env, &.{ "runner", "--admission=true" })).admission);
}

test "load: GH_TOKEN or a GitHub App, not both and not neither" {
    var env: std.process.Environ.Map = .init(std.testing.allocator);
    defer env.deinit();
    try env.put("GH_SCOPE", "o/r");
    try env.put("GH_TOKEN", "");
    try std.testing.expectError(error.MissingGhToken, Config.load(&env, &.{"runner"}));

    try env.put("GH_APP_ID", "5561426");
    try std.testing.expectError(error.MissingGhAppKey, Config.load(&env, &.{"runner"}));
    try env.put("GH_APP_PRIVATE_KEY_FILE", "/run/secrets/app.pem");
    const c = try Config.load(&env, &.{"runner"});
    try std.testing.expectEqualStrings("5561426", c.gh_app.?.id);
    try std.testing.expectEqualStrings("/run/secrets/app.pem", c.gh_app.?.key.file);
    try std.testing.expectEqual(@as(?u64, null), c.gh_app.?.installation_id);
    try std.testing.expectEqualStrings("", c.gh_token);

    try env.put("GH_TOKEN", "t");
    try std.testing.expectError(error.GhTokenAndApp, Config.load(&env, &.{"runner"}));
    try env.put("GH_TOKEN", "");
    const flag = [_][:0]const u8{ "runner", "--token=t" };
    try std.testing.expectError(error.GhTokenAndApp, Config.load(&env, &flag));

    try env.put("GH_APP_PRIVATE_KEY", "-----BEGIN ...");
    try std.testing.expectError(error.GhAppKeyTwice, Config.load(&env, &.{"runner"}));
    try env.put("GH_APP_PRIVATE_KEY_FILE", "");
    try env.put("GH_APP_ID", "Iv23liJ9gsvCyFqhKLrM");
    try env.put("GH_APP_INSTALLATION_ID", "99");
    const d = try Config.load(&env, &.{"runner"});
    try std.testing.expectEqualStrings("Iv23liJ9gsvCyFqhKLrM", d.gh_app.?.id);
    try std.testing.expectEqualStrings("-----BEGIN ...", d.gh_app.?.key.pem);
    try std.testing.expectEqual(@as(?u64, 99), d.gh_app.?.installation_id);

    try env.put("GH_APP_ID", "1\",\"x");
    try std.testing.expectError(error.InvalidGhAppId, Config.load(&env, &.{"runner"}));
    try env.put("GH_APP_ID", "");
    try std.testing.expectError(error.MissingGhAppId, Config.load(&env, &.{"runner"}));
}
