//! "Set up job": the base container the job's steps start from (the image, provisioning of the
//! default image, the workspace, package cache volumes and the job's env), built in one query
//! with the job's actions loaded, and the `Exec` the steps run with.

const std = @import("std");
const builtin = @import("builtin");
const job_mod = @import("../job.zig");
const sink = @import("../sink.zig");
const expr = @import("../expr.zig");
const config = @import("../config.zig");
const zig_release = @import("../zig_release.zig");
const Query = @import("query.zig").Query;
const JobLog = @import("JobLog.zig");
const Evaluator = @import("Evaluator.zig");
const Exec = @import("Exec.zig");
const Transport = @import("../dagger.zig").Transport;
const SecretRef = @import("../dagger.zig").SecretRef;
const Secrets = @import("../dagger.zig").Secrets;
const Options = @import("../dagger.zig").Options;
const provisioned = @import("provisioned.zig");
const Outcome = @import("../dagger.zig").Outcome;
const StepResult = @import("../dagger.zig").StepResult;
const Result = @import("../dagger.zig").Result;
const run = @import("../dagger.zig").run;
const gql = @import("../dagger.zig").gql;
const jsonFind = @import("../dagger.zig").jsonFind;
const jsonFindString = @import("../dagger.zig").jsonFindString;
const splitEnv = @import("../dagger.zig").splitEnv;
const containsSecret = @import("../dagger.zig").containsSecret;
const envVarNode = @import("../dagger.zig").envVarNode;
const isVolatile = @import("../dagger.zig").isVolatile;
const logSteps = @import("../dagger.zig").logSteps;
const finish = @import("../dagger.zig").finish;
const default_image = @import("../dagger.zig").default_image;
const resolveImage = @import("../dagger.zig").resolveImage;
const imageName = @import("../dagger.zig").imageName;
const jobWorkspace = @import("../dagger.zig").jobWorkspace;
const work_root = @import("../dagger.zig").work_root;
const runner_user = @import("../dagger.zig").runner_user;
const runner_home = @import("../dagger.zig").runner_home;
const docker_home = @import("../dagger.zig").docker_home;
const event_path = @import("../dagger.zig").event_path;
const event_env = @import("../dagger.zig").event_env;
const ran_env = @import("../dagger.zig").ran_env;
const mark_env = @import("../dagger.zig").mark_env;
const registryCredentials = @import("docker.zig").registryCredentials;
const registryAuth = @import("docker.zig").registryAuth;
const outputKeysKey = @import("output_keys.zig").outputKeysKey;
const FakeSession = @import("testing.zig").FakeSession;
const fake_child = @import("testing.zig").fake_child;
const base_answer = @import("testing.zig").base_answer;
const exec = @import("testing.zig").exec;
const testStep = @import("testing.zig").testStep;
const testJob = @import("testing.zig").testJob;
const usesStep = @import("testing.zig").usesStep;
const braceBalanced = @import("testing.zig").braceBalanced;

const Allocator = std.mem.Allocator;

/// What the default image (`ubuntu:24.04`, pinned by digest) gets before a job: what workflows written for GitHub's
/// `ubuntu-latest` most often assume without a setup action. `sudo` (steps run as `runner_user`, as
/// on GitHub, and many call `sudo apt-get`), compilers and `make`, Python with pip and venv (and
/// `python`), `psql` for a Postgres service, archive and transfer tools, and what composite actions
/// often use (`jq`, `curl`). Installed once per engine: Dagger caches this exec, and the pre-warm
/// (`warm`) builds it before the first job.
///
/// The packages are not pinned: they come from the archive on the day the engine builds this exec,
/// so the seed is "image-pinned, packages from the archive on build date". Pinning `pkg=version`
/// breaks provisioning within weeks, as noble-updates and noble-security list only their latest
/// versions; snapshot.ubuntu.com serves amd64 only (not ubuntu-ports, which arm64 installs from).
/// The pre-warm logs a fingerprint of what got installed (`package_fingerprint_script`), so a
/// seed is identifiable.
pub const provision_packages = [_][]const u8{
    "git",            "git-lfs",     "ca-certificates", "curl",              "wget",
    "xz-utils",       "bzip2",       "zstd",            "zip",               "unzip",
    "jq",             "sudo",        "gnupg",           "openssh-client",    "rsync",
    "file",           "lsb-release", "tzdata",          "build-essential",   "pkg-config",
    "python3",        "python3-pip", "python3-venv",    "python-is-python3", "postgresql-client",
    "netcat-openbsd", "procps",
};

pub const provision_script = "apt-get update -qq && DEBIAN_FRONTEND=noninteractive " ++
    "apt-get install -y -qq --no-install-recommends " ++ packageList() ++
    " >/dev/null && rm -rf /var/lib/apt/lists/*";

/// Every installed package and version, hashed: the pre-warm's line names the provisioned seed by it.
const package_fingerprint_script =
    "dpkg-query -W -f '${Package}=${Version}\\n' | sha256sum | cut -c1-12";

const chown_runner = " && chown -R " ++ runner_user ++ ":" ++ runner_user ++ " " ++ work_root;

pub const provision_runner_script = provision_script ++
    " && (id -u " ++ runner_user ++ " >/dev/null 2>&1 || " ++
    "useradd -m -u 1001 -s /bin/bash " ++ runner_user ++ ")" ++
    " && printf '%s\\n' '" ++ runner_user ++ " ALL=(ALL) NOPASSWD:ALL' > " ++
    "/etc/sudoers.d/" ++ runner_user ++ " && chmod 0440 /etc/sudoers.d/" ++ runner_user ++
    " && mkdir -p " ++ work_root ++ " " ++ docker_home ++ runnerCacheDirs() ++
    " && chown -R " ++ runner_user ++ ":" ++ runner_user ++ " /github " ++ runner_home;

/// The package caches' directories under the user's home, made in advance: Dagger creates a cache
/// mount's missing parents as root (`/home/runner/go` for `/home/runner/go/pkg/mod`), and then the
/// user could not create anything next to the mount (setup-go's `~/go/bin`).
fn runnerCacheDirs() []const u8 {
    comptime {
        var out: []const u8 = "";
        for (package_cache_dirs) |d| {
            if (std.mem.startsWith(u8, d.path, "/root/"))
                out = out ++ " " ++ runner_home ++ d.path["/root".len..];
        }
        return out ++ " " ++ runner_home ++ "/.cache/yarn";
    }
}

/// Where package cache `i` is mounted for steps that run as `runner_user`: its directory under the
/// user's home instead of root's.
pub fn runnerCachePath(arena: Allocator, i: usize) ![]const u8 {
    const p = package_cache_dirs[i].path;
    if (std.mem.startsWith(u8, p, "/root/"))
        return std.mem.concat(arena, u8, &.{ runner_home, p["/root".len..] });
    // Yarn's cache is under /usr/local/share for root, in the home directory for anyone else.
    if (std.mem.eql(u8, package_cache_dirs[i].name, "yarn")) return runner_home ++ "/.cache/yarn";
    return p;
}

/// Where Zig's local cache (`.zig-cache`) is mounted with `zig_local_cache`, instead of the workspace,
/// which goes with the job. The volume is per repository (and apart for forks' pull requests), and
/// Zig locks its cache entries, so jobs running at once share it safely.
pub fn zigLocalCacheDir(as_runner: bool) []const u8 {
    return if (as_runner) runner_home ++ "/.cache/zig-local" else "/root/.cache/zig-local";
}

/// ZIG_LOCAL_CACHE_DIR with `zig_local_cache`: the volume's root, or with a limit
/// (`zig_local_cache_max_mb`) the `current` link into its live generation (`rollZigLocal`). One
/// value for every job either way, so it never changes a step's cache key.
pub fn zigLocalCacheEnv(as_runner: bool, max_mb: u32) []const u8 {
    if (max_mb == 0) return zigLocalCacheDir(as_runner);
    return if (as_runner)
        runner_home ++ "/.cache/zig-local/current"
    else
        "/root/.cache/zig-local/current";
}

/// Keeps Zig's local cache under a limit without ever removing part of one (an `h/` manifest
/// whose `o/` outputs are gone breaks a Zig cache for good): the cache lives in `gen-<N>` and
/// `current` links to it. Past the limit the next job starts `gen-<N+1>` and moves the link
/// (`mv -T`, a rename: atomic). A Zig process resolves the link once, when it opens the cache, so
/// one that is running keeps its generation; a `mkdir` of the new one decides between two jobs
/// rolling at once. A generation goes once its successor has been current for 6 hours, GitHub's
/// default job timeout: nothing started since then can still be using it. The volume's root from
/// before generations is removed (the runner's restart into this version ended the jobs that used
/// it); a `current` that Zig made as a directory after a failed roll becomes the newest generation
/// in place, and a running job keeps its open directory through the rename.
/// Arguments: $1 the volume, $2 the limit in KB, $3 the owner (or empty), $4 a nonce for the
/// temporary link (concurrent jobs' containers have the same PIDs).
pub const zig_local_roll_script =
    \\owner=$3 nonce=$4
    \\cd "$1" || exit 0
    \\own() { [ -z "$owner" ] || chown -h "$owner" "$@"; }
    \\gens() { ls -d gen-* 2>/dev/null | sed -n 's/^gen-\([0-9][0-9]*\)$/\1/p' | sort -n; }
    \\point() {
    \\  touch "gen-$1/.zig-runner-since" && ln -s "gen-$1" ".current-$nonce" &&
    \\    own "gen-$1" "gen-$1/.zig-runner-since" ".current-$nonce" &&
    \\    mv -T ".current-$nonce" current
    \\}
    \\if [ -L current ]; then
    \\  n=$(readlink current); n=${n#gen-}
    \\else
    \\  m=$(gens | tail -n 1); n=$((${m:--1} + 1))
    \\  if [ -d current ]; then mv -T current "gen-$n"; else mkdir "gen-$n"; fi
    \\  point "$n" || exit 0
    \\  rm -rf c h o tmp z
    \\fi
    \\case $n in '' | *[!0-9]*) exit 0 ;; esac
    \\if [ "$(du -sk "gen-$n" | cut -f1)" -gt "$2" ] && mkdir "gen-$((n + 1))"; then
    \\  point "$((n + 1))" && n=$((n + 1))
    \\fi
    \\p=
    \\for k in $(gens); do
    \\  [ "$k" -le "$n" ] || break
    \\  [ -n "$p" ] && [ -n "$(find "gen-$k/.zig-runner-since" -mmin +360)" ] && rm -rf "gen-$p"
    \\  p=$k
    \\done
;

/// Runs `zig_local_roll_script` on the job's Zig local-cache volume, in a container of its own
/// before the job's base container: the base container's nodes, and so every step's key, stay
/// what they were. A per-job variable keeps the engine from caching the exec. Nothing of it can
/// fail the job: a cache that did not roll is only bigger. The volume is mounted exactly as the
/// steps mount it (`writeZigLocalMount`): the engine gives a cache volume mounted with another
/// owner a store of its own. The step user's owner needs the provisioned image, which has the user
/// (and which the engine has cached for the base container anyway).
fn rollZigLocal(
    arena: Allocator,
    transport: Transport,
    volume: []const u8,
    max_mb: u32,
    as_runner: bool,
    pulled: ?[]const u8,
    nonce: []const u8,
) !void {
    var q: Query = .init(arena);
    try q.open("container");
    try q.call("from", .{ .address = pulled orelse default_image });
    if (as_runner and pulled == null) try writeProvision(&q, true);
    try writeZigLocalMount(&q, volume, as_runner);
    try q.call("withEnvVariable", .{ .name = "ZIG_RUNNER_ROLL", .value = nonce });
    const limit_kb = try std.fmt.allocPrint(arena, "{d}", .{@as(u64, max_mb) * 1024});
    try q.call("withExec", .{ .args = &[_][]const u8{
        "sh",
        "-c",
        zig_local_roll_script,
        "zig-local-roll",
        zigLocalCacheDir(as_runner),
        limit_kb,
        if (as_runner) "1001:1001" else "",
        nonce,
    } });
    try q.leaf("sync");
    var err_msg: []const u8 = "";
    _ = gql(arena, transport, try q.finish(), &err_msg) catch
        std.log.warn("Zig local cache not rolled: {s}", .{err_msg});
}

/// Fills the `builtin.zig` volume (`zigBuiltinDir`) with what the seed has in its own `b/`, which
/// the volume's mount hides: the seed's manifests name those files, and without them every job
/// would build Zig's build runner again. Files that are there stay. Arguments: $1 the volume, $2 the
/// seed's `b/`, $3 the owner (or empty).
pub const zig_builtin_seed_script =
    \\cp -an "$2/." "$1/" 2>/dev/null
    \\[ -z "$3" ] || chown -hR "$3" "$1"
    \\exit 0
;

/// Runs `zig_builtin_seed_script`, as `rollZigLocal` runs its script: in a container of its own,
/// the volume mounted as the steps mount it, a per-job variable keeping the engine from caching
/// the exec. Nothing of it can fail the job: a volume that was not filled costs one build of Zig's
/// build runner, after which it has what the seed had.
fn seedBuiltin(
    arena: Allocator,
    transport: Transport,
    volume: []const u8,
    seed: []const u8,
    as_runner: bool,
    pulled: ?[]const u8,
    nonce: []const u8,
) !void {
    const dir = try zigBuiltinDir(arena, as_runner);
    var q: Query = .init(arena);
    try q.open("container");
    try q.call("from", .{ .address = pulled orelse default_image });
    if (as_runner and pulled == null) try writeProvision(&q, true);
    try q.call("withMountedDirectory", .{ .path = zig_seed_dir, .source = seed });
    try q.call("withMountedCache", .{
        .path = dir,
        .cache = volume,
        .owner = if (as_runner) runner_user else null,
    });
    try q.call("withEnvVariable", .{ .name = "ZIG_RUNNER_ROLL", .value = nonce });
    try q.call("withExec", .{ .args = &[_][]const u8{
        "sh",
        "-c",
        zig_builtin_seed_script,
        "zig-builtin-seed",
        dir,
        zig_seed_dir ++ "/b",
        if (as_runner) "1001:1001" else "",
    } });
    try q.leaf("sync");
    var err_msg: []const u8 = "";
    _ = gql(arena, transport, try q.finish(), &err_msg) catch
        std.log.warn("Zig builtin volume not filled: {s}", .{err_msg});
}

/// The Zig local-cache volume's mount, one writer for the base container and the roll, so both
/// reach the same store.
fn writeZigLocalMount(q: *Query, volume: []const u8, as_runner: bool) !void {
    try q.call("withMountedCache", .{
        .path = zigLocalCacheDir(as_runner),
        .cache = volume,
        .owner = if (as_runner) runner_user else null,
    });
}

/// Where Zig's global cache keeps the `builtin.zig` it generates for each compilation (`b/`).
/// Zig names these files in the *local* cache's manifests, so with the local cache in a volume and
/// this directory in the job's own container, every job found them gone and recompiled everything
/// the local cache held. It has a volume of its own, in the jobs that keep the local cache
/// (`zigLocalShared`): what Zig reads from it is as trusted as the local cache's `o/`.
pub fn zigBuiltinDir(arena: Allocator, as_runner: bool) ![]const u8 {
    for (package_cache_dirs, 0..) |d, i| if (std.mem.eql(u8, d.name, zig_packages)) {
        const path = if (as_runner) try runnerCachePath(arena, i) else d.path;
        return std.mem.concat(arena, u8, &.{ path, "/b" });
    };
    unreachable;
}

/// Where uv's project environment goes with `uv_env_in_cache`: inside its own cache volume, the
/// only place a hardlink from that cache can reach (every mount is its own device, even two of one
/// volume). Keyed by the ref, so jobs on different branches do not reconcile one environment to
/// their own lockfiles in turn, and concurrent jobs on one branch want the same state anyway. Never
/// with step caching (see `uvEnvFor`).
pub fn uvEnvPath(arena: Allocator, cache_path: []const u8, ref: []const u8) ![]const u8 {
    var key: std.ArrayList(u8) = .empty;
    for (if (ref.len > 0) ref else "default") |c| {
        try key.append(
            arena,
            if (std.ascii.isAlphanumeric(c) or c == '.' or c == '-' or c == '_') c else '-',
        );
    }
    const trimmed = std.mem.trim(u8, key.items, "-");
    return std.fmt.allocPrint(
        arena,
        "{s}/zig-runner-envs/{s}",
        .{ cache_path, if (trimmed.len > 0) trimmed else "default" },
    );
}

fn packageList() []const u8 {
    comptime {
        var out: []const u8 = "";
        for (provision_packages, 0..) |p, n| out = out ++ (if (n == 0) "" else " ") ++ p;
        return out;
    }
}

fn writeEnvNodes(q: *Query, plain: []const job_mod.EnvVar, secret: []const SecretRef) !void {
    for (plain) |e| try q.call("withEnvVariable", .{ .name = e.name, .value = e.value });
    for (secret) |sr| try q.call("withSecretVariable", .{ .name = sr.name, .secret = sr.id });
}

/// Runs the job's steps once a session is up (through `dagger run` or directly).
/// What the base container is built from, decided before any query is sent.
const BasePlan = struct {
    job_image: []const u8,
    provision: bool,
    /// The pre-provisioned image the base starts from instead of `job_image` and the provisioning
    /// exec (`pulledBase`); null provisions with apt.
    pulled: ?[]const u8 = null,
    /// What "Set up job" says of it: pulled, or why provisioning ran.
    pulled_note: ?[]const u8 = null,
    as_runner: bool,
    step_cache: bool,
    uv_env: ?[]const u8,
    cache_ids: []const []const u8,
    /// Which of `cache_ids` are mounted (`cachesUsed`): all of them unless the job decides less.
    cache_used: [package_cache_dirs.len]bool = @splat(true),
    /// The volume for Zig's local cache, with `zig_local_cache`.
    zig_local: ?[]const u8 = null,
    /// ZIG_LOCAL_CACHE_DIR when `zig_local` is set (`zigLocalCacheEnv`).
    zig_local_env: ?[]const u8 = null,
    /// The volume for the `builtin.zig` files the local cache's manifests name (`zigBuiltinDir`).
    zig_builtin: ?[]const u8 = null,
    /// The Zig cache seed's directory, for a Zig job on a runner with one (`zigSeedFor`).
    zig_seed: ?[]const u8 = null,
    /// What "Set up job" says of the seed: applied, or why not.
    zig_seed_note: ?[]const u8 = null,
    /// What "Set up job" says when `zig_local_cache` is on but the job's scope does not keep it.
    zig_local_note: ?[]const u8 = null,
    /// The output-key store (`Exec.outputs_volume`), when the job setup's query asked for it.
    outputs_volume: ?[]const u8 = null,
    /// The volume of the tool cache's lists, when the tool cache's trees are checked
    /// (`verifyToolTrees`).
    tool_trees: ?[]const u8 = null,
    /// Where a `repo` job's checked trees report the Zig versions its tool cache holds, to be
    /// verified and seeded in later jobs (`zig_release.Registry`).
    zig_discover: ?*zig_release.Registry = null,
    ran_marker: []const u8,
    /// The job's `mark_env` value (`JobLog.mark`).
    mark: []const u8,
    /// A `container:` job's own `env:` (`containerEnv`); empty for any other job.
    container_env: []const job_mod.EnvVar = &.{},
};

/// The container every step starts from, as one query: the job image behind its registry auth and
/// its own env, the provisioning exec, the workspace and user, the cache mounts, the event payload
/// and the job's environment. Each writer adds its calls to the query; `finish` closes them. On
/// failure the message is in `err_msg` and the caller fails the job with it.
pub fn baseContainerId(
    arena: Allocator,
    transport: Transport,
    ev: *Evaluator,
    job: job_mod.Job,
    plan: BasePlan,
    secrets: *Secrets,
    err_msg: *[]const u8,
) !Base {
    var q: Query = .init(arena);
    try q.open("container");
    try writeImage(&q, arena, transport, ev, job, plan, secrets, err_msg);
    try writeProvisionAndWorkspace(&q, arena, ev, plan);
    try writeCacheMounts(&q, arena, plan);
    try writeRunEnv(&q, ev, plan);
    try writeJobEnv(&q, arena, transport, ev, job, secrets, err_msg);
    try q.leaf("id");
    const data = gql(arena, transport, try q.finish(), err_msg) catch
        return error.BaseContainerFailed;
    const id = jsonFindString(data, "id") orelse {
        err_msg.* = "Dagger returned no container";
        return error.BaseContainerFailed;
    };
    const runtime_path = jsonFindString(data, "zig_runtime_path");
    const lists = plan.tool_trees orelse return .{ .id = id, .runtime_path = runtime_path };
    const checked = try verifyToolTrees(arena, transport, id, lists, plan.ran_marker, err_msg);
    if (plan.zig_discover) |r| r.discover(tool_cache_dir, checked.env);
    return .{
        .id = checked.id,
        .runtime_path = runtime_path,
        .tool_trees_note = checked.note,
        .tool_trees = checked.env,
    };
}

/// The base container, a `container:` job's own PATH (`Exec.container_path`), and what "Set up
/// job" says of the tool cache's trees (`verifyToolTrees`).
pub const Base = struct {
    id: []const u8,
    runtime_path: ?[]const u8,
    tool_trees_note: ?[]const u8 = null,
    /// `tool_trees_env`'s value, when the trees were checked (`Exec.tool_trees`).
    tool_trees: ?[]const u8 = null,
};

// The tool cache's trees, checked in "Set up job". A script that pins a tree's digest, as
// install-zig.sh pins Zig's, would otherwise read the whole tree in every job (19,500 files and
// 309 MB for Zig: 0.7-1 s on the laptop, 10-19 s on razorbill under load), because the tool cache
// is shared by every job of its scope and any of them could have changed it. tool_trees.sh reads
// only the files whose stat changed since a list it keeps; that list is only worth trusting if
// no job can write it, so it lives in a volume of its own that only this exec mounts, on a branch
// of the base container that no step starts from. A job that could write the list could record a
// replaced file's new stat line with its old hash.
//
// Never in a job with Dagger nesting: its steps can open any cache volume by its key, and run
// privileged containers that can set the clock, which the stat lines rely on (#228).

/// The lists' volume, mounted only on the check's own branch.
const tool_trees_dir = "/zig-runner-tool-trees";
/// What steps are given: one `DIGEST TREE` line per tree checked, TREE an absolute path.
pub const tool_trees_env = "ZIG_RUNNER_TOOL_TREES";
const tool_cache_index = for (package_cache_dirs, 0..) |d, i| {
    if (std.mem.eql(u8, d.name, "toolcache")) break i;
} else unreachable;
/// Where the tool cache volume (`toolcache` in `package_cache_dirs`) is mounted in the job's
/// container.
pub const tool_cache_dir = package_cache_dirs[tool_cache_index].path;
/// The check runs with the image's bash and none of the job's environment (a workflow's
/// `BASH_ENV` or `PATH` must not run in it).
const tool_trees_argv = [_][]const u8{
    "/usr/bin/env",  "-i",           "PATH=/usr/sbin:/usr/bin:/sbin:/bin",
    "bash",          "-c",           @embedFile("tool_trees.sh"),
    "tool_trees.sh", tool_cache_dir, tool_trees_dir,
};

/// Runs tool_trees.sh on a branch of the base container with the lists' volume mounted, as root,
/// and returns the base container with `tool_trees_env` set from what it printed. `nonce` (the
/// job's run marker) makes the exec run in every job: the engine would reuse it by its recipe,
/// in which a volume's content has no part. The variable is set even when the check failed or
/// found nothing, empty then, so a workflow's own value never stands in for the runner's.
///
/// The variable is part of every step's key, which is what keeps replay sound: its value is the
/// trees' paths and digests, a function of the tool cache's content, so it is the same in every
/// job until a tree is added, removed or changed, and then every step's key changes once.
fn verifyToolTrees(
    arena: Allocator,
    transport: Transport,
    base: []const u8,
    lists: []const u8,
    nonce: []const u8,
    err_msg: *[]const u8,
) !struct { id: []const u8, note: []const u8, env: []const u8 } {
    var check: Query = .init(arena);
    try check.call("loadContainerFromID", .{ .id = base });
    try check.call("withMountedCache", .{ .path = tool_trees_dir, .cache = lists });
    try check.call("withUser", .{ .name = "root" });
    try check.call("withEnvVariable", .{ .name = "ZIG_RUNNER_TOOL_TREES_RUN", .value = nonce });
    try check.call("withExec", .{ .args = &tool_trees_argv });
    try check.leaf("stdout");
    var msg: []const u8 = "";
    const out: ?[]const u8 = if (gql(arena, transport, try check.finish(), &msg)) |data|
        jsonFindString(data, "stdout")
    else |_|
        null;
    const verdict = try toolTreesVerdict(arena, out orelse "");
    var set: Query = .init(arena);
    try set.call("loadContainerFromID", .{ .id = base });
    try set.call("withEnvVariable", .{ .name = tool_trees_env, .value = verdict.env });
    try set.leaf("id");
    const data = gql(arena, transport, try set.finish(), err_msg) catch
        return error.BaseContainerFailed;
    const id = jsonFindString(data, "id") orelse {
        err_msg.* = "Dagger returned no container";
        return error.BaseContainerFailed;
    };
    const note = if (out == null) try std.fmt.allocPrint(
        arena,
        "Tool cache: not checked ({s}); steps check what they use themselves",
        .{msg},
    ) else verdict.note;
    return .{ .id = id, .note = note, .env = verdict.env };
}

/// `tool_trees_env`'s value and "Set up job"'s line, from tool_trees.sh's `DIGEST TREE FILES
/// REHASHED` lines. A line that does not have that form, or names a tree outside the tool cache
/// or through a dot-named directory, is left out: a step then checks that tree itself.
fn toolTreesVerdict(
    arena: Allocator,
    out: []const u8,
) !struct { env: []const u8, note: []const u8 } {
    var env: std.ArrayList(u8) = .empty;
    var note: std.ArrayList(u8) = .empty;
    var lines = std.mem.tokenizeScalar(u8, out, '\n');
    while (lines.next()) |line| {
        var fields = std.mem.tokenizeScalar(u8, line, ' ');
        const digest = fields.next() orelse continue;
        const tree = fields.next() orelse continue;
        const files = fields.next() orelse continue;
        const rehashed = fields.next() orelse continue;
        if (fields.next() != null) continue;
        if (digest.len != 64 or std.mem.indexOfNone(u8, digest, "0123456789abcdef") != null)
            continue;
        if (!std.mem.startsWith(u8, tree, tool_cache_dir ++ "/") or
            std.mem.indexOf(u8, tree, "/.") != null or
            std.mem.indexOfNone(u8, tree, path_chars) != null) continue;
        if (std.mem.indexOfNone(u8, files, "0123456789") != null or
            std.mem.indexOfNone(u8, rehashed, "0123456789") != null) continue;
        // One string of an environment may not pass 128 KiB (`execve`): past this a tree is left
        // out, as one the script did not print is, rather than every later job failing to start.
        if (env.items.len + digest.len + tree.len + 2 > max_tool_trees_env) continue;
        try env.print(arena, "{s}{s} {s}", .{ if (env.items.len > 0) "\n" else "", digest, tree });
        try note.print(arena, "{s}{s} ({s} files, {s} read)", .{
            if (note.items.len > 0) ", " else "",
            tree[tool_cache_dir.len + 1 ..],
            files,
            rehashed,
        });
    }
    return .{
        .env = env.items,
        .note = if (note.items.len == 0)
            "Tool cache: no trees to check"
        else
            try std.fmt.allocPrint(arena, "Tool cache: checked {s}", .{note.items}),
    };
}

const max_tool_trees_env = 64 << 10;

/// What tool_trees.sh lets into a tree's path: no spaces, quotes or newlines.
const path_chars = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789._+-/";

/// `from` the job image, behind a private registry's credentials when there are any, with a
/// container job's cache variables and its own `env:` set on it.
fn writeImage(
    q: *Query,
    arena: Allocator,
    transport: Transport,
    ev: *Evaluator,
    job: job_mod.Job,
    plan: BasePlan,
    secrets: *Secrets,
    err_msg: *[]const u8,
) !void {
    if (job.container) |jc| {
        // A private image: its registry's credentials.
        if (try registryAuth(
            arena,
            ev,
            transport,
            secrets,
            jc,
            plan.job_image,
            err_msg,
        )) |auth| {
            try q.call("withRegistryAuth", auth);
        } else if (err_msg.len > 0) return error.BaseContainerFailed;
    }
    try writeFrom(q, plan.pulled orelse plan.job_image, plan.zig_local_env);
    if (job.container != null) for (plan.cache_ids, 0..) |_, i| {
        // Before the container's env, so its own value wins.
        if (package_cache_dirs[i].env.len == 0 or !plan.cache_used[i]) continue;
        try q.call(
            "withEnvVariable",
            .{ .name = package_cache_dirs[i].env, .value = package_cache_dirs[i].path },
        );
    };
    // The container's env, as `docker create -e` sets it: every step sees it. What carries a
    // secret goes in as a Dagger secret, as the job's env does (#101).
    var plain: std.ArrayList(job_mod.EnvVar) = .empty;
    var secret: std.ArrayList(SecretRef) = .empty;
    splitEnv(
        arena,
        transport,
        job,
        null,
        secrets,
        plan.container_env,
        &plain,
        &secret,
        err_msg,
    ) catch
        return error.BaseContainerFailed;
    try writeEnvNodes(q, plain.items, secret.items);
    // The container's own PATH, which GitHub's runner reads from the container and puts after the
    // $GITHUB_PATH directories (`ContainerInfo.ContainerRuntimePath`, see `Exec.container_path`).
    if (job.container != null)
        try q.leafArgs("zig_runtime_path", "envVariable", .{ .name = "PATH" });
}

/// `from` the image, and Zig's local cache directory when it has a volume: the first nodes of
/// every job's base container, which depend on nothing of the job.
fn writeFrom(q: *Query, image: []const u8, zig_local_env: ?[]const u8) !void {
    try q.call("from", .{ .address = image });
    // Before the container's env too, so its value (or the workflow's) wins.
    if (zig_local_env) |dir| try q.call(
        "withEnvVariable",
        .{ .name = "ZIG_LOCAL_CACHE_DIR", .value = dir },
    );
}

/// A `container:` job's own `env:`, evaluated, without the names the job's env sets: those win
/// on GitHub (`docker exec -e` over `docker create -e`), and a secret variable and a plain one of
/// one name would leave it to the engine which of them a step sees. Null when it cannot be
/// evaluated (the reason in `ev.diag`).
fn containerEnv(arena: Allocator, ev: *Evaluator, job: job_mod.Job) !?[]const job_mod.EnvVar {
    const jc = job.container orelse return &.{};
    const env = ev.renderEnv(jc.env, try ev.scope(&.{})) catch return null;
    var out: std.ArrayList(job_mod.EnvVar) = .empty;
    for (env) |e| {
        for (ev.job_env.items) |j| {
            if (std.mem.eql(u8, j.name, e.name)) break;
        } else try out.append(arena, e);
    }
    return out.items;
}

/// The pre-provisioned image for the default image's job (`provisioned.zig`), when this build pins
/// one that is current and the operator has not turned it off: `sync`ed, so a registry that cannot
/// be reached, or an image that cannot be pulled, is found here and not in the middle of the job's
/// base container. Null provisions with apt (`writeProvision`); `note` says why when a pull failed,
/// and which image when it did not.
fn pulledBase(
    arena: Allocator,
    transport: Transport,
    opts: Options,
    as_runner: bool,
    note: *?[]const u8,
) !?[]const u8 {
    const ref = try provisioned.reference(arena, opts.provisioned_image, opts.provisioned_pins, .of(as_runner)) orelse
        return null;
    var q: Query = .init(arena);
    try q.open("container");
    try q.call("from", .{ .address = ref });
    try q.leaf("sync");
    var why: []const u8 = "";
    _ = gql(arena, transport, try q.finish(), &why) catch |e| {
        note.* = try provisioned.fallbackNote(arena, ref, if (why.len > 0) why else @errorName(e));
        return null;
    };
    note.* = try provisioned.usedNote(arena, ref);
    return ref;
}

/// Provisioning in the default image, the workspace and RUNNER_TEMP, the step user, and the
/// workdir.
fn writeProvisionAndWorkspace(q: *Query, arena: Allocator, ev: *Evaluator, plan: BasePlan) !void {
    if (plan.provision and plan.pulled == null) try writeProvision(q, plan.as_runner);
    // The job's workspace and RUNNER_TEMP, the step user's in the default image (cached per
    // repository). A job container's user may be unable to make them; its steps then report
    // that themselves.
    // With `uv_env_in_cache`, `.venv` in the workspace is a symlink to the environment in the
    // cache, so `uv run`, `.venv/bin/...` and `activate` all keep working. The link is made
    // here, before the checkout, which merges the repository over it and leaves it.
    const link = if (plan.uv_env) |e| try std.fmt.allocPrint(
        arena,
        " && ln -sfn {s} {s}/.venv",
        .{ e, ev.workspace },
    ) else "";
    const chown = if (plan.as_runner) chown_runner else "";
    const mk = if (plan.provision)
        try std.fmt.allocPrint(
            arena,
            "mkdir -p {s} {s}{s}{s}",
            .{ ev.workspace, ev.temp, link, chown },
        )
    else
        try std.fmt.allocPrint(
            arena,
            "mkdir -p {s} {s}{s} 2>/dev/null || true",
            .{ ev.workspace, ev.temp, link },
        );
    try q.call("withExec", .{ .args = &[_][]const u8{ "sh", "-c", mk } });
    if (plan.as_runner) {
        try q.call("withUser", .{ .name = runner_user });
        try q.call("withEnvVariable", .{ .name = "HOME", .value = runner_home });
    }
    try q.call("withWorkdir", .{ .path = ev.workspace });
}

/// The provisioning exec (`provision_script`, or `provision_runner_script` with the step user):
/// the one expensive node of the base container, and a job-independent one, cached per engine.
fn writeProvision(q: *Query, as_runner: bool) !void {
    const script = if (as_runner) provision_runner_script else provision_script;
    try q.call("withExec", .{ .args = &[_][]const u8{ "sh", "-c", script } });
}

/// One cache volume mount per package manager the job uses (`cachesUsed`), owned by the step user
/// when steps run as it. Zig's global cache is the job's own, never a volume: Zig trusts the
/// outputs it finds in `o/` without checking them, so a shared one would let one job plant a binary
/// every later job runs. It starts as the seed, mounted as a directory whose writes go with the
/// job's container, or empty in the container without one; only its package tarballs (`p/`, which
/// Zig hashes again when it unpacks them) are in a volume.
fn writeCacheMounts(q: *Query, arena: Allocator, plan: BasePlan) !void {
    for (plan.cache_ids, 0..) |id, i| {
        if (!plan.cache_used[i]) continue;
        const path = if (plan.as_runner) try runnerCachePath(
            arena,
            i,
        ) else package_cache_dirs[i].path;
        const owner: ?[]const u8 = if (plan.as_runner) runner_user else null;
        const zig = std.mem.eql(u8, package_cache_dirs[i].name, zig_packages);
        if (zig) if (plan.zig_seed) |seed|
            try q.call("withMountedDirectory", .{ .path = path, .source = seed, .owner = owner });
        try q.call("withMountedCache", .{
            .path = if (zig) try std.mem.concat(arena, u8, &.{ path, "/p" }) else path,
            .cache = id,
            .owner = owner,
        });
    }
    if (plan.zig_builtin) |id| try q.call("withMountedCache", .{
        .path = try zigBuiltinDir(arena, plan.as_runner),
        .cache = id,
        .owner = if (plan.as_runner) runner_user else null,
    });
    if (plan.zig_local) |id| try writeZigLocalMount(q, id, plan.as_runner);
}

/// The values that identify this run: the event payload, the ran marker, uv's environment, and the
/// default variables — volatile under step caching, so they do not reach exec cache keys.
fn writeRunEnv(q: *Query, ev: *Evaluator, plan: BasePlan) !void {
    // The event payload, as on GitHub (actions read it through GITHUB_EVENT_PATH). It differs on
    // every run, so with step caching it travels in a volatile variable that each step writes to
    // the file; a payload too large for one variable is written into the container instead.
    const event = try ev.eventJson();
    if (plan.step_cache and event.len <= max_event_env) {
        try q.call("withVolatileVariable", .{ .name = event_env, .value = event });
    } else {
        try q.call("withNewFile", .{ .path = event_path, .contents = event });
    }
    if (plan.step_cache)
        try q.call("withVolatileVariable", .{ .name = ran_env, .value = plan.ran_marker });
    // Every step's markers carry it, with step caching or without (`mark_env`).
    try q.call(envVarNode(plan.step_cache), .{ .name = mark_env, .value = plan.mark });
    if (plan.uv_env) |e| {
        try q.call("withEnvVariable", .{ .name = "UV_PROJECT_ENVIRONMENT", .value = e });
        // The environment outlives the job, and `uv venv` refuses to replace one that exists
        // ("A virtual environment already exists at ..."), where on a hosted runner the
        // workspace is new every job and it always succeeds. This keeps `uv venv` meaning
        // "make me a fresh environment"; `uv sync` still reconciles the one that is there.
        try q.call("withEnvVariable", .{ .name = "UV_VENV_CLEAR", .value = "1" });
    }
    for (try ev.defaultEnv()) |e| {
        // Run-specific values do not take part in exec cache keys, so unchanged steps are reused.
        const node = envVarNode(plan.step_cache and isVolatile(e.name));
        try q.call(node, .{ .name = e.name, .value = e.value });
    }
}

/// Workflow- and job-level env is part of every step's environment, but for the defaults GitHub
/// sets again over it (`Evaluator.withoutReapplied`); what carries a secret goes in as a Dagger
/// secret.
fn writeJobEnv(
    q: *Query,
    arena: Allocator,
    transport: Transport,
    ev: *Evaluator,
    job: job_mod.Job,
    secrets: *Secrets,
    err_msg: *[]const u8,
) !void {
    var plain: std.ArrayList(job_mod.EnvVar) = .empty;
    var secret: std.ArrayList(SecretRef) = .empty;
    splitEnv(
        arena,
        transport,
        job,
        null,
        secrets,
        try ev.withoutReapplied(ev.job_env.items),
        &plain,
        &secret,
        err_msg,
    ) catch
        return error.BaseContainerFailed;
    try writeEnvNodes(q, plain.items, secret.items);
}

/// The job's name as GitHub shows it: its display name, else its key in the workflow, else "job".
fn jobLabel(job: job_mod.Job) []const u8 {
    if (job.display_name.len > 0) return job.display_name;
    return if (job.github.job.len > 0) job.github.job else "job";
}

/// What the job runs in, decided before any step: the image, whether it is provisioned and steps
/// run as the runner user, uv's environment, the package cache volumes, and this job's run marker.
/// On failure the message is in `err_msg` and the caller fails the job with it.
pub fn basePlan(
    arena: Allocator,
    io: std.Io,
    transport: Transport,
    ev: *Evaluator,
    job: job_mod.Job,
    opts: Options,
    step_cache: bool,
    mark: []const u8,
    secrets: *Secrets,
    err_msg: *[]const u8,
) !BasePlan {
    // `container:` replaces the image every step runs in.
    // The default image's bare name (`container: ubuntu:24.04`) is the pinned default.
    const job_image: []const u8 = resolveImage(if (job.container) |jc| (ev.render(
        jc.image,
        try ev.scope(&.{}),
    ) catch "") else opts.image);
    if (job_image.len == 0) {
        err_msg.* = try std.fmt.allocPrint(arena, "container: has no image: {s}", .{ev.diag});
        return error.BaseContainerFailed;
    }
    const container_env = try containerEnv(arena, ev, job) orelse {
        err_msg.* = try std.fmt.allocPrint(
            arena,
            "could not evaluate the container's env: {s}",
            .{ev.diag},
        );
        return error.BaseContainerFailed;
    };
    const provision = opts.provision and std.mem.eql(u8, job_image, default_image);
    const as_runner = provision and opts.step_user == .runner;
    const ran_marker = opts.test_ran_marker orelse ran: {
        var raw: [12]u8 = undefined;
        io.random(&raw);
        break :ran try arena.dupe(u8, &std.fmt.bytesToHex(raw, .lower));
    };
    var pulled_note: ?[]const u8 = null;
    const pulled = if (provision) try pulledBase(arena, transport, opts, as_runner, &pulled_note) else null;
    var zig_seed_note: ?[]const u8 = null;
    const zig_seed = try zigSeedFor(arena, transport, job, opts, pulled, &zig_seed_note);
    const volumes = try cacheVolumeIds(
        arena,
        transport,
        ev,
        job,
        opts,
        job_image,
        container_env,
        as_runner,
        step_cache,
        secrets,
        err_msg,
    );
    if (volumes.zig_local) |id| if (opts.zig_local_cache_max_mb > 0)
        try rollZigLocal(arena, transport, id, opts.zig_local_cache_max_mb, as_runner, pulled, ran_marker);
    if (volumes.zig_builtin) |id| if (zig_seed) |seed|
        try seedBuiltin(arena, transport, id, seed, as_runner, pulled, ran_marker);
    return .{
        .container_env = container_env,
        .job_image = job_image,
        .provision = provision,
        .pulled = pulled,
        .pulled_note = pulled_note,
        .as_runner = as_runner,
        .step_cache = step_cache,
        .uv_env = try uvEnvFor(arena, opts, job, as_runner, step_cache),
        .cache_ids = volumes.ids,
        .cache_used = cachesUsed(job),
        .zig_local = volumes.zig_local,
        .zig_builtin = volumes.zig_builtin,
        .zig_local_env = if (opts.zig_local_cache and opts.package_caches and
            job.github.repository.len > 0)
            zigLocalCacheEnv(as_runner, opts.zig_local_cache_max_mb)
        else
            null,
        .zig_seed = zig_seed,
        .zig_seed_note = zig_seed_note,
        .zig_local_note = if (opts.zig_local_cache and volumes.ids.len > 0 and
            volumes.zig_local == null)
            "Zig local cache: this job's own (not kept between untrusted jobs)"
        else
            null,
        .outputs_volume = volumes.outputs,
        .tool_trees = volumes.tool_trees,
        .zig_discover = if (opts.zig_seed_registry) |r| if (std.mem.eql(
            u8,
            try packageCacheScope(arena, ev, job.github.repository, opts.trusted),
            "repo",
        )) r else null else null,
        .ran_marker = ran_marker,
        .mark = mark,
    };
}

/// uv's project environment, inside its cache volume so uv can hardlink into it (see `uvEnvPath`).
/// Null when there is no cache volume to put it in, and when the job's steps are cached: a cache
/// volume's content is not part of a step's key and a replayed step's writes into one are not made
/// again, so a replayed `uv sync` would leave the environment another commit's job synced there,
/// and later steps would run against its dependencies (#70). Left in the workspace, the environment
/// is part of the container each step produces, and a replay restores it exactly; uv's download
/// and wheel cache stays in its volume, content-addressed and safe to share.
fn uvEnvFor(
    arena: Allocator,
    opts: Options,
    job: job_mod.Job,
    as_runner: bool,
    step_cache: bool,
) !?[]const u8 {
    if (!opts.uv_env_in_cache or !opts.package_caches or job.github.repository.len == 0)
        return null;
    if (step_cache) return null;
    const i = for (
        package_cache_dirs,
        0..,
    ) |d, n| (if (std.mem.eql(u8, d.name, "uv")) break n) else return null;
    // Without its volume the venv would land in the container: a job that runs no uv has none.
    if (!cachesUsed(job)[i]) return null;
    const path = if (job.container != null)
        package_cache_dirs[i].path
    else if (as_runner)
        try runnerCachePath(arena, i)
    else
        package_cache_dirs[i].path;
    return try uvEnvPath(arena, path, job.github.ref);
}

const CacheVolumes = struct {
    ids: []const []const u8 = &.{},
    zig_local: ?[]const u8 = null,
    zig_builtin: ?[]const u8 = null,
    outputs: ?[]const u8 = null,
    tool_trees: ?[]const u8 = null,
};

/// Package managers' caches persist across jobs in Dagger cache volumes (see `package_cache_dirs`):
/// one query asks for every volume's id, and for Zig's local cache's with `zig_local_cache`. None
/// when caches are off or there is no repository to key them by.
///
/// The same query registers the secrets the base container needs (`baseSecrets`) and, being sent
/// anyway, those the job's steps will (`stepSecrets`), and asks for the output-key store: one round
/// trip where each was one of its own. Without caches the secrets the base needs go in it alone;
/// with neither, nothing is sent. Should the query fail with secrets in it, it is sent again
/// without them, which are then registered when first needed, failing as they always did.
fn cacheVolumeIds(
    arena: Allocator,
    transport: Transport,
    ev: *Evaluator,
    job: job_mod.Job,
    opts: Options,
    job_image: []const u8,
    container_env: []const job_mod.EnvVar,
    as_runner: bool,
    step_cache: bool,
    secrets: *Secrets,
    err_msg: *[]const u8,
) !CacheVolumes {
    const caches = opts.package_caches and job.github.repository.len > 0;
    const needed = try baseSecrets(arena, ev, job, container_env);
    if (!caches and (try secrets.missing(arena, needed)).len == 0) return .{};
    const ahead = try std.mem.concat(arena, []const u8, &.{ needed, try stepSecrets(arena, job) });
    const pending = try secrets.missing(arena, ahead);
    const set_up: SetUpQuery = .{
        .ev = ev,
        .job = job,
        .opts = opts,
        .job_image = job_image,
        .as_runner = as_runner,
        .caches = caches,
        .outputs_key = try outputKeysKey(arena, ev, job, opts, step_cache),
        .tool_trees_key = if (caches)
            try toolTreesKey(arena, ev, job, opts, job_image, as_runner)
        else
            null,
    };
    var msg: []const u8 = "";
    if (try set_up.send(arena, transport, secrets, pending, &msg)) |v| return v;
    if (!caches) return .{};
    if (pending.len == 0) {
        err_msg.* = msg;
        return error.BaseContainerFailed;
    }
    return try set_up.send(arena, transport, secrets, &.{}, err_msg) orelse
        error.BaseContainerFailed;
}

/// `cacheVolumeIds`' query: the cache volumes with `caches`, the output-key store with
/// `outputs_key`, and the secrets asked for.
const SetUpQuery = struct {
    ev: *Evaluator,
    job: job_mod.Job,
    opts: Options,
    job_image: []const u8,
    as_runner: bool,
    caches: bool,
    outputs_key: ?[]const u8,
    tool_trees_key: ?[]const u8,

    /// Sends the query with `pending` registered. Null, with the reason in `err_msg`, when it
    /// failed or lacked an answer.
    fn send(
        u: SetUpQuery,
        arena: Allocator,
        transport: Transport,
        secrets: *Secrets,
        pending: []const []const u8,
        err_msg: *[]const u8,
    ) !?CacheVolumes {
        var q: Query = .init(arena);
        try secrets.write(arena, &q, pending);
        if (u.outputs_key) |key| {
            try q.callAs("cout", "cacheVolume", .{ .key = key });
            try q.leaf("id");
            try q.close(1);
        }
        if (u.tool_trees_key) |key| {
            try q.callAs("ctt", "cacheVolume", .{ .key = key });
            try q.leaf("id");
            try q.close(1);
        }
        if (u.caches) try writeCacheVolumes(&q, arena, u.ev, u.job, u.opts, u.job_image, u.as_runner);
        const data = gql(arena, transport, try q.finish(), err_msg) catch return null;
        if (!try secrets.read(arena, data, pending)) {
            err_msg.* = "Dagger returned no secret id";
            return null;
        }
        var out: CacheVolumes = .{};
        if (u.outputs_key != null)
            out.outputs = if (jsonFind(data, "cout")) |v| jsonFindString(v, "id") else null;
        if (u.tool_trees_key != null)
            out.tool_trees = if (jsonFind(data, "ctt")) |v| jsonFindString(v, "id") else null;
        if (!u.caches) return out;
        const no_volume = "Dagger returned no cache volume";
        const ids = try arena.alloc([]const u8, package_cache_dirs.len);
        for (ids, 0..) |*id, i| {
            const v = jsonFind(data, try std.fmt.allocPrint(arena, "c{d}", .{i})) orelse {
                err_msg.* = no_volume;
                return null;
            };
            id.* = jsonFindString(v, "id") orelse {
                err_msg.* = no_volume;
                return null;
            };
        }
        out.ids = ids;
        if (try zigLocalShared(arena, u.ev, u.job, u.opts)) {
            const v = jsonFind(data, "czl") orelse {
                err_msg.* = no_volume;
                return null;
            };
            out.zig_local = jsonFindString(v, "id") orelse {
                err_msg.* = no_volume;
                return null;
            };
            const b = jsonFind(data, "czb") orelse {
                err_msg.* = no_volume;
                return null;
            };
            out.zig_builtin = jsonFindString(b, "id") orelse {
                err_msg.* = no_volume;
                return null;
            };
        }
        return out;
    }
};

/// Whether the job keeps Zig's local cache in its volume (`zig_local_cache`): only in the `repo`
/// scope. Zig runs the outputs it finds there without checking them, so in `untrusted`, where every
/// job is a stranger's, one job could plant what the next one runs; there the cache is the job's
/// own, in its container at the same path (so the base container's recipe is the pre-warm's), and
/// "Set up job" says so. In `repo` every job is code the runner vouches for: a shared cache risks
/// only what a compromised trusted job could do anyway.
fn zigLocalShared(arena: Allocator, ev: *Evaluator, job: job_mod.Job, opts: Options) !bool {
    if (!opts.zig_local_cache) return false;
    const scope = try packageCacheScope(arena, ev, job.github.repository, opts.trusted);
    return std.mem.eql(u8, scope, "repo");
}

/// The key of the volume `verifyToolTrees` keeps its lists in, beside the tool cache's own (the
/// same scope, image and user), or null when the job's trees are not checked: with
/// `tool_trees` off, and in a job with Dagger nesting, whose steps could open it by its key.
fn toolTreesKey(
    arena: Allocator,
    ev: *Evaluator,
    job: job_mod.Job,
    opts: Options,
    job_image: []const u8,
    as_runner: bool,
) !?[]const u8 {
    const scope = try packageCacheScope(arena, ev, job.github.repository, opts.trusted);
    if (!opts.tool_trees or (opts.nesting and std.mem.eql(u8, scope, "repo"))) return null;
    return try std.fmt.allocPrint(arena, "zig-runner/{s}/{s}/tool-trees/{s}{s}", .{
        job.github.repository,
        scope,
        // The tool cache's own key drops the digest (`imageName`); its lists follow the same volume.
        imageName(job_image),
        if (as_runner) "/" ++ runner_user else "",
    });
}

/// One `cacheVolume` per package manager (`c<i>`), and Zig's local cache's (`czl`) and its
/// `builtin.zig` files' (`czb`).
fn writeCacheVolumes(
    q: *Query,
    arena: Allocator,
    ev: *Evaluator,
    job: job_mod.Job,
    opts: Options,
    job_image: []const u8,
    as_runner: bool,
) !void {
    const scope = try packageCacheScope(arena, ev, job.github.repository, opts.trusted);
    // Its own volume, so the engine can collect it (it only grows) without the global cache.
    if (try zigLocalShared(arena, ev, job, opts)) {
        const key = try std.fmt.allocPrint(
            arena,
            "zig-runner/{s}/{s}/zig-local{s}",
            .{ job.github.repository, scope, if (as_runner) "/" ++ runner_user else "" },
        );
        try q.callAs("czl", "cacheVolume", .{ .key = key });
        try q.leaf("id");
        try q.close(1);
        try q.callAs("czb", "cacheVolume", .{ .key = try std.fmt.allocPrint(
            arena,
            "zig-runner/{s}/{s}/zig-builtin{s}",
            .{ job.github.repository, scope, if (as_runner) "/" ++ runner_user else "" },
        ) });
        try q.leaf("id");
        try q.close(1);
    }
    for (package_cache_dirs, 0..) |d, i| {
        // The tool cache holds binaries built for one image (glibc or musl, its libraries), so
        // each image has its own: by name, as a rebuild of the same release (a new digest) runs
        // them alike, and a digest update keeps the volume.
        const key = if (std.mem.eql(u8, d.name, "toolcache"))
            try std.fmt.allocPrint(
                arena,
                "zig-runner/{s}/{s}/{s}/{s}",
                .{ job.github.repository, scope, d.name, imageName(job_image) },
            )
        else
            try std.fmt.allocPrint(
                arena,
                "zig-runner/{s}/{s}/{s}",
                .{ job.github.repository, scope, d.name },
            );
        // Volumes root filled hold files `runner_user` cannot write: steps that run as it get
        // their own.
        const user_key = if (as_runner) try std.mem.concat(
            arena,
            u8,
            &.{ key, "/", runner_user },
        ) else key;
        try q.callAs(
            try std.fmt.allocPrint(arena, "c{d}", .{i}),
            "cacheVolume",
            .{ .key = user_key },
        );
        try q.leaf("id");
        try q.close(1);
    }
}

/// The secrets the base container is made with: a private job image's registry password, and
/// job-level and container env that carries one.
fn baseSecrets(
    arena: Allocator,
    ev: *Evaluator,
    job: job_mod.Job,
    container_env: []const job_mod.EnvVar,
) ![]const []const u8 {
    var out: std.ArrayList([]const u8) = .empty;
    if (job.container) |jc| if (try registryCredentials(ev, jc)) |c| try out.append(arena, c.pass);
    for (ev.job_env.items) |e| if (containsSecret(job, e.value)) try out.append(arena, e.value);
    for (container_env) |e| if (containsSecret(job, e.value)) try out.append(arena, e.value);
    return out.items;
}

/// Secrets the job's steps will register if nothing else does: the job token, which every action
/// gets (ACTIONS_RUNTIME_TOKEN) and OIDC requests use, and GITHUB_TOKEN, which fetches checkouts
/// and the job's own repository's actions. One costs only its field in a query sent anyway.
fn stepSecrets(arena: Allocator, job: job_mod.Job) ![]const []const u8 {
    var actions = false;
    var fetches = false;
    for (job.steps) |st| switch (st.action) {
        .uses => {
            actions = true;
            fetches = true;
        },
        .docker => actions = true,
        .checkout => fetches = true,
        else => {},
    };
    var out: std.ArrayList([]const u8) = .empty;
    if ((actions or job.runtime.id_token_url.len > 0) and containsSecret(job, job.job_token))
        try out.append(arena, job.job_token);
    if (fetches) for (job.secret_vars) |sv| {
        if (std.mem.eql(u8, sv.name, "GITHUB_TOKEN") and sv.value.len > 0)
            try out.append(arena, sv.value);
    };
    return out.items;
}

/// The Exec a job's steps run through, from everything decided before the first step.
pub fn execFor(
    arena: Allocator,
    io: std.Io,
    transport: Transport,
    sh: *JobLog,
    ev: *Evaluator,
    job: *const job_mod.Job,
    opts: Options,
    plan: BasePlan,
    container_id: []const u8,
    secrets: Secrets,
    step_cache: bool,
) !Exec {
    // What the base container set as Dagger secrets (`writeJobEnv`, `writeImage`).
    var secret_vars: std.StringHashMapUnmanaged(void) = .empty;
    const job_env = try ev.withoutReapplied(ev.job_env.items);
    for ([_][]const job_mod.EnvVar{ job_env, plan.container_env }) |env| for (env) |e| {
        if (containsSecret(job.*, e.value)) try secret_vars.put(arena, e.name, {});
    };
    const scope = try packageCacheScope(arena, ev, job.github.repository, opts.trusted);
    const vouched = std.mem.eql(u8, scope, "repo");
    return .{
        .arena = arena,
        .io = io,
        .transport = transport,
        .sh = sh,
        .ev = ev,
        .job = job,
        .container_id = container_id,
        .secrets = secrets,
        .next_fc = @intCast(job.steps.len + 1),
        .js_runtime = opts.js_runtime,
        // Dagger inside steps only for a job whose caches are the trusted jobs' own: a step's
        // nested client is in the runner's namespace and can open any cache volume by its key,
        // the `repo` volumes and the output-key store included, and the keys are no secret
        // (#228).
        .nesting = opts.nesting and vouched,
        .nesting_withheld = opts.nesting and !vouched,
        .step_cache = step_cache,
        // Mounted at the same path for every step user (`runnerCachePath`).
        .tool_cache = if (plan.cache_ids.len > tool_cache_index and
            plan.cache_used[tool_cache_index]) tool_cache_dir else null,
        .enforce_volatile = step_cache and opts.enforce_volatile,
        .output_keys = try outputKeysKey(arena, ev, job.*, opts, step_cache),
        .outputs_volume = plan.outputs_volume,
        .outputs_days = opts.output_keys_days,
        .event_from_env = step_cache and (try ev.eventJson()).len <= max_event_env,
        .job_secret_env = secret_vars.count() > 0,
        .secret_vars = secret_vars,
        // Per job, not per run: a run's matrix jobs share its id and attempt, and a step that must
        // run in each of them would otherwise be replayed from the first one's result.
        .run_nonce = try std.fmt.allocPrint(
            arena,
            "{s}, job {s}",
            .{ try runNonce(arena, io, ev), plan.ran_marker },
        ),
        .ran_marker = plan.ran_marker,
        .dir_owner = if (plan.as_runner) runner_user else null,
        .execs = try zeroed(arena, u32, logSteps(job.steps.len)),
        .next_log_step = @intCast(job.steps.len + 1),
        .loaded = try nulls(arena, Exec.LoadResult, job.steps.len),
        .pre_state = try emptySlices(arena, job_mod.EnvVar, job.steps.len),
        .summaries = try emptySlices(arena, u8, logSteps(job.steps.len)),
        .job_image = plan.job_image,
        .observer = opts.observer,
    };
}

/// "Set up job": what GitHub's runner logs before the first step, including fetching every action.
/// As on GitHub, an action that cannot be resolved (even one whose step would be skipped) fails
/// "Set up job" with one error naming them all, and no step runs: that is the Result returned. So
/// does `defaults.run` that cannot be read or evaluated.
pub fn setUpJob(x: *Exec, opts: Options, results: []StepResult) !?Result {
    const arena = x.arena;
    try x.logSetUp(opts);
    if (try evalRunDefaults(x)) |why| return try failSetUp(x, results, why);
    try warnDroppedContainerSettings(x);
    var downloaded: std.StringHashMapUnmanaged(void) = .empty;
    var unresolved: std.StringArrayHashMapUnmanaged(void) = .empty;
    for (x.job.steps, 1..) |step, n| if (step.action == .uses and !step.action.uses.local) {
        const lr = try x.loadFor(@intCast(n), step.action.uses);
        if (lr == .unresolved) try unresolved.put(arena, lr.unresolved, {});
        if (lr != .ok) continue;
        const u = step.action.uses;
        const label = try std.fmt.allocPrint(arena, "{s}/{s}@{s}", .{ u.owner, u.name, u.ref });
        if ((try downloaded.getOrPut(arena, label)).found_existing) continue;
        x.setUpLine(if (lr.ok.sha.len > 0)
            try std.fmt.allocPrint(
                arena,
                "Download action repository '{s}' (SHA:{s})",
                .{ label, lr.ok.sha },
            )
        else
            try std.fmt.allocPrint(arena, "Download action repository '{s}'", .{label}));
    };
    if (unresolved.count() > 0)
        return try failSetUp(x, results, try std.mem.join(arena, ". ", unresolved.keys()));
    const job = x.job;
    x.setUpLine(try std.fmt.allocPrint(arena, "Complete job name: {s}", .{jobLabel(job.*)}));
    return null;
}

/// "Set up job" failed with `why`: logged as its error, and no step runs.
fn failSetUp(x: *Exec, results: []StepResult, why: []const u8) !Result {
    x.sh.errorLine(0, why);
    var failed = try finish(x.arena, x.sh, results, "");
    failed.succeeded = false;
    failed.engine_error = null;
    failed.set_up_failed = true;
    return failed;
}

/// A `container:` job's `options`, `ports` and `volumes` are not read on this path: the job runs
/// without them, and the log says which (#368). A warning, not a failure, so jobs that fell back
/// to Dagger with these set keep running. Values are rendered and logged through the job's log,
/// which masks secrets; one that cannot be evaluated is named without its value. Not on the native
/// backend, which takes a job only when it carries all of them out (`container_options.unsupported`).
fn warnDroppedContainerSettings(x: *Exec) !void {
    if (x.native != null) return;
    const jc = x.job.container orelse return;
    const sc = try x.ev.scope(&.{});
    if (jc.options) |t| {
        const text = std.mem.trim(u8, x.ev.render(t, sc) catch "(not evaluated)", " \t\n");
        if (text.len > 0) x.setUpLine(try std.fmt.allocPrint(
            x.arena,
            "##[warning]Job container options not supported here and ignored: {s}",
            .{text},
        ));
    }
    inline for (.{ .{ "ports", jc.ports }, .{ "volumes", jc.volumes } }) |field| {
        if (field[1].len > 0) {
            var list: std.ArrayList(u8) = .empty;
            for (field[1]) |t| {
                if (list.items.len > 0) try list.appendSlice(x.arena, ", ");
                try list.appendSlice(x.arena, x.ev.render(t, sc) catch "(not evaluated)");
            }
            x.setUpLine(try std.fmt.allocPrint(
                x.arena,
                "##[warning]Job container " ++ field[0] ++ " not supported here and ignored: {s}",
                .{list.items},
            ));
        }
    }
}

/// Evaluates `defaults.run` into `Exec.default_shell` and `default_working_directory`, once for
/// the job as GitHub's runner does in "Set up job"; an empty value counts as unset (actions/runner
/// src/Runner.Worker/JobExtension.cs 277-293). Returns why, when it cannot.
fn evalRunDefaults(x: *Exec) !?[]const u8 {
    if (x.job.defaults_error) |why| return why;
    const d = x.job.defaults_run;
    const sc = try x.ev.scope(&.{});
    if (d.shell) |t| {
        const v = x.ev.render(t, sc) catch return try std.fmt.allocPrint(
            x.arena,
            "defaults.run.shell: {s}",
            .{x.ev.diag},
        );
        if (v.len > 0) x.default_shell = v;
    }
    if (d.working_directory) |t| {
        const v = x.ev.render(t, sc) catch return try std.fmt.allocPrint(
            x.arena,
            "defaults.run.working-directory: {s}",
            .{x.ev.diag},
        );
        if (v.len > 0) x.default_working_directory = v;
    }
    return null;
}

fn zeroed(arena: Allocator, comptime T: type, n: usize) ![]T {
    const s = try arena.alloc(T, n);
    @memset(s, 0);
    return s;
}

fn nulls(arena: Allocator, comptime T: type, n: usize) ![]?T {
    const s = try arena.alloc(?T, n);
    @memset(s, null);
    return s;
}

fn emptySlices(arena: Allocator, comptime T: type, n: usize) ![][]const T {
    const s = try arena.alloc([]const T, n);
    @memset(s, &.{});
    return s;
}

/// Linux limits one environment string to 128 KiB; larger payloads are written as a file instead.
pub const max_event_env = 100 * 1024;

/// `<run_id>.<run_attempt>`, or the time when the job has no run id (`--exec-job`).
fn runNonce(arena: Allocator, io: std.Io, ev: *const Evaluator) ![]const u8 {
    const id = ev.githubString("run_id");
    if (id.len > 0)
        return std.fmt.allocPrint(arena, "{s}.{s}", .{ id, ev.githubString("run_attempt") });
    return std.fmt.allocPrint(arena, "t{d}", .{std.Io.Clock.real.now(io).toMilliseconds()});
}

/// Package managers' cache directories (for root, the default images' user), each mounted from its
/// own cache volume. Their contents are caches the tools validate themselves, so sharing them
/// between jobs is safe; they are keyed by repository (see `packageCacheScope`).
///
/// A `container:` image may put them elsewhere (the golang image's GOPATH is /go), so in a
/// container job a tool with a variable naming its cache directory gets the variable pointing at
/// the volume. The paths stay the default image's: Go keys compiled packages on their source
/// directory, so a module cache at one path everywhere lets every image share the build cache. The
/// container's or the workflow's own value wins (and the tool then works without the volume).
///
/// `tools` are the words that say a job uses one (`cachesUsed`).
pub const package_cache_dirs = [_]struct {
    name: []const u8,
    path: []const u8,
    env: []const u8 = "",
    tools: []const []const u8,
}{
    // RUNNER_TOOL_CACHE: what setup-node, setup-python, setup-go and the like download and unpack,
    // found again by the next job instead of fetched (GitHub's images come with it filled). Any
    // action may install into it, so every job with one mounts it.
    .{
        .name = "toolcache",
        .path = "/opt/hostedtoolcache",
        .tools = &.{ "hostedtoolcache", "runner_tool_cache" },
    },
    .{ .name = "npm", .path = "/root/.npm", .env = "npm_config_cache", .tools = &node_tools },
    .{ .name = "pnpm", .path = "/root/.local/share/pnpm/store", .tools = &.{ "pnpm", "corepack" } },
    .{ .name = "yarn", .path = "/usr/local/share/.cache/yarn", .tools = &.{ "yarn", "corepack" } },
    .{
        .name = "pip",
        .path = "/root/.cache/pip",
        .env = "PIP_CACHE_DIR",
        .tools = &.{ "pip", "pipx", "python" },
    },
    .{ .name = "uv", .path = "/root/.cache/uv", .env = "UV_CACHE_DIR", .tools = &.{ "uv", "uvx" } },
    .{ .name = "go-mod", .path = "/root/go/pkg/mod", .env = "GOMODCACHE", .tools = &go_tools },
    .{ .name = "go-build", .path = "/root/.cache/go-build", .env = "GOCACHE", .tools = &go_tools },
    .{ .name = "cargo-registry", .path = "/root/.cargo/registry", .tools = &rust_tools },
    .{ .name = "cargo-git", .path = "/root/.cargo/git", .tools = &rust_tools },
    .{
        .name = "bun",
        .path = "/root/.bun/install/cache",
        .env = "BUN_INSTALL_CACHE_DIR",
        .tools = &.{ "bun", "bunx" },
    },
    // Zig's global cache, of which only the package tarballs are in the volume (`writeCacheMounts`).
    // Decided by `usesZig`, as the seed is.
    .{
        .name = zig_packages,
        .path = "/root/.cache/zig",
        .env = "ZIG_GLOBAL_CACHE_DIR",
        .tools = &.{},
    },
    .{
        .name = "gradle",
        .path = "/root/.gradle/caches",
        .tools = &.{ "gradle", "gradlew", "java" },
    },
    .{
        .name = "maven",
        .path = "/root/.m2/repository",
        .tools = &.{ "mvn", "mvnw", "maven", "java" },
    },
    // Not package caches, but state tools rewrite on every run, kept out of the container's
    // filesystem so that what a step leaves there is what it produced (see `Options.output_keys`).
    // Node's compile cache: V8 code npm and Node write and Node validates, which also lets them
    // start faster. No variable: NODE_COMPILE_CACHE would turn it on for every Node program; this
    // is where Node puts it when a program turns it on. And Go's local telemetry counters.
    .{
        .name = "node-compile-cache",
        .path = "/tmp/node-compile-cache",
        .tools = &(node_tools ++ .{ "pnpm", "yarn", "corepack" }),
    },
    .{ .name = "go-telemetry", .path = "/root/.config/go/telemetry", .tools = &go_tools },
};
/// The name of the `package_cache_dirs` entry that holds Zig's package cache.
pub const zig_packages = "zig-packages";
const node_tools = [_][]const u8{ "npm", "npx", "node", "nodejs" };
const go_tools = [_][]const u8{ "go", "golang", "gofmt" };
const rust_tools = [_][]const u8{ "cargo", "rust", "rustup", "rustc" };

/// Which package caches the job mounts: those whose `tools` a `run:` script or an action's owner or
/// name names as a word (`setup-node`, `python3 -m pip`), and Zig's when `usesZig`. Each mount costs
/// every step engine time (about 45 ms of CPU for all of them), so a job pays only for those it
/// plausibly uses: a miss there costs a cold cache, the tool filling its directory under the home
/// directory as on a fresh machine. The tool cache is the exception, mounted for every job: it is
/// under /opt, where the step user cannot make it, so a miss there failed the job (v0.22.0: a
/// script file that installs into it, such as zig-runner's install-zig.sh, names it nowhere in the
/// workflow). A step's key holds its mounts, so a job's keys change only when its mounts do.
pub fn cachesUsed(job: job_mod.Job) [package_cache_dirs.len]bool {
    var used: [package_cache_dirs.len]bool = @splat(false);
    for (job.steps) |st| for (package_cache_dirs, &used) |d, *u| switch (st.action) {
        .script => |s| switch (s.script) {
            inline else => |t| u.* = u.* or namesAny(t, d.tools),
        },
        .uses => |a| u.* = u.* or std.mem.eql(u8, d.name, "toolcache") or
            namesAny(a.owner, d.tools) or namesAny(a.name, d.tools),
        else => {},
    };
    for (package_cache_dirs, &used) |d, *u| {
        if (std.mem.eql(u8, d.name, zig_packages)) u.* = usesZig(job);
        if (std.mem.eql(u8, d.name, "toolcache")) u.* = true;
    }
    return used;
}

/// Whether `text` holds one of `words` as a word of its own, ignoring case: no letter, digit or `_`
/// on either side, except digits after it (`python3`, `pip3`). So `go` is not in `cargo`.
fn namesAny(text: []const u8, words: []const []const u8) bool {
    for (words) |word| {
        var from: usize = 0;
        while (std.ascii.findIgnoreCasePos(text, from, word)) |at| : (from = at + 1) {
            const end = at + word.len;
            const before = at > 0 and
                (std.ascii.isAlphanumeric(text[at - 1]) or text[at - 1] == '_');
            const after = end < text.len and
                (std.ascii.isAlphabetic(text[end]) or text[end] == '_');
            if (!before and !after) return true;
        }
    }
    return false;
}

/// Which volumes the job shares: `repo`, the repository's trusted jobs', only for a job the runner
/// vouches for (`Options.trusted`, `trust.vouches`); every other job gets `untrusted`, so untrusted
/// code cannot plant content in the caches trusted jobs read (GitHub scopes its cache by branch for
/// the same reason). Several of them are not checked again on use (Go's module cache, Zig's local
/// cache, cargo's sources, the tool cache's binaries). It fails closed (#105): it used to give a
/// separate scope only to a pull request whose head repository was named and was another, so a
/// same-repository pull request, a `workflow_run` or `issue_comment` a fork triggered, or a fork's
/// pull request whose repository was deleted all shared `repo`. A fork's pull request stays apart
/// even on a runner that vouches for pull requests.
pub fn packageCacheScope(
    arena: Allocator,
    ev: *Evaluator,
    repository: []const u8,
    trusted: bool,
) ![]const u8 {
    if (!trusted) return "untrusted";
    const ctxs = [_]expr.Value.Entry{.{ .key = "github", .value = ev.github }};
    const head = expr.evalString(
        arena,
        "github.event.pull_request.head.repo.full_name",
        .{ .contexts = &ctxs },
    ) catch "";
    return if (head.len > 0 and !std.ascii.eqlIgnoreCase(head, repository)) "untrusted" else "repo";
}

// The Zig cache seed (`Options.zig_seeds`): the global cache `zig build --help` leaves on a trivial
// `build.zig`, so no Zig job compiles the build runner (Zig 0.17's "maker") itself: 104 s on one
// core and about 1 GB; a cold `zig build test` of zig-runner went from 146 s to 49 s (README.md).
// Zig trusts what it finds in `o/` without checking it, so the seed comes from trusted inputs only:
// the Zig tarball, checked against the pinned sha256 inside the exec, and a `build.zig` the runner
// writes. Nothing a job produced or can write goes in, which is why one seed may go to every
// repository's jobs, `repo` and `untrusted` alike, and what a job adds to it stays in that job
// (`writeCacheMounts`). The engine caches the exec by its recipe, so
// it runs once per engine, and Zig builds it bit for bit the same. Zig keys it on its version, the
// OS and ABI and the CPU model, which the exec's `zig` detects in the default image on the engine's
// host just as a job's does there.

/// The project the seed is built from, outside where Zig is unpacked: Zig names a file in its
/// cache relative to the first of its directories that holds it.
pub const zig_seed_project = "/zig-runner-seed";
pub const zig_seed_build_zig =
    \\const std = @import("std");
    \\pub fn build(b: *std.Build) void {
    \\    _ = b;
    \\}
    \\
;
/// Where the seed is built.
pub const zig_seed_dir = "/zig-seed";

/// The seed for this job, built or found in the engine's cache, when the runner has any (one per
/// verified Zig release, `Options.zig_seeds`), the job has cache volumes and it runs Zig
/// (`usesZig`), so no other job's recipe changes. With several, one directory holds them all: Zig
/// keys every entry on its version, so they do not collide. A seed that cannot be built is left
/// out, and with none the job runs unseeded, its global cache still its own. `note` says which,
/// for "Set up job".
fn zigSeedFor(
    arena: Allocator,
    transport: Transport,
    job: job_mod.Job,
    opts: Options,
    pulled: ?[]const u8,
    note: *?[]const u8,
) !?[]const u8 {
    if (!opts.package_caches or job.github.repository.len == 0 or !usesZig(job)) return null;
    const unverified = if (opts.zig_seeds_unverified.len == 0) "" else try std.fmt.allocPrint(
        arena,
        "; not seeded from Zig {s}: its tarball's signature was not verified",
        .{try std.mem.join(arena, ", ", opts.zig_seeds_unverified)},
    );
    if (opts.zig_seeds.len == 0) {
        if (unverified.len > 0) note.* = try std.fmt.allocPrint(
            arena,
            "Zig global cache not seeded, this job's own{s}",
            .{unverified},
        );
        return null;
    }
    var ids: std.ArrayList([]const u8) = .empty;
    var seeded: std.ArrayList(u8) = .empty;
    var msg: []const u8 = "";
    for (opts.zig_seeds) |seed| {
        const doc = try zigSeedDocument(arena, seed, opts.step_user == .runner, pulled);
        const data = gql(arena, transport, doc, &msg) catch continue;
        const id = jsonFindString(data, "sync") orelse continue;
        try ids.append(arena, id);
        if (seeded.items.len > 0) try seeded.appendSlice(arena, ", ");
        try seeded.appendSlice(arena, seed.version);
    }
    const id = switch (ids.items.len) {
        0 => null,
        1 => ids.items[0],
        else => merged: {
            var q: Query = .init(arena);
            try q.call("loadDirectoryFromID", .{ .id = ids.items[0] });
            for (ids.items[1..]) |more|
                try q.call("withDirectory", .{ .path = "/", .source = more });
            try q.leaf("sync");
            const data = gql(arena, transport, try q.finish(), &msg) catch break :merged null;
            break :merged jsonFindString(data, "sync");
        },
    };
    note.* = if (id != null)
        try std.fmt.allocPrint(
            arena,
            "Zig global cache seeded from Zig {s}{s}",
            .{ seeded.items, unverified },
        )
    else
        try std.fmt.allocPrint(arena, "Zig cache seed not built, running unseeded: {s}{s}", .{
            if (msg.len > 0) msg else "Dagger returned no directory",
            unverified,
        });
    return id;
}

/// The seed's query, evaluated (`sync`) where a failure leaves the job unseeded, not in the base
/// container. One writer for the job (`zigSeedFor`) and the pre-warm (`warmDocuments`), so both
/// send the same document and the seed the pre-warm built is the one the job finds.
fn zigSeedDocument(arena: Allocator, seed: config.ZigSeed, as_runner: bool, pulled: ?[]const u8) ![]const u8 {
    var q: Query = .init(arena);
    try q.open("container");
    try q.call("from", .{ .address = pulled orelse default_image });
    // The base container's own provisioning (curl and xz), which the engine has cached.
    if (pulled == null) try writeProvision(&q, as_runner);
    try q.call("withNewFile", .{
        .path = zig_seed_project ++ "/build.zig",
        .contents = zig_seed_build_zig,
    });
    const script = try zigSeedScript(arena, seed);
    try q.call("withExec", .{ .args = &[_][]const u8{ "sh", "-c", script } });
    try q.call("directory", .{ .path = zig_seed_dir });
    try q.leaf("sync");
    return q.finish();
}

/// The exec that builds the seed: Zig for the engine host's architecture (the runner's own: they
/// share a machine), checked against its pinned sha256 before it runs, then `zig build --help`,
/// and the cache without `tmp/`.
pub fn zigSeedScript(arena: Allocator, seed: config.ZigSeed) ![]const u8 {
    const tree = try std.fmt.allocPrint(
        arena,
        "zig-{s}-linux-{s}",
        .{ @tagName(builtin.cpu.arch), seed.version },
    );
    return std.fmt.allocPrint(
        arena,
        "set -e; cd /tmp; " ++
            "curl -fsSL -o zig.tar.xz {s}; " ++
            "echo '{s}  zig.tar.xz' | sha256sum -c --quiet; tar -xJf zig.tar.xz; cd {s}; " ++
            "ZIG_GLOBAL_CACHE_DIR={s} /tmp/{s}/zig build --help >/dev/null; rm -rf {s}/tmp",
        .{
            try zig_release.tarballUrl(arena, seed.version),
            seed.sha256,
            zig_seed_project,
            zig_seed_dir,
            tree,
            zig_seed_dir,
        },
    );
}

/// Whether a job looks like it runs Zig: a `run:` script or an action that names it
/// (`mlugg/setup-zig`). A miss runs the job unseeded, as before; a false hit costs its Zig volume
/// the seed's 60 MB.
pub fn usesZig(job: job_mod.Job) bool {
    for (job.steps) |st| switch (st.action) {
        .script => |s| switch (s.script) {
            inline else => |t| if (std.ascii.findIgnoreCase(t, "zig") != null) return true,
        },
        .uses => |u| if (std.ascii.findIgnoreCase(u.owner, "zig") != null or
            std.ascii.findIgnoreCase(u.name, "zig") != null) return true,
        else => {},
    };
    return false;
}

// The pre-warm (`loop.Warmer`): what every job of this runner builds before its first step and
// that depends on nothing of a job, built with no job at all, at startup and when the engine comes
// back after a restart, so the first job finds it in the engine's cache. The engine caches by
// recipe, so the documents are written by the job's own writers: the base container's from and
// provisioning nodes (`writeFrom`, `writeProvision`) and the Zig seed (`zigSeedDocument`). Nothing
// of a job goes in (no volume, mount, secret, registry credential nor workspace), so no scope's
// data can reach another through it.

/// The pre-warm's documents: the base container's prefix as `basePlan` derives it for a job with
/// cache volumes, evaluated (`sync`); what its image resolves to; and the Zig seed when a Zig job
/// would get one (one per verified seed); and the provisioned packages' fingerprint, on top of
/// the base, when provisioned.
const WarmDocuments = struct {
    base: []const u8,
    image_ref: []const u8,
    seeds: []const []const u8,
    packages: ?[]const u8,
};

fn warmDocuments(arena: Allocator, opts: Options, pulled: ?[]const u8) !WarmDocuments {
    const image = resolveImage(opts.image);
    const provision = opts.provision and std.mem.eql(u8, image, default_image);
    const as_runner = provision and opts.step_user == .runner;
    var docs: [2][]const u8 = undefined;
    for (&docs, [_][]const u8{ "sync", "stdout" }) |*doc, leaf| {
        var q: Query = .init(arena);
        try q.open("container");
        try writeFrom(
            &q,
            pulled orelse image,
            if (opts.package_caches and opts.zig_local_cache)
                zigLocalCacheEnv(as_runner, opts.zig_local_cache_max_mb)
            else
                null,
        );
        if (provision and pulled == null) try writeProvision(&q, as_runner);
        if (std.mem.eql(u8, leaf, "stdout")) try q.call("withExec", .{
            .args = &[_][]const u8{ "sh", "-c", package_fingerprint_script },
        });
        try q.leaf(leaf);
        doc.* = try q.finish();
    }
    var ref: Query = .init(arena);
    try ref.open("container");
    try ref.call("from", .{ .address = pulled orelse image });
    try ref.leaf("imageRef");
    const seeds = try arena.alloc([]const u8, if (opts.package_caches) opts.zig_seeds.len else 0);
    for (seeds, opts.zig_seeds[0..seeds.len]) |*doc, z|
        doc.* = try zigSeedDocument(arena, z, opts.step_user == .runner, pulled);
    return .{
        .base = docs[0],
        .image_ref = try ref.finish(),
        .seeds = seeds,
        .packages = if (provision) docs[1] else null,
    };
}

/// What the pre-warm built: the image as the engine resolved it (with its digest when the
/// registry gave one, as services do for a job's images), whether the seed was built too, and the
/// provisioned packages' fingerprint (`package_fingerprint_script`) when there is one.
pub const Warmed = struct {
    image: []const u8,
    seeded: bool,
    packages: ?[]const u8 = null,
    /// Set when the pre-provisioned image could not be pulled and apt provisioned instead
    /// (`provisioned.fallbackNote`).
    pulled_note: ?[]const u8 = null,
};

/// Sends the pre-warm's documents, the base container first. On failure the message is in
/// `err_msg`.
pub fn warm(arena: Allocator, transport: Transport, opts: Options, err_msg: *[]const u8) !Warmed {
    const image_name = resolveImage(opts.image);
    const provision = opts.provision and std.mem.eql(u8, image_name, default_image);
    const pulled = if (provision) try provisioned.reference(
        arena,
        opts.provisioned_image,
        opts.provisioned_pins,
        .of(opts.step_user == .runner),
    ) else null;
    var pulled_note: ?[]const u8 = null;
    var docs = try warmDocuments(arena, opts, pulled);
    _ = gql(arena, transport, docs.base, err_msg) catch |e| {
        // The pre-provisioned image could not be pulled: provision with apt, as before it.
        const ref = pulled orelse return error.BaseContainerFailed;
        pulled_note = try provisioned.fallbackNote(arena, ref, if (err_msg.len > 0) err_msg.* else @errorName(e));
        err_msg.* = "";
        docs = try warmDocuments(arena, opts, null);
        _ = gql(arena, transport, docs.base, err_msg) catch return error.BaseContainerFailed;
    };
    // The base is built: what is left is a name for the log, and the engine may refuse `imageRef`
    // for a container it just pulled, so a failure is the unpinned name, as a missing field is.
    var ignored: []const u8 = "";
    const image = if (gql(arena, transport, docs.image_ref, &ignored)) |ref|
        jsonFindString(ref, "imageRef") orelse resolveImage(opts.image)
    else |_|
        resolveImage(opts.image);
    // Only a name for the log: a fingerprint that cannot be read leaves it out.
    var packages: ?[]const u8 = null;
    if (docs.packages) |doc| {
        if (gql(arena, transport, doc, &ignored)) |r| {
            if (jsonFindString(r, "stdout")) |out| packages = std.mem.trim(u8, out, " \n");
        } else |_| {}
    }
    for (docs.seeds) |seed| _ = gql(arena, transport, seed, err_msg) catch
        return error.ZigSeedFailed;
    return .{ .image = image, .seeded = docs.seeds.len > 0, .packages = packages, .pulled_note = pulled_note };
}

test "the default image is provisioned with git; a custom image is left alone" {
    var a: std.heap.ArenaAllocator = .init(std.testing.allocator);
    defer a.deinit();
    const arena = a.allocator();
    var env: std.process.Environ.Map = .init(arena);
    const steps = [_]job_mod.Step{testStep("true")};
    for ([_]struct { image: []const u8, expect_provision: bool }{
        .{ .image = default_image, .expect_provision = true },
        .{ .image = "custom/image:1", .expect_provision = false },
    }) |case| {
        const answers = [_][]const u8{ base_answer, try exec(arena, "C1", 0, "") };
        var fake: FakeSession = .{ .answers = &answers, .arena = arena };
        var buf: [512]u8 = undefined;
        var w: std.Io.Writer = .fixed(&buf);
        var log: sink.LogSink = .{ .stdout = .{ .writer = &w } };
        _ = try run(arena, std.testing.io, &env, .{ .image = case.image, .test_session_argv = &.{ "sh", "-c", fake_child }, .test_transport = fake.transport() }, testJob(&steps), &log);
        const base = fake.seen.items[0];
        try std.testing.expect(braceBalanced(base));
        try std.testing.expectEqual(case.expect_provision, std.mem.indexOf(u8, base, "apt-get install") != null);
        try std.testing.expect(std.mem.indexOf(u8, base, case.image) != null);
    }
}

/// The pins of a pre-provisioned image published for the scripts this build has.
fn currentPins(arena: Allocator) !provisioned.Pins {
    const digest = "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";
    return .{
        .root = .{ .fingerprint = try arena.dupe(u8, &provisioned.fingerprint(.root)), .digest = digest },
        .runner = .{ .fingerprint = try arena.dupe(u8, &provisioned.fingerprint(.runner)), .digest = digest },
    };
}

/// A default-image job through the fake session, `answers` first: the documents sent and the log.
fn pulledRun(arena: Allocator, opts: Options, answers: []const []const u8) !SeedRun {
    var env: std.process.Environ.Map = .init(arena);
    const steps = [_]job_mod.Step{testStep("true")};
    const fake = try arena.create(FakeSession);
    fake.* = .{ .answers = answers, .arena = arena };
    const w = try arena.create(std.Io.Writer);
    w.* = .fixed(try arena.alloc(u8, 8192));
    var log: sink.LogSink = .{ .stdout = .{ .writer = w } };
    var o = opts;
    o.test_session_argv = &.{ "sh", "-c", fake_child };
    o.test_transport = fake.transport();
    _ = try run(arena, std.testing.io, &env, o, testJob(&steps), &log);
    return .{ .seen = fake.seen.items, .log = w.buffered() };
}

test "a pinned provisioned image is pulled instead of provisioning; a failed pull, or the setting, provisions" {
    var a: std.heap.ArenaAllocator = .init(std.testing.allocator);
    defer a.deinit();
    const arena = a.allocator();
    const pins = try currentPins(arena);
    const ref = (try provisioned.reference(arena, true, pins, .root)).?;
    const synced = "{\"data\":{\"container\":{\"from\":{\"sync\":\"C\"}}}}";
    const pulled_answers = [_][]const u8{ synced, base_answer, try exec(arena, "C1", 0, "") };

    // Pulled: the probe, then a base that starts from the image and runs no apt-get.
    const used = try pulledRun(arena, .{ .provisioned_pins = pins }, &pulled_answers);
    try std.testing.expect(std.mem.indexOf(u8, used.seen[0], ref) != null);
    try std.testing.expect(std.mem.indexOf(u8, used.seen[0], "sync") != null);
    try std.testing.expect(std.mem.indexOf(u8, used.seen[1], ref) != null);
    try std.testing.expect(std.mem.indexOf(u8, used.seen[1], "apt-get") == null);
    try std.testing.expect(std.mem.indexOf(u8, used.seen[1], "from(address:\"" ++ default_image) == null);
    try std.testing.expect(std.mem.indexOf(u8, used.log, "Provisioned image: ghcr.io/open-blue/zig-runner-base:") != null);

    // The registry cannot be reached: the base is provisioned as before, and "Set up job" says why.
    const refused = [_][]const u8{
        "{\"errors\":[{\"message\":\"failed to resolve source metadata: no route to host\"}]}",
        base_answer,
        try exec(arena, "C1", 0, ""),
    };
    const fell = try pulledRun(arena, .{ .provisioned_pins = pins }, &refused);
    try std.testing.expect(std.mem.indexOf(u8, fell.seen[1], "apt-get install") != null);
    try std.testing.expect(std.mem.indexOf(u8, fell.seen[1], ref) == null);
    try std.testing.expect(std.mem.indexOf(u8, fell.log, "could not pull ghcr.io/open-blue/zig-runner-base:") != null);
    try std.testing.expect(std.mem.indexOf(u8, fell.log, "no route to host") != null);
    try std.testing.expect(std.mem.indexOf(u8, fell.log, "provisioning with apt-get instead") != null);

    // RUNNER_PROVISIONED_IMAGE=false, a pin of another script and no pin: no probe, apt.
    const plain = [_][]const u8{ base_answer, try exec(arena, "C1", 0, "") };
    const stale: provisioned.Pins = .{
        .root = .{ .fingerprint = "000000000000", .digest = pins.root.digest },
        .runner = pins.runner,
    };
    for ([_]Options{
        .{ .provisioned_pins = pins, .provisioned_image = false },
        .{ .provisioned_pins = stale },
        .{},
    }) |o| {
        const r = try pulledRun(arena, o, &plain);
        try std.testing.expect(std.mem.indexOf(u8, r.seen[0], "apt-get install") != null);
        try std.testing.expect(std.mem.indexOf(u8, r.seen[0], provisioned.repository) == null);
        try std.testing.expect(std.mem.indexOf(u8, r.log, "Provisioned image") == null);
    }

    // The runner variant: its own image, which the step user's setup is already in.
    const runner_ref = (try provisioned.reference(arena, true, pins, .runner)).?;
    const as_runner = try pulledRun(arena, .{ .provisioned_pins = pins, .step_user = .runner }, &pulled_answers);
    try std.testing.expect(std.mem.indexOf(u8, as_runner.seen[1], runner_ref) != null);
    try std.testing.expect(std.mem.indexOf(u8, as_runner.seen[1], "useradd") == null);
    try std.testing.expect(std.mem.indexOf(u8, as_runner.seen[1], "withUser") != null);

    // A custom image is never swapped for it.
    const custom = try pulledRun(arena, .{ .provisioned_pins = pins, .image = "custom/image:1" }, &plain);
    try std.testing.expect(std.mem.indexOf(u8, custom.seen[0], provisioned.repository) == null);
}

test "the pre-warm builds the pulled image's base, and provisions when it cannot be pulled" {
    var a: std.heap.ArenaAllocator = .init(std.testing.allocator);
    defer a.deinit();
    const arena = a.allocator();
    const pins = try currentPins(arena);
    const ref = (try provisioned.reference(arena, true, pins, .root)).?;
    var msg: []const u8 = "";
    const built = "{\"data\":{\"container\":{\"from\":{\"sync\":\"C0\"}}}}";
    const named = "{\"data\":{\"container\":{\"from\":{\"imageRef\":\"" ++ "ghcr.io/x@sha256:1" ++ "\"}}}}";
    const stdout = "{\"data\":{\"container\":{\"from\":{\"withExec\":{\"stdout\":\"6980617ef435\\n\"}}}}}";

    const ok = [_][]const u8{ built, named, stdout };
    var fake: FakeSession = .{ .answers = &ok, .arena = arena };
    const pulled = try warm(arena, fake.transport(), .{ .provisioned_pins = pins }, &msg);
    try std.testing.expect(pulled.pulled_note == null);
    try std.testing.expect(std.mem.indexOf(u8, fake.seen.items[0], ref) != null);
    try std.testing.expect(std.mem.indexOf(u8, fake.seen.items[0], "apt-get") == null);

    const failing = [_][]const u8{
        "{\"errors\":[{\"message\":\"denied: not found\"}]}",
        built,
        named,
        stdout,
    };
    var refusing: FakeSession = .{ .answers = &failing, .arena = arena };
    const fell = try warm(arena, refusing.transport(), .{ .provisioned_pins = pins }, &msg);
    try std.testing.expect(std.mem.indexOf(u8, fell.pulled_note.?, "denied: not found") != null);
    try std.testing.expect(std.mem.indexOf(u8, refusing.seen.items[1], "apt-get install") != null);
    try std.testing.expect(std.mem.indexOf(u8, refusing.seen.items[1], ref) == null);
    try std.testing.expectEqualStrings("6980617ef435", fell.packages.?);

    // Off, or nothing pinned: one attempt, with apt, and a failure is the job's as before.
    var off: FakeSession = .{ .answers = &failing, .arena = arena };
    try std.testing.expectError(error.BaseContainerFailed, warm(arena, off.transport(), .{ .provisioned_pins = pins, .provisioned_image = false }, &msg));
    try std.testing.expectEqual(@as(usize, 1), off.seen.items.len);
}

test "a job without container:, or with the default's bare name, gets the pinned, provisioned default" {
    var a: std.heap.ArenaAllocator = .init(std.testing.allocator);
    defer a.deinit();
    const arena = a.allocator();
    var env: std.process.Environ.Map = .init(arena);
    const steps = [_]job_mod.Step{testStep("true")};
    var vols: std.Io.Writer.Allocating = .init(arena);
    try vols.writer.writeAll("{\"data\":{");
    for (package_cache_dirs, 0..) |_, i| try vols.writer.print("{s}\"c{d}\":{{\"id\":\"V{d}\"}}", .{ if (i == 0) "" else ",", i, i });
    try vols.writer.writeAll("}}");
    const other_digest = "ubuntu:24.04@sha256:0000000000000000000000000000000000000000000000000000000000000000";
    for ([_]struct { container: ?[]const u8, config: []const u8, image: []const u8, provision: bool }{
        .{ .container = null, .config = default_image, .image = default_image, .provision = true },
        // An older config that names the image keeps getting the default.
        .{ .container = null, .config = "ubuntu:24.04", .image = default_image, .provision = true },
        .{ .container = "ubuntu:24.04", .config = default_image, .image = default_image, .provision = true },
        // Another digest is the user's own image: used as is, not provisioned.
        .{ .container = other_digest, .config = default_image, .image = other_digest, .provision = false },
    }) |case| {
        var job = testJob(&steps);
        if (case.container) |c| job.container = .{ .name = "", .image = .{ .lit = c }, .env = &.{} };
        const answers = [_][]const u8{ vols.written(), base_answer };
        var fake: FakeSession = .{ .answers = &answers, .arena = arena };
        var buf: [4096]u8 = undefined;
        var w: std.Io.Writer = .fixed(&buf);
        var log: sink.LogSink = .{ .stdout = .{ .writer = &w } };
        // Only the base container matters here: the job stops when the answers run out.
        _ = try run(arena, std.testing.io, &env, .{ .image = case.config, .package_caches = true, .step_user = .runner, .test_session_argv = &.{ "sh", "-c", fake_child }, .test_transport = fake.transport() }, job, &log);
        const base = fake.seen.items[1];
        const from = try std.fmt.allocPrint(arena, "from(address:\"{s}\")", .{case.image});
        try std.testing.expect(std.mem.indexOf(u8, base, from) != null);
        // sudo, the runner user and git, as on GitHub (steps run as the runner user, the config's
        // default).
        for ([_][]const u8{ "apt-get install", " sudo ", " git ", "useradd", "/etc/sudoers.d/runner" }) |part|
            try std.testing.expectEqual(case.provision, std.mem.indexOf(u8, base, part) != null);
        // One tool cache for the release, whichever digest.
        try std.testing.expect(std.mem.indexOf(u8, fake.seen.items[0], "/toolcache/ubuntu:24.04/runner\")") != null or
            std.mem.indexOf(u8, fake.seen.items[0], "/toolcache/ubuntu:24.04\")") != null);
    }
}

test "the from and provisioning nodes are a byte prefix of every job's base document, and carry nothing of a job" {
    var a: std.heap.ArenaAllocator = .init(std.testing.allocator);
    defer a.deinit();
    const arena = a.allocator();
    var env: std.process.Environ.Map = .init(arena);
    const steps = [_]job_mod.Step{testStep("true")};
    var vols: std.Io.Writer.Allocating = .init(arena);
    try vols.writer.writeAll("{\"data\":{\"czl\":{\"id\":\"VZL\"},\"czb\":{\"id\":\"VZB\"}");
    for (package_cache_dirs, 0..) |_, i| try vols.writer.print(",\"c{d}\":{{\"id\":\"V{d}\"}}", .{ i, i });
    try vols.writer.writeAll("}}");
    for ([_]config.StepUser{ .runner, .root }) |step_user| {
        for ([_]bool{ true, false }) |zig_local| {
            for ([_][]const u8{ default_image, "custom/image:1" }) |image| {
                const answers = [_][]const u8{ vols.written(), base_answer, try exec(arena, "C1", 0, "") };
                var fake: FakeSession = .{ .answers = &answers, .arena = arena };
                var buf: [4096]u8 = undefined;
                var w: std.Io.Writer = .fixed(&buf);
                var log: sink.LogSink = .{ .stdout = .{ .writer = &w } };
                const res = try run(arena, std.testing.io, &env, .{
                    .image = image,
                    .package_caches = true,
                    .trusted = true,
                    .zig_local_cache = zig_local,
                    .step_user = step_user,
                    .test_session_argv = &.{ "sh", "-c", fake_child },
                    .test_transport = fake.transport(),
                }, testJob(&steps), &log);
                try std.testing.expect(res.succeeded);
                const base = fake.seen.items[1];
                try std.testing.expect(braceBalanced(base));
                // The same writers, with what `basePlan` derives from the options, and nothing else.
                const provision = std.mem.eql(u8, image, default_image);
                const as_runner = provision and step_user == .runner;
                var q: Query = .init(arena);
                try q.open("container");
                try writeFrom(&q, image, if (zig_local) zigLocalCacheEnv(as_runner, 0) else null);
                if (provision) try writeProvision(&q, as_runner);
                const prefix = q.fragment().text;
                try std.testing.expect(std.mem.startsWith(u8, base, prefix));
                // The pre-warm sends that prefix and evaluates it, and nothing else.
                const warm_docs = try warmDocuments(arena, .{
                    .image = image,
                    .package_caches = true,
                    .zig_local_cache = zig_local,
                    .step_user = step_user,
                }, null);
                try std.testing.expect(std.mem.startsWith(u8, warm_docs.base, prefix));
                try std.testing.expectEqualStrings("sync } } }", warm_docs.base[prefix.len..][0..10]);
                try std.testing.expect(warm_docs.seeds.len == 0);
                try std.testing.expectEqual(provision, std.mem.indexOf(u8, prefix, "apt-get install") != null);
                try std.testing.expectEqual(zig_local, std.mem.indexOf(u8, prefix, "ZIG_LOCAL_CACHE_DIR") != null);
                // Nothing of the job: no volume, mount, secret, file, registry credential, nor the
                // job's workspace (which the rest of the document makes), so the prefix can be
                // issued with no job at all. The provisioning script's own `mkdir -p` makes fixed
                // directories.
                const workspace = try jobWorkspace(arena, testJob(&steps));
                try std.testing.expect(std.mem.indexOf(u8, base, workspace) != null);
                for ([_][]const u8{
                    "experimentalPrivilegedNesting", "withMountedCache", "cacheVolume",
                    "setSecret",                     "withNewFile",      "withVolatileVariable",
                    "loadContainerFromID",           "withRegistryAuth", workspace,
                }) |job_only| try std.testing.expect(std.mem.indexOf(u8, prefix, job_only) == null);
            }
        }
    }
}

test "an action that cannot be resolved fails Set up job, and no step runs" {
    var a: std.heap.ArenaAllocator = .init(std.testing.allocator);
    defer a.deinit();
    const arena = a.allocator();
    var env: std.process.Environ.Map = .init(arena);
    // The second action's step would be skipped; GitHub resolves it anyway.
    var skipped = usesStep("gone", "Someone", "Gone", "v1", &.{});
    skipped.condition = "failure()";
    const steps = [_]job_mod.Step{ testStep("echo before"), usesStep("uv", "astral-sh", "setup-uv", "v10", &.{}), skipped };
    const job = testJob(&steps);
    const answers = [_][]const u8{
        base_answer,
        "{\"errors\":[{\"message\":\"git error: repository does not contain ref \\\"v10\\\"\"}]}",
        "{\"errors\":[{\"message\":\"git error: git authentication failed\"}]}",
    };
    var fake: FakeSession = .{ .answers = &answers, .arena = arena };
    var buf: [8192]u8 = undefined;
    var w: std.Io.Writer = .fixed(&buf);
    var log: sink.LogSink = .{ .stdout = .{ .writer = &w } };
    const res = try run(arena, std.testing.io, &env, .{ .test_session_argv = &.{ "sh", "-c", fake_child }, .test_transport = fake.transport() }, job, &log);
    try std.testing.expect(!res.succeeded and res.set_up_failed);
    try std.testing.expect(res.engine_error == null);
    for (res.steps) |r| try std.testing.expectEqual(Outcome.not_run, r.outcome);
    // Nothing ran: the base container and the two fetches were the only queries.
    try std.testing.expectEqual(@as(usize, 3), fake.seen.items.len);
    const out = w.buffered();
    try std.testing.expect(std.mem.indexOf(u8, out, "[job 0 step 0 stdout] ##[error]Unable to resolve action `astral-sh/setup-uv@v10`, unable to find version `v10`. Unable to resolve action someone/gone, repository not found") != null);
    try std.testing.expect(std.mem.indexOf(u8, out, "Complete job name") == null);
    try std.testing.expectEqual(@as(usize, 1), res.annotations.len);
}

test "uv's environment goes in its cache, with a .venv symlink to it" {
    var a: std.heap.ArenaAllocator = .init(std.testing.allocator);
    defer a.deinit();
    const arena = a.allocator();
    // Keyed by the ref, with anything else in a path turned into a dash.
    try std.testing.expectEqualStrings("/home/runner/.cache/uv/zig-runner-envs/refs-heads-main", try uvEnvPath(arena, "/home/runner/.cache/uv", "refs/heads/main"));
    try std.testing.expectEqualStrings("/c/zig-runner-envs/refs-pull-7-merge", try uvEnvPath(arena, "/c", "refs/pull/7/merge"));
    try std.testing.expectEqualStrings("/c/zig-runner-envs/default", try uvEnvPath(arena, "/c", ""));

    var env: std.process.Environ.Map = .init(arena);
    const steps = [_]job_mod.Step{testStep("uv sync")};
    var job = testJob(&steps);
    job.github.ref = "refs/heads/main";
    const vols = "{\"data\":{\"c0\":{\"id\":\"V\"},\"c1\":{\"id\":\"V\"},\"c2\":{\"id\":\"V\"},\"c3\":{\"id\":\"V\"},\"c4\":{\"id\":\"V\"},\"c5\":{\"id\":\"V\"},\"c6\":{\"id\":\"V\"},\"c7\":{\"id\":\"V\"},\"c8\":{\"id\":\"V\"},\"c9\":{\"id\":\"V\"},\"c10\":{\"id\":\"V\"},\"c11\":{\"id\":\"V\"},\"c12\":{\"id\":\"V\"},\"c13\":{\"id\":\"V\"},\"c14\":{\"id\":\"V\"},\"c15\":{\"id\":\"V\"},\"c16\":{\"id\":\"V\"}}}";
    const answers = [_][]const u8{ vols, base_answer, try exec(arena, "C1", 0, "") };
    var fake: FakeSession = .{ .answers = &answers, .arena = arena };
    var buf: [4096]u8 = undefined;
    var w: std.Io.Writer = .fixed(&buf);
    var log: sink.LogSink = .{ .stdout = .{ .writer = &w } };
    const res = try run(arena, std.testing.io, &env, .{ .step_user = .runner, .package_caches = true, .test_session_argv = &.{ "sh", "-c", fake_child }, .test_transport = fake.transport() }, job, &log);
    try std.testing.expect(res.succeeded);
    const base = fake.seen.items[1];
    const path = "/home/runner/.cache/uv/zig-runner-envs/refs-heads-main";
    try std.testing.expect(std.mem.indexOf(u8, base, "withEnvVariable(name:\"UV_PROJECT_ENVIRONMENT\",value:\"" ++ path ++ "\")") != null);
    // `uv venv` would otherwise fail on the second job for a ref, the environment being there already.
    try std.testing.expect(std.mem.indexOf(u8, base, "withEnvVariable(name:\"UV_VENV_CLEAR\",value:\"1\")") != null);
    try std.testing.expect(std.mem.indexOf(u8, base, "ln -sfn " ++ path ++ " /home/runner/work/r/r/.venv") != null);

    // Off: no variable, no link.
    var fake2: FakeSession = .{ .answers = &answers, .arena = arena };
    var w2: std.Io.Writer = .fixed(&buf);
    var log2: sink.LogSink = .{ .stdout = .{ .writer = &w2 } };
    _ = try run(arena, std.testing.io, &env, .{ .step_user = .runner, .package_caches = true, .uv_env_in_cache = false, .test_session_argv = &.{ "sh", "-c", fake_child }, .test_transport = fake2.transport() }, job, &log2);
    try std.testing.expect(std.mem.indexOf(u8, fake2.seen.items[1], "UV_PROJECT_ENVIRONMENT") == null);
    try std.testing.expect(std.mem.indexOf(u8, fake2.seen.items[1], "ln -sfn") == null);

    // With step caching, the environment stays in the workspace, where a replayed `uv sync`
    // restores it with the rest of the container, not in a volume another commit's job synced
    // (#70). uv's own cache is still mounted from its volume.
    var fake3: FakeSession = .{ .answers = &answers, .arena = arena };
    var w3: std.Io.Writer = .fixed(&buf);
    var log3: sink.LogSink = .{ .stdout = .{ .writer = &w3 } };
    const res3 = try run(arena, std.testing.io, &env, .{ .step_user = .runner, .package_caches = true, .step_cache = true, .test_session_argv = &.{ "sh", "-c", fake_child }, .test_transport = fake3.transport() }, job, &log3);
    try std.testing.expect(res3.succeeded);
    const cached = fake3.seen.items[1];
    try std.testing.expect(std.mem.indexOf(u8, cached, "UV_PROJECT_ENVIRONMENT") == null);
    try std.testing.expect(std.mem.indexOf(u8, cached, "UV_VENV_CLEAR") == null);
    try std.testing.expect(std.mem.indexOf(u8, cached, "ln -sfn") == null);
    try std.testing.expect(std.mem.indexOf(u8, cached, "zig-runner-envs") == null);
    try std.testing.expect(std.mem.indexOf(u8, cached, "withMountedCache(path:\"/home/runner/.cache/uv\"") != null);
    // The step's own query does not point uv at the volume either.
    try std.testing.expect(std.mem.indexOf(u8, fake3.seen.items[2], "UV_PROJECT_ENVIRONMENT") == null);
}

test "package caches: one volume per tool, keyed by repository, shared only by vouched-for jobs" {
    var a: std.heap.ArenaAllocator = .init(std.testing.allocator);
    defer a.deinit();
    const arena = a.allocator();
    var env: std.process.Environ.Map = .init(arena);
    const steps = [_]job_mod.Step{testStep("npm ci; zig build; go vet; ls $RUNNER_TOOL_CACHE")};
    const pr_head =
        \\{"github":{"t":2,"d":[{"k":"repository","v":"o/r"},{"k":"event","v":{"t":2,"d":[
    ++
        \\{"k":"pull_request","v":{"t":2,"d":[{"k":"head","v":
    ;
    const pr_tail = "}]}}]}}]}}";
    const head_repo =
        \\{"t":2,"d":[{"k":"repo","v":{"t":2,"d":[{"k":"full_name","v":
    ;
    const fork_ctx = pr_head ++ head_repo ++ "\"someone/r\"}]}}]}" ++ pr_tail;
    const same_repo_ctx = pr_head ++ head_repo ++ "\"o/r\"}]}}]}" ++ pr_tail;
    // A fork's pull request whose repository was deleted: GitHub sends `head.repo: null`.
    const deleted_ctx = pr_head ++ "{\"t\":2,\"d\":[{\"k\":\"repo\",\"v\":null}]}" ++ pr_tail;
    const Case = struct { trusted: bool, ctx: ?[]const u8, scope: []const u8 };
    for ([_]Case{
        .{ .trusted = true, .ctx = null, .scope = "repo" },
        // A runner that vouches for pull requests (RUNNER_TRUSTED_EVENTS names them): its own.
        .{ .trusted = true, .ctx = same_repo_ctx, .scope = "repo" },
        // ...but not for a fork's, whatever the lists say.
        .{ .trusted = true, .ctx = fork_ctx, .scope = "untrusted" },
        // Not vouched for (`trust.vouches`): a same-repository pull request, an event the lists
        // do not name (`workflow_run`, `issue_comment`), any job on a `*` runner, and a fork's
        // pull request whose head repository is gone, which the old rule could not tell apart.
        .{ .trusted = false, .ctx = null, .scope = "untrusted" },
        .{ .trusted = false, .ctx = same_repo_ctx, .scope = "untrusted" },
        .{ .trusted = false, .ctx = deleted_ctx, .scope = "untrusted" },
        .{ .trusted = false, .ctx = fork_ctx, .scope = "untrusted" },
    }) |case| {
        var job = testJob(&steps);
        if (case.ctx) |ctx| {
            job.context_data = try std.json.parseFromSliceLeaky(std.json.Value, arena, ctx, .{});
        }
        var vols: std.Io.Writer.Allocating = .init(arena);
        try vols.writer.writeAll("{\"data\":{");
        for (package_cache_dirs, 0..) |_, i| try vols.writer.print("{s}\"c{d}\":{{\"id\":\"V{d}\"}}", .{ if (i == 0) "" else ",", i, i });
        try vols.writer.writeAll("}}");
        const answers = [_][]const u8{ vols.written(), base_answer, try exec(arena, "C1", 0, "") };
        var fake: FakeSession = .{ .answers = &answers, .arena = arena };
        var buf: [1024]u8 = undefined;
        var w: std.Io.Writer = .fixed(&buf);
        var log: sink.LogSink = .{ .stdout = .{ .writer = &w } };
        const res = try run(arena, std.testing.io, &env, .{ .package_caches = true, .trusted = case.trusted, .test_session_argv = &.{ "sh", "-c", fake_child }, .test_transport = fake.transport() }, job, &log);
        try std.testing.expect(res.succeeded);
        const scope = case.scope;
        try std.testing.expect(std.mem.indexOf(u8, fake.seen.items[0], try std.fmt.allocPrint(arena, "c1: cacheVolume(key:\"zig-runner/o/r/{s}/npm\")", .{scope})) != null);
        // The tool cache is also keyed by the job's image (its binaries are built for it), by
        // name: the pinned default's key is the one it had before the pin, and a digest update
        // keeps it.
        try std.testing.expect(std.mem.indexOf(u8, fake.seen.items[0], try std.fmt.allocPrint(arena, "c0: cacheVolume(key:\"zig-runner/o/r/{s}/toolcache/ubuntu:24.04\")", .{scope})) != null);
        try std.testing.expect(std.mem.indexOf(u8, fake.seen.items[0], try std.fmt.allocPrint(arena, "cacheVolume(key:\"zig-runner/o/r/{s}/zig-packages\")", .{scope})) != null);
        // Asked for by key alone: a `source:` seed would put a Directory ID into every step's
        // recipe, so one may only ever be a trusted, pinned input (proofs/README.md, `Key` row).
        try std.testing.expect(std.mem.indexOf(u8, fake.seen.items[0], "source:") == null);
        try std.testing.expect(std.mem.indexOf(u8, fake.seen.items[0], "sharing:") == null);
        // Mounted on the base container, so every step has them.
        try std.testing.expect(std.mem.indexOf(u8, fake.seen.items[1], "withMountedCache(path:\"/opt/hostedtoolcache\",cache:\"V0\")") != null);
        try std.testing.expect(std.mem.indexOf(u8, fake.seen.items[1], "withMountedCache(path:\"/root/.npm\",cache:\"V1\")") != null);
        try std.testing.expect(std.mem.indexOf(u8, fake.seen.items[1], "withMountedCache(path:\"/root/.cache/zig/p\",cache:\"V11\")") != null);
        // Zig's local cache stays in the workspace unless `zig_local_cache` is on.
        try std.testing.expect(std.mem.indexOf(u8, fake.seen.items[0], "zig-local") == null);
        try std.testing.expect(std.mem.indexOf(u8, fake.seen.items[1], "ZIG_LOCAL_CACHE_DIR") == null);
        // State tools rewrite on every run stays out of the container's filesystem.
        try std.testing.expect(std.mem.indexOf(u8, fake.seen.items[1], "withMountedCache(path:\"/tmp/node-compile-cache\"") != null);
        try std.testing.expect(std.mem.indexOf(u8, fake.seen.items[1], "withMountedCache(path:\"/root/.config/go/telemetry\"") != null);
        try std.testing.expect(braceBalanced(fake.seen.items[1]));
    }
}

test "with zig_local_cache, Zig's local cache gets a volume of its own, outside the workspace" {
    var a: std.heap.ArenaAllocator = .init(std.testing.allocator);
    defer a.deinit();
    const arena = a.allocator();
    var env: std.process.Environ.Map = .init(arena);
    const steps = [_]job_mod.Step{testStep("zig build test")};
    const job = testJob(&steps);
    var vols: std.Io.Writer.Allocating = .init(arena);
    try vols.writer.writeAll("{\"data\":{\"czl\":{\"id\":\"VZL\"},\"czb\":{\"id\":\"VZB\"}");
    for (package_cache_dirs, 0..) |_, i| try vols.writer.print(",\"c{d}\":{{\"id\":\"V{d}\"}}", .{ i, i });
    try vols.writer.writeAll("}}");
    const answers = [_][]const u8{ vols.written(), base_answer, try exec(arena, "C1", 0, "") };
    var fake: FakeSession = .{ .answers = &answers, .arena = arena };
    var buf: [4096]u8 = undefined;
    var w: std.Io.Writer = .fixed(&buf);
    var log: sink.LogSink = .{ .stdout = .{ .writer = &w } };
    const res = try run(arena, std.testing.io, &env, .{
        .package_caches = true,
        .trusted = true,
        .zig_local_cache = true,
        .step_user = .runner,
        .test_session_argv = &.{ "sh", "-c", fake_child },
        .test_transport = fake.transport(),
    }, job, &log);
    try std.testing.expect(res.succeeded);
    const keys = fake.seen.items[0];
    const base = fake.seen.items[1];
    try std.testing.expect(braceBalanced(base));
    // Apart from the global cache's volume, so the engine can collect it alone.
    try std.testing.expect(std.mem.indexOf(u8, keys, "czl: cacheVolume(key:\"zig-runner/o/r/repo/zig-local/runner\")") != null);
    try std.testing.expect(std.mem.indexOf(u8, base, "withEnvVariable(name:\"ZIG_LOCAL_CACHE_DIR\",value:\"/home/runner/.cache/zig-local\")") != null);
    try std.testing.expect(std.mem.indexOf(u8, base, "withMountedCache(path:\"/home/runner/.cache/zig-local\",cache:\"VZL\",owner:\"runner\")") != null);
    // The `builtin.zig` files its manifests name are kept too, in the global cache's `b/`.
    try std.testing.expect(std.mem.indexOf(u8, keys, "czb: cacheVolume(key:\"zig-runner/o/r/repo/zig-builtin/runner\")") != null);
    try std.testing.expect(std.mem.indexOf(u8, base, "withMountedCache(path:\"/home/runner/.cache/zig/b\",cache:\"VZB\",owner:\"runner\")") != null);
}

test "with zig_local_cache, an untrusted job's Zig local cache is its own: no volume, a Set up job note" {
    var a: std.heap.ArenaAllocator = .init(std.testing.allocator);
    defer a.deinit();
    const arena = a.allocator();
    var env: std.process.Environ.Map = .init(arena);
    const steps = [_]job_mod.Step{testStep("zig build test")};
    var vols: std.Io.Writer.Allocating = .init(arena);
    try vols.writer.writeAll("{\"data\":{");
    for (package_cache_dirs, 0..) |_, i| try vols.writer.print("{s}\"c{d}\":{{\"id\":\"V{d}\"}}", .{ if (i == 0) "" else ",", i, i });
    try vols.writer.writeAll("}}");
    const answers = [_][]const u8{ vols.written(), base_answer, try exec(arena, "C1", 0, "") };
    var fake: FakeSession = .{ .answers = &answers, .arena = arena };
    var buf: [4096]u8 = undefined;
    var w: std.Io.Writer = .fixed(&buf);
    var log: sink.LogSink = .{ .stdout = .{ .writer = &w } };
    const res = try run(arena, std.testing.io, &env, .{
        .package_caches = true,
        .trusted = false,
        .zig_local_cache = true,
        .zig_local_cache_max_mb = 4096,
        .step_user = .runner,
        .test_session_argv = &.{ "sh", "-c", fake_child },
        .test_transport = fake.transport(),
    }, testJob(&steps), &log);
    try std.testing.expect(res.succeeded);
    // No volume asked for or mounted, and no roll (its own exec, which would be a query of its own).
    try std.testing.expectEqual(@as(usize, 3), fake.seen.items.len);
    for (fake.seen.items) |d| try std.testing.expect(std.mem.indexOf(u8, d, "zig-local\",cache:") == null and std.mem.indexOf(u8, d, "czl") == null);
    // The same variable as a `repo` job's, so the base container is the pre-warm's.
    try std.testing.expect(std.mem.indexOf(u8, fake.seen.items[1], "withEnvVariable(name:\"ZIG_LOCAL_CACHE_DIR\",value:\"/home/runner/.cache/zig-local/current\")") != null);
    try std.testing.expect(std.mem.indexOf(u8, w.buffered(), "Zig local cache: this job's own (not kept between untrusted jobs)") != null);
}

/// The `withMountedCache(...)` call of a document that mounts the volume `cache` (quoted).
fn mountArgs(doc: []const u8, cache: []const u8) ?[]const u8 {
    var at: usize = 0;
    while (std.mem.indexOfPos(u8, doc, at, "withMountedCache(")) |start| {
        const end = std.mem.indexOfScalarPos(u8, doc, start, ')') orelse return null;
        const call = doc[start .. end + 1];
        if (std.mem.indexOf(u8, call, cache) != null) return call;
        at = end;
    }
    return null;
}

test "with a limit, Zig's local cache rolls before the base container, under one path every job shares" {
    var a: std.heap.ArenaAllocator = .init(std.testing.allocator);
    defer a.deinit();
    const arena = a.allocator();
    var env: std.process.Environ.Map = .init(arena);
    const steps = [_]job_mod.Step{testStep("zig build test")};
    var vols: std.Io.Writer.Allocating = .init(arena);
    try vols.writer.writeAll("{\"data\":{\"czl\":{\"id\":\"VZL\"},\"czb\":{\"id\":\"VZB\"}");
    for (package_cache_dirs, 0..) |_, i| try vols.writer.print(",\"c{d}\":{{\"id\":\"V{d}\"}}", .{ i, i });
    try vols.writer.writeAll("}}");
    var bases: [2][]const u8 = undefined;
    for (&bases, [_][]const u8{ "R1", "R2" }) |*base, marker| {
        // The roll failing does not fail the job.
        const answers = [_][]const u8{
            vols.written(),
            "{\"errors\":[{\"message\":\"no space left\"}]}",
            base_answer,
            try exec(arena, "C1", 0, ""),
        };
        var fake: FakeSession = .{ .answers = &answers, .arena = arena };
        var buf: [4096]u8 = undefined;
        var w: std.Io.Writer = .fixed(&buf);
        var log: sink.LogSink = .{ .stdout = .{ .writer = &w } };
        const opts: Options = .{
            .package_caches = true,
            .trusted = true,
            .zig_local_cache = true,
            .zig_local_cache_max_mb = 4096,
            .step_user = .runner,
            .test_ran_marker = marker,
            .test_session_argv = &.{ "sh", "-c", fake_child },
            .test_transport = fake.transport(),
        };
        const res = try run(arena, std.testing.io, &env, opts, testJob(&steps), &log);
        try std.testing.expect(res.succeeded);
        const roll = fake.seen.items[1];
        base.* = fake.seen.items[2];
        try std.testing.expect(braceBalanced(roll));
        // The volume, the limit in KB and the step user's id; the job's marker keeps the engine
        // from reusing the exec.
        try std.testing.expect(std.mem.indexOf(u8, roll, "\"zig-local-roll\",\"/home/runner/.cache/zig-local\",\"4194304\",\"1001:1001\"") != null);
        // The roll mounts the volume byte for byte as the steps do: the engine keeps a store per
        // owner, and a roll under another one rolls a volume no step reads.
        const mount = "withMountedCache(path:\"/home/runner/.cache/zig-local\",cache:\"VZL\",owner:\"runner\")";
        try std.testing.expectEqualStrings(mountArgs(base.*, "\"VZL\"").?, mountArgs(roll, "\"VZL\"").?);
        try std.testing.expectEqualStrings(mount, mountArgs(roll, "\"VZL\"").?);
        // As the step user, who exists only in the provisioned image.
        try std.testing.expect(std.mem.indexOf(u8, roll, "useradd -m -u 1001") != null);
        try std.testing.expect(std.mem.indexOf(u8, roll, marker) != null);
        try std.testing.expect(std.mem.indexOf(u8, base.*, "zig-local-roll") == null);
        try std.testing.expect(std.mem.indexOf(u8, base.*, "withEnvVariable(name:\"ZIG_LOCAL_CACHE_DIR\",value:\"/home/runner/.cache/zig-local/current\")") != null);
        try std.testing.expect(std.mem.indexOf(u8, base.*, "withMountedCache(path:\"/home/runner/.cache/zig-local\",cache:\"VZL\",owner:\"runner\")") != null);
        // The pre-warm's prefix is still the base container's.
        var q: Query = .init(arena);
        try q.open("container");
        try writeFrom(&q, default_image, zigLocalCacheEnv(true, opts.zig_local_cache_max_mb));
        try writeProvision(&q, true);
        const prefix = q.fragment().text;
        try std.testing.expect(std.mem.startsWith(u8, base.*, prefix));
        try std.testing.expect(std.mem.startsWith(u8, (try warmDocuments(arena, opts, null)).base, prefix));
    }
    // Up to the job's mark, two jobs' base containers are one: the generation is in neither, so it
    // reaches no step's key.
    const cut = std.mem.indexOf(u8, bases[0], mark_env).?;
    try std.testing.expectEqualStrings(bases[0][0..cut], bases[1][0..cut]);
}

const test_zig_seed: config.ZigSeed = .{
    .version = "0.17.0",
    .sha256 = "1cbe9df9f27e6b78d14ccbca43b6703a404ef79ef1c463de901d7f088d4e2026",
};
const seed_answer = "{\"data\":{\"container\":{\"from\":{\"withExec\":{\"withNewFile\":{\"withExec\":{\"directory\":{\"sync\":\"SEED\"}}}}}}}}";

/// One job through the fake session, `seed` answering the seed query when one is expected: the
/// documents sent, and the job's log.
const SeedRun = struct {
    seen: []const []const u8,
    log: []const u8,

    /// `text` with this job's random `mark_env` value replaced, so two jobs' documents compare.
    fn masked(r: SeedRun, arena: Allocator, text: []const u8) ![]const u8 {
        const prefix = mark_env ++ "\",value:\"";
        for (r.seen) |d| if (std.mem.indexOf(u8, d, prefix)) |at| {
            const rest = d[at + prefix.len ..];
            const mark = rest[0..std.mem.indexOfScalar(u8, rest, '"').?];
            return std.mem.replaceOwned(u8, arena, text, mark, "MARK");
        };
        return text;
    }
};
fn seedRun(arena: Allocator, opts: Options, job: job_mod.Job, seeds: []const []const u8) !SeedRun {
    var env: std.process.Environ.Map = .init(arena);
    var vols: std.Io.Writer.Allocating = .init(arena);
    try vols.writer.writeAll("{\"data\":{");
    for (package_cache_dirs, 0..) |_, i| try vols.writer.print("{s}\"c{d}\":{{\"id\":\"V{d}\"}}", .{ if (i == 0) "" else ",", i, i });
    try vols.writer.writeAll("}}");
    var answers: std.ArrayList([]const u8) = .empty;
    try answers.appendSlice(arena, seeds);
    if (opts.package_caches) try answers.append(arena, vols.written());
    try answers.appendSlice(arena, &.{ base_answer, try exec(arena, "C1", 0, "") });
    const fake = try arena.create(FakeSession);
    fake.* = .{ .answers = answers.items, .arena = arena };
    const buf = try arena.alloc(u8, 16 * 1024);
    const w = try arena.create(std.Io.Writer);
    w.* = .fixed(buf);
    var log: sink.LogSink = .{ .stdout = .{ .writer = w } };
    var o = opts;
    o.test_session_argv = &.{ "sh", "-c", fake_child };
    o.test_transport = fake.transport();
    const res = try run(arena, std.testing.io, &env, o, job, &log);
    try std.testing.expect(res.succeeded);
    return .{ .seen = fake.seen.items, .log = w.buffered() };
}

test "with the Zig local cache and a seed, the volume of builtin.zig files starts with the seed's own, apart from the job" {
    var a: std.heap.ArenaAllocator = .init(std.testing.allocator);
    defer a.deinit();
    const arena = a.allocator();
    var env: std.process.Environ.Map = .init(arena);
    const steps = [_]job_mod.Step{testStep("zig build test")};
    var vols: std.Io.Writer.Allocating = .init(arena);
    try vols.writer.writeAll("{\"data\":{\"czl\":{\"id\":\"VZL\"},\"czb\":{\"id\":\"VZB\"}");
    for (package_cache_dirs, 0..) |_, i| try vols.writer.print(",\"c{d}\":{{\"id\":\"V{d}\"}}", .{ i, i });
    try vols.writer.writeAll("}}");
    const answers = [_][]const u8{ seed_answer, vols.written(), "{\"data\":{}}", base_answer, try exec(arena, "C1", 0, "") };
    var fake: FakeSession = .{ .answers = &answers, .arena = arena };
    var buf: [4096]u8 = undefined;
    var w: std.Io.Writer = .fixed(&buf);
    var log: sink.LogSink = .{ .stdout = .{ .writer = &w } };
    const res = try run(arena, std.testing.io, &env, .{
        .package_caches = true,
        .trusted = true,
        .zig_local_cache = true,
        .zig_seeds = &.{test_zig_seed},
        .step_user = .runner,
        .test_ran_marker = "R1",
        .test_session_argv = &.{ "sh", "-c", fake_child },
        .test_transport = fake.transport(),
    }, testJob(&steps), &log);
    try std.testing.expect(res.succeeded);
    const fill = fake.seen.items[2];
    const base = fake.seen.items[3];
    try std.testing.expect(braceBalanced(fill));
    // The volume mounted as the steps mount it, the seed beside it, copied in without replacing.
    const mount = "withMountedCache(path:\"/home/runner/.cache/zig/b\",cache:\"VZB\",owner:\"runner\")";
    try std.testing.expectEqualStrings(mount, mountArgs(fill, "\"VZB\"").?);
    try std.testing.expectEqualStrings(mount, mountArgs(base, "\"VZB\"").?);
    try std.testing.expect(std.mem.indexOf(u8, fill, "withMountedDirectory(path:\"/zig-seed\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, fill, "cp -an") != null);
    try std.testing.expect(std.mem.indexOf(u8, fill, "\"/zig-seed/b\",\"1001:1001\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, fill, "R1") != null);
    // In the job it comes after the seed, whose `b/` its mount hides.
    try std.testing.expect(std.mem.indexOf(u8, base, "withMountedDirectory(path:\"/home/runner/.cache/zig\"").? <
        std.mem.indexOf(u8, base, mount).?);
}

test "the Zig cache seed: built from pinned, runner-written inputs, the same for every scope, on the Zig volume only" {
    var a: std.heap.ArenaAllocator = .init(std.testing.allocator);
    defer a.deinit();
    const arena = a.allocator();
    const steps = [_]job_mod.Step{testStep("zig build test")};
    var first: ?[]const u8 = null;
    for ([_]struct { trusted: bool, scope: []const u8, user: config.StepUser }{
        .{ .trusted = true, .scope = "repo", .user = .root },
        .{ .trusted = false, .scope = "untrusted", .user = .root },
        .{ .trusted = true, .scope = "repo", .user = .runner },
    }) |case| {
        var job = testJob(&steps);
        // Another repository's job gets the same seed too.
        if (case.user == .runner) job.github.repository = "other/repo";
        const r = try seedRun(arena, .{ .package_caches = true, .trusted = case.trusted, .step_user = case.user, .zig_seeds = &.{test_zig_seed} }, job, &.{seed_answer});
        const seed_q = r.seen[0];
        try std.testing.expect(braceBalanced(seed_q));
        // The inputs: the default image's provisioning, the tarball by URL and pinned sha256,
        // checked before Zig runs, and the runner's own build.zig.
        const url = "https://ziglang.org/download/0.17.0/zig-" ++ @tagName(builtin.cpu.arch) ++ "-linux-0.17.0.tar.xz";
        try std.testing.expect(std.mem.startsWith(u8, seed_q, "{ container { from(address:\"" ++ default_image ++ "\") { withExec(args:[\"sh\",\"-c\",\"apt-get update"));
        try std.testing.expect(std.mem.indexOf(u8, seed_q, url) != null);
        const check = std.mem.indexOf(u8, seed_q, "echo '" ++ test_zig_seed.sha256 ++ "  zig.tar.xz' | sha256sum -c --quiet").?;
        const build = std.mem.indexOf(u8, seed_q, "ZIG_GLOBAL_CACHE_DIR=/zig-seed /tmp/zig-").?;
        try std.testing.expect(check < build);
        try std.testing.expect(std.mem.indexOf(u8, seed_q, "set -e;") != null);
        try std.testing.expect(std.mem.indexOf(u8, seed_q, "zig build --help >/dev/null; rm -rf /zig-seed/tmp\"]) { directory(path:\"/zig-seed\") { sync } } } } } }") != null);
        try std.testing.expect(std.mem.indexOf(u8, seed_q, "withNewFile(path:\"/zig-runner-seed/build.zig\",contents:\"const std = @import(\\\"std\\\");\\npub fn build(b: *std.Build) void {\\n    _ = b;\\n}\\n\")") != null);
        // Nothing of the job: not its repository, scope, workspace or commit.
        for ([_][]const u8{ job.github.repository, try std.fmt.allocPrint(arena, "/{s}/", .{case.scope}), try std.fmt.allocPrint(arena, "/home/runner/work/{s}", .{job.github.repository[std.mem.indexOfScalar(u8, job.github.repository, '/').? + 1 ..]}), job.github.sha, "cacheVolume", "loadContainerFromID" }) |job_text|
            try std.testing.expect(std.mem.indexOf(u8, seed_q, job_text) == null);
        // One seed for every scope and repository (the step user only picks which cached
        // provisioning it starts from).
        if (case.user == .root) {
            if (first) |f| try std.testing.expectEqualStrings(f, seed_q) else first = seed_q;
        }
        // The volumes are asked for as before: the seed goes on the mount, not into keys.
        const user_suffix: []const u8 = if (case.user == .runner) "/runner" else "";
        try std.testing.expect(std.mem.indexOf(u8, r.seen[1], try std.fmt.allocPrint(arena, "c11: cacheVolume(key:\"zig-runner/{s}/{s}/zig-packages{s}\")", .{ job.github.repository, case.scope, user_suffix })) != null);
        try std.testing.expect(std.mem.indexOf(u8, r.seen[1], "source:") == null);
        const base = r.seen[2];
        try std.testing.expect(braceBalanced(base));
        // The global cache is the seed as a directory of the job's own container, so what a job
        // writes there goes with it; only the package tarballs (`p/`, hashed again on unpack) are
        // in the volume.
        const mount = if (case.user == .runner)
            "withMountedDirectory(path:\"/home/runner/.cache/zig\",source:\"SEED\",owner:\"runner\") { withMountedCache(path:\"/home/runner/.cache/zig/p\",cache:\"V11\",owner:\"runner\")"
        else
            "withMountedDirectory(path:\"/root/.cache/zig\",source:\"SEED\") { withMountedCache(path:\"/root/.cache/zig/p\",cache:\"V11\")";
        try std.testing.expect(std.mem.indexOf(u8, base, mount) != null);
        try std.testing.expectEqual(@as(usize, 1), std.mem.count(u8, base, "\"SEED\""));
        try std.testing.expectEqual(@as(usize, 1), std.mem.count(u8, base, "cache:\"V11\""));
        try std.testing.expect(std.mem.indexOf(u8, base, "source:\"SEED\") { withExec") == null);
        try std.testing.expect(std.mem.indexOf(u8, base, "zig-seed") == null);
        // Before anything run-specific, so the seed's mount is in no run's key of its own.
        try std.testing.expect(std.mem.indexOf(u8, base, mount).? < std.mem.indexOf(u8, base, mark_env).?);
        try std.testing.expect(std.mem.indexOf(u8, r.log, "Zig global cache seeded from Zig 0.17.0") != null);
    }
}

test "the Zig cache seed changes nothing for a job without Zig, without caches, or with the knob off" {
    var a: std.heap.ArenaAllocator = .init(std.testing.allocator);
    defer a.deinit();
    const arena = a.allocator();
    const npm = [_]job_mod.Step{testStep("npm ci")};
    const zig = [_]job_mod.Step{testStep("zig build test")};
    for ([_]struct { steps: []const job_mod.Step, caches: bool }{
        .{ .steps = &npm, .caches = true },
        .{ .steps = &zig, .caches = false },
    }) |case| {
        const job = testJob(case.steps);
        const off = try seedRun(arena, .{ .package_caches = case.caches, .step_cache = true, .test_ran_marker = "j1" }, job, &.{});
        const on = try seedRun(arena, .{ .package_caches = case.caches, .step_cache = true, .test_ran_marker = "j1", .zig_seeds = &.{test_zig_seed} }, job, &.{});
        // Byte for byte what the runner sends without a seed, so no step key moves.
        try std.testing.expectEqual(off.seen.len, on.seen.len);
        for (off.seen, on.seen) |x, y| try std.testing.expectEqualStrings(try off.masked(arena, x), try on.masked(arena, y));
        try std.testing.expectEqualStrings(try off.masked(arena, off.log), try on.masked(arena, on.log));
    }
    // With the knob off, a Zig job sends what it always has: no seed query, no `source:`.
    const job = testJob(&zig);
    const r = try seedRun(arena, .{ .package_caches = true }, job, &.{});
    try std.testing.expectEqual(@as(usize, 3), r.seen.len);
    for (r.seen) |d| try std.testing.expect(std.mem.indexOf(u8, d, "zig-seed") == null and std.mem.indexOf(u8, d, "source:") == null);
    try std.testing.expect(std.mem.indexOf(u8, r.log, "Zig global cache") == null);
    // Unseeded, the global cache is in the job's container: only `p/` is in a volume.
    try std.testing.expect(std.mem.indexOf(u8, r.seen[1], "withMountedCache(path:\"/root/.cache/zig/p\",cache:\"V11\")") != null);
    try std.testing.expect(std.mem.indexOf(u8, r.seen[1], "path:\"/root/.cache/zig\"") == null);
}

test "several verified Zig releases seed one directory; one that did not verify is said and left out" {
    var a: std.heap.ArenaAllocator = .init(std.testing.allocator);
    defer a.deinit();
    const arena = a.allocator();
    const steps = [_]job_mod.Step{testStep("zig build test")};
    const older: config.ZigSeed = .{ .version = "0.16.0", .sha256 = test_zig_seed.sha256 };
    const second = try std.mem.replaceOwned(u8, arena, seed_answer, "SEED", "SEED2");
    const merged = "{\"data\":{\"loadDirectoryFromID\":{\"withDirectory\":{\"sync\":\"MERGED\"}}}}";
    const r = try seedRun(arena, .{
        .package_caches = true,
        .zig_seeds = &.{ test_zig_seed, older },
        .zig_seeds_unverified = &.{"0.15.2"},
    }, testJob(&steps), &.{ seed_answer, second, merged });
    try std.testing.expect(std.mem.indexOf(u8, r.seen[0], "/download/0.17.0/") != null);
    try std.testing.expect(std.mem.indexOf(u8, r.seen[1], "/download/0.16.0/") != null);
    try std.testing.expectEqualStrings("{ loadDirectoryFromID(id:\"SEED\") { withDirectory(path:\"/\",source:\"SEED2\") { sync } } }", r.seen[2]);
    try std.testing.expect(std.mem.indexOf(u8, r.seen[4], "withMountedDirectory(path:\"/root/.cache/zig\",source:\"MERGED\") { withMountedCache(path:\"/root/.cache/zig/p\",cache:\"V11\")") != null);
    try std.testing.expect(std.mem.indexOf(u8, r.log, "Zig global cache seeded from Zig 0.17.0, 0.16.0; not seeded from Zig 0.15.2: its tarball's signature was not verified") != null);
}

test "a Zig release whose signature did not verify is not seeded: the job's global cache is its own, and it says so" {
    var a: std.heap.ArenaAllocator = .init(std.testing.allocator);
    defer a.deinit();
    const arena = a.allocator();
    const steps = [_]job_mod.Step{testStep("zig build test")};
    const r = try seedRun(arena, .{ .package_caches = true, .zig_seeds_unverified = &.{"0.17.0"} }, testJob(&steps), &.{});
    try std.testing.expectEqual(@as(usize, 3), r.seen.len);
    try std.testing.expect(std.mem.indexOf(u8, r.seen[1], "path:\"/root/.cache/zig\"") == null);
    try std.testing.expect(std.mem.indexOf(u8, r.seen[1], "withMountedCache(path:\"/root/.cache/zig/p\",cache:\"V11\")") != null);
    try std.testing.expect(std.mem.indexOf(u8, r.log, "Zig global cache not seeded, this job's own; not seeded from Zig 0.17.0: its tarball's signature was not verified") != null);
}

test "a Zig cache seed that cannot be built leaves the job running, unseeded" {
    var a: std.heap.ArenaAllocator = .init(std.testing.allocator);
    defer a.deinit();
    const arena = a.allocator();
    const steps = [_]job_mod.Step{testStep("zig build test")};
    for ([_][]const u8{
        "{\"errors\":[{\"message\":\"process \\\"sh -c set -e\\\" did not complete successfully: exit code: 1\"}]}",
        "{\"data\":{}}",
    }) |answer| {
        const r = try seedRun(arena, .{ .package_caches = true, .zig_seeds = &.{test_zig_seed} }, testJob(&steps), &.{answer});
        try std.testing.expectEqual(@as(usize, 4), r.seen.len);
        try std.testing.expect(std.mem.indexOf(u8, r.seen[2], "source:") == null);
        try std.testing.expect(std.mem.indexOf(u8, r.seen[2], "zig-seed") == null);
        try std.testing.expect(std.mem.indexOf(u8, r.seen[2], "withMountedDirectory(path:\"/root/.cache/zig\"") == null);
        try std.testing.expect(std.mem.indexOf(u8, r.log, "Zig cache seed not built, running unseeded: ") != null);
    }
}

test "usesZig: a script or an action that names Zig" {
    const uses_setup = usesStep("s", "mlugg", "setup-zig", "v2", &.{});
    const uses_node = usesStep("s", "actions", "setup-node", "v4", &.{});
    try std.testing.expect(usesZig(testJob(&.{testStep("zig build test --summary all")})));
    try std.testing.expect(usesZig(testJob(&.{ testStep("echo hi"), uses_setup })));
    try std.testing.expect(!usesZig(testJob(&.{ testStep("npm ci"), uses_node })));
}

test "cachesUsed: a job mounts the caches of the tools it names, Zig's as usesZig decides, and the tool cache always" {
    const zig_only = cachesUsed(testJob(&.{testStep("zig build test --summary all")}));
    for (package_cache_dirs, zig_only) |d, u| {
        const want = std.mem.eql(u8, d.name, zig_packages) or std.mem.eql(u8, d.name, "toolcache");
        try std.testing.expectEqual(want, u);
    }
    // A script file that installs into the tool cache names it nowhere in the workflow (v0.22.0).
    const nothing = cachesUsed(testJob(&.{testStep(".github/scripts/install-tools.sh")}));
    for (package_cache_dirs, nothing) |d, u| {
        try std.testing.expectEqual(std.mem.eql(u8, d.name, "toolcache"), u);
    }
    // `go` is a word of its own: not in `cargo`, though it is in `setup-go`.
    const cargo = cachesUsed(testJob(&.{testStep("cargo build --release")}));
    for (package_cache_dirs, cargo) |d, u| {
        const want = std.mem.startsWith(u8, d.name, "cargo-") or std.mem.eql(u8, d.name, "toolcache");
        try std.testing.expectEqual(want, u);
    }
    const setup_go = cachesUsed(testJob(&.{usesStep("s", "actions", "setup-go", "v5", &.{})}));
    for (package_cache_dirs, setup_go) |d, u| {
        const go = std.mem.startsWith(u8, d.name, "go-") or std.mem.eql(u8, d.name, "toolcache");
        try std.testing.expectEqual(go, u);
    }
    try std.testing.expect(cachesUsed(testJob(&.{testStep("python3 -m pip install .")}))[4]);
}

test "a job that uses every cache mounts byte for byte what it did when every job mounted all" {
    var a: std.heap.ArenaAllocator = .init(std.testing.allocator);
    defer a.deinit();
    const arena = a.allocator();
    const steps = [_]job_mod.Step{
        testStep("hostedtoolcache; npm; pnpm; yarn; pip; uv; go; cargo; bun; zig; gradle; mvn"),
    };
    const used = cachesUsed(testJob(&steps));
    for (used) |u| try std.testing.expect(u);
    const ids = try arena.alloc([]const u8, package_cache_dirs.len);
    for (ids, 0..) |*id, i| id.* = try std.fmt.allocPrint(arena, "V{d}", .{i});
    var docs: [2][]const u8 = undefined;
    for (&docs, [_]bool{ false, true }) |*doc, decided| {
        var plan: BasePlan = .{
            .job_image = default_image,
            .provision = true,
            .as_runner = true,
            .step_cache = true,
            .uv_env = null,
            .cache_ids = ids,
            .ran_marker = "r",
            .mark = "m",
        };
        if (decided) plan.cache_used = used;
        var q: Query = .init(arena);
        try q.open("container");
        try writeCacheMounts(&q, arena, plan);
        try q.leaf("id");
        doc.* = try q.finish();
    }
    try std.testing.expectEqualStrings(docs[0], docs[1]);
    const mounts = std.mem.count(u8, docs[1], "withMountedCache");
    try std.testing.expectEqual(package_cache_dirs.len, mounts);
}

test "steps run as runner in the default image, as on GitHub, with their own package caches" {
    var a: std.heap.ArenaAllocator = .init(std.testing.allocator);
    defer a.deinit();
    const arena = a.allocator();
    var env: std.process.Environ.Map = .init(arena);
    const steps = [_]job_mod.Step{testStep("go test ./... && yarn && ls $RUNNER_TOOL_CACHE")};
    const job = testJob(&steps);
    var vols: std.Io.Writer.Allocating = .init(arena);
    try vols.writer.writeAll("{\"data\":{");
    for (package_cache_dirs, 0..) |_, i| try vols.writer.print("{s}\"c{d}\":{{\"id\":\"V{d}\"}}", .{ if (i == 0) "" else ",", i, i });
    try vols.writer.writeAll("}}");
    const answers = [_][]const u8{ vols.written(), base_answer, try exec(arena, "C1", 0, "") };
    var fake: FakeSession = .{ .answers = &answers, .arena = arena };
    var buf: [4096]u8 = undefined;
    var w: std.Io.Writer = .fixed(&buf);
    var log: sink.LogSink = .{ .stdout = .{ .writer = &w } };
    const res = try run(arena, std.testing.io, &env, .{ .package_caches = true, .trusted = true, .step_user = .runner, .test_session_argv = &.{ "sh", "-c", fake_child }, .test_transport = fake.transport() }, job, &log);
    try std.testing.expect(res.succeeded);
    const keys = fake.seen.items[0];
    const base = fake.seen.items[1];
    try std.testing.expect(braceBalanced(base));
    // Volumes of their own: root's hold files the user cannot write.
    try std.testing.expect(std.mem.indexOf(u8, keys, "cacheVolume(key:\"zig-runner/o/r/repo/npm/runner\")") != null);
    // Provisioned with the user (uid 1001, passwordless sudo, /github its own), then run as it.
    try std.testing.expect(std.mem.indexOf(u8, base, "useradd -m -u 1001 -s /bin/bash runner") != null);
    try std.testing.expect(std.mem.indexOf(u8, base, "runner ALL=(ALL) NOPASSWD:ALL") != null);
    // The caches' directories exist and are its own before they are mounted (Dagger would make the
    // parents of a mount as root).
    try std.testing.expect(std.mem.indexOf(u8, base, " /home/runner/go/pkg/mod ") != null);
    try std.testing.expect(std.mem.indexOf(u8, base, "chown -R runner:runner /github /home/runner") != null);
    try std.testing.expect(std.mem.indexOf(u8, base, "withUser(name:\"runner\") { withEnvVariable(name:\"HOME\",value:\"/home/runner\")") != null);
    // Caches under its home, owned by it; the tool cache stays where actions look for it.
    try std.testing.expect(std.mem.indexOf(u8, base, "withMountedCache(path:\"/home/runner/go/pkg/mod\",cache:\"V6\",owner:\"runner\")") != null);
    try std.testing.expect(std.mem.indexOf(u8, base, "withMountedCache(path:\"/home/runner/.cache/yarn\",cache:\"V3\",owner:\"runner\")") != null);
    try std.testing.expect(std.mem.indexOf(u8, base, "withMountedCache(path:\"/opt/hostedtoolcache\",cache:\"V0\",owner:\"runner\")") != null);
    try std.testing.expect(std.mem.indexOf(u8, base, "/root/") == null);
}

test "package caches in a container job: variables point the tools at the volumes, the image's own value winning" {
    var a: std.heap.ArenaAllocator = .init(std.testing.allocator);
    defer a.deinit();
    const arena = a.allocator();
    var env: std.process.Environ.Map = .init(arena);
    const steps = [_]job_mod.Step{testStep("go test ./...")};
    var job = testJob(&steps);
    job.container = .{ .name = "", .image = .{ .lit = "golang:1.25" }, .env = &.{.{ .name = "GOCACHE", .value = .{ .lit = "/tmp/gocache" } }} };
    var vols: std.Io.Writer.Allocating = .init(arena);
    try vols.writer.writeAll("{\"data\":{");
    for (package_cache_dirs, 0..) |_, i| try vols.writer.print("{s}\"c{d}\":{{\"id\":\"V{d}\"}}", .{ if (i == 0) "" else ",", i, i });
    try vols.writer.writeAll("}}");
    // Only the base container matters here: the job stops when the answers run out.
    const answers = [_][]const u8{ vols.written(), base_answer };
    var fake: FakeSession = .{ .answers = &answers, .arena = arena };
    var buf: [4096]u8 = undefined;
    var w: std.Io.Writer = .fixed(&buf);
    var log: sink.LogSink = .{ .stdout = .{ .writer = &w } };
    _ = try run(arena, std.testing.io, &env, .{ .package_caches = true, .test_session_argv = &.{ "sh", "-c", fake_child }, .test_transport = fake.transport() }, job, &log);
    const base = fake.seen.items[1];
    // The golang image's GOPATH is /go, not /root/go: the variable says where the volume is.
    try std.testing.expect(std.mem.indexOf(u8, base, "withEnvVariable(name:\"GOMODCACHE\",value:\"/root/go/pkg/mod\")") != null);
    try std.testing.expect(std.mem.indexOf(u8, base, "withMountedCache(path:\"/root/go/pkg/mod\"") != null);
    // A tool without such a variable gets none.
    try std.testing.expect(std.mem.indexOf(u8, base, "CARGO_HOME") == null);
    // The container's env comes after, so its GOCACHE is the one the steps see.
    const ours = std.mem.indexOf(u8, base, "withEnvVariable(name:\"GOCACHE\",value:\"/root/.cache/go-build\")").?;
    const theirs = std.mem.indexOf(u8, base, "withEnvVariable(name:\"GOCACHE\",value:\"/tmp/gocache\")").?;
    try std.testing.expect(ours < theirs);
    try std.testing.expect(braceBalanced(base));
}

test "the pre-warm sends a Zig job's own seed and base documents, and fails with Dagger's message" {
    var a: std.heap.ArenaAllocator = .init(std.testing.allocator);
    defer a.deinit();
    const arena = a.allocator();
    const steps = [_]job_mod.Step{testStep("zig build test")};
    for ([_]config.StepUser{ .runner, .root }) |user| {
        const opts: Options = .{ .package_caches = true, .step_user = user, .zig_seeds = &.{test_zig_seed} };
        const r = try seedRun(arena, opts, testJob(&steps), &.{seed_answer});
        const docs = try warmDocuments(arena, opts, null);
        // Byte for byte the job's seed query, so the engine answers the job from its cache.
        try std.testing.expectEqualStrings(r.seen[0], docs.seeds[0]);
        const prefix = docs.base[0..std.mem.indexOf(u8, docs.base, "sync ").?];
        try std.testing.expect(std.mem.startsWith(u8, r.seen[2], prefix));
        try std.testing.expect(std.mem.indexOf(u8, prefix, "apt-get install") != null);
        try std.testing.expect(braceBalanced(docs.base) and braceBalanced(docs.image_ref));

        const answers = [_][]const u8{
            "{\"data\":{\"container\":{\"from\":{\"withExec\":{\"sync\":\"C0\"}}}}}",
            "{\"data\":{\"container\":{\"from\":{\"imageRef\":\"docker.io/library/ubuntu:24.04@sha256:abc\"}}}}",
            "{\"data\":{\"container\":{\"from\":{\"withExec\":{\"withExec\":{\"stdout\":\"0123456789ab\\n\"}}}}}}",
            seed_answer,
        };
        var fake: FakeSession = .{ .answers = &answers, .arena = arena };
        var msg: []const u8 = "";
        const w = try warm(arena, fake.transport(), opts, &msg);
        try std.testing.expectEqualStrings("docker.io/library/ubuntu:24.04@sha256:abc", w.image);
        try std.testing.expect(w.seeded);
        try std.testing.expectEqualStrings("0123456789ab", w.packages.?);
        try std.testing.expectEqualStrings(docs.base, fake.seen.items[0]);
        // The fingerprint runs on top of the provisioned base, so the engine reuses it.
        try std.testing.expectEqualStrings(docs.packages.?, fake.seen.items[2]);
        try std.testing.expect(std.mem.startsWith(u8, docs.packages.?, prefix));
        try std.testing.expect(std.mem.indexOf(u8, docs.packages.?, "dpkg-query") != null);
        try std.testing.expectEqualStrings(docs.seeds[0], fake.seen.items[3]);
    }
    // No seed without package caches, as a job gets none; a pull that fails says why.
    const off = try warmDocuments(arena, .{ .zig_seeds = &.{test_zig_seed} }, null);
    try std.testing.expect(off.seeds.len == 0);
    // A custom image is not provisioned, so it has no fingerprint; the bare default name is the pin.
    try std.testing.expect((try warmDocuments(arena, .{ .image = "custom/image:1" }, null)).packages == null);
    const bare = try warmDocuments(arena, .{ .image = "ubuntu:24.04" }, null);
    try std.testing.expectEqualStrings((try warmDocuments(arena, .{}, null)).base, bare.base);
    try std.testing.expect(std.mem.indexOf(u8, bare.base, default_image) != null);
    const denied = [_][]const u8{"{\"errors\":[{\"message\":\"pull access denied\"}]}"};
    var fake: FakeSession = .{ .answers = &denied, .arena = arena };
    var msg: []const u8 = "";
    try std.testing.expectError(error.BaseContainerFailed, warm(arena, fake.transport(), .{}, &msg));
    try std.testing.expect(std.mem.indexOf(u8, msg, "pull access denied") != null);
    // The base built, then the engine refusing `imageRef`: the pinned name stands in for the digest.
    const refused = [_][]const u8{
        "{\"data\":{\"container\":{\"from\":{\"withExec\":{\"sync\":\"C0\"}}}}}",
        "{\"errors\":[{\"message\":\"Image reference can only be retrieved immediately\"}]}",
    };
    var refusing: FakeSession = .{ .answers = &refused, .arena = arena };
    const named = try warm(arena, refusing.transport(), .{}, &msg);
    try std.testing.expectEqualStrings(default_image, named.image);
}

/// A job run with the tool cache's trees checked, `check` the check exec's answer: what each query
/// asked for, and the job's log.
fn toolTreesRun(arena: Allocator, opts: Options, check: []const u8) !SeedRun {
    var env: std.process.Environ.Map = .init(arena);
    const steps = [_]job_mod.Step{testStep("zig build")};
    var vols: std.Io.Writer.Allocating = .init(arena);
    try vols.writer.writeAll("{\"data\":{\"ctt\":{\"id\":\"VT\"}");
    for (package_cache_dirs, 0..) |_, i| try vols.writer.print(",\"c{d}\":{{\"id\":\"V{d}\"}}", .{ i, i });
    try vols.writer.writeAll("}}");
    const set = "{\"data\":{\"loadContainerFromID\":{\"withEnvVariable\":{\"id\":\"C0T\"}}}}";
    const answers = try arena.dupe([]const u8, &.{ vols.written(), base_answer, check, set, try exec(arena, "C1", 0, "") });
    const fake = try arena.create(FakeSession);
    fake.* = .{ .answers = answers, .arena = arena };
    const w = try arena.create(std.Io.Writer);
    w.* = .fixed(try arena.alloc(u8, 8192));
    var log: sink.LogSink = .{ .stdout = .{ .writer = w } };
    var o = opts;
    o.package_caches = true;
    o.tool_trees = true;
    o.test_session_argv = &.{ "sh", "-c", fake_child };
    o.test_transport = fake.transport();
    o.test_ran_marker = "j1";
    const res = try run(arena, std.testing.io, &env, o, testJob(&steps), &log);
    try std.testing.expect(res.succeeded);
    return .{ .seen = fake.seen.items, .log = w.buffered() };
}

const zig_tree = tool_cache_dir ++ "/zig/0.17.0/zig-x86_64-linux-0.17.0";
const zig_digest = "310d0a4a95f328f94a350c4339226a4796daee589472b23f2a816d18874efaed";

test "a repo job's checked trees tell the seed registry the Zig versions its tool cache holds; an untrusted job's do not" {
    var a: std.heap.ArenaAllocator = .init(std.testing.allocator);
    defer a.deinit();
    const arena = a.allocator();
    const older = tool_cache_dir ++ "/zig/0.16.0/zig-x86_64-linux-0.16.0";
    const check = "{\"data\":{\"loadContainerFromID\":{\"withMountedCache\":{\"withUser\":{\"withEnvVariable\":{\"withExec\":{\"stdout\":\"" ++
        zig_digest ++ " " ++ zig_tree ++ " 19500 0\\n" ++ zig_digest ++ " " ++ older ++ " 19400 0\\n\"}}}}}}}";
    for ([_]bool{ true, false }) |trusted| {
        var reg: zig_release.Registry = .{ .io = std.testing.io, .gpa = arena, .client = null };
        try reg.add(.{ .seeds = &.{test_zig_seed}, .unverified = &.{} });
        _ = try toolTreesRun(arena, .{ .trusted = trusted, .nesting = false, .zig_seed_registry = &reg }, check);
        if (trusted) {
            try std.testing.expectEqual(@as(usize, 1), reg.pending.items.len);
            try std.testing.expectEqualStrings("0.16.0", reg.pending.items[0]);
        } else try std.testing.expectEqual(@as(usize, 0), reg.pending.items.len);
    }
}

test "the tool cache's trees are checked on a branch of their own, and steps get only the digests" {
    var a: std.heap.ArenaAllocator = .init(std.testing.allocator);
    defer a.deinit();
    const arena = a.allocator();
    const check = "{\"data\":{\"loadContainerFromID\":{\"withMountedCache\":{\"withUser\":" ++
        "{\"withEnvVariable\":{\"withExec\":{\"stdout\":\"" ++ zig_digest ++ " " ++ zig_tree ++
        " 19500 3\\n\"}}}}}}}";
    const r = try toolTreesRun(arena, .{ .trusted = true, .nesting = false }, check);
    try std.testing.expectEqual(5, r.seen.len);
    // The lists' volume sits beside the tool cache's, keyed like it.
    try std.testing.expect(std.mem.indexOf(u8, r.seen[0], "ctt: cacheVolume(key:\"zig-runner/o/r/repo/tool-trees/ubuntu:24.04\")") != null);
    // The check: on the base container, the lists mounted, as root, run in every job (the nonce),
    // with none of the job's environment, its stdout read.
    const c = r.seen[2];
    try std.testing.expect(braceBalanced(c));
    try std.testing.expect(std.mem.startsWith(u8, c, "{ loadContainerFromID(id:\"C0\") { withMountedCache(path:\"" ++ tool_trees_dir ++ "\",cache:\"VT\") { withUser(name:\"root\") { withEnvVariable(name:\"ZIG_RUNNER_TOOL_TREES_RUN\",value:\"j1\") { withExec(args:[\"/usr/bin/env\",\"-i\","));
    try std.testing.expect(std.mem.indexOf(u8, c, "\"tool_trees.sh\",\"/opt/hostedtoolcache\",\"" ++ tool_trees_dir ++ "\"]) { stdout ") != null);
    // Steps start from the base container with the digests set, not from the check's branch.
    try std.testing.expectEqualStrings("{ loadContainerFromID(id:\"C0\") { withEnvVariable(name:\"" ++ tool_trees_env ++ "\",value:\"" ++ zig_digest ++ " " ++ zig_tree ++ "\") { id } } }", r.seen[3]);
    try std.testing.expect(std.mem.indexOf(u8, r.seen[4], "loadContainerFromID(id:\"C0T\")") != null);
    // The lists' volume is in no query but the check's: not the base container's, not a step's.
    for (r.seen, 0..) |doc, i| if (i != 0 and i != 2) {
        try std.testing.expect(std.mem.indexOf(u8, doc, "\"VT\"") == null);
        try std.testing.expect(std.mem.indexOf(u8, doc, tool_trees_dir) == null);
    };
    try std.testing.expect(std.mem.indexOf(u8, r.log, "Tool cache: checked zig/0.17.0/zig-x86_64-linux-0.17.0 (19500 files, 3 read)") != null);
}

test "the tool cache's trees: a failed check sets the variable empty, and nesting means no check" {
    var a: std.heap.ArenaAllocator = .init(std.testing.allocator);
    defer a.deinit();
    const arena = a.allocator();
    const failed = try toolTreesRun(arena, .{ .nesting = false }, "{\"errors\":[{\"message\":\"bash: not found\"}]}");
    try std.testing.expect(std.mem.indexOf(u8, failed.seen[0], "zig-runner/o/r/untrusted/tool-trees/") != null);
    // Empty, so a workflow's own value does not stand in for the runner's: steps check themselves.
    try std.testing.expect(std.mem.indexOf(u8, failed.seen[3], "withEnvVariable(name:\"" ++ tool_trees_env ++ "\",value:\"\")") != null);
    try std.testing.expect(std.mem.indexOf(u8, failed.log, "Tool cache: not checked (bash: not found)") != null);

    // A trusted job with Dagger nesting: its steps could open the lists' volume by its key.
    var env: std.process.Environ.Map = .init(arena);
    const steps = [_]job_mod.Step{testStep("zig build")};
    var vols: std.Io.Writer.Allocating = .init(arena);
    try vols.writer.writeAll("{\"data\":{");
    for (package_cache_dirs, 0..) |_, i| try vols.writer.print("{s}\"c{d}\":{{\"id\":\"V{d}\"}}", .{ if (i == 0) "" else ",", i, i });
    try vols.writer.writeAll("}}");
    const answers = [_][]const u8{ vols.written(), base_answer, try exec(arena, "C1", 0, "") };
    var fake: FakeSession = .{ .answers = &answers, .arena = arena };
    var buf: [4096]u8 = undefined;
    var w: std.Io.Writer = .fixed(&buf);
    var log: sink.LogSink = .{ .stdout = .{ .writer = &w } };
    const res = try run(arena, std.testing.io, &env, .{ .package_caches = true, .tool_trees = true, .trusted = true, .nesting = true, .test_session_argv = &.{ "sh", "-c", fake_child }, .test_transport = fake.transport() }, testJob(&steps), &log);
    try std.testing.expect(res.succeeded);
    try std.testing.expectEqual(3, fake.seen.items.len);
    try std.testing.expect(std.mem.indexOf(u8, fake.seen.items[0], "tool-trees") == null);
    try std.testing.expect(std.mem.indexOf(u8, w.buffered(), "Tool cache") == null);
}

test "toolTreesVerdict keeps only well-formed lines for trees in the tool cache" {
    var a: std.heap.ArenaAllocator = .init(std.testing.allocator);
    defer a.deinit();
    const arena = a.allocator();
    const node = tool_cache_dir ++ "/node/22.1.0/x64";
    const out = zig_digest ++ " " ++ zig_tree ++ " 19500 0\n" ++
        // Outside the tool cache, through a dot-named directory, an odd path, a short digest,
        // uppercase hex, a missing or an extra field, a count that is not one: all left out.
        zig_digest ++ " /etc/x/y/z 1 1\n" ++
        zig_digest ++ " " ++ tool_cache_dir ++ "/zig/../../etc 1 1\n" ++
        zig_digest ++ " " ++ tool_cache_dir ++ "/a/b/c\"d 1 1\n" ++
        zig_digest[1..] ++ " " ++ node ++ " 1 1\n" ++
        "310D0A4A95F328F94A350C4339226A4796DAEE589472B23F2A816D18874EFAED " ++ node ++ " 1 1\n" ++
        zig_digest ++ " " ++ node ++ " 1\n" ++
        zig_digest ++ " " ++ node ++ " 1 1 1\n" ++
        zig_digest ++ " " ++ node ++ " 7 x\n" ++
        zig_digest ++ " " ++ node ++ " 7 7\n";
    const v = try toolTreesVerdict(arena, out);
    try std.testing.expectEqualStrings(zig_digest ++ " " ++ zig_tree ++ "\n" ++ zig_digest ++ " " ++ node, v.env);
    try std.testing.expectEqualStrings("Tool cache: checked zig/0.17.0/zig-x86_64-linux-0.17.0 (19500 files, 0 read), node/22.1.0/x64 (7 files, 7 read)", v.note);
    const none = try toolTreesVerdict(arena, "");
    try std.testing.expectEqualStrings("", none.env);
    try std.testing.expectEqualStrings("Tool cache: no trees to check", none.note);
}

/// A job of one step under step caching whose first answer is an earlier job's, with `path` its
/// $GITHUB_PATH and `env_line` its $GITHUB_ENV, and the tool cache's trees checked when `check`
/// is given (#229).
fn replayedToolPathRun(arena: Allocator, opts: Options, check: ?[]const u8, path: []const u8, env_line: []const u8) !SeedRun {
    var env: std.process.Environ.Map = .init(arena);
    // Naming it mounts the tool cache (`cachesUsed`).
    const steps = [_]job_mod.Step{testStep("./install-protoc.sh \"$RUNNER_TOOL_CACHE\"")};
    var vols: std.Io.Writer.Allocating = .init(arena);
    try vols.writer.writeAll(if (check != null) "{\"data\":{\"ctt\":{\"id\":\"VT\"}," else "{\"data\":{");
    for (package_cache_dirs, 0..) |_, i| try vols.writer.print("{s}\"c{d}\":{{\"id\":\"V{d}\"}}", .{ if (i == 0) "" else ",", i, i });
    try vols.writer.writeAll("}}");
    const replayed = try std.fmt.allocPrint(arena, "{{\"data\":{{\"loadContainerFromID\":{{\"withExec\":{{" ++
        "\"id\":\"C1\",\"exitCode\":0,\"stdout\":\"\",\"stderr\":\"\",\"fc_ran\":{{\"contents\":\"earlier-job\"}}," ++
        "\"fc_path\":{{\"contents\":\"{s}\\n\"}},\"fc_env\":{{\"contents\":\"{s}\\n\"}}}}}}}}}}", .{ path, env_line });
    const ran = "{\"data\":{\"loadContainerFromID\":{\"withExec\":{\"id\":\"C2\",\"exitCode\":0," ++
        "\"stdout\":\"\",\"stderr\":\"\",\"fc_ran\":{\"contents\":\"j1\"}}}}}";
    const set = "{\"data\":{\"loadContainerFromID\":{\"withEnvVariable\":{\"id\":\"C0T\"}}}}";
    const answers = if (check) |c|
        try arena.dupe([]const u8, &.{ vols.written(), base_answer, c, set, replayed, ran })
    else if (opts.package_caches)
        try arena.dupe([]const u8, &.{ vols.written(), base_answer, replayed, ran })
    else
        try arena.dupe([]const u8, &.{ base_answer, replayed, ran });
    const fake = try arena.create(FakeSession);
    fake.* = .{ .answers = answers, .arena = arena };
    const w = try arena.create(std.Io.Writer);
    w.* = .fixed(try arena.alloc(u8, 8192));
    var log: sink.LogSink = .{ .stdout = .{ .writer = w } };
    var o = opts;
    o.step_cache = true;
    o.tool_trees = check != null;
    o.test_session_argv = &.{ "sh", "-c", fake_child };
    o.test_transport = fake.transport();
    o.test_ran_marker = "j1";
    const res = try run(arena, std.testing.io, &env, o, testJob(&steps), &log);
    try std.testing.expect(res.succeeded);
    return .{ .seen = fake.seen.items, .log = w.buffered() };
}

test "step caching: a replayed step that put a tool cache directory no checked tree holds on PATH runs again" {
    var a: std.heap.ArenaAllocator = .init(std.testing.allocator);
    defer a.deinit();
    const arena = a.allocator();
    const protoc = tool_cache_dir ++ "/protoc/27.0/x64";
    const check_of = struct {
        fn f(comptime trees: []const u8) []const u8 {
            return "{\"data\":{\"loadContainerFromID\":{\"withMountedCache\":{\"withUser\":" ++
                "{\"withEnvVariable\":{\"withExec\":{\"stdout\":\"" ++ trees ++ "\"}}}}}}}";
        }
    }.f;
    const reason = "zig-runner runs this step every time: its record names " ++ protoc ++
        "/bin in the tool cache, where \\\"Set up job\\\" found no tree holding it";
    const opts: Options = .{ .package_caches = true, .trusted = true, .nesting = false };

    // The volume was pruned since the recorded run: "Set up job" found no protoc tree, as the
    // cold run that recorded the install found none, so the key matched. It runs again.
    const zig_only = check_of(zig_digest ++ " " ++ zig_tree ++ " 19500 0\\n");
    const gone = try replayedToolPathRun(arena, opts, zig_only, protoc ++ "/bin", "MODE=ci");
    try std.testing.expectEqual(6, gone.seen.len);
    try std.testing.expect(std.mem.indexOf(u8, gone.seen[4], "runs this step every time") == null);
    try std.testing.expect(std.mem.indexOf(u8, gone.seen[5], reason) != null);
    // The earlier run's PATH entry is never applied: the step that ran here sets its own.
    try std.testing.expect(std.mem.indexOf(u8, gone.seen[5], protoc ++ "/bin:") == null);

    // A $GITHUB_ENV value naming it, alone or in a list, does the same.
    const in_env = try replayedToolPathRun(arena, opts, zig_only, "/usr/local/bin", "PROTOC_HOME=/x:" ++ protoc ++ "/bin");
    try std.testing.expectEqual(6, in_env.seen.len);
    try std.testing.expect(std.mem.indexOf(u8, in_env.seen[5], reason) != null);

    // The tree is there: the replay stands.
    const protoc_tree = check_of(zig_digest ++ " " ++ protoc ++ " 12 0\\n");
    const held = try replayedToolPathRun(arena, opts, protoc_tree, protoc ++ "/bin", "PROTOC_HOME=" ++ protoc);
    try std.testing.expectEqual(5, held.seen.len);

    // A path that climbs out of a checked tree is not held by it, nor is a sibling's prefix.
    const climbs = try replayedToolPathRun(arena, opts, protoc_tree, protoc ++ "/../../gone/1/x64/bin", "MODE=ci");
    try std.testing.expectEqual(6, climbs.seen.len);
    const sibling = try replayedToolPathRun(arena, opts, protoc_tree, protoc ++ "-old/bin", "MODE=ci");
    try std.testing.expectEqual(6, sibling.seen.len);

    // Trees not checked: nothing says it is there, so it runs again.
    const unchecked = try replayedToolPathRun(arena, opts, null, protoc ++ "/bin", "MODE=ci");
    try std.testing.expectEqual(4, unchecked.seen.len);
    try std.testing.expect(std.mem.indexOf(u8, unchecked.seen[3], reason) != null);

    // Without package caches the tool cache is no volume: it went with the recorded container.
    const layer = try replayedToolPathRun(arena, .{}, null, protoc ++ "/bin", "MODE=ci");
    try std.testing.expectEqual(2, layer.seen.len);

    // Outside the tool cache, or the tool cache itself (the mount): the replay stands.
    const own = try replayedToolPathRun(arena, opts, check_of(""), "/usr/local/protoc/bin", "TOOLS=" ++ tool_cache_dir);
    try std.testing.expectEqual(5, own.seen.len);
}
