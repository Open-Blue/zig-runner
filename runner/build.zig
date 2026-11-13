const std = @import("std");

pub fn build(b: *std.Build) void {
    // `zig build test -Dsanitize-thread`: ThreadSanitizer reports data races the tests run into.
    const sanitize_thread = b.option(bool, "sanitize-thread", "Build with ThreadSanitizer") orelse null;
    // musl, as the release is, whatever the machine's libc: the network library is built for musl and
    // two libcs in one process is a crash (zig-modules.sh has the same default). ThreadSanitizer's
    // runtime needs glibc's loader (.github/scripts/zig-test.sh), so its builds take glibc.
    const target = b.standardTargetOptions(.{ .default_target = .{ .abi = if (sanitize_thread == true) .gnu else .musl } });
    const optimize = b.standardOptimizeOption(.{});
    // Release builds for deployment drop debug info (`zig build -Doptimize=ReleaseSafe -Dstrip`).
    const strip = b.option(bool, "strip", "Omit debug information") orelse null;
    // A position-independent executable, static still: the kernel loads it at a random address, so
    // its code is not where an exploit of the runner (root on prod, reading untrusted input) knows
    // to find it. On by default, so the release (build-binaries.sh, zig-modules.sh's -fPIE), the
    // image and a developer's build are the same binary; it costs 0-3% on the hot paths (docs/BENCHMARKS.md).
    const pie = b.option(bool, "pie", "Build a position-independent executable (default: true)") orelse true;

    // The build's own version, in every job's "Set up job" and in `--version`. Answering "which
    // binary is on that machine?" by comparing file sizes and timestamps is how an hour went
    // missing once; `git describe` answers it exactly.
    const version = b.createModule(.{ .root_source_file = versionFile(b) });

    const exe = b.addExecutable(.{
        .name = "runner",
        .root_module = b.createModule(.{
            .root_source_file = b.path("src/main.zig"),
            .target = target,
            .optimize = optimize,
            .strip = strip,
            .sanitize_thread = sanitize_thread,
            .imports = &.{
                .{ .name = "build_version", .module = version },
            },
        }),
    });
    addZrNet(exe.root_module, target.result.cpu.arch, target.result.abi);
    exe.pie = pie;
    b.installArtifact(exe);

    const run_cmd = b.addRunArtifact(exe);
    run_cmd.step.dependOn(b.getInstallStep());
    run_cmd.addPassthruArgs();
    b.step("run", "Run the runner").dependOn(&run_cmd.step);

    // `zig build test -Dtest-filter='fuzz: YAML' --fuzz=100K`: one fuzz target at a time, as the
    // fuzz workflow runs them (.github/scripts/zig-fuzz.sh).
    const test_filters = b.option([]const []const u8, "test-filter", "Only the tests whose names contain this") orelse &.{};
    // `-Dllvm`: the tests compiled by LLVM rather than Zig's own x86_64 backend, which instruments
    // no code for the fuzzer (`--fuzz` then fails on an empty coverage file).
    const use_llvm = b.option(bool, "llvm", "Compile the tests with LLVM (needed by --fuzz on x86_64)") orelse null;
    const tests = b.addTest(.{ .root_module = exe.root_module, .filters = test_filters, .use_llvm = use_llvm });
    tests.pie = pie;
    const test_step = b.step("test", "Run tests");
    // The tests run in as many processes as the machine has cores (`tools/test_shards.zig`), which
    // the build system's runner, one test at a time, does not. `--fuzz` needs that runner, and so
    // `-Dllvm`, which it needs too, turns this off.
    const shard_tests = b.option(bool, "shard-tests", "Run the tests in several processes (default: unless -Dllvm)") orelse
        (use_llvm != true);
    const run_tests = if (shard_tests) run: {
        const shards = b.addExecutable(.{
            .name = "test_shards",
            .root_module = b.createModule(.{
                .root_source_file = b.path("tools/test_shards.zig"),
                .target = target,
            }),
        });
        const run_shards = b.addRunArtifact(shards);
        run_shards.addArtifactArg(tests);
        break :run run_shards;
    } else b.addRunArtifact(tests);
    // Which tests run depends on the environment (PG*, ZIG_TEST_PG_URL, ZIG_TEST_REQUIRE_DB), which
    // the cache does not see: a run without a database would otherwise be replayed as the run with.
    run_tests.has_side_effects = true;
    // The native backend's tests run steps in sandboxes, which the runner binary makes
    // (`native/sandbox.zig`, `zig-runner native-step`): they are told where it is installed.
    // The test runner takes no arguments of ours and the install prefix is not known here, so
    // the binary is copied to a fixed place under the build's cache directory.
    const native_exe = b.addUpdateSourceFiles();
    native_exe.addCopyFileToSource(exe.getEmittedBin(), ".zig-cache/native-step/runner");
    run_tests.step.dependOn(&native_exe.step);
    run_tests.setEnvironmentVariable("ZIG_RUNNER_TEST_EXE", ".zig-cache/native-step/runner");
    test_step.dependOn(&run_tests.step);
    // The runner itself too. Zig compiles only what is reached, and the tests never reach the
    // runner's main loop (`loop.cycle`): a type error there passed `zig build test`, and CI with
    // it, and turned up only when the release image was built.
    test_step.dependOn(&exe.step);

    // The old TLS client as an oracle for the new one (`tls_oracle.zig`, docs/rust-net.md): tls.zig,
    // which the database's TLS was before the network library, is a lazy dependency in
    // build.zig.zon, and only this step needs it. Zig's configure phase does not know which steps
    // were asked for, so a lazy dependency requested in it is fetched for every invocation: the
    // request is behind `-Dtls-oracle`, and no other build, `zig build test` included, fetches or
    // compiles it. Where the Database fixture is: `zig build test-tls-oracle -Dtls-oracle`.
    const oracle_step = b.step("test-tls-oracle", "Compare the old TLS client with the new one (needs -Dtls-oracle, which fetches tls.zig)");
    if (b.option(bool, "tls-oracle", "Fetch tls.zig for test-tls-oracle") orelse false) {
        if (b.lazyDependency("tls", .{ .target = target, .optimize = optimize })) |tls| {
            const oracle = b.addTest(.{ .root_module = b.createModule(.{
                .root_source_file = b.path("tls_oracle.zig"),
                .target = target,
                .optimize = optimize,
                .sanitize_thread = sanitize_thread,
                .imports = &.{.{ .name = "tls", .module = tls.module("tls") }},
            }) });
            oracle.pie = pie;
            addZrNet(oracle.root_module, target.result.cpu.arch, target.result.abi);
            const run_oracle = b.addRunArtifact(oracle);
            // Which servers it finds depends on the environment (PG*, ZIG_TEST_PG_TLS_DIR).
            run_oracle.has_side_effects = true;
            oracle_step.dependOn(&run_oracle.step);
        }
    } else {
        oracle_step.dependOn(&b.addFail("test-tls-oracle fetches tls.zig: run it as `zig build test-tls-oracle -Dtls-oracle`").step);
    }
}

/// A file holding the version, for `src/version.zig` to `@embedFile`: `v0.2.0-118-g5063ae36`, with
/// `-dirty` when the tree has uncommitted changes — the release it follows, how far past it, and
/// the exact commit.
///
/// Computed when the build *runs*, not when it is configured. `zig build` caches its configuration
/// per set of `-D` options, so a version read while configuring survives HEAD moving: the first
/// version of this produced an aarch64 binary that named the commit before the one it was built
/// from, which is worse than no version at all. `has_side_effects` makes git run every build, and
/// the compilation downstream of it only redo itself when the output actually changes.
///
/// `-Dversion=...` skips git, which is how the builds with no history to read get a real version:
/// the release workflow passes the tag, the image build takes a build argument. Where there is
/// neither git nor a flag, the package's version stands in — honest, and visibly not a build.
fn versionFile(b: *std.Build) std.Build.LazyPath {
    if (b.option([]const u8, "version", "The version in the job log and --version")) |v|
        return b.addWriteFiles().add("version", v);
    // Whether git works here is a property of the checkout, not of HEAD, so this probe can be
    // cached with the configuration; what must not be cached is the answer it produces.
    var code: u8 = 0;
    _ = b.runAllowFail(&.{ "git", "rev-parse", "--git-dir" }, &code, .ignore) catch
        return b.addWriteFiles().add("version", @import("build.zig.zon").version);
    const git = b.addSystemCommand(&.{ "git", "describe", "--tags", "--always", "--dirty", "--abbrev=8" });
    git.has_side_effects = true;
    return git.captureStdOut(.{ .basename = "version" });
}

/// The network library (`rust/zr-net`, docs/rust-net.md): cargo builds it as a static archive for
/// the target with `zig cc` (`.github/scripts/build-zr-net.sh`, which the release runs too), and the
/// module links it. Rust's standard library is built on libc, so this is where the runner starts
/// linking musl (Zig's own), and Rust's unwinder (Zig's bundled libunwind) for the symbols std
/// references even with `panic = "abort"`. The step runs on every build, as the version's does:
/// cargo has its own cache and a clean tree costs it about a second; the Zig compilation after it
/// repeats only when the archive's bytes change.
fn addZrNet(module: *std.Build.Module, arch: std.Target.Cpu.Arch, abi: std.Target.Abi) void {
    const b = module.owner;
    const cargo = b.addSystemCommand(&.{ "../.github/scripts/build-zr-net.sh", @tagName(arch) });
    const archive = cargo.addOutputFileArg("libzr_net.a");
    cargo.addArg(if (abi.isMusl()) "musl" else "gnu");
    cargo.has_side_effects = true;
    module.addObjectFile(archive);
    module.link_libc = true;
    module.linkSystemLibrary("unwind", .{});
}
