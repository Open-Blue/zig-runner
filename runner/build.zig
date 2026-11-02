const std = @import("std");

pub fn build(b: *std.Build) void {
    const target = b.standardTargetOptions(.{});
    const optimize = b.standardOptimizeOption(.{});
    // Release builds for deployment drop debug info (`zig build -Doptimize=ReleaseSafe -Dstrip`).
    const strip = b.option(bool, "strip", "Omit debug information") orelse null;
    // `zig build test -Dsanitize-thread`: ThreadSanitizer reports data races the tests run into.
    const sanitize_thread = b.option(bool, "sanitize-thread", "Build with ThreadSanitizer") orelse null;

    // The build's own version, in every job's "Set up job" and in `--version`. Answering "which
    // binary is on that machine?" by comparing file sizes and timestamps is how an hour went
    // missing once; `git describe` answers it exactly.
    const version = b.createModule(.{ .root_source_file = versionFile(b) });
    // TLS to the database (`src/pg.zig`): std's client cannot answer a server that asks for a
    // client certificate, which Tiger Data does.
    const tls = b.dependency("tls", .{}).module("tls");

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
                .{ .name = "tls", .module = tls },
            },
        }),
    });
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
    const test_step = b.step("test", "Run tests");
    const run_tests = b.addRunArtifact(tests);
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
