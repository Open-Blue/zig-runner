//! The `sh -c` script each step runs: its file commands, its env and shell, and the markers
//! around its output.

const std = @import("std");
const job_mod = @import("../job.zig");
const Resolved = @import("../dagger.zig").Resolved;
const shellQuote = @import("../dagger.zig").shellQuote;
const marker = @import("../dagger.zig").marker;
const checkout = @import("checkout.zig");
const event_dir = @import("../dagger.zig").event_dir;
const event_path = @import("../dagger.zig").event_path;
const event_env = @import("../dagger.zig").event_env;
const withheld_event = @import("../dagger.zig").withheld_event;
const mark_env = @import("../dagger.zig").mark_env;
const ran_env = @import("../dagger.zig").ran_env;
const volatile_env = @import("../dagger.zig").volatile_env;
const volatile_sentinel = @import("../dagger.zig").volatile_sentinel;
const containerScript = @import("docker.zig").containerScript;
const readsRunSpecific = @import("../dagger.zig").readsRunSpecific;

const Allocator = std.mem.Allocator;

/// Where a job's file command files live, in the container, as `<fc_dir>/<kind>_<step>`.
pub const fc_dir = "/github/file_commands";
/// GITHUB_STATE is written by JavaScript actions (`core.saveState`) for their post scripts.
pub const fc_kinds = [_][]const u8{ "output", "env", "path", "step_summary", "state" };

/// The path of step `n`'s file for the file command `kind` (one of `fc_kinds`).
pub fn fcPath(arena: Allocator, kind: []const u8, n: u32) ![]const u8 {
    return std.fmt.allocPrint(arena, "{s}/{s}_{d}", .{ fc_dir, kind, n });
}

/// The `sh -c` script of step number `n` (1-based). Its exit code is the step's.
///
/// The script creates the step's file commands first and touches them again afterwards, so the
/// query can always read them even if the step deleted them. A `run:` step sees them as
/// `$GITHUB_OUTPUT`, `$GITHUB_ENV`, `$GITHUB_PATH` and `$GITHUB_STEP_SUMMARY`.
///
/// This text is part of every step's cache key, so none of it is only for the log: changing the
/// markers, the file-command paths or the order of the lines gives every step of every job a new
/// key, and the first run after such a change replays nothing. What keeps two steps of one job
/// apart is not the number here but the container each starts from (see proofs/,
/// `Runner.Counterexamples.SameStepTwice`).
///
/// The script's stderr goes to its stdout (`stream_prologue`), so its output is one stream in the
/// order it was written: the live log and a replay of the recorded stdout are the same lines in
/// the same order (issue #71).
pub fn stepScript(arena: Allocator, n: u32, r: Resolved, action_name: []const u8) ![]const u8 {
    return stepScriptFc(arena, n, n, r, action_name);
}

/// As `stepScript`, with file commands numbered `fc` instead of `n`. The steps of a composite
/// action all log as their `uses:` step (`n`), but each needs its own file commands.
pub fn stepScriptFc(
    arena: Allocator,
    n: u32,
    fc: u32,
    r: Resolved,
    action_name: []const u8,
) ![]const u8 {
    var aw: std.Io.Writer.Allocating = .init(arena);
    const w = &aw.writer;
    try w.writeAll(stream_prologue);
    try writeMarkerEcho(w, "begin", n);
    try w.writeAll("mkdir -p " ++ fc_dir ++ " && : ");
    for (fc_kinds) |k| try w.print("> {s} ", .{try fcPath(arena, k, fc)});
    try w.writeByte('\n');
    switch (r) {
        .run => |sc| try writeRunScript(w, arena, sc, fc, action_name),
        .checkout => |f| {
            // The tree is mounted by the query (`withDirectory`); the step reports it in the shape
            // actions/checkout's log has (the same folds, and the commit last), with what happened.
            for (try checkout.log(arena, f)) |line| {
                try w.writeAll("printf '%s\\n' ");
                try shellQuote(w, line);
                try w.writeByte('\n');
            }
            if (f.git_ref) |ref| try w.writeAll(try checkout.refCommands(arena, f.mount, ref));
            try w.writeAll("printf '%s\\n' '##[endgroup]'\n");
            // The commit, as actions/checkout ends (it runs the same git command).
            try w.writeAll("git -C ");
            try shellQuote(w, f.mount);
            try w.writeAll(" log -1 --format=%H 2>/dev/null\nrc=0\n");
        },
    }
    try writeEndMarker(w, n);
    // The script file goes once it ran: otherwise every later step's filesystem holds it,
    // and with it whatever the script embeds (a commit from `${{ github.sha }}`). A mounted one
    // is unmounted by the query instead.
    switch (r) {
        .run => |sc| if (!sc.script_mounted)
            try w.print("rm -f {s}\n", .{try scriptPath(arena, fc, sc.shell)}),
        .checkout => {},
    }
    try w.writeAll("mkdir -p " ++ fc_dir ++ " && : ");
    for (fc_kinds) |k| try w.print(">> {s} ", .{try fcPath(arena, k, fc)});
    try w.writeByte('\n');
    try writeCombinedFileCommands(w, arena, "", fc);
    try w.writeAll("exit $rc\n");
    return aw.written();
}

/// The first line of every step's script: its stderr from here on is its stdout.
///
/// Why one stream. A step's output is logged as it streams, and replayed from the exec's recorded
/// `stdout` and `stderr` when Dagger serves the exec from cache. Recorded as two strings, the order
/// between them is lost, and workflow commands depend on it: an `::add-mask::` on stdout masks a
/// stderr line after it, `::stop-commands::` turns later lines of either stream into text, and
/// problem matchers read lines in order. With one stream the recorded stdout is the log in the
/// order it was written, which is what the live log shows too, and the live log gets the exact
/// order as well, where two pipes read apart could reorder lines close in time.
///
/// What it costs: a step's programs see one pipe for both, where GitHub's runner gives two and
/// merges them as it reads them. Nothing in this runner tells the streams apart for a step: its
/// lines are all logged alike (`JobLog.appendLocked`), GitHub's log has no stream either, and
/// workflow commands and problem matchers are read on both. The one place that read `stderr` alone
/// (`bun_load_errors`) reads both. A program can still tell, by comparing its file descriptors,
/// but none a workflow runs is known to care. Recording a second, ordered copy of the output (a
/// `tee` of both streams into a file command) would keep the pipes apart, at the price of every
/// step's output stored twice and a process between the step and its output, and was not worth
/// it.
pub const stream_prologue = "exec 2>&1\n";

/// `echo '<marker><kind> <n>' "$ZIG_RUNNER_MARK"`: a marker that carries the job's secret (see
/// `mark_env`). The variable's name, not its value, is in the script, so the script text (part of
/// the step's cache key) is the same in every job.
pub fn writeMarkerEcho(w: *std.Io.Writer, kind: []const u8, n: u32) !void {
    try w.print("echo '{s}{s} {d}' \"${{" ++ mark_env ++ "-}}\"\n", .{ marker, kind, n });
}

/// The `end` marker, written straight after the step's `rc=$?`, before the script's own
/// bookkeeping (the file commands touched and combined, the script file removed). The runner
/// waits for it after the exec has answered (`JobLog.awaitLive`), and the engine exports a
/// container's output in batches about 100 ms apart: each process started between the step's
/// last line and the marker widens the window in which a batch boundary falls between them, and
/// one that does holds the step's end for the next batch. That bookkeeping (eight processes, about
/// 20 ms) put the marker a batch late after about a third of the steps. It prints nothing, so the
/// marker still follows every line of the step.
pub fn writeEndMarker(w: *std.Io.Writer, n: u32) !void {
    try writeMarkerEcho(w, "end", n);
}

/// The `run:` part of a step's script: the event file when asked, the script written to its file,
/// then run under its shell in a subshell with the step's env (`stepScriptFc` removes it).
fn writeRunScript(
    w: *std.Io.Writer,
    arena: Allocator,
    sc: anytype,
    fc: u32,
    action_name: []const u8,
) !void {
    if (sc.always_run) |why| {
        try w.writeAll(": ");
        try shellQuote(w, why);
        try w.writeByte('\n');
    }
    // A replayable step is given the withheld payload, not this run's (`withheld_event`).
    if (sc.write_event) try w.writeAll(if (sc.withhold_volatile)
        "mkdir -p " ++ event_dir ++ " && printf '%s' '" ++ withheld_event ++ "' > " ++ event_path ++ "\n"
    else
        "if [ -n \"${" ++ event_env ++ "+x}\" ]; then mkdir -p " ++
            event_dir ++ " && printf '%s' \"$" ++ event_env ++ "\" > " ++ event_path ++ "; fi\n");
    // The script is a file, as on GitHub: `$0`, BASH_SOURCE and error messages name it, and
    // a Python traceback names it too — hence the extension following the shell.
    const path = try scriptPath(arena, fc, sc.shell);
    if (!sc.script_mounted) {
        try w.writeAll("printf '%s' ");
        try shellQuote(w, sc.script);
        try w.print(" > {s}\n", .{path});
    }
    if (sc.shell == null) try w.writeAll("if command -v bash >/dev/null 2>&1; then " ++
        "zig_shell=bash; else zig_shell=sh; fi\n");
    try w.writeAll("( ");
    if (sc.working_directory) |wd| {
        try w.writeAll("cd ");
        try shellQuote(w, wd);
        try w.writeAll(" && ");
    }
    // The alias is the shell's, for its `cd`, not the step's: the command does not inherit it.
    if (sc.working_directory_alias) |alias| try w.print("cd \"${s}\" && ", .{alias});
    try writeEnvCommand(
        w,
        arena,
        if (sc.working_directory_alias) |alias|
            try std.fmt.allocPrint(arena, "env -u {s} ", .{alias})
        else
            "env ",
        sc.env,
        sc.secret_env,
        sc.write_event,
        sc.withhold_volatile,
        fc,
        action_name,
    );
    try writeShellCommand(w, arena, sc.shell, path);
    try w.writeAll(")\nrc=$?\n");
}

/// After a step: its file commands in one file (`all_<fc>`), so the query reads one file instead
/// of one per kind (each read mounts the step's snapshot in the engine). Each kind's file follows a
/// `::zig-file-command::<kind> <bytes>` line, which says how long it is, and one newline; the
/// job's ran marker comes last, on the line after `::zig-file-command::ran` (`combinedPart` reads
/// it). Only `cat`, `wc` and `printf` are needed.
///
/// The lengths are what keep one file's text from passing for another's: the file commands are
/// the step's to write, and a step's output or summary often holds text it does not control (a
/// pull request's title). When each file instead ran to the next marker line, a value holding
/// `::zig-file-command::env` and lines after it, in a heredoc of GITHUB_OUTPUT, was read as the
/// step's GITHUB_ENV: `BASH_ENV=...` there ran code in every later step.
pub fn writeCombinedFileCommands(
    w: *std.Io.Writer,
    arena: Allocator,
    prefix: []const u8,
    fc: u32,
) !void {
    try w.writeAll("{ ");
    for (fc_kinds) |k| {
        const path = try fcPath(arena, k, fc);
        try w.print(
            "printf '%s %s\\n' '" ++ fc_marker ++ "{s}' \"$({s}wc -c < {s})\"; {s}cat {s}; printf '\\n'; ",
            .{ k, prefix, path, prefix, path },
        );
    }
    // The job's marker (see `ran_env`): a result replayed from Dagger's cache has an earlier job's.
    try w.writeAll("printf '%s\\n%s\\n' '" ++ fc_marker ++ "ran' \"${" ++ ran_env ++ "-}\"; ");
    try w.print("}} > {s}\n", .{try fcPath(arena, "all", fc)});
}

const fc_marker = "::zig-file-command::";

/// `parts` (a kind and its file's text each) and then `ran`, as `writeCombinedFileCommands`'s
/// script writes them.
pub fn combine(arena: Allocator, parts: []const [2][]const u8, ran: []const u8) ![]const u8 {
    var aw: std.Io.Writer.Allocating = .init(arena);
    const w = &aw.writer;
    for (parts) |p| try w.print(fc_marker ++ "{s} {d}\n{s}\n", .{ p[0], p[1].len, p[1] });
    try w.print(fc_marker ++ "ran\n{s}\n", .{ran});
    return aw.written();
}

/// One kind's text in a combined file (`writeCombinedFileCommands`); for `ran`, the ran marker's
/// value. Null when the file has no such kind, or is not whole: a part's length (`wc` failed, or
/// the file grew while it was read) or the newline after a part out of place, or no ran marker
/// at the end. The parts are read in turn, each its length long, so nothing inside one is ever
/// taken for a marker.
pub fn combinedPart(all: []const u8, kind: []const u8) ?[]const u8 {
    var rest = all;
    while (true) {
        if (!std.mem.startsWith(u8, rest, fc_marker)) return null;
        const nl = std.mem.indexOfScalar(u8, rest, '\n') orelse return null;
        const head = rest[fc_marker.len..nl];
        const body = rest[nl + 1 ..];
        const space = std.mem.indexOfScalar(u8, head, ' ') orelse {
            // The ran marker, last: its value up to the newline the script ends it with.
            if (!std.mem.eql(u8, head, "ran")) return null;
            const value = if (std.mem.endsWith(u8, body, "\n")) body[0 .. body.len - 1] else body;
            return if (std.mem.eql(u8, kind, "ran")) value else null;
        };
        const len = std.fmt.parseInt(usize, std.mem.trim(u8, head[space + 1 ..], " \t"), 10) catch
            return null;
        if (body.len <= len or body[len] != '\n') return null;
        if (std.mem.eql(u8, head[0..space], kind)) return body[0..len];
        rest = body[len + 1 ..];
    }
}

/// Whether a combined file is well formed (`combinedPart`): every part where its length says,
/// up to its end or its ran marker. (Whether the ran marker is there is `combinedPart`'s to say.)
pub fn combinedWhole(all: []const u8) bool {
    var rest = all;
    while (rest.len > 0) {
        if (!std.mem.startsWith(u8, rest, fc_marker)) return false;
        const nl = std.mem.indexOfScalar(u8, rest, '\n') orelse return false;
        const head = rest[fc_marker.len..nl];
        const body = rest[nl + 1 ..];
        const space = std.mem.indexOfScalar(u8, head, ' ') orelse return std.mem.eql(u8, head, "ran");
        const len = std.fmt.parseInt(usize, std.mem.trim(u8, head[space + 1 ..], " \t"), 10) catch
            return false;
        if (body.len <= len or body[len] != '\n') return false;
        rest = body[len + 1 ..];
    }
    return true;
}

test "a combined file's parts are read by their lengths: a marker inside one is its text" {
    var a: std.heap.ArenaAllocator = .init(std.testing.allocator);
    defer a.deinit();
    const ar = a.allocator();
    // GITHUB_OUTPUT's value holds what passed for the env part, and the ran marker.
    const output = "title<<EOF_7f3a\n::zig-file-command::env 13\nBASH_ENV=/x\n\n" ++
        "::zig-file-command::ran\nforged\nEOF_7f3a\n";
    const all = try combine(ar, &.{
        .{ "output", output },
        .{ "env", "" },
        .{ "path", "/opt/x/bin\n" },
        .{ "step_summary", "no newline at end" },
        .{ "state", "" },
    }, "j1");
    try std.testing.expectEqualStrings(output, combinedPart(all, "output").?);
    try std.testing.expectEqualStrings("", combinedPart(all, "env").?);
    try std.testing.expectEqualStrings("/opt/x/bin\n", combinedPart(all, "path").?);
    try std.testing.expectEqualStrings("no newline at end", combinedPart(all, "step_summary").?);
    try std.testing.expectEqualStrings("j1", combinedPart(all, "ran").?);
    try std.testing.expect(combinedPart(all, "missing") == null);
    try std.testing.expect(combinedWhole(all));
    // Cut short, a length wrong, or `wc`'s answer missing: nothing is read from it.
    try std.testing.expect(!combinedWhole(all[0 .. all.len - 40]));
    try std.testing.expect(combinedPart(all[0 .. all.len - 40], "ran") == null);
    try std.testing.expect(combinedPart("::zig-file-command::env 2\nA=1\n::zig-file-command::ran\nj\n", "env") == null);
    try std.testing.expect(combinedPart("::zig-file-command::env \nA=1\n::zig-file-command::ran\nj\n", "env") == null);
    // As wc may pad it.
    try std.testing.expectEqualStrings("A=1\n", combinedPart("::zig-file-command::env    4\nA=1\n\n::zig-file-command::ran\nj\n", "env").?);
}

test "the combined file the script writes is read back part by part" {
    const io = std.testing.io;
    var a: std.heap.ArenaAllocator = .init(std.testing.allocator);
    defer a.deinit();
    const ar = a.allocator();
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    const dir = try tmp.dir.realPathFileAlloc(io, ".", ar);
    var script: std.Io.Writer.Allocating = .init(ar);
    try writeCombinedFileCommands(&script.writer, ar, "", 3);
    // The script's paths, under the test's directory.
    const text = try std.mem.replaceOwned(u8, ar, script.written(), fc_dir, dir);
    const contents = [_][]const u8{ "a<<E\n::zig-file-command::env 4\nX=1\n\nE\n", "", "/p\n", "no newline", "s=1\n" };
    for (fc_kinds, contents) |k, c| try tmp.dir.writeFile(io, .{
        .sub_path = try std.fmt.allocPrint(ar, "{s}_3", .{k}),
        .data = c,
    });
    _ = try std.process.run(ar, io, .{ .argv = &.{ "sh", "-c", text } });
    const all = try tmp.dir.readFileAlloc(io, "all_3", ar, .limited(1 << 20));
    for (fc_kinds, contents) |k, c| try std.testing.expectEqualStrings(c, combinedPart(all, k).?);
    try std.testing.expectEqualStrings("", combinedPart(all, "ran").?);
}

/// `<env_cmd>-u <aliases> NAME=value ... GITHUB_OUTPUT=... GITHUB_ACTION=... `: what a step's
/// command starts with, so it gets its env (secret values expanded from their aliases, see
/// `Resolved.run`).
pub fn writeEnvCommand(
    w: *std.Io.Writer,
    arena: Allocator,
    env_cmd: []const u8,
    env: []const job_mod.EnvVar,
    secret_env: []const []const u8,
    write_event: bool,
    withhold_volatile: bool,
    fc: u32,
    action_name: []const u8,
) !void {
    try w.writeAll(env_cmd);
    for (secret_env, 0..) |_, i| try w.print("-u {s} ", .{try secretAlias(arena, i)});
    if (write_event) try w.writeAll("-u " ++ event_env ++ " ");
    try w.writeAll("-u " ++ ran_env ++ " -u " ++ mark_env ++ " ");
    // Before the step's own env, so a workflow that sets one of these itself still wins.
    if (withhold_volatile) for (volatile_env) |name| {
        try shellQuote(w, try std.fmt.allocPrint(arena, "{s}=" ++ volatile_sentinel, .{name}));
        try w.writeByte(' ');
    };
    for (env) |e| {
        const pair = try std.fmt.allocPrint(arena, "{s}={s}", .{ e.name, e.value });
        try shellQuote(w, pair);
        try w.writeByte(' ');
    }
    // The value is expanded by the shell from the alias; only the variable's name is in the
    // command.
    for (secret_env, 0..) |name, i| {
        try shellQuote(w, try std.fmt.allocPrint(arena, "{s}=", .{name}));
        try w.print("\"${s}\" ", .{try secretAlias(arena, i)});
    }
    // Set after the step's own env, so a step cannot point these somewhere else.
    const names = [_][]const u8{
        "GITHUB_OUTPUT",
        "GITHUB_ENV",
        "GITHUB_PATH",
        "GITHUB_STEP_SUMMARY",
        "GITHUB_STATE",
    };
    for (names, fc_kinds) |name, kind| {
        try shellQuote(
            w,
            try std.fmt.allocPrint(arena, "{s}={s}", .{ name, try fcPath(arena, kind, fc) }),
        );
        try w.writeByte(' ');
    }
    try shellQuote(w, try std.fmt.allocPrint(arena, "GITHUB_ACTION={s}", .{action_name}));
    try w.writeByte(' ');
}

/// The program and arguments for a step's `shell:` as GitHub runs it, `{0}` being the script
/// file: no `shell:` is `bash -e {0}` (`sh -e {0}` when the image has no bash, decided in the
/// script), and a program named alone gets GitHub's arguments for it (`job.Shell`): `bash` adds
/// pipefail and skips the profile and rc files, `sh` is `sh -e {0}`, `python` is `python {0}`.
/// The name is `python` and not `python3` because that is what GitHub runs; the default image
/// provides it (SPEC §6), and an image that only has `python3` needs `shell: python3 {0}`.
fn shellTemplate(shell: ?[]const u8) job_mod.Shell {
    const s = shell orelse return .{ .program = "bash", .args = "-e {0}" };
    return job_mod.Shell.parse(s);
}

/// A script's file extension for its shell: `.sh` for bash and sh, `.py` for python, and none for
/// any other program, as GitHub names it (actions/runner
/// src/Runner.Worker/Handlers/ScriptHandlerHelpers.cs, `_extensions`). The name reaches the
/// step's own output — a traceback names the file it came from — so it is not cosmetic. GitHub
/// looks the program up as written, in any case (`GetScriptFileExtension(shellCommand)`), so a
/// path (`/bin/bash`) and `python3` get none. #196 had known them by their name; #214 decided to
/// match GitHub byte for byte.
fn shellExtension(shell: ?[]const u8) []const u8 {
    const s = shell orelse return "sh";
    const prog = job_mod.Shell.parse(s).program;
    if (std.ascii.eqlIgnoreCase(prog, "bash") or std.ascii.eqlIgnoreCase(prog, "sh")) return "sh";
    if (std.ascii.eqlIgnoreCase(prog, "python")) return "py";
    return "";
}

/// The command that runs the script file `path`: the program and each argument, quoted, with
/// `{0}` replaced.
fn writeShellCommand(
    w: *std.Io.Writer,
    arena: Allocator,
    shell: ?[]const u8,
    path: []const u8,
) !void {
    const t = shellTemplate(shell);
    // No `shell:`: bash, or sh where the image has no bash (`$zig_shell`, set by the script).
    if (shell == null) try w.writeAll("\"$zig_shell\" ") else {
        try shellQuote(w, t.program);
        try w.writeByte(' ');
    }
    var it = std.mem.tokenizeAny(u8, t.args, " \t");
    while (it.next()) |word| {
        try shellQuote(w, try std.mem.replaceOwned(u8, arena, word, "{0}", path));
        try w.writeByte(' ');
    }
}

/// The `shell:` line of a run step's log header, as GitHub's runner prints it: the program and its
/// arguments, with a bare `bash`, `sh` or `python` as its full path.
pub fn shellLine(arena: Allocator, shell: ?[]const u8) ![]const u8 {
    const t = shellTemplate(shell);
    // Verified against `ubuntu-latest` on the same workflow: a bare `python` prints as
    // `shell: /usr/bin/python {0}`, exactly as bash and sh do.
    const bare = std.mem.eql(u8, t.program, "bash") or std.mem.eql(u8, t.program, "sh") or
        std.mem.eql(u8, t.program, "python");
    const full = if (bare)
        try std.fmt.allocPrint(arena, "/usr/bin/{s}", .{t.program})
    else
        t.program;
    return std.fmt.allocPrint(arena, "shell: {s} {s}", .{ full, t.args });
}

/// Where a step's script is written for its shell, as GitHub writes it under RUNNER_TEMP.
pub fn scriptPath(arena: Allocator, fc: u32, shell: ?[]const u8) ![]const u8 {
    const ext = shellExtension(shell);
    return std.fmt.allocPrint(
        arena,
        "/tmp/zig-runner-step-{d}{s}{s}",
        .{ fc, if (ext.len > 0) "." else "", ext },
    );
}

/// The name under which a step's `i`th secret variable is attached to the container. Dagger
/// silently drops variables whose names are not identifiers (`INPUT_GITHUB-TOKEN`), and a variable
/// attached to the container would outlive the step; the alias is removed again after the step's
/// exec.
pub fn secretAlias(arena: Allocator, i: usize) ![]const u8 {
    return std.fmt.allocPrint(arena, "ZIG_SECRET_{d}", .{i});
}

test "each shell's script extension is GitHub's: the program as written, in any case" {
    // `_extensions` in actions/runner's ScriptHandlerHelpers.cs, keyed by the first word of
    // `shell:` (`ParseShellOptionString`); the Windows shells are refused before this.
    const Case = struct { ?[]const u8, []const u8 };
    for ([_]Case{
        .{ null, "sh" },
        .{ "bash", "sh" },
        .{ "BASH -e {0}", "sh" },
        .{ "sh", "sh" },
        .{ "sh -x {0}", "sh" },
        .{ "python", "py" },
        .{ "Python {0}", "py" },
        .{ "python3 {0}", "" },
        .{ "/bin/bash --login -e {0}", "" },
        .{ "/usr/bin/python {0}", "" },
        .{ "node {0}", "" },
        .{ "perl {0}", "" },
    }) |c| try std.testing.expectEqualStrings(c[1], shellExtension(c[0]));
}

test "script quotes, applies env, shell and working directory, and propagates the exit code" {
    var a: std.heap.ArenaAllocator = .init(std.testing.allocator);
    defer a.deinit();
    const w = try stepScript(a.allocator(), 2, .{ .run = .{
        .script = "echo 'hi' && echo $X",
        .shell = "sh",
        .working_directory = "sub dir",
        .env = &.{.{ .name = "X", .value = "a b" }},
    } }, "build");
    try std.testing.expect(std.mem.indexOf(u8, w, "cd 'sub dir' && env -u ZIG_RUNNER_RAN -u ZIG_RUNNER_MARK 'X=a b' 'GITHUB_OUTPUT=/github/file_commands/output_2'") != null);
    // The script is written to a file that the shell runs, as GitHub does.
    try std.testing.expect(std.mem.indexOf(u8, w, "printf '%s' 'echo '\\''hi'\\'' && echo $X' > /tmp/zig-runner-step-2.sh\n") != null);
    try std.testing.expect(std.mem.indexOf(u8, w, "'GITHUB_ACTION=build' 'sh' '-e' '/tmp/zig-runner-step-2.sh' )") != null);
    // A custom bash command, with {0} replaced by the file.
    const custom = try stepScript(a.allocator(), 3, .{ .run = .{ .script = "echo hi", .shell = "bash -l {0}", .working_directory = null, .env = &.{} } }, "x");
    try std.testing.expect(std.mem.indexOf(u8, custom, "'bash' '-l' '/tmp/zig-runner-step-3.sh' )") != null);
    try std.testing.expect(std.mem.indexOf(u8, custom, "zig_shell") == null);
    // No shell: bash -e, or sh -e where the image has no bash.
    const default = try stepScript(a.allocator(), 4, .{ .run = .{ .script = "echo hi", .shell = null, .working_directory = null, .env = &.{} } }, "x");
    try std.testing.expect(std.mem.indexOf(u8, default, "if command -v bash >/dev/null 2>&1; then zig_shell=bash; else zig_shell=sh; fi\n") != null);
    try std.testing.expect(std.mem.indexOf(u8, default, "\"$zig_shell\" '-e' '/tmp/zig-runner-step-4.sh' )") != null);
    try std.testing.expectEqualStrings("shell: /usr/bin/bash -e {0}", try shellLine(a.allocator(), null));
    try std.testing.expectEqualStrings("shell: /usr/bin/bash -l {0}", try shellLine(a.allocator(), "bash -l {0}"));
    try std.testing.expectEqualStrings("shell: /bin/bash --login -eo pipefail {0}", try shellLine(a.allocator(), "/bin/bash --login -eo pipefail {0}"));

    // `shell: python`, as GitHub runs it. All three expectations were read off `ubuntu-latest` on
    // the same workflow: the log line, the interpreter, and the `.py` file whose name reaches the
    // step's own output (`sys.argv[0]` there was `..._temp/<uuid>.py`).
    try std.testing.expectEqualStrings("shell: /usr/bin/python {0}", try shellLine(a.allocator(), "python"));
    const py = try stepScript(a.allocator(), 5, .{ .run = .{ .script = "print(1)", .shell = "python", .working_directory = null, .env = &.{} } }, "x");
    try std.testing.expect(std.mem.indexOf(u8, py, "'python' '/tmp/zig-runner-step-5.py' )") != null);
    try std.testing.expect(std.mem.indexOf(u8, py, "> /tmp/zig-runner-step-5.py\n") != null);
    // An image with no `python` can still name one, and its file has no extension, as GitHub
    // names it (#214).
    const py3 = try stepScript(a.allocator(), 6, .{ .run = .{ .script = "print(1)", .shell = "python3 {0}", .working_directory = null, .env = &.{} } }, "x");
    try std.testing.expect(std.mem.indexOf(u8, py3, "'python3' '/tmp/zig-runner-step-6' )") != null);
    // A bash step is unaffected: still `.sh`.
    try std.testing.expect(std.mem.indexOf(u8, custom, ".sh' )") != null);
    // Any other program runs the script as GitHub runs it: its file has no extension, and the
    // arguments are split at spaces.
    const node = try stepScript(a.allocator(), 7, .{ .run = .{ .script = "console.log(1)", .shell = "node  --no-warnings {0}", .working_directory = null, .env = &.{} } }, "x");
    try std.testing.expect(std.mem.indexOf(u8, node, "> /tmp/zig-runner-step-7\n") != null);
    try std.testing.expect(std.mem.indexOf(u8, node, "'node' '--no-warnings' '/tmp/zig-runner-step-7' )") != null);
    try std.testing.expectEqualStrings("shell: node --no-warnings {0}", try shellLine(a.allocator(), "node  --no-warnings {0}"));
    try std.testing.expectEqualStrings("shell: /usr/bin/bash --noprofile --norc -e -o pipefail {0}", try shellLine(a.allocator(), "bash"));
    // The file commands exist before the step and are touched again after it.
    try std.testing.expect(std.mem.indexOf(u8, w, ": > /github/file_commands/output_2 > /github/file_commands/env_2") != null);
    try std.testing.expect(std.mem.indexOf(u8, w, ">> /github/file_commands/path_2") != null);
    try std.testing.expect(std.mem.indexOf(u8, w, marker ++ "begin 2") != null);
    try std.testing.expect(std.mem.endsWith(u8, w, "exit $rc\n"));
    // One stream from the first line, and markers with the job's secret by name only (#71).
    try std.testing.expect(std.mem.startsWith(u8, w, "exec 2>&1\necho '" ++ marker ++ "begin 2' \"${ZIG_RUNNER_MARK-}\"\n"));
    // The end marker straight after the step, with nothing started in between (`writeEndMarker`).
    const end_2 = "echo '" ++ marker ++ "end 2' \"${ZIG_RUNNER_MARK-}\"\n";
    try std.testing.expect(std.mem.indexOf(u8, w, ")\nrc=$?\n" ++ end_2 ++ "rm -f ") != null);
    // A Docker action's script too.
    const c = try containerScript(a.allocator(), 3, 3, &.{.{ .text = "/entry" }}, &.{}, &.{}, null, false, false, "x");
    try std.testing.expect(std.mem.startsWith(u8, c, "exec 2>&1\necho '" ++ marker ++ "begin 3' \"${ZIG_RUNNER_MARK-}\"\n"));
    try std.testing.expect(std.mem.indexOf(u8, c, "-u ZIG_RUNNER_MARK ") != null);
    try std.testing.expect(std.mem.indexOf(u8, c, "\nrc=$?\necho '" ++ marker ++ "end 3' \"${ZIG_RUNNER_MARK-}\"\n: >> ") != null);
}

test "a step's end marker follows its output and comes before the script's bookkeeping" {
    var a: std.heap.ArenaAllocator = .init(std.testing.allocator);
    defer a.deinit();
    const end_4 = "echo '" ++ marker ++ "end 4' \"${ZIG_RUNNER_MARK-}\"\n";
    // A mounted script is not removed, a checkout has no script: the marker still comes first.
    const mounted = try stepScript(a.allocator(), 4, .{ .run = .{ .script = "true", .shell = null, .working_directory = null, .env = &.{}, .script_mounted = true } }, "x");
    try std.testing.expect(std.mem.indexOf(u8, mounted, ")\nrc=$?\n" ++ end_4 ++ "mkdir -p ") != null);
    try std.testing.expect(std.mem.indexOf(u8, mounted, "rm -f") == null);
    const plain = try stepScript(a.allocator(), 4, .{ .run = .{ .script = "true", .shell = null, .working_directory = null, .env = &.{} } }, "x");
    const end_at = std.mem.indexOf(u8, plain, end_4).?;
    // Only the bookkeeping follows it: what it does prints nothing, so no line of the step's can
    // come after the marker.
    try std.testing.expect(std.mem.indexOf(u8, plain, "rm -f /tmp/zig-runner-step-4") == end_at + end_4.len);
    try std.testing.expect(std.mem.indexOf(u8, plain, "> " ++ fc_dir ++ "/all_4\nexit $rc\n").? > end_at);
    try std.testing.expect(std.mem.lastIndexOf(u8, plain, "echo ").? == end_at);
}

test "secret variables reach the script through aliases, whatever their names" {
    var a: std.heap.ArenaAllocator = .init(std.testing.allocator);
    defer a.deinit();
    const w = try stepScript(a.allocator(), 1, .{ .run = .{
        .script = "node main.js",
        .shell = "sh",
        .working_directory = null,
        .env = &.{.{ .name = "PLAIN", .value = "p" }},
        .secret_env = &.{ "INPUT_GITHUB-TOKEN", "TOKEN" },
    } }, "a");
    // Aliases are unset before the assignments; the real names come after the plain env.
    try std.testing.expect(std.mem.indexOf(u8, w, "env -u ZIG_SECRET_0 -u ZIG_SECRET_1 -u ZIG_RUNNER_RAN -u ZIG_RUNNER_MARK 'PLAIN=p' 'INPUT_GITHUB-TOKEN='\"$ZIG_SECRET_0\" 'TOKEN='\"$ZIG_SECRET_1\" ") != null);
}

test "enforcement: a replayable step is not given the run-specific values, an always-run step is" {
    var arena_state: std.heap.ArenaAllocator = .init(std.testing.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();

    // The same step, told once that it is replayable and once that it always runs.
    const plain = try stepScript(arena, 1, .{ .run = .{
        .script = "echo hi",
        .shell = null,
        .working_directory = null,
        .env = &.{},
        .withhold_volatile = true,
    } }, "");
    const marked = try stepScript(arena, 1, .{ .run = .{
        .script = "echo hi",
        .shell = null,
        .working_directory = null,
        .env = &.{},
        .always_run = "zig-runner runs this step every time: it uses secrets (run 1.1, job j1)",
    } }, "");

    // A replayable step gets the sentinel for every name in `volatile_env`, in the script's own env
    // prefix, so the value is part of its cache key and cannot differ between runs.
    for (volatile_env) |name| {
        const pair = try std.fmt.allocPrint(arena, "{s}={s}", .{ name, volatile_sentinel });
        try std.testing.expect(std.mem.indexOf(u8, plain, pair) != null);
        try std.testing.expect(std.mem.indexOf(u8, marked, pair) == null);
    }
    // And a step that always runs is given nothing of the sort: it is never replayed, so the real
    // values the container carries are safe for it to read.
    try std.testing.expect(std.mem.indexOf(u8, marked, volatile_sentinel) == null);
}

test "enforcement: a replayable step finds the withheld payload at GITHUB_EVENT_PATH, an always-run step the real one" {
    var arena_state: std.heap.ArenaAllocator = .init(std.testing.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();
    const plain = try stepScript(arena, 1, .{ .run = .{
        .script = "./build-release.sh",
        .shell = null,
        .working_directory = null,
        .env = &.{},
        .write_event = true,
        .withhold_volatile = true,
    } }, "");
    const marked = try stepScript(arena, 1, .{ .run = .{
        .script = "jq -r .inputs.version \"$GITHUB_EVENT_PATH\"",
        .shell = null,
        .working_directory = null,
        .env = &.{},
        .write_event = true,
        .always_run = "zig-runner runs this step every time: it reads run- or commit-specific values (run 1.1, job j1)",
    } }, "");
    // Issue #68: the payload is not in the key, so a replayable step must not see it. It gets a
    // constant instead, which is in its script (so its key) and the same in every run.
    try std.testing.expect(std.mem.indexOf(u8, plain, "printf '%s' '\"zig-runner-withheld\"' > " ++ event_path) != null);
    try std.testing.expect(std.mem.indexOf(u8, plain, "\"$" ++ event_env ++ "\"") == null);
    try std.testing.expect(std.mem.indexOf(u8, marked, "\"$" ++ event_env ++ "\" > " ++ event_path) != null);
    try std.testing.expect(std.mem.indexOf(u8, marked, withheld_event) == null);
    // Naming the variable or the file is reading the payload; a script in a file cannot be seen.
    try std.testing.expect(readsRunSpecific("jq . \"$GITHUB_EVENT_PATH\""));
    try std.testing.expect(readsRunSpecific("cat /github/workflow/event.json"));
    try std.testing.expect(!readsRunSpecific("./build-release.sh"));
}

test "enforcement: off by configuration, a replayable step keeps GitHub's behaviour" {
    var arena_state: std.heap.ArenaAllocator = .init(std.testing.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();
    // `withhold_volatile` is what `Options.enforce_volatile` decides; with it false the script has
    // no sentinel in it, which is what RUNNER_ENFORCE_VOLATILE=false asks for.
    const script = try stepScript(arena, 1, .{ .run = .{
        .script = "echo hi",
        .shell = null,
        .working_directory = null,
        .env = &.{},
        .withhold_volatile = false,
    } }, "");
    try std.testing.expect(std.mem.indexOf(u8, script, volatile_sentinel) == null);
}
