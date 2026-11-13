//! What a Gitea or Forgejo runner keeps between restarts: the credentials `Register` gave it, in a
//! file of the runner's state directory, as `act_runner` keeps its `.runner` file. Without it every
//! restart would register a new runner, and the instance would list a dead one for each.
//!
//! The file holds the runner's token, so it is created readable by its user alone and replaced as a
//! whole (written beside it, then renamed): a crash leaves the old file or the new one, never half.
const std = @import("std");

const Allocator = std.mem.Allocator;

/// The credentials of one registered runner. `url` is the instance they are for: a state file left
/// from another instance (the setting moved) is not used.
pub const State = struct {
    url: []const u8,
    id: i64,
    uuid: []const u8,
    token: []const u8,
    name: []const u8,
};

pub const Error = error{
    /// The file exists and holds no state: someone's to look at, never silently registered over.
    BadState,
} || Allocator.Error || std.Io.Dir.CreateDirPathError || std.Io.Dir.OpenError;

/// The file's name for a pool: pools sharing a state directory (named by `RUNNER_NAME_PREFIX`) keep
/// one each.
pub fn fileName(arena: Allocator, name_prefix: []const u8) Allocator.Error![]const u8 {
    return std.fmt.allocPrint(arena, "gitea-runner-{s}.json", .{name_prefix});
}

/// The saved state, or null when there is none yet.
pub fn load(arena: Allocator, io: std.Io, dir: []const u8, file: []const u8) Error!?State {
    const path = try std.fs.path.join(arena, &.{ dir, file });
    const text = std.Io.Dir.cwd().readFileAlloc(io, path, arena, .limited(64 * 1024)) catch |e| switch (e) {
        error.FileNotFound => return null,
        else => return error.BadState,
    };
    return std.json.parseFromSliceLeaky(State, arena, text, .{}) catch error.BadState;
}

/// Writes `state` (mode 0600), replacing the file.
pub fn save(
    arena: Allocator,
    io: std.Io,
    dir_path: []const u8,
    file: []const u8,
    state: State,
) !void {
    try std.Io.Dir.cwd().createDirPath(io, dir_path);
    var dir = try std.Io.Dir.cwd().openDir(io, dir_path, .{});
    defer dir.close(io);
    var suffix: [4]u8 = undefined;
    io.random(&suffix);
    const tmp = try std.fmt.allocPrint(arena, "{s}.{x}.tmp", .{ file, suffix });
    var body: std.Io.Writer.Allocating = .init(arena);
    try std.json.Stringify.value(state, .{ .whitespace = .indent_2 }, &body.writer);
    try body.writer.writeByte('\n');
    // Created, never opened: nothing already at the name is written through.
    var f = try dir.createFile(io, tmp, .{ .exclusive = true, .permissions = .fromMode(0o600) });
    errdefer dir.deleteFile(io, tmp) catch |e| std.log.warn("state: {s} left behind: {s}", .{ tmp, @errorName(e) });
    {
        defer f.close(io);
        try f.writeStreamingAll(io, body.writer.buffered());
    }
    try dir.rename(tmp, dir, file, io);
}

test "state is kept in a file only its user can read, and loaded again" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    var arena_state: std.heap.ArenaAllocator = .init(std.testing.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();
    const io = std.testing.io;
    const root = try tmp.dir.realPathFileAlloc(io, ".", arena);
    const dir = try std.fs.path.join(arena, &.{ root, "nested", "state" });

    try std.testing.expectEqual(@as(?State, null), try load(arena, io, dir, "r.json"));
    const s: State = .{ .url = "http://g", .id = 7, .uuid = "u-1", .token = "t-1", .name = "zig-ab" };
    try save(arena, io, dir, "r.json", s);
    // A second save replaces it.
    try save(arena, io, dir, "r.json", .{ .url = "http://g", .id = 8, .uuid = "u-2", .token = "t-2", .name = "zig-ab" });

    const got = (try load(arena, io, dir, "r.json")).?;
    try std.testing.expectEqual(@as(i64, 8), got.id);
    try std.testing.expectEqualStrings("t-2", got.token);

    var d = try std.Io.Dir.cwd().openDir(io, dir, .{ .iterate = true });
    defer d.close(io);
    const st = try d.statFile(io, "r.json", .{});
    try std.testing.expectEqual(@as(u32, 0o600), @as(u32, st.permissions.toMode()) & 0o777);
    // No temporary file is left behind.
    var it = d.iterate();
    var n: usize = 0;
    while (try it.next(io)) |_| n += 1;
    try std.testing.expectEqual(@as(usize, 1), n);
}

test "a state file that is not state is refused, not registered over" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    var arena_state: std.heap.ArenaAllocator = .init(std.testing.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();
    const io = std.testing.io;
    try tmp.dir.writeFile(io, .{ .sub_path = "r.json", .data = "{\"url\":" });
    const dir = try tmp.dir.realPathFileAlloc(io, ".", arena);
    try std.testing.expectError(error.BadState, load(arena, io, dir, "r.json"));
}
