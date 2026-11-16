//! The parts of the job's Docker API that `docker build` needs (#448, stage 1b), which know no
//! sockets and no job: a build request's query (`parseQuery`), the context's tar unpacked into a
//! directory with its limits (`unpack`), a reference as the tag index keeps it (`parseRef`,
//! `Index`), and an image's config and ID (`configJson`, `imageId`, `inspectJson`).
//!
//! The server (`docker_api.zig`) reads the HTTP; `Backend.zig` and `docker_action.zig` build.
//! What is decided here:
//!
//! - **The context** is a tar the client sends. It is unpacked into a directory of the job's by
//!   walking it with `openat` and `O_NOFOLLOW`, one component at a time, so no entry is ever
//!   written through a link; a link is made only when its target is a relative path that climbs no
//!   higher than its directory and never climbs after a name (so no chain of links can lead out).
//!   Hard links, devices and FIFOs are refused. The bytes, the entries, the path's depth and
//!   length are limited.
//! - **The image's ID** is `sha256:` and the hex of a SHA-256 of the image's config as
//!   `configJson` renders it, a newline and the key of the build's last step: it names what the
//!   image is made of and is the same for the same build, but it is not Docker's value (which
//!   needs Docker's own layer digests).
//! - **The tags** are a per-job index: memory, gone with the job. Nothing of it is shared.

const std = @import("std");
const linux = std.os.linux;
const images = @import("images.zig");
const Sha256 = @import("../sha256.zig").Sha256;

const Allocator = std.mem.Allocator;

// --- the request ---

pub const Pair = struct { name: []const u8, value: []const u8 };

/// What a `POST /build` asks.
pub const Query = struct {
    /// The Dockerfile's path in the context.
    dockerfile: []const u8 = "Dockerfile",
    /// `-t`, as written.
    tags: []const []const u8 = &.{},
    build_args: []const Pair = &.{},
    labels: []const Pair = &.{},
    target: []const u8 = "",
    /// `--platform`, "" for the runner's own.
    platform: []const u8 = "",
    nocache: bool = false,
    pull: bool = false,
    quiet: bool = false,
};

pub const Parsed = union(enum) {
    ok: Query,
    /// What is wrong with the request, in Docker's voice: a 400's message.
    bad: []const u8,
    /// An option that changes what a build is and is not served yet: a 501's message.
    unsupported: []const u8,
};

/// Docker's `BoolValue`: empty, `0`, `no`, `false` and `none` are false, anything else true.
pub fn boolValue(v: []const u8) bool {
    for ([_][]const u8{ "", "0", "no", "false", "none" }) |f| if (std.ascii.eqlIgnoreCase(v, f)) return false;
    return true;
}

/// A query component with `%XX` and `+` decoded; null when a `%` is not followed by two hex digits.
pub fn percentDecode(arena: Allocator, text: []const u8) !?[]const u8 {
    return decode(arena, text, true);
}

/// A path component with `%XX` decoded (`+` stays).
pub fn pathDecode(arena: Allocator, text: []const u8) !?[]const u8 {
    return decode(arena, text, false);
}

fn decode(arena: Allocator, text: []const u8, plus: bool) !?[]const u8 {
    var out: std.ArrayList(u8) = .empty;
    var i: usize = 0;
    while (i < text.len) : (i += 1) {
        const c = text[i];
        if (c == '+' and plus) {
            try out.append(arena, ' ');
        } else if (c == '%') {
            if (i + 2 >= text.len) return null;
            const hi = std.fmt.charToDigit(text[i + 1], 16) catch return null;
            const lo = std.fmt.charToDigit(text[i + 2], 16) catch return null;
            try out.append(arena, hi * 16 + lo);
            i += 2;
        } else try out.append(arena, c);
    }
    return out.items;
}

/// The most `-t`, `--build-arg` and `--label` a build takes, and the longest of any value.
pub const max_params = 128;
pub const max_value = 64 * 1024;

/// Options Docker's classic builder takes that the runner does not honour, and what each would
/// change: a build is refused rather than made differently. Others (`rm`, `forcerm`, `cachefrom`,
/// `memory`, `cpushares`, `shmsize`, `ulimits`, `buildid`, `isolation` ...) are accepted: the job's
/// own cgroup bounds a RUN, whatever the client asks for.
const refused_options = [_]struct { name: []const u8, why: []const u8 }{
    .{ .name = "squash", .why = "--squash" },
    .{ .name = "remote", .why = "a remote build context (a URL or a git repository)" },
    .{ .name = "extrahosts", .why = "--add-host" },
    .{ .name = "outputs", .why = "--output" },
    .{ .name = "cgroupparent", .why = "--cgroup-parent" },
    .{ .name = "securityopt", .why = "--security-opt" },
};

/// `query` (the part after `?`) read as a build's options.
pub fn parseQuery(arena: Allocator, query: []const u8) !Parsed {
    var q: Query = .{};
    var tags: std.ArrayList([]const u8) = .empty;
    var args: std.ArrayList(Pair) = .empty;
    var labels: std.ArrayList(Pair) = .empty;
    var it = std.mem.splitScalar(u8, query, '&');
    while (it.next()) |part| {
        if (part.len == 0) continue;
        const eq = std.mem.indexOfScalar(u8, part, '=');
        const name = (try percentDecode(arena, part[0 .. eq orelse part.len])) orelse
            return .{ .bad = "invalid URL query: a bad percent escape" };
        const value = (try percentDecode(arena, if (eq) |e| part[e + 1 ..] else "")) orelse
            return .{ .bad = "invalid URL query: a bad percent escape" };
        if (value.len > max_value) return .{ .bad = try std.fmt.allocPrint(arena, "the build option {s} is too long", .{name}) };
        if (std.mem.eql(u8, name, "dockerfile")) {
            if (value.len > 0) q.dockerfile = value;
        } else if (std.mem.eql(u8, name, "t")) {
            if (value.len == 0) continue;
            if (tags.items.len >= max_params) return .{ .bad = "too many -t tags" };
            try tags.append(arena, value);
        } else if (std.mem.eql(u8, name, "buildargs") or std.mem.eql(u8, name, "labels")) {
            const into = if (name[0] == 'b') &args else &labels;
            if (value.len == 0) continue;
            const parsed = std.json.parseFromSliceLeaky(std.json.Value, arena, value, .{}) catch
                return .{ .bad = try std.fmt.allocPrint(arena, "the build option {s} is not a JSON object", .{name}) };
            if (parsed != .object) return .{ .bad = try std.fmt.allocPrint(arena, "the build option {s} is not a JSON object", .{name}) };
            var kv = parsed.object.iterator();
            while (kv.next()) |e| {
                // The client sends null for a build argument it has no value for: Docker leaves
                // it unset too.
                if (e.value_ptr.* != .string) continue;
                if (into.items.len >= max_params) return .{ .bad = try std.fmt.allocPrint(arena, "too many {s}", .{name}) };
                if (e.key_ptr.len == 0 or std.mem.indexOfAny(u8, e.key_ptr.*, "=\n\x00") != null)
                    return .{ .bad = try std.fmt.allocPrint(arena, "a name in {s} is not valid", .{name}) };
                try into.append(arena, .{ .name = e.key_ptr.*, .value = e.value_ptr.string });
            }
        } else if (std.mem.eql(u8, name, "target")) {
            q.target = value;
        } else if (std.mem.eql(u8, name, "platform")) {
            q.platform = value;
            if (value.len > 0 and !std.mem.eql(u8, value, ownPlatform())) return .{ .bad = try std.fmt.allocPrint(
                arena,
                "platform {s} is not supported by zig-runner: this runner builds {s} only",
                .{ value, ownPlatform() },
            ) };
        } else if (std.mem.eql(u8, name, "nocache")) {
            q.nocache = boolValue(value);
        } else if (std.mem.eql(u8, name, "pull")) {
            q.pull = boolValue(value);
        } else if (std.mem.eql(u8, name, "q")) {
            q.quiet = boolValue(value);
        } else if (std.mem.eql(u8, name, "networkmode")) {
            const plain = value.len == 0 or std.mem.eql(u8, value, "default") or std.mem.eql(u8, value, "bridge");
            if (!plain) return .{ .unsupported = try std.fmt.allocPrint(arena, "--network={s} is not " ++
                "supported by zig-runner yet: a RUN has the job's network", .{value}) };
        } else if (std.mem.eql(u8, name, "version")) {
            if (std.mem.eql(u8, value, "2")) return .{ .unsupported = "BuildKit is not supported by zig-runner yet" };
        } else for (refused_options) |r| if (std.mem.eql(u8, name, r.name)) {
            if (boolValue(value)) return .{ .unsupported = try std.fmt.allocPrint(
                arena,
                "{s} is not supported by zig-runner yet",
                .{r.why},
            ) };
        };
    }
    q.tags = tags.items;
    q.build_args = args.items;
    q.labels = labels.items;
    return .{ .ok = q };
}

// --- references ---

/// The Docker reference `ref` as the index keeps it: the repository's path and a tag, the form
/// `docker image ls` shows (`x` is `x:latest`). Null when it is no reference a tag can have (a
/// digest, an uppercase repository, an empty component).
pub fn parseRef(arena: Allocator, ref: []const u8) !?[]const u8 {
    if (ref.len == 0 or ref.len > 255) return null;
    if (std.mem.indexOfScalar(u8, ref, '@') != null) return null;
    const slash = std.mem.lastIndexOfScalar(u8, ref, '/') orelse 0;
    const colon = if (std.mem.lastIndexOfScalar(u8, ref[slash..], ':')) |c| slash + c else null;
    const repo = ref[0 .. colon orelse ref.len];
    const tag = if (colon) |c| ref[c + 1 ..] else "latest";
    if (repo.len == 0 or !validTag(tag)) return null;
    var parts = std.mem.splitScalar(u8, repo, '/');
    var first = true;
    while (parts.next()) |p| : (first = false) {
        if (p.len == 0) return null;
        // The registry's host may have a port and capitals, as `localhost:5000` or `Registry.io`.
        if (first and std.mem.indexOfScalar(u8, repo, '/') != null and
            (std.mem.indexOfAny(u8, p, ".:") != null or std.mem.eql(u8, p, "localhost")))
        {
            for (p) |c| if (!std.ascii.isAlphanumeric(c) and c != '.' and c != '-' and c != ':') return null;
            continue;
        }
        if (!validComponent(p)) return null;
    }
    const familiar = familiarRepo(repo);
    return try std.fmt.allocPrint(arena, "{s}:{s}", .{ familiar, tag });
}

/// `[a-z0-9]+(?:(?:[._]|__|[-]*)[a-z0-9]+)*`, the grammar of a path component.
fn validComponent(p: []const u8) bool {
    if (p.len == 0) return false;
    if (!std.ascii.isLower(p[0]) and !std.ascii.isDigit(p[0])) return false;
    if (!std.ascii.isLower(p[p.len - 1]) and !std.ascii.isDigit(p[p.len - 1])) return false;
    for (p) |c| if (!std.ascii.isLower(c) and !std.ascii.isDigit(c) and c != '.' and c != '_' and c != '-') return false;
    return true;
}

/// `[\w][\w.-]{0,127}`.
fn validTag(tag: []const u8) bool {
    if (tag.len == 0 or tag.len > 128) return false;
    if (!std.ascii.isAlphanumeric(tag[0]) and tag[0] != '_') return false;
    for (tag) |c| if (!std.ascii.isAlphanumeric(c) and c != '_' and c != '.' and c != '-') return false;
    return true;
}

/// Docker Hub's repositories shown as a person writes them.
fn familiarRepo(repo: []const u8) []const u8 {
    for ([_][]const u8{ "docker.io/library/", "index.docker.io/library/", "docker.io/", "index.docker.io/" }) |p|
        if (std.mem.startsWith(u8, repo, p)) return repo[p.len..];
    return repo;
}

// --- the context ---

pub const Limits = struct {
    /// What the files of the context hold, and its entries (files, directories and links).
    bytes: u64 = 1 << 30,
    entries: u32 = 200_000,
    /// A name's length and its components.
    name_bytes: usize = 4096,
    depth: u32 = 128,
    /// A link's target.
    link_bytes: usize = 4096,
};

/// Directories whose own mode is kept in memory until the end.
const max_modes = 10_000;

pub const Unpacked = struct { entries: u32, bytes: u64 };

pub const UnpackError = error{BadContext} || Allocator.Error;

/// A name of the tar as components, or null when it is not one a context can hold: absolute,
/// climbing, empty. `./a//b/` is `a/b`; `.` is no components (the root).
pub fn components(arena: Allocator, name: []const u8, lim: Limits) !?[]const []const u8 {
    if (name.len > lim.name_bytes) return null;
    if (std.mem.indexOfScalar(u8, name, 0) != null) return null;
    if (name.len > 0 and name[0] == '/') return null;
    var out: std.ArrayList([]const u8) = .empty;
    var it = std.mem.splitScalar(u8, name, '/');
    while (it.next()) |c| {
        if (c.len == 0 or std.mem.eql(u8, c, ".")) continue;
        if (std.mem.eql(u8, c, "..")) return null;
        if (out.items.len >= lim.depth) return null;
        try out.append(arena, c);
    }
    return out.items;
}

/// Whether a link at depth `depth` (the components above it) may point at `target`: relative,
/// climbing `..` only at its start and no further than its own directory, naming no `.` and no
/// empty component after that, so that however links are chained a path never leaves the root.
pub fn linkInside(target: []const u8, depth: usize) bool {
    if (target.len == 0 or target[0] == '/') return false;
    if (std.mem.indexOfScalar(u8, target, 0) != null) return false;
    if (std.mem.eql(u8, target, ".")) return true;
    var it = std.mem.splitScalar(u8, target, '/');
    var up: usize = 0;
    var names = false;
    while (it.next()) |c| {
        if (c.len == 0) {
            // A trailing `/` is fine (`../dir/`), an empty component inside is not.
            if (it.peek() != null) return false;
            continue;
        }
        if (std.mem.eql(u8, c, "..")) {
            if (names) return false;
            up += 1;
            if (up > depth) return false;
        } else if (std.mem.eql(u8, c, ".")) {
            return false;
        } else names = true;
    }
    return true;
}

fn zname(arena: Allocator, name: []const u8) ![:0]u8 {
    return arena.dupeSentinel(u8, name, 0);
}

fn errnoOk(rc: usize) bool {
    return linux.errno(rc) == .SUCCESS;
}

/// The directory `parts` (all components but the last, which the caller makes) of the context at
/// `root`, each made when missing and entered with `O_NOFOLLOW`: null when one is a link or a file.
/// The descriptor is the caller's to close, unless it is `root` itself.
fn walkTo(arena: Allocator, root: linux.fd_t, parts: []const []const u8) !?linux.fd_t {
    var cur = root;
    for (parts) |p| {
        const name = try zname(arena, p);
        const made = linux.mkdirat(cur, name, 0o755);
        if (!errnoOk(made) and linux.errno(made) != .EXIST) {
            if (cur != root) _ = linux.close(cur);
            return null;
        }
        const rc = linux.openat(cur, name, .{
            .ACCMODE = .RDONLY,
            .DIRECTORY = true,
            .NOFOLLOW = true,
            .CLOEXEC = true,
        }, 0);
        if (cur != root) _ = linux.close(cur);
        if (!errnoOk(rc)) return null;
        cur = std.math.cast(linux.fd_t, rc) orelse return null;
    }
    return cur;
}

/// Unpacks the tar at `tar_path` into the directory `dest` (which exists): files, directories and
/// links, under `lim`. `why` says what is wrong with a context that is refused.
pub fn unpack(
    arena: Allocator,
    io: std.Io,
    dest: []const u8,
    tar_path: []const u8,
    lim: Limits,
    cancel: ?*const std.atomic.Value(bool),
    why: *[]const u8,
) UnpackError!Unpacked {
    const root_rc = linux.open(try zname(arena, dest), .{
        .ACCMODE = .RDONLY,
        .DIRECTORY = true,
        .CLOEXEC = true,
    }, 0);
    if (!errnoOk(root_rc)) {
        why.* = "the context's directory could not be opened";
        return error.BadContext;
    }
    const root = std.math.cast(linux.fd_t, root_rc) orelse return error.BadContext;
    defer _ = linux.close(root);
    var file = std.Io.Dir.cwd().openFile(io, tar_path, .{}) catch {
        why.* = "the context could not be read back";
        return error.BadContext;
    };
    defer file.close(io);
    var rbuf: [64 * 1024]u8 = undefined;
    var reader = file.reader(io, &rbuf);
    // The CLI's `--compress` sends gzip; only the plain tar is read (yet).
    if (reader.interface.peek(2)) |magic| {
        if (std.mem.eql(u8, magic, "\x1f\x8b")) {
            why.* = "a compressed build context (--compress) is not supported yet";
            return error.BadContext;
        }
    } else |_| {}
    var name_buf: [4096]u8 = undefined;
    var link_buf: [4096]u8 = undefined;
    // No diagnostics: the first entry of a kind that is not read ends it, so a tar of a million
    // FIFOs costs nothing.
    var it: std.tar.Iterator = .init(&reader.interface, .{
        .file_name_buffer = &name_buf,
        .link_name_buffer = &link_buf,
    });
    // What one entry needs is freed at the next; a directory whose mode is not the default is
    // remembered (at most `max_modes`) to be given it at the end.
    var scratch: std.heap.ArenaAllocator = .init(std.heap.page_allocator);
    defer scratch.deinit();
    const sa = scratch.allocator();
    var dirs: std.ArrayList(struct { path: []const u8, mode: u32 }) = .empty;
    var done: Unpacked = .{ .entries = 0, .bytes = 0 };
    while (true) {
        _ = scratch.reset(.retain_capacity);
        if (cancel) |c| if (done.entries % 256 == 0 and c.load(.acquire)) {
            why.* = "the build was cancelled";
            return error.BadContext;
        };
        const entry = (it.next() catch |e| {
            why.* = switch (e) {
                error.TarInsufficientBuffer => "a name in the context is too long",
                error.UnexpectedEndOfStream, error.EndOfStream => "the context's tar ends in the middle of an entry",
                error.TarUnsupportedHeader => "the context has an entry of a type that is not supported yet (a hard link, a device, a FIFO or a sparse file)",
                else => try std.fmt.allocPrint(arena, "the context is not a valid tar: {t}", .{e}),
            };
            return error.BadContext;
        }) orelse break;
        done.entries += 1;
        if (done.entries > lim.entries) {
            why.* = try std.fmt.allocPrint(arena, "the context has more than {d} entries", .{lim.entries});
            return error.BadContext;
        }
        const parts = (try components(sa, entry.name, lim)) orelse {
            why.* = try std.fmt.allocPrint(arena, "the context has an entry whose name is not " ++
                "inside it: {s}", .{try printable(arena, entry.name)});
            return error.BadContext;
        };
        if (parts.len == 0) {
            // `./` itself.
            continue;
        }
        const parent = (try walkTo(sa, root, parts[0 .. parts.len - 1])) orelse {
            why.* = try std.fmt.allocPrint(arena, "the context's entry {s} is inside a link or a file", .{
                try printable(arena, entry.name),
            });
            return error.BadContext;
        };
        defer if (parent != root) {
            _ = linux.close(parent);
        };
        const leaf = try zname(sa, parts[parts.len - 1]);
        switch (entry.kind) {
            .directory => {
                const rc = linux.mkdirat(parent, leaf, 0o755);
                if (!errnoOk(rc) and linux.errno(rc) != .EXIST) {
                    why.* = try std.fmt.allocPrint(arena, "the directory {s} could not be made", .{try printable(arena, entry.name)});
                    return error.BadContext;
                }
                if (entry.mode & 0o777 != 0o755 and dirs.items.len < max_modes) {
                    const joined = try std.mem.join(arena, "/", parts);
                    try dirs.append(arena, .{ .path = joined, .mode = entry.mode });
                }
            },
            .sym_link => {
                if (entry.link_name.len > lim.link_bytes or !linkInside(entry.link_name, parts.len - 1)) {
                    why.* = try std.fmt.allocPrint(arena, "the context's link {s} points outside the " ++
                        "context, or in a way that cannot be told to stay inside it", .{try printable(arena, entry.name)});
                    return error.BadContext;
                }
                _ = linux.unlinkat(parent, leaf, 0);
                const rc = linux.symlinkat(try zname(sa, entry.link_name), parent, leaf);
                if (!errnoOk(rc)) {
                    why.* = try std.fmt.allocPrint(arena, "the link {s} could not be made", .{try printable(arena, entry.name)});
                    return error.BadContext;
                }
            },
            .file => {
                if (entry.size > lim.bytes - done.bytes) {
                    why.* = try std.fmt.allocPrint(arena, "the context holds more than {d} bytes", .{lim.bytes});
                    return error.BadContext;
                }
                try writeFile(arena, &it, entry, parent, leaf, why);
                done.bytes += entry.size;
            },
        }
    }
    // Directories' own modes last, so that one without write permission was written into first.
    var i = dirs.items.len;
    while (i > 0) {
        i -= 1;
        const d = dirs.items[i];
        _ = scratch.reset(.retain_capacity);
        const parts = (try components(sa, d.path, lim)) orelse continue;
        const fd = (try walkTo(sa, root, parts)) orelse continue;
        defer if (fd != root) {
            _ = linux.close(fd);
        };
        _ = linux.fchmod(fd, (d.mode & 0o777) | 0o700);
    }
    return done;
}

/// A name as one printable line, cut: a context's names are the client's.
fn printable(arena: Allocator, name: []const u8) ![]const u8 {
    var out: std.ArrayList(u8) = .empty;
    for (name[0..@min(name.len, 120)]) |c| try out.append(arena, if (c < 0x20 or c == 0x7f) '?' else c);
    if (name.len > 120) try out.appendSlice(arena, "...");
    return out.items;
}

fn writeFile(
    arena: Allocator,
    it: *std.tar.Iterator,
    entry: std.tar.Iterator.File,
    parent: linux.fd_t,
    leaf: [:0]const u8,
    why: *[]const u8,
) UnpackError!void {
    // A file that is there (a name twice in the tar: the later one wins) is replaced, not written
    // through.
    _ = linux.unlinkat(parent, leaf, 0);
    const rc = linux.openat(parent, leaf, .{
        .ACCMODE = .WRONLY,
        .CREAT = true,
        .EXCL = true,
        .NOFOLLOW = true,
        .CLOEXEC = true,
    }, 0o600);
    if (!errnoOk(rc)) {
        why.* = try std.fmt.allocPrint(arena, "the file {s} could not be made", .{try printable(arena, entry.name)});
        return error.BadContext;
    }
    const fd = std.math.cast(linux.fd_t, rc) orelse return error.BadContext;
    defer _ = linux.close(fd);
    var buf: [64 * 1024]u8 = undefined;
    var left = entry.size;
    while (left > 0) {
        const n = std.math.lossyCast(usize, @min(left, buf.len));
        it.reader.readSliceAll(buf[0..n]) catch {
            why.* = "the context's tar ends in the middle of a file";
            return error.BadContext;
        };
        var off: usize = 0;
        while (off < n) {
            const w = linux.write(fd, buf[off..n].ptr, n - off);
            switch (linux.errno(w)) {
                .SUCCESS => off += w,
                .INTR => {},
                else => {
                    why.* = try std.fmt.allocPrint(arena, "the file {s} could not be written (disk full?)", .{try printable(arena, entry.name)});
                    return error.BadContext;
                },
            }
        }
        left -= n;
    }
    it.unread_file_bytes = 0;
    // Its own mode, but never unreadable to the runner, which copies it; no setuid bits.
    _ = linux.fchmod(fd, (entry.mode & 0o777) | 0o400);
}

// --- images ---

/// An image the job built, as the index keeps it.
pub const Record = struct {
    /// `sha256:<hex>`.
    id: []const u8,
    /// The layers' directories, top first, ending with the base's rootfs (`dockerfile.Built`).
    lowers: []const []const u8,
    config: images.Image,
    /// The key of the build's last step: with the config, what the ID is of.
    final_key: []const u8,
    /// RFC 3339.
    created: []const u8,
    /// `repo:tag`, as `docker image ls` shows them.
    tags: []const []const u8 = &.{},
};

/// The image's config as the ID hashes it and `docker image inspect` shows it as `Config`: the
/// parts the builder leaves (entrypoint, command, env, working directory, user, labels), in a fixed
/// order, so equal builds render equal text. No timestamp: it is what the image is, not when.
pub fn configJson(arena: Allocator, c: images.Image, layer_keys: []const []const u8) ![]const u8 {
    var out: std.Io.Writer.Allocating = .init(arena);
    const w = &out.writer;
    var s: std.json.Stringify = .{ .writer = w };
    try s.beginObject();
    try s.objectField("architecture");
    try s.write(archName());
    try s.objectField("os");
    try s.write("linux");
    try s.objectField("config");
    try s.beginObject();
    try s.objectField("User");
    try s.write(c.user);
    try s.objectField("Env");
    try s.write(c.env);
    try s.objectField("Entrypoint");
    try s.write(if (c.entrypoint.len == 0) null else c.entrypoint);
    try s.objectField("Cmd");
    try s.write(if (c.cmd.len == 0) null else c.cmd);
    try s.objectField("WorkingDir");
    try s.write(c.workdir);
    try s.objectField("Labels");
    if (c.labels.len == 0) {
        try s.write(null);
    } else {
        try s.beginObject();
        for (sortedLabels(arena, c.labels) catch c.labels) |l| {
            try s.objectField(l.name);
            try s.write(l.value);
        }
        try s.endObject();
    }
    try s.endObject();
    try s.objectField("rootfs");
    try s.beginObject();
    try s.objectField("type");
    try s.write("layers");
    try s.objectField("diff_ids");
    try s.beginArray();
    for (layer_keys) |k| try s.write(try std.fmt.allocPrint(arena, "sha256:{s}", .{k}));
    try s.endArray();
    try s.endObject();
    try s.endObject();
    return out.written();
}

fn sortedLabels(arena: Allocator, labels: []const images.Label) ![]const images.Label {
    const copy = try arena.dupe(images.Label, labels);
    std.mem.sort(images.Label, copy, {}, struct {
        fn less(_: void, a: images.Label, b: images.Label) bool {
            return std.mem.lessThan(u8, a.name, b.name);
        }
    }.less);
    return copy;
}

/// The platform this runner builds for, as `--platform` names it.
pub fn ownPlatform() []const u8 {
    return "linux/" ++ comptime archName();
}

inline fn archName() []const u8 {
    return switch (@import("builtin").cpu.arch) {
        .x86_64 => "amd64",
        .aarch64 => "arm64",
        else => @tagName(@import("builtin").cpu.arch),
    };
}

/// `sha256:` and the hex of the SHA-256 of `config` (`configJson`), a newline and `final_key`.
pub fn imageId(arena: Allocator, config: []const u8, final_key: []const u8) ![]const u8 {
    var h = Sha256.init(.{});
    h.update(config);
    h.update("\n");
    h.update(final_key);
    var sum: [32]u8 = undefined;
    h.final(&sum);
    return std.fmt.allocPrint(arena, "sha256:{s}", .{std.fmt.bytesToHex(sum, .lower)});
}

/// The body of `GET /images/{name}/json`, as `docker image inspect` reads it.
pub fn inspectJson(arena: Allocator, r: Record) ![]const u8 {
    var out: std.Io.Writer.Allocating = .init(arena);
    var s: std.json.Stringify = .{ .writer = &out.writer };
    const c = r.config;
    try s.beginObject();
    try s.objectField("Id");
    try s.write(r.id);
    try s.objectField("RepoTags");
    try s.write(r.tags);
    try s.objectField("RepoDigests");
    try s.beginArray();
    try s.endArray();
    try s.objectField("Parent");
    try s.write("");
    try s.objectField("Comment");
    try s.write("built by zig-runner");
    try s.objectField("Created");
    try s.write(r.created);
    try s.objectField("DockerVersion");
    try s.write("");
    try s.objectField("Author");
    try s.write("");
    try s.objectField("Config");
    try s.beginObject();
    try s.objectField("User");
    try s.write(c.user);
    try s.objectField("Env");
    try s.write(c.env);
    try s.objectField("Entrypoint");
    try s.write(if (c.entrypoint.len == 0) null else c.entrypoint);
    try s.objectField("Cmd");
    try s.write(if (c.cmd.len == 0) null else c.cmd);
    try s.objectField("WorkingDir");
    try s.write(c.workdir);
    try s.objectField("Labels");
    if (c.labels.len == 0) {
        try s.write(null);
    } else {
        try s.beginObject();
        for (sortedLabels(arena, c.labels) catch c.labels) |l| {
            try s.objectField(l.name);
            try s.write(l.value);
        }
        try s.endObject();
    }
    try s.endObject();
    try s.objectField("Architecture");
    try s.write(archName());
    try s.objectField("Os");
    try s.write("linux");
    try s.objectField("Size");
    try s.write(@as(u64, 0));
    try s.objectField("VirtualSize");
    try s.write(@as(u64, 0));
    try s.objectField("GraphDriver");
    try s.beginObject();
    try s.objectField("Data");
    try s.write(null);
    try s.objectField("Name");
    try s.write("zig-runner");
    try s.endObject();
    try s.objectField("RootFS");
    try s.beginObject();
    try s.objectField("Type");
    try s.write("layers");
    try s.objectField("Layers");
    try s.beginArray();
    for (try layerKeys(arena, r.lowers)) |k| try s.write(try std.fmt.allocPrint(arena, "sha256:{s}", .{k}));
    try s.endArray();
    try s.endObject();
    try s.objectField("Metadata");
    try s.beginObject();
    try s.objectField("LastTagTime");
    try s.write("0001-01-01T00:00:00Z");
    try s.endObject();
    try s.endObject();
    return out.written();
}

/// The store's keys of an image's own layers, bottom first: its `lowers` (top first, ending with
/// the base's rootfs) without that, each named by the store's directory (`.../layers/<key>/fs`).
pub fn layerKeys(arena: Allocator, lowers: []const []const u8) ![]const []const u8 {
    var out: std.ArrayList([]const u8) = .empty;
    var i = lowers.len -| 1;
    while (i > 0) {
        i -= 1;
        const dir = std.fs.path.dirname(lowers[i]) orelse lowers[i];
        try out.append(arena, std.fs.path.basename(dir));
    }
    return out.items;
}

/// `secs` since the epoch as RFC 3339 in UTC, as Docker prints `Created`.
pub fn rfc3339(arena: Allocator, secs: i64) ![]const u8 {
    const es: std.time.epoch.EpochSeconds = .{ .secs = std.math.lossyCast(u64, @max(secs, 0)) };
    const day = es.getEpochDay().calculateYearDay();
    const md = day.calculateMonthDay();
    const t = es.getDaySeconds();
    return std.fmt.allocPrint(arena, "{d:0>4}-{d:0>2}-{d:0>2}T{d:0>2}:{d:0>2}:{d:0>2}Z", .{
        day.year,            md.month.numeric(),     md.day_index + 1,
        t.getHoursIntoDay(), t.getMinutesIntoHour(), t.getSecondsIntoMinute(),
    });
}

// --- the tag index ---

/// The job's images by tag and ID. All of it is the job's own memory (`gpa`), freed with the job:
/// no file, nothing another job or trust scope could read.
pub const Index = struct {
    arena: std.heap.ArenaAllocator,
    mu: std.Io.Mutex = .init,
    records: std.ArrayList(Record) = .empty,

    pub const max_images = 100;
    pub const max_tags = 256;

    pub fn init(gpa: Allocator) Index {
        return .{ .arena = .init(gpa) };
    }

    pub fn deinit(i: *Index) void {
        i.arena.deinit();
    }

    pub fn lock(i: *Index, io: std.Io) void {
        i.mu.lockUncancelable(io);
    }

    pub fn unlock(i: *Index, io: std.Io) void {
        i.mu.unlock(io);
    }

    /// Adds `r` (copied) with `tags`, taking each tag from the image that had it. An image with
    /// the ID is the same image: it gets the tags. Call with the lock held.
    pub fn add(i: *Index, r: Record, tags: []const []const u8) !*Record {
        const a = i.arena.allocator();
        for (i.records.items) |*have| if (std.mem.eql(u8, have.id, r.id)) {
            for (tags) |t| try i.tagLocked(have, t);
            return have;
        };
        if (i.records.items.len >= max_images) return error.TooManyImages;
        var copy = r;
        copy.tags = &.{};
        try i.records.append(a, copy);
        const rec = &i.records.items[i.records.items.len - 1];
        for (tags) |t| try i.tagLocked(rec, t);
        return rec;
    }

    fn tagLocked(i: *Index, rec: *Record, new: []const u8) !void {
        const a = i.arena.allocator();
        for (rec.tags) |t| if (std.mem.eql(u8, t, new)) return;
        var total: usize = 0;
        for (i.records.items) |r| total += r.tags.len;
        // A tag that moves from another image frees its place.
        for (i.records.items) |*other| {
            if (other == rec) continue;
            for (other.tags, 0..) |t, k| if (std.mem.eql(u8, t, new)) {
                var keep: std.ArrayList([]const u8) = .empty;
                for (other.tags, 0..) |u, j| if (j != k) try keep.append(a, u);
                other.tags = keep.items;
                total -= 1;
                break;
            };
        }
        if (total >= max_tags) return error.TooManyTags;
        var next: std.ArrayList([]const u8) = .empty;
        try next.appendSlice(a, rec.tags);
        try next.append(a, try a.dupe(u8, new));
        rec.tags = next.items;
    }

    /// Gives the image `source` names (a tag or an ID) one more tag.
    pub fn addTag(i: *Index, source: *Record, new_tag: []const u8) !void {
        try i.tagLocked(source, new_tag);
    }

    /// The image `name` is: a tag (`parseRef`'s form, already normalised by the caller) or an
    /// ID, whole or by a prefix of at least `min_prefix` hex digits that only one image has.
    pub fn find(i: *Index, ref: ?[]const u8, name: []const u8) ?*Record {
        if (ref) |r| for (i.records.items) |*rec| for (rec.tags) |t| if (std.mem.eql(u8, t, r)) return rec;
        return i.byId(name);
    }

    pub const min_prefix = 4;

    fn byId(i: *Index, name: []const u8) ?*Record {
        const hex = if (std.mem.startsWith(u8, name, "sha256:")) name["sha256:".len..] else name;
        if (hex.len < min_prefix or hex.len > 64) return null;
        for (hex) |c| if (!std.ascii.isHex(c) or std.ascii.isUpper(c)) return null;
        var found: ?*Record = null;
        for (i.records.items) |*rec| {
            if (!std.mem.startsWith(u8, rec.id["sha256:".len..], hex)) continue;
            if (found != null) return null;
            found = rec;
        }
        return found;
    }

    pub const Removed = union(enum) {
        /// `Untagged` (the tag) and, when the image has none left, `Deleted` (its ID).
        done: struct { untagged: ?[]const u8, deleted: ?[]const u8 },
        missing,
        /// An ID with several tags and no `force`.
        conflict: []const u8,
    };

    /// `docker rmi name`: a tag is taken off its image, which goes with its last tag; an ID takes
    /// the image and every tag it has (only with `force` when there are several).
    pub fn remove(i: *Index, arena: Allocator, ref: ?[]const u8, name: []const u8, force: bool) !Removed {
        const a = i.arena.allocator();
        if (ref) |r| for (i.records.items, 0..) |*rec, at| for (rec.tags) |t| if (std.mem.eql(u8, t, r)) {
            var keep: std.ArrayList([]const u8) = .empty;
            for (rec.tags) |u| if (!std.mem.eql(u8, u, r)) try keep.append(a, u);
            rec.tags = keep.items;
            const tag_text = try arena.dupe(u8, r);
            if (rec.tags.len == 0) {
                const id = try arena.dupe(u8, rec.id);
                _ = i.records.orderedRemove(at);
                return .{ .done = .{ .untagged = tag_text, .deleted = id } };
            }
            return .{ .done = .{ .untagged = tag_text, .deleted = null } };
        };
        const rec = i.byId(name) orelse return .missing;
        if (rec.tags.len > 1 and !force) return .{ .conflict = try arena.dupe(u8, rec.id) };
        const id = try arena.dupe(u8, rec.id);
        const tag_text: ?[]const u8 = if (rec.tags.len > 0) try arena.dupe(u8, rec.tags[0]) else null;
        const at = (@intFromPtr(rec) - @intFromPtr(i.records.items.ptr)) / @sizeOf(Record);
        _ = i.records.orderedRemove(at);
        return .{ .done = .{ .untagged = tag_text, .deleted = id } };
    }
};

// --- the stream's lines ---

/// One JSON message of a build's stream: `{"stream":"..."}`.
pub fn streamLine(arena: Allocator, text: []const u8) ![]const u8 {
    return std.fmt.allocPrint(arena, "{f}\n", .{std.json.fmt(.{ .stream = text }, .{})});
}

/// `{"aux":{"ID":"sha256:..."}}`, which the CLI reads the image's ID from.
pub fn auxLine(arena: Allocator, id: []const u8) ![]const u8 {
    return std.fmt.allocPrint(arena, "{f}\n", .{std.json.fmt(.{ .aux = .{ .ID = id } }, .{})});
}

/// `{"errorDetail":{"message":".."},"error":".."}`: the build failed; the CLI prints it and exits 1.
pub fn errorLine(arena: Allocator, message: []const u8) ![]const u8 {
    return std.fmt.allocPrint(arena, "{f}\n", .{std.json.fmt(.{
        .errorDetail = .{ .message = message },
        .@"error" = message,
    }, .{})});
}

// --- tests ---

const testing = std.testing;

test "docker build: the query's options are read, repeated tags and JSON maps included" {
    var a: std.heap.ArenaAllocator = .init(testing.allocator);
    defer a.deinit();
    // The runner's own platform, whichever machine this is.
    const text = "t=x%3A1&t=y&dockerfile=sub%2FDockerfile&" ++
        "buildargs=%7B%22A%22%3A%221%22%2C%22B%22%3Anull%7D&labels=%7B%22k%22%3A%22v+w%22%7D&" ++
        "target=build&nocache=1&pull=false&q=true&rm=1&cachefrom=%5B%5D&memory=0&platform=linux%2F" ++ comptime archName();
    const q = (try parseQuery(a.allocator(), text)).ok;
    try testing.expectEqual(@as(usize, 2), q.tags.len);
    try testing.expectEqualStrings("x:1", q.tags[0]);
    try testing.expectEqualStrings("y", q.tags[1]);
    try testing.expectEqualStrings("sub/Dockerfile", q.dockerfile);
    try testing.expectEqual(@as(usize, 1), q.build_args.len);
    try testing.expectEqualStrings("A", q.build_args[0].name);
    try testing.expectEqualStrings("1", q.build_args[0].value);
    try testing.expectEqualStrings("v w", q.labels[0].value);
    try testing.expectEqualStrings("build", q.target);
    try testing.expect(q.nocache and !q.pull and q.quiet);
    try testing.expectEqualStrings(ownPlatform(), q.platform);
    // Nothing set: Docker's defaults.
    const none = (try parseQuery(a.allocator(), "")).ok;
    try testing.expectEqualStrings("Dockerfile", none.dockerfile);
    try testing.expectEqual(@as(usize, 0), none.tags.len);
}

test "docker build: an option that would change the build is refused, a bad one is a 400" {
    var a: std.heap.ArenaAllocator = .init(testing.allocator);
    defer a.deinit();
    const arena = a.allocator();
    for ([_][]const u8{ "squash=1", "remote=https%3A%2F%2Fx", "networkmode=host", "extrahosts=a%3A1.2.3.4", "version=2" }) |bad|
        try testing.expect((try parseQuery(arena, bad)) == .unsupported);
    // Off or unset: accepted.
    try testing.expect((try parseQuery(arena, "squash=0&networkmode=default&networkmode=bridge&version=1")) == .ok);
    for ([_][]const u8{ "buildargs=%5B%5D", "buildargs=nope", "labels=%7B%22a%3Db%22%3A%221%22%7D", "t=a%zz" }) |bad|
        try testing.expect((try parseQuery(arena, bad)) == .bad);
}

test "docker build: boolValue is Docker's" {
    for ([_][]const u8{ "", "0", "no", "false", "none", "FALSE" }) |f| try testing.expect(!boolValue(f));
    for ([_][]const u8{ "1", "true", "yes", "anything" }) |t| try testing.expect(boolValue(t));
}

test "docker build: a reference is a repository and a tag, familiar" {
    var a: std.heap.ArenaAllocator = .init(testing.allocator);
    defer a.deinit();
    const arena = a.allocator();
    const cases = [_][2][]const u8{
        .{ "x", "x:latest" },
        .{ "x:1.2", "x:1.2" },
        .{ "my-org/app_v2:rc.1", "my-org/app_v2:rc.1" },
        .{ "docker.io/library/alpine:3.22", "alpine:3.22" },
        .{ "localhost:5000/team/app", "localhost:5000/team/app:latest" },
        .{ "ghcr.io/open-blue/x:1", "ghcr.io/open-blue/x:1" },
    };
    for (cases) |c| try testing.expectEqualStrings(c[1], (try parseRef(arena, c[0])).?);
    for ([_][]const u8{ "", "X", "a//b", "a/B", "x:", "x:-1", "ghcr.io/Open-Blue/x:1", "x@sha256:00", "/x", "x/", "a b", "_x" }) |bad|
        try testing.expect((try parseRef(arena, bad)) == null);
}

test "docker build: a name's components and a link's target are checked" {
    var a: std.heap.ArenaAllocator = .init(testing.allocator);
    defer a.deinit();
    const arena = a.allocator();
    const ok = (try components(arena, "./a//b/./c/", .{})).?;
    try testing.expectEqual(@as(usize, 3), ok.len);
    try testing.expectEqualStrings("c", ok[2]);
    try testing.expectEqual(@as(usize, 0), (try components(arena, "./", .{})).?.len);
    for ([_][]const u8{ "/etc/passwd", "../x", "a/../../x", "a/..", "a\x00b" }) |bad|
        try testing.expect((try components(arena, bad, .{})) == null);
    // A link at depth 1 (`a/l`): it may name a sibling, climb one, never two, never after a name.
    for ([_][]const u8{ "b", "b/c", "../x", "..", "../x/y", "." }) |good|
        try testing.expect(linkInside(good, 1));
    for ([_][]const u8{ "", "/etc", "../../x", "b/../c", "b//c", "./b", "../b/..", "a/./b" }) |bad|
        try testing.expect(!linkInside(bad, 1));
    try testing.expect(!linkInside("..", 0));
    try testing.expect(linkInside("x", 0));
}

/// A tar of `entries`, as GNU tar would write the plain kinds, for the unpacker's tests.
fn tarOf(arena: Allocator, entries: []const struct {
    name: []const u8,
    kind: u8 = '0',
    data: []const u8 = "",
    link: []const u8 = "",
    mode: u32 = 0o644,
}) ![]const u8 {
    var out: std.ArrayList(u8) = .empty;
    for (entries) |e| {
        var h: [512]u8 = @splat(0);
        @memcpy(h[0..e.name.len], e.name);
        _ = try std.fmt.bufPrint(h[100..108], "{o:0>7}", .{e.mode});
        _ = try std.fmt.bufPrint(h[108..116], "{o:0>7}", .{0});
        _ = try std.fmt.bufPrint(h[116..124], "{o:0>7}", .{0});
        _ = try std.fmt.bufPrint(h[124..136], "{o:0>11}", .{e.data.len});
        _ = try std.fmt.bufPrint(h[136..148], "{o:0>11}", .{0});
        @memset(h[148..156], ' ');
        h[156] = e.kind;
        @memcpy(h[157 .. 157 + e.link.len], e.link);
        @memcpy(h[257..263], "ustar\x00");
        @memcpy(h[263..265], "00");
        var sum: u32 = 0;
        for (h) |c| sum += c;
        _ = try std.fmt.bufPrint(h[148..155], "{o:0>6}\x00", .{sum});
        h[155] = ' ';
        try out.appendSlice(arena, &h);
        try out.appendSlice(arena, e.data);
        try out.appendNTimes(arena, 0, (512 - e.data.len % 512) % 512);
    }
    try out.appendNTimes(arena, 0, 1024);
    return out.items;
}

fn unpackTest(arena: Allocator, tmp: *testing.TmpDir, tar: []const u8, lim: Limits) !struct { got: UnpackError!Unpacked, why: []const u8, root: []const u8 } {
    const io = testing.io;
    try tmp.dir.writeFile(io, .{ .sub_path = "in.tar", .data = tar });
    try tmp.dir.createDirPath(io, "out");
    const base = try tmp.dir.realPathFileAlloc(io, ".", arena);
    const root = try std.fmt.allocPrint(arena, "{s}/out", .{base});
    var why: []const u8 = "";
    const got = unpack(arena, io, root, try std.fmt.allocPrint(arena, "{s}/in.tar", .{base}), lim, null, &why);
    return .{ .got = got, .why = why, .root = root };
}

test "docker build: a context's files, directories and links are unpacked, with their modes" {
    var a: std.heap.ArenaAllocator = .init(testing.allocator);
    defer a.deinit();
    const arena = a.allocator();
    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();
    const tar = try tarOf(arena, &.{
        .{ .name = "./", .kind = '5', .mode = 0o755 },
        .{ .name = "Dockerfile", .data = "FROM scratch\n" },
        .{ .name = "src/", .kind = '5', .mode = 0o555 },
        .{ .name = "src/run.sh", .data = "#!/bin/sh\n", .mode = 0o755 },
        .{ .name = "src/link", .kind = '2', .link = "run.sh" },
        .{ .name = "up", .kind = '2', .link = "src" },
        .{ .name = "empty", .data = "" },
    });
    const r = try unpackTest(arena, &tmp, tar, .{});
    const got = try r.got;
    try testing.expectEqual(@as(u32, 7), got.entries);
    try testing.expectEqual(@as(u64, 23), got.bytes);
    const io = testing.io;
    const df = try tmp.dir.readFileAlloc(io, "out/Dockerfile", arena, .limited(100));
    try testing.expectEqualStrings("FROM scratch\n", df);
    var buf: [64]u8 = undefined;
    const target = try tmp.dir.readLink(io, "out/src/link", &buf);
    try testing.expectEqualStrings("run.sh", buf[0..target]);
    const st = try tmp.dir.statFile(io, "out/src/run.sh", .{});
    try testing.expectEqual(@as(u32, 0o755), std.math.lossyCast(u32, st.permissions.toMode() & 0o777));
}

test "docker build: a context with an entry outside it, a link out of it or a type it has no use for is refused" {
    var a: std.heap.ArenaAllocator = .init(testing.allocator);
    defer a.deinit();
    const arena = a.allocator();
    const Case = struct { name: []const u8, tar: []const u8, why: []const u8 };
    const cases = [_]Case{
        .{ .name = "absolute", .tar = try tarOf(arena, &.{.{ .name = "/etc/x", .data = "x" }}), .why = "not inside it" },
        .{ .name = "dotdot", .tar = try tarOf(arena, &.{.{ .name = "../x", .data = "x" }}), .why = "not inside it" },
        .{ .name = "climb", .tar = try tarOf(arena, &.{.{ .name = "a/../../x", .data = "x" }}), .why = "not inside it" },
        .{ .name = "absolute link", .tar = try tarOf(arena, &.{.{ .name = "l", .kind = '2', .link = "/etc/passwd" }}), .why = "points outside" },
        .{ .name = "link out", .tar = try tarOf(arena, &.{.{ .name = "l", .kind = '2', .link = "../out" }}), .why = "points outside" },
        .{ .name = "link out of a directory", .tar = try tarOf(arena, &.{
            .{ .name = "d/", .kind = '5' },
            .{ .name = "d/l", .kind = '2', .link = "../../x" },
        }), .why = "points outside" },
        .{ .name = "link that climbs after a name", .tar = try tarOf(arena, &.{
            .{ .name = "a/", .kind = '5' },
            .{ .name = "a/s", .kind = '2', .link = ".." },
            .{ .name = "t", .kind = '2', .link = "a/s/../.." },
        }), .why = "points outside" },
        .{ .name = "through a link", .tar = try tarOf(arena, &.{
            .{ .name = "l", .kind = '2', .link = "." },
            .{ .name = "l/x", .data = "x" },
        }), .why = "inside a link" },
        .{ .name = "hard link", .tar = try tarOf(arena, &.{
            .{ .name = "f", .data = "x" },
            .{ .name = "h", .kind = '1', .link = "f" },
        }), .why = "not supported yet" },
        .{ .name = "device", .tar = try tarOf(arena, &.{.{ .name = "dev", .kind = '3' }}), .why = "not supported yet" },
        .{ .name = "gzip", .tar = "\x1f\x8b\x08\x00 a gzip, not a tar", .why = "--compress" },
    };
    for (cases) |c| {
        var tmp = testing.tmpDir(.{});
        defer tmp.cleanup();
        const r = try unpackTest(arena, &tmp, c.tar, .{});
        testing.expectError(error.BadContext, r.got) catch |e| {
            std.debug.print("case {s}\n", .{c.name});
            return e;
        };
        testing.expect(std.mem.indexOf(u8, r.why, c.why) != null) catch |e| {
            std.debug.print("case {s}: {s}\n", .{ c.name, r.why });
            return e;
        };
        // Nothing was written outside the context's directory.
        try testing.expectError(error.FileNotFound, tmp.dir.access(testing.io, "x", .{}));
    }
}

test "docker build: the context's limits are enforced" {
    var a: std.heap.ArenaAllocator = .init(testing.allocator);
    defer a.deinit();
    const arena = a.allocator();
    const tar = try tarOf(arena, &.{
        .{ .name = "a", .data = "0123456789" },
        .{ .name = "b", .data = "0123456789" },
        .{ .name = "d/e/f/g", .data = "x" },
    });
    {
        var tmp = testing.tmpDir(.{});
        defer tmp.cleanup();
        const r = try unpackTest(arena, &tmp, tar, .{ .bytes = 15 });
        try testing.expectError(error.BadContext, r.got);
        try testing.expect(std.mem.indexOf(u8, r.why, "more than 15 bytes") != null);
    }
    {
        var tmp = testing.tmpDir(.{});
        defer tmp.cleanup();
        const r = try unpackTest(arena, &tmp, tar, .{ .entries = 2 });
        try testing.expectError(error.BadContext, r.got);
        try testing.expect(std.mem.indexOf(u8, r.why, "more than 2 entries") != null);
    }
    {
        var tmp = testing.tmpDir(.{});
        defer tmp.cleanup();
        const r = try unpackTest(arena, &tmp, tar, .{ .depth = 3 });
        try testing.expectError(error.BadContext, r.got);
    }
    {
        // Cut in the middle of a file.
        var tmp = testing.tmpDir(.{});
        defer tmp.cleanup();
        const r = try unpackTest(arena, &tmp, tar[0 .. 512 + 5], .{});
        try testing.expectError(error.BadContext, r.got);
    }
}

test "docker build: the image's ID is of its config and its last step's key, and moves with either" {
    var a: std.heap.ArenaAllocator = .init(testing.allocator);
    defer a.deinit();
    const arena = a.allocator();
    const base: images.Image = .{ .rootfs = "/r", .env = &.{"A=1"}, .cmd = &.{"sh"}, .labels = &.{.{ .name = "k", .value = "v" }} };
    const c1 = try configJson(arena, base, &.{ "k1", "k2" });
    const id1 = try imageId(arena, c1, "final1");
    try testing.expect(std.mem.startsWith(u8, id1, "sha256:"));
    try testing.expectEqual(@as(usize, 7 + 64), id1.len);
    try testing.expectEqualStrings(id1, try imageId(arena, try configJson(arena, base, &.{ "k1", "k2" }), "final1"));
    try testing.expect(!std.mem.eql(u8, id1, try imageId(arena, c1, "final2")));
    var other = base;
    other.labels = &.{.{ .name = "k", .value = "w" }};
    try testing.expect(!std.mem.eql(u8, id1, try imageId(arena, try configJson(arena, other, &.{ "k1", "k2" }), "final1")));
    // Labels in any order are one config.
    var two = base;
    two.labels = &.{ .{ .name = "b", .value = "1" }, .{ .name = "a", .value = "2" } };
    var swapped = base;
    swapped.labels = &.{ .{ .name = "a", .value = "2" }, .{ .name = "b", .value = "1" } };
    try testing.expectEqualStrings(try configJson(arena, two, &.{}), try configJson(arena, swapped, &.{}));
}

test "docker build: inspect is JSON with the ID, tags and labels" {
    var a: std.heap.ArenaAllocator = .init(testing.allocator);
    defer a.deinit();
    const arena = a.allocator();
    const r: Record = .{
        .id = "sha256:abc",
        .lowers = &.{ "/store/layers/k1/fs", "/base" },
        .config = .{ .rootfs = "/base", .labels = &.{.{ .name = "who", .value = "me" }}, .cmd = &.{"sh"} },
        .final_key = "k1",
        .created = "2026-11-16T00:00:00Z",
        .tags = &.{"x:latest"},
    };
    const text = try inspectJson(arena, r);
    const v = try std.json.parseFromSliceLeaky(std.json.Value, arena, text, .{});
    try testing.expectEqualStrings("sha256:abc", v.object.get("Id").?.string);
    try testing.expectEqualStrings("x:latest", v.object.get("RepoTags").?.array.items[0].string);
    try testing.expectEqualStrings("me", v.object.get("Config").?.object.get("Labels").?.object.get("who").?.string);
    try testing.expectEqual(@as(usize, 1), v.object.get("RootFS").?.object.get("Layers").?.array.items.len);
}

test "docker build: the index tags, moves tags, finds by tag, ID and prefix, and removes" {
    var idx: Index = .init(testing.allocator);
    defer idx.deinit();
    var a: std.heap.ArenaAllocator = .init(testing.allocator);
    defer a.deinit();
    const arena = a.allocator();
    const io = testing.io;
    idx.lock(io);
    defer idx.unlock(io);
    const mk = struct {
        fn rec(id: []const u8) Record {
            return .{ .id = id, .lowers = &.{}, .config = .{ .rootfs = "" }, .final_key = "k", .created = "t" };
        }
    };
    const one = try idx.add(mk.rec("sha256:aaaa1111"), &.{ "x:latest", "x:1" });
    try testing.expectEqual(@as(usize, 2), one.tags.len);
    // The same ID is the same image: tags join.
    const again = try idx.add(mk.rec("sha256:aaaa1111"), &.{"y:latest"});
    try testing.expectEqual(one, again);
    try testing.expectEqual(@as(usize, 3), one.tags.len);
    // A tag moves to the image that is tagged with it now.
    const two = try idx.add(mk.rec("sha256:bbbb2222"), &.{"x:latest"});
    try testing.expectEqual(@as(usize, 1), two.tags.len);
    try testing.expectEqual(@as(usize, 2), idx.find("x:1", "x:1").?.tags.len);
    try testing.expectEqual(idx.find("x:latest", "x").?, idx.find(null, "sha256:bbbb2222").?);
    try testing.expectEqual(idx.find(null, "aaaa").?.id.ptr, idx.find("y:latest", "y").?.id.ptr);
    try testing.expect(idx.find(null, "aaa") == null);
    try testing.expect(idx.find(null, "cccc") == null);
    // `docker rmi x:1` untags; the image stays for its other tag.
    const r1 = try idx.remove(arena, "x:1", "x:1", false);
    try testing.expectEqualStrings("x:1", r1.done.untagged.?);
    try testing.expect(r1.done.deleted == null);
    // Its last tag takes the image.
    const r2 = try idx.remove(arena, "y:latest", "y", false);
    try testing.expectEqualStrings("sha256:aaaa1111", r2.done.deleted.?);
    try testing.expect((try idx.remove(arena, "y:latest", "y", false)) == .missing);
    // An ID with two tags needs force.
    _ = try idx.add(mk.rec("sha256:bbbb2222"), &.{"z:latest"});
    try testing.expect((try idx.remove(arena, null, "bbbb2222", false)) == .conflict);
    try testing.expect((try idx.remove(arena, null, "bbbb2222", true)) == .done);
    try testing.expectEqual(@as(usize, 0), idx.records.items.len);
}

test "docker build: the index is bounded" {
    var idx: Index = .init(testing.allocator);
    defer idx.deinit();
    const io = testing.io;
    idx.lock(io);
    defer idx.unlock(io);
    var buf: [32]u8 = undefined;
    var n: usize = 0;
    while (n < Index.max_images) : (n += 1) {
        const id = try std.fmt.bufPrint(&buf, "sha256:{x:0>8}", .{n});
        _ = try idx.add(.{ .id = try idx.arena.allocator().dupe(u8, id), .lowers = &.{}, .config = .{ .rootfs = "" }, .final_key = "k", .created = "t" }, &.{});
    }
    try testing.expectError(error.TooManyImages, idx.add(.{ .id = "sha256:ffffffff", .lowers = &.{}, .config = .{ .rootfs = "" }, .final_key = "k", .created = "t" }, &.{}));
}

test "docker build: the stream's lines are JSON the CLI reads" {
    var a: std.heap.ArenaAllocator = .init(testing.allocator);
    defer a.deinit();
    const arena = a.allocator();
    try testing.expectEqualStrings("{\"stream\":\"Step 1/2 : FROM x\\n\"}\n", try streamLine(arena, "Step 1/2 : FROM x\n"));
    try testing.expectEqualStrings("{\"aux\":{\"ID\":\"sha256:ab\"}}\n", try auxLine(arena, "sha256:ab"));
    const e = try errorLine(arena, "the RUN on line 3 exited with 1");
    const v = try std.json.parseFromSliceLeaky(std.json.Value, arena, e, .{});
    try testing.expectEqualStrings("the RUN on line 3 exited with 1", v.object.get("error").?.string);
    try testing.expectEqualStrings("the RUN on line 3 exited with 1", v.object.get("errorDetail").?.object.get("message").?.string);
}

test "docker build: a time is RFC 3339 and layer keys come bottom first" {
    var a: std.heap.ArenaAllocator = .init(testing.allocator);
    defer a.deinit();
    const arena = a.allocator();
    try testing.expectEqualStrings("2026-11-16T11:30:05Z", try rfc3339(arena, 1_794_828_605));
    try testing.expectEqualStrings("1970-01-01T00:00:00Z", try rfc3339(arena, 0));
    const keys = try layerKeys(arena, &.{ "/s/layers/top/fs", "/s/layers/bottom/fs", "/base/rootfs" });
    try testing.expectEqual(@as(usize, 2), keys.len);
    try testing.expectEqualStrings("bottom", keys[0]);
    try testing.expectEqualStrings("top", keys[1]);
}

test "docker build: a directory keeps its mode with or without the slash; a cancel ends the unpack; the first unsupported entry ends it" {
    var a: std.heap.ArenaAllocator = .init(testing.allocator);
    defer a.deinit();
    const arena = a.allocator();
    {
        var tmp = testing.tmpDir(.{});
        defer tmp.cleanup();
        const tar = try tarOf(arena, &.{
            .{ .name = "wide/", .kind = '5', .mode = 0o777 },
            .{ .name = "wide2", .kind = '5', .mode = 0o777 },
            .{ .name = "tight/", .kind = '5', .mode = 0o700 },
            .{ .name = "tight/f", .data = "x" },
        });
        const r = try unpackTest(arena, &tmp, tar, .{});
        _ = try r.got;
        for ([_][]const u8{ "out/wide", "out/wide2" }) |d| {
            const st = try tmp.dir.statFile(testing.io, d, .{});
            try testing.expectEqual(@as(u32, 0o777), std.math.lossyCast(u32, st.permissions.toMode() & 0o777));
        }
        const st = try tmp.dir.statFile(testing.io, "out/tight", .{});
        try testing.expectEqual(@as(u32, 0o700), std.math.lossyCast(u32, st.permissions.toMode() & 0o777));
    }
    {
        // Cancelled before it starts: nothing is unpacked.
        var tmp = testing.tmpDir(.{});
        defer tmp.cleanup();
        try tmp.dir.writeFile(testing.io, .{ .sub_path = "in.tar", .data = try tarOf(arena, &.{.{ .name = "f", .data = "x" }}) });
        try tmp.dir.createDirPath(testing.io, "out");
        const base = try tmp.dir.realPathFileAlloc(testing.io, ".", arena);
        var flag: std.atomic.Value(bool) = .init(true);
        var why: []const u8 = "";
        try testing.expectError(error.BadContext, unpack(arena, testing.io, try std.fmt.allocPrint(arena, "{s}/out", .{base}), try std.fmt.allocPrint(arena, "{s}/in.tar", .{base}), .{}, &flag, &why));
        try testing.expect(std.mem.indexOf(u8, why, "cancelled") != null);
    }
    {
        // A FIFO ends it at once, whatever follows.
        var tmp = testing.tmpDir(.{});
        defer tmp.cleanup();
        const r = try unpackTest(arena, &tmp, try tarOf(arena, &.{
            .{ .name = "a", .data = "x" },
            .{ .name = "p", .kind = '6' },
            .{ .name = "b", .data = "y" },
        }), .{});
        try testing.expectError(error.BadContext, r.got);
        try testing.expectError(error.FileNotFound, tmp.dir.access(testing.io, "out/b", .{}));
    }
}
