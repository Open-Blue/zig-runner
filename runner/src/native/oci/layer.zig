//! One image layer applied to a rootfs directory: the blob decompressed (gzip, zstd or plain, by
//! its first bytes), its tar read with owners, modes, times, hard links and xattrs, and every entry
//! written inside the rootfs and nowhere else. OCI's whiteouts are applied as they are met, so the
//! directory is the image flattened, as `docker export` gives it (docs/native-backend.md, P3).
//!
//! The archive is the registry's, so every path in it is hostile until proven otherwise:
//!
//! - a `..` component anywhere in an entry's or a hard link's path refuses the layer, as Docker's
//!   extraction does (it calls the path a breakout);
//! - a parent directory is opened with `openat2(RESOLVE_IN_ROOT)`, so a symlink an earlier entry
//!   planted (`etc -> /etc`) is followed inside the rootfs, never out of it, as Docker follows one
//!   "in scope" (`/bin -> usr/bin` in a usrmerged image must keep working);
//! - the last component is never followed: what is there is removed and made anew, unless both
//!   are directories (Docker's rule), and a file is opened with `O_EXCL | O_NOFOLLOW`;
//! - a hard link's target is opened in the rootfs with `O_PATH | O_NOFOLLOW` and linked from its
//!   descriptor, so it cannot name a host file, and never a directory;
//! - device nodes are skipped: they would be real devices on the store's disk, and the sandbox
//!   builds its own /dev (`sandbox.zig`). FIFOs are made;
//! - xattrs: only `security.capability` (a root runner) and `user.*`, never `trusted.*` or
//!   `user.overlay.*`, which overlay reads as its own when the rootfs is a lower layer;
//! - the unpacked size and the entry count are capped, against a decompression bomb.

const std = @import("std");
const linux = std.os.linux;
const sandbox = @import("../sandbox.zig");

const Allocator = std.mem.Allocator;
const Sha256 = std.crypto.hash.sha2.Sha256;

/// How a layer is written.
pub const Options = struct {
    /// Give entries the archive's owners: a root runner, whose rootfs is idmapped into each job's
    /// range (`sandbox.idmapRootfs`). Rootless, every file is the runner's, which is root inside.
    owners: bool,
    /// Caps over every layer of an image (`Totals`).
    max_bytes: u64 = 32 << 30,
    max_entries: u64 = 4_000_000,
};

/// What the layers of one image added up to, so far.
pub const Totals = struct {
    entries: u64 = 0,
    bytes: u64 = 0,
    /// Character and block devices left out (see the file's comment).
    devices: u64 = 0,
};

pub const Error = error{
    PathEscapesRootfs,
    BadWhiteout,
    BadTarHeader,
    UnsupportedTarEntry,
    LayerTooLarge,
    TooManyEntries,
    HardLinkTarget,
    DiffIdMismatch,
    UnexpectedEndOfStream,
    ReadFailed,
} || Allocator.Error || FsError;

pub const FsError = error{FsFailed};

/// The last failing call, for the message (`FsError` carries no detail).
pub threadlocal var last_fs_error: struct { op: []const u8 = "", errno: linux.E = .SUCCESS } = .{};

fn fsFail(op: []const u8, e: linux.E) FsError {
    last_fs_error = .{ .op = op, .errno = e };
    return error.FsFailed;
}

/// Applies one layer blob (`in`, compressed or not) to the rootfs open at `root`. `diff_id` is
/// the image config's digest of the uncompressed tar (`sha256:<hex>`), checked when not empty.
pub fn apply(
    gpa: Allocator,
    io: std.Io,
    root: linux.fd_t,
    in: *std.Io.Reader,
    diff_id: []const u8,
    opts: Options,
    totals: *Totals,
) Error!void {
    const magic = in.peek(4) catch |e| switch (e) {
        error.EndOfStream => in.buffered(),
        error.ReadFailed => return error.ReadFailed,
    };
    var hash_buf: [64 * 1024]u8 = undefined;
    if (std.mem.startsWith(u8, magic, "\x1f\x8b")) {
        const window = try gpa.alloc(u8, std.compress.flate.max_window_len);
        defer gpa.free(window);
        var d: std.compress.flate.Decompress = .init(in, .gzip, window);
        var h = d.reader.hashed(Sha256.init(.{}), &hash_buf);
        try applyTar(gpa, io, root, &h.reader, opts, totals);
        try checkDiffId(&h, diff_id);
    } else if (std.mem.startsWith(u8, magic, "\x28\xb5\x2f\xfd")) {
        const window = try gpa.alloc(u8, std.compress.zstd.default_window_len +
            std.compress.zstd.block_size_max);
        defer gpa.free(window);
        // Not its frame checksum (std's zstd cannot check it while streaming yet): the blob's
        // digest is checked before, and the diff id after.
        var d: std.compress.zstd.Decompress = .init(in, window, .{});
        var h = d.reader.hashed(Sha256.init(.{}), &hash_buf);
        try applyTar(gpa, io, root, &h.reader, opts, totals);
        try checkDiffId(&h, diff_id);
    } else {
        var h = in.hashed(Sha256.init(.{}), &hash_buf);
        try applyTar(gpa, io, root, &h.reader, opts, totals);
        try checkDiffId(&h, diff_id);
    }
}

/// The rest of the stream (the archive's end blocks) read, and its digest compared.
fn checkDiffId(h: anytype, diff_id: []const u8) Error!void {
    _ = h.reader.discardRemaining() catch return error.ReadFailed;
    if (diff_id.len == 0) return;
    var sum: [32]u8 = undefined;
    h.hasher.final(&sum);
    const want = std.mem.cutPrefix(u8, diff_id, "sha256:") orelse return error.DiffIdMismatch;
    if (!std.mem.eql(u8, &std.fmt.bytesToHex(sum, .lower), want)) return error.DiffIdMismatch;
}

// --- the tar format ---

pub const Kind = enum { file, hard_link, symlink, char, block, directory, fifo };

pub const Entry = struct {
    path: []const u8,
    link: []const u8 = "",
    kind: Kind,
    mode: u32 = 0o644,
    uid: u32 = 0,
    gid: u32 = 0,
    mtime: i64 = 0,
    size: u64 = 0,
    xattrs: []const Xattr = &.{},
};

pub const Xattr = struct { name: []const u8, value: []const u8 };

/// ustar, GNU long names and links, and PAX (path, linkpath, size, uid, gid, mtime and
/// `SCHILY.xattr.*`), which is what image builders write. Strings live in `scratch` until the
/// next entry.
pub const TarReader = struct {
    in: *std.Io.Reader,
    scratch: Allocator,
    /// The current entry's body not yet read, and the padding after it.
    left: u64 = 0,
    pad: u64 = 0,

    const block = 512;
    const max_meta = 1 << 20;

    pub fn next(r: *TarReader) Error!?Entry {
        try r.skipBody();
        var long_name: ?[]const u8 = null;
        var long_link: ?[]const u8 = null;
        var pax: Pax = .{};
        while (true) {
            var hdr: [block]u8 = undefined;
            r.in.readSliceAll(&hdr) catch |e| switch (e) {
                // An archive cut short of its end blocks still ends at an entry's boundary.
                error.EndOfStream => return null,
                error.ReadFailed => return error.ReadFailed,
            };
            if (std.mem.allEqual(u8, &hdr, 0)) return null;
            try checksum(&hdr);
            const size = try number(hdr[124..136]);
            const flag = hdr[156];
            switch (flag) {
                'L', 'K', 'x' => {
                    if (size > max_meta) return error.BadTarHeader;
                    const data = try r.scratch.alloc(u8, @intCast(size));
                    try r.readAll(data);
                    try r.discard(padding(size));
                    switch (flag) {
                        'L' => long_name = std.mem.sliceTo(data, 0),
                        'K' => long_link = std.mem.sliceTo(data, 0),
                        else => try pax.parse(r.scratch, data),
                    }
                    continue;
                },
                'g' => {
                    try r.discard(size + padding(size));
                    continue;
                },
                else => {},
            }
            // Copied: `hdr` is gone once this returns.
            var e: Entry = .{
                .path = long_name orelse pax.path orelse try ustarName(r.scratch, &hdr),
                .link = long_link orelse pax.linkpath orelse try r.scratch.dupe(u8, field(hdr[157..257])),
                .kind = .file,
                .mode = @intCast((try number(hdr[100..108])) & 0o7777),
                .uid = pax.uid orelse @truncate(try number(hdr[108..116])),
                .gid = pax.gid orelse @truncate(try number(hdr[116..124])),
                .mtime = pax.mtime orelse @intCast(@min(try number(hdr[136..148]), std.math.maxInt(i64))),
                .size = pax.size orelse size,
                .xattrs = pax.xattrs.items,
            };
            e.kind = switch (flag) {
                0, '0', '7' => if (std.mem.endsWith(u8, e.path, "/")) .directory else .file,
                '1' => .hard_link,
                '2' => .symlink,
                '3' => .char,
                '4' => .block,
                '5' => .directory,
                '6' => .fifo,
                else => return error.UnsupportedTarEntry,
            };
            // Only a regular file's size is its body (a hard link's is usually 0, but not always).
            r.left = e.size;
            r.pad = padding(e.size);
            if (e.kind != .file) e.size = 0;
            return e;
        }
    }

    /// Up to `buf.len` bytes of the current entry's body; 0 at its end.
    pub fn read(r: *TarReader, buf: []u8) Error!usize {
        const want: usize = @intCast(@min(buf.len, r.left));
        if (want == 0) return 0;
        const n = r.in.readSliceShort(buf[0..want]) catch return error.ReadFailed;
        if (n == 0) return error.UnexpectedEndOfStream;
        r.left -= n;
        return n;
    }

    fn readAll(r: *TarReader, buf: []u8) Error!void {
        r.in.readSliceAll(buf) catch |e| return switch (e) {
            error.EndOfStream => error.UnexpectedEndOfStream,
            error.ReadFailed => error.ReadFailed,
        };
    }

    fn skipBody(r: *TarReader) Error!void {
        try r.discard(r.left + r.pad);
        r.left = 0;
        r.pad = 0;
    }

    fn discard(r: *TarReader, n: u64) Error!void {
        r.in.discardAll64(n) catch |e| return switch (e) {
            error.EndOfStream => error.UnexpectedEndOfStream,
            error.ReadFailed => error.ReadFailed,
        };
    }

    fn padding(size: u64) u64 {
        return (block - size % block) % block;
    }

    fn checksum(hdr: *const [block]u8) Error!void {
        const want = try number(hdr[148..156]);
        var sum: u64 = 0;
        var signed: i64 = 0;
        for (hdr, 0..) |c, i| {
            const b: u8 = if (i >= 148 and i < 156) ' ' else c;
            sum += b;
            // Some old tars summed the bytes as signed chars: each byte's two's complement value.
            signed += @as(i8, @bitCast(b));
        }
        if (want != sum and @as(i64, @intCast(want)) != signed) return error.BadTarHeader;
    }

    /// An octal field, or base-256 when its first byte has the high bit (GNU, for large values).
    fn number(f: []const u8) Error!u64 {
        if (f.len > 0 and f[0] & 0x80 != 0) {
            if (f[0] == 0xff) return error.BadTarHeader;
            var v: u64 = f[0] & 0x7f;
            for (f[1..]) |c| {
                if (v >> 56 != 0) return error.BadTarHeader;
                v = (v << 8) | c;
            }
            return v;
        }
        const t = std.mem.trim(u8, field(f), " ");
        if (t.len == 0) return 0;
        return std.fmt.parseInt(u64, t, 8) catch error.BadTarHeader;
    }

    fn field(f: []const u8) []const u8 {
        return std.mem.sliceTo(f, 0);
    }

    /// The name, with POSIX ustar's prefix (GNU's magic uses that space for other things).
    fn ustarName(scratch: Allocator, hdr: *const [block]u8) Error![]const u8 {
        const name = field(hdr[0..100]);
        const prefix = field(hdr[345..500]);
        if (!std.mem.eql(u8, hdr[257..263], "ustar\x00") or prefix.len == 0) return scratch.dupe(u8, name);
        return std.mem.concat(scratch, u8, &.{ prefix, "/", name });
    }
};

const Pax = struct {
    path: ?[]const u8 = null,
    linkpath: ?[]const u8 = null,
    size: ?u64 = null,
    uid: ?u32 = null,
    gid: ?u32 = null,
    mtime: ?i64 = null,
    xattrs: std.ArrayList(Xattr) = .empty,

    /// Records of `<len> <key>=<value>\n`, where `len` counts the whole record.
    fn parse(p: *Pax, scratch: Allocator, data: []const u8) Error!void {
        var rest = data;
        while (rest.len > 0) {
            const sp = std.mem.indexOfScalar(u8, rest, ' ') orelse return error.BadTarHeader;
            const len = std.fmt.parseInt(usize, rest[0..sp], 10) catch return error.BadTarHeader;
            if (len <= sp + 1 or len > rest.len or rest[len - 1] != '\n') return error.BadTarHeader;
            const rec = rest[sp + 1 .. len - 1];
            rest = rest[len..];
            const eq = std.mem.indexOfScalar(u8, rec, '=') orelse return error.BadTarHeader;
            const key = rec[0..eq];
            const value = rec[eq + 1 ..];
            if (std.mem.eql(u8, key, "path")) {
                p.path = value;
            } else if (std.mem.eql(u8, key, "linkpath")) {
                p.linkpath = value;
            } else if (std.mem.eql(u8, key, "size")) {
                p.size = std.fmt.parseInt(u64, value, 10) catch return error.BadTarHeader;
            } else if (std.mem.eql(u8, key, "uid")) {
                p.uid = std.fmt.parseInt(u32, value, 10) catch return error.BadTarHeader;
            } else if (std.mem.eql(u8, key, "gid")) {
                p.gid = std.fmt.parseInt(u32, value, 10) catch return error.BadTarHeader;
            } else if (std.mem.eql(u8, key, "mtime")) {
                // Seconds, maybe with a fraction, which is dropped.
                const whole = value[0 .. std.mem.indexOfScalar(u8, value, '.') orelse value.len];
                p.mtime = std.fmt.parseInt(i64, whole, 10) catch return error.BadTarHeader;
            } else if (std.mem.cutPrefix(u8, key, "SCHILY.xattr.")) |name| {
                try p.xattrs.append(scratch, .{ .name = name, .value = value });
            }
        }
    }
};

// --- writing a layer ---

/// The whiteout prefix, and the name that makes a directory opaque (what lower layers had in it
/// is gone), from the OCI image spec ("Whiteouts").
pub const wh_prefix = ".wh.";
pub const wh_opaque = ".wh..wh..opq";

fn applyTar(
    gpa: Allocator,
    io: std.Io,
    root: linux.fd_t,
    in: *std.Io.Reader,
    opts: Options,
    totals: *Totals,
) Error!void {
    var entry_arena: std.heap.ArenaAllocator = .init(gpa);
    defer entry_arena.deinit();
    var layer_arena: std.heap.ArenaAllocator = .init(gpa);
    defer layer_arena.deinit();
    const keep = layer_arena.allocator();
    // Every path this layer made, and its parents: an opaque directory keeps those, whichever
    // order the archive has them in.
    var made: std.StringHashMapUnmanaged(void) = .empty;
    // Directories' modes, owners and times, set once the layer is in: a directory made read-only
    // before its children are written would refuse them (rootless), and writing them moves its
    // time.
    var dirs: std.ArrayList(Entry) = .empty;

    var tr: TarReader = .{ .in = in, .scratch = entry_arena.allocator() };
    var buf: [64 * 1024]u8 = undefined;
    while (true) {
        _ = entry_arena.reset(.retain_capacity);
        const e = try tr.next() orelse break;
        totals.entries += 1;
        if (totals.entries > opts.max_entries) return error.TooManyEntries;
        const path = try clean(tr.scratch, e.path);
        const slash = std.mem.lastIndexOfScalar(u8, path, '/');
        const parent_path = if (slash) |s| path[0..s] else "";
        const name = if (slash) |s| path[s + 1 ..] else path;

        if (std.mem.startsWith(u8, name, wh_prefix)) {
            try whiteout(gpa, io, root, parent_path, name, &made);
            continue;
        }
        try markMade(keep, &made, path);
        if (path.len == 0) {
            // The archive's own root ("./"): only its metadata.
            if (e.kind == .directory) try dirs.append(keep, try dupeEntry(keep, e, path));
            continue;
        }
        const parent = try ensureDir(tr.scratch, root, parent_path);
        defer _ = linux.close(parent);
        const z = try tr.scratch.dupeSentinel(u8, name, 0);
        try replace(io, parent, z, e.kind == .directory);
        switch (e.kind) {
            .directory => {
                const rc = linux.mkdirat(parent, z, 0o700);
                if (linux.errno(rc) != .SUCCESS and linux.errno(rc) != .EXIST)
                    return fsFail("mkdir", linux.errno(rc));
                try dirs.append(keep, try dupeEntry(keep, e, path));
            },
            .file => {
                const rc = linux.openat(parent, z, .{
                    .ACCMODE = .WRONLY,
                    .CREAT = true,
                    .EXCL = true,
                    .NOFOLLOW = true,
                    .CLOEXEC = true,
                }, 0o600);
                if (linux.errno(rc) != .SUCCESS) return fsFail("create a file", linux.errno(rc));
                const fd: linux.fd_t = @intCast(rc);
                defer _ = linux.close(fd);
                totals.bytes += e.size;
                if (totals.bytes > opts.max_bytes) return error.LayerTooLarge;
                while (true) {
                    const n = try tr.read(&buf);
                    if (n == 0) break;
                    try writeAll(fd, buf[0..n]);
                }
                try setXattrs(fd, e.xattrs, opts);
                try own(fd, e, opts);
            },
            .symlink => {
                const target = try tr.scratch.dupeSentinel(u8, e.link, 0);
                const rc = linux.symlinkat(target, parent, z);
                if (linux.errno(rc) != .SUCCESS) return fsFail("symlink", linux.errno(rc));
                if (opts.owners) {
                    const c = linux.fchownat(parent, z, e.uid, e.gid, linux.AT.SYMLINK_NOFOLLOW);
                    if (linux.errno(c) != .SUCCESS) return fsFail("chown a symlink", linux.errno(c));
                }
            },
            .hard_link => try hardLink(tr.scratch, root, parent, z, e.link),
            .fifo => {
                const rc = linux.mknodat(parent, z, linux.S.IFIFO | (e.mode & 0o777), 0);
                if (linux.errno(rc) != .SUCCESS) return fsFail("mkfifo", linux.errno(rc));
                if (opts.owners) {
                    const c = linux.fchownat(parent, z, e.uid, e.gid, linux.AT.SYMLINK_NOFOLLOW);
                    if (linux.errno(c) != .SUCCESS) return fsFail("chown a fifo", linux.errno(c));
                }
                _ = linux.fchmodat(parent, z, e.mode & 0o7777);
            },
            .char, .block => {
                totals.devices += 1;
                continue;
            },
        }
        if (e.kind != .directory and e.kind != .hard_link) setTime(parent, z, e.mtime);
    }

    // Deepest first, so a parent's time is set after its children's directories are done.
    var i = dirs.items.len;
    while (i > 0) {
        i -= 1;
        const d = dirs.items[i];
        _ = entry_arena.reset(.retain_capacity);
        const p = try entry_arena.allocator().dupeSentinel(u8, if (d.path.len == 0) "." else d.path, 0);
        const fd = switch (sandbox.openIn(root, p, .{
            .ACCMODE = .RDONLY,
            .DIRECTORY = true,
            .NOFOLLOW = true,
        }, 0, 0)) {
            .fd => |f| f,
            // Replaced by something else later in the layer.
            .err => continue,
        };
        defer _ = linux.close(fd);
        try setXattrs(fd, d.xattrs, opts);
        var dir_entry = d;
        // Rootless, the runner must still be able to write into it (the next layer, a removal):
        // inside, the step's root passes every permission check on the runner's files anyway.
        if (!opts.owners) dir_entry.mode |= 0o700;
        try own(fd, dir_entry, opts);
        setTime(fd, null, d.mtime);
    }
}

fn dupeEntry(a: Allocator, e: Entry, path: []const u8) Allocator.Error!Entry {
    var out = e;
    out.path = try a.dupe(u8, path);
    out.link = "";
    const xs = try a.alloc(Xattr, e.xattrs.len);
    for (e.xattrs, xs) |x, *o| o.* = .{ .name = try a.dupe(u8, x.name), .value = try a.dupe(u8, x.value) };
    out.xattrs = xs;
    return out;
}

fn markMade(a: Allocator, made: *std.StringHashMapUnmanaged(void), path: []const u8) Allocator.Error!void {
    var end = path.len;
    while (true) {
        const gop = try made.getOrPut(a, path[0..end]);
        if (gop.found_existing) return;
        gop.key_ptr.* = try a.dupe(u8, path[0..end]);
        end = std.mem.lastIndexOfScalar(u8, path[0..end], '/') orelse return;
    }
}

/// An archive path as a relative path with no `.` or empty components ("" for the root), or
/// `error.PathEscapesRootfs` for any `..`.
pub fn clean(a: Allocator, raw: []const u8) Error![]const u8 {
    var out: std.ArrayList(u8) = .empty;
    var it = std.mem.tokenizeScalar(u8, raw, '/');
    while (it.next()) |c| {
        if (std.mem.eql(u8, c, ".")) continue;
        if (std.mem.eql(u8, c, "..")) return error.PathEscapesRootfs;
        if (std.mem.indexOfScalar(u8, c, 0) != null) return error.BadTarHeader;
        if (out.items.len > 0) try out.append(a, '/');
        try out.appendSlice(a, c);
    }
    return out.items;
}

/// `.wh.<name>` removes `name` from the layers below; `.wh..wh..opq` empties its directory of
/// what they had, keeping what this layer made. Neither is written.
fn whiteout(
    gpa: Allocator,
    io: std.Io,
    root: linux.fd_t,
    parent_path: []const u8,
    name: []const u8,
    made: *const std.StringHashMapUnmanaged(void),
) Error!void {
    var scratch: std.heap.ArenaAllocator = .init(gpa);
    defer scratch.deinit();
    const a = scratch.allocator();
    const p = try a.dupeSentinel(u8, if (parent_path.len == 0) "." else parent_path, 0);
    const parent = switch (sandbox.openIn(root, p, .{ .ACCMODE = .RDONLY, .DIRECTORY = true }, 0, 0)) {
        .fd => |f| f,
        .err => return, // Nothing below to hide.
    };
    defer _ = linux.close(parent);
    if (std.mem.eql(u8, name, wh_opaque)) {
        var dir: std.Io.Dir = .{ .handle = parent };
        var names: std.ArrayList([]const u8) = .empty;
        var it = dir.iterate();
        while (it.next(io) catch return fsFail("read a directory", .IO)) |child| {
            const full = if (parent_path.len == 0)
                child.name
            else
                try std.fmt.allocPrint(a, "{s}/{s}", .{ parent_path, child.name });
            if (!made.contains(full)) try names.append(a, try a.dupe(u8, child.name));
        }
        for (names.items) |n| try removeAt(io, parent, try a.dupeSentinel(u8, n, 0));
        return;
    }
    const target = name[wh_prefix.len..];
    // Other `.wh..wh.` names are aufs's own bookkeeping (`.wh..wh.plnk`), not whiteouts.
    if (std.mem.startsWith(u8, target, wh_prefix)) return;
    if (target.len == 0 or std.mem.eql(u8, target, ".") or std.mem.eql(u8, target, ".."))
        return error.BadWhiteout;
    try removeAt(io, parent, try a.dupeSentinel(u8, target, 0));
}

/// Makes room for an entry named `name` in `parent`: what is there goes, unless it and the new
/// entry are both directories.
fn replace(io: std.Io, parent: linux.fd_t, name: [:0]const u8, dir: bool) Error!void {
    var st: linux.Statx = undefined;
    const rc = linux.statx(parent, name, linux.AT.SYMLINK_NOFOLLOW, .{ .TYPE = true }, &st);
    if (linux.errno(rc) == .NOENT) return;
    if (linux.errno(rc) != .SUCCESS) return fsFail("stat", linux.errno(rc));
    if (dir and st.mode & linux.S.IFMT == linux.S.IFDIR) return;
    try removeAt(io, parent, name);
}

/// Removes `name` in `parent` and, for a directory, everything under it, through no symlink. A
/// directory without write permission for its owner gets it first (a rootless runner's files).
pub fn removeAt(io: std.Io, parent: linux.fd_t, name: [:0]const u8) FsError!void {
    const rc = linux.unlinkat(parent, name, 0);
    switch (linux.errno(rc)) {
        .SUCCESS, .NOENT => return,
        .ISDIR, .PERM => {},
        else => |e| return fsFail("unlink", e),
    }
    const o = linux.openat(parent, name, .{
        .ACCMODE = .RDONLY,
        .DIRECTORY = true,
        .NOFOLLOW = true,
        .CLOEXEC = true,
    }, 0);
    if (linux.errno(o) != .SUCCESS) return fsFail("open a directory to remove", linux.errno(o));
    const fd: linux.fd_t = @intCast(o);
    {
        defer _ = linux.close(fd);
        _ = linux.fchmod(fd, 0o700);
        var dir: std.Io.Dir = .{ .handle = fd };
        var it = dir.iterate();
        var name_buf: [256]u8 = undefined;
        while (it.next(io) catch return fsFail("read a directory", .IO)) |child| {
            if (child.name.len >= name_buf.len) return fsFail("read a directory", .NAMETOOLONG);
            @memcpy(name_buf[0..child.name.len], child.name);
            name_buf[child.name.len] = 0;
            try removeAt(io, fd, name_buf[0..child.name.len :0]);
            // The directory changed under the iterator: start it again.
            it = dir.iterate();
        }
    }
    const r = linux.unlinkat(parent, name, linux.AT.REMOVEDIR);
    if (linux.errno(r) != .SUCCESS) return fsFail("rmdir", linux.errno(r));
}

/// The directory at `path` in the rootfs, made (with its parents, mode 0755) when missing, for
/// the `*at` calls. Symlinks on the way are followed inside the rootfs.
pub fn ensureDir(a: Allocator, root: linux.fd_t, path: []const u8) Error!linux.fd_t {
    const p = try a.dupeSentinel(u8, if (path.len == 0) "." else path, 0);
    const flags: linux.O = .{ .ACCMODE = .RDONLY, .DIRECTORY = true, .PATH = true };
    switch (sandbox.openIn(root, p, flags, 0, 0)) {
        .fd => |f| return f,
        .err => |e| if (e != .NOENT or path.len == 0) return fsFail("open a directory", e),
    }
    const slash = std.mem.lastIndexOfScalar(u8, path, '/');
    const up = try ensureDir(a, root, if (slash) |s| path[0..s] else "");
    defer _ = linux.close(up);
    const name = try a.dupeSentinel(u8, if (slash) |s| path[s + 1 ..] else path, 0);
    const rc = linux.mkdirat(up, name, 0o755);
    if (linux.errno(rc) != .SUCCESS and linux.errno(rc) != .EXIST) return fsFail("mkdir", linux.errno(rc));
    return switch (sandbox.openIn(up, name, flags, 0, 0)) {
        .fd => |f| f,
        .err => |e| fsFail("open a directory", e),
    };
}

/// A hard link `name` in `parent` to `target`, a path in the rootfs: opened there without
/// following its last component, and linked from the descriptor, never a directory.
fn hardLink(a: Allocator, root: linux.fd_t, parent: linux.fd_t, name: [:0]const u8, target: []const u8) Error!void {
    const t = try clean(a, target);
    if (t.len == 0) return error.HardLinkTarget;
    const fd = switch (sandbox.openIn(root, try a.dupeSentinel(u8, t, 0), .{
        .ACCMODE = .RDONLY,
        .PATH = true,
        .NOFOLLOW = true,
    }, 0, 0)) {
        .fd => |f| f,
        .err => return error.HardLinkTarget,
    };
    defer _ = linux.close(fd);
    var st: linux.Statx = undefined;
    if (linux.errno(linux.statx(fd, "", linux.AT.EMPTY_PATH, .{ .TYPE = true }, &st)) != .SUCCESS or
        st.mode & linux.S.IFMT == linux.S.IFDIR) return error.HardLinkTarget;
    // From the descriptor: AT_EMPTY_PATH needs CAP_DAC_READ_SEARCH, which a rootless runner has
    // not; its /proc link does the same without it.
    var rc = linux.linkat(fd, "", parent, name, linux.AT.EMPTY_PATH);
    if (linux.errno(rc) == .NOENT or linux.errno(rc) == .PERM) {
        var buf: [32]u8 = undefined;
        const proc = std.fmt.bufPrintSentinel(&buf, "/proc/self/fd/{d}", .{fd}, 0) catch unreachable;
        rc = linux.linkat(linux.AT.FDCWD, proc, parent, name, linux.AT.SYMLINK_FOLLOW);
    }
    if (linux.errno(rc) != .SUCCESS) return fsFail("hard link", linux.errno(rc));
}

/// Owner first, then mode: changing the owner clears set-uid and set-gid bits.
fn own(fd: linux.fd_t, e: Entry, opts: Options) FsError!void {
    if (opts.owners) {
        const rc = linux.fchown(fd, e.uid, e.gid);
        if (linux.errno(rc) != .SUCCESS) return fsFail("chown", linux.errno(rc));
    }
    const rc = linux.fchmod(fd, e.mode & 0o7777);
    if (linux.errno(rc) != .SUCCESS) return fsFail("chmod", linux.errno(rc));
}

fn setXattrs(fd: linux.fd_t, xattrs: []const Xattr, opts: Options) Error!void {
    for (xattrs) |x| {
        const allowed = (opts.owners and std.mem.eql(u8, x.name, "security.capability")) or
            (std.mem.startsWith(u8, x.name, "user.") and !std.mem.startsWith(u8, x.name, "user.overlay."));
        if (!allowed) continue;
        var buf: [256]u8 = undefined;
        if (x.name.len >= buf.len) continue;
        @memcpy(buf[0..x.name.len], x.name);
        buf[x.name.len] = 0;
        // Best effort, as Docker's is for xattrs the filesystem refuses.
        _ = linux.fsetxattr(fd, buf[0..x.name.len :0], x.value.ptr, x.value.len, 0);
    }
}

fn setTime(dir: linux.fd_t, name: ?[*:0]const u8, mtime: i64) void {
    const t: linux.timespec = .{ .sec = @intCast(mtime), .nsec = 0 };
    const times = [2]linux.timespec{ t, t };
    _ = linux.utimensat(dir, name, &times, if (name != null) linux.AT.SYMLINK_NOFOLLOW else 0);
}

fn writeAll(fd: linux.fd_t, bytes: []const u8) FsError!void {
    var rest = bytes;
    while (rest.len > 0) {
        const rc = linux.write(fd, rest.ptr, rest.len);
        switch (linux.errno(rc)) {
            .SUCCESS => rest = rest[rc..],
            .INTR => {},
            else => |e| return fsFail("write", e),
        }
    }
}

// --- tests ---

/// A tar archive built in memory, for the tests: entries as an image builder writes them.
pub const TestTar = struct {
    out: std.ArrayList(u8) = .empty,
    a: Allocator,

    pub const Spec = struct {
        path: []const u8,
        kind: Kind = .file,
        body: []const u8 = "",
        link: []const u8 = "",
        mode: u32 = 0o644,
        uid: u32 = 0,
        gid: u32 = 0,
        mtime: u64 = 1_700_000_000,
        /// Written as a PAX header before the entry.
        pax: []const u8 = "",
    };

    pub fn add(t: *TestTar, s: Spec) !void {
        if (s.pax.len > 0) try t.header(.{ .path = "pax", .body = s.pax }, 'x');
        try t.header(s, switch (s.kind) {
            .file => '0',
            .hard_link => '1',
            .symlink => '2',
            .char => '3',
            .block => '4',
            .directory => '5',
            .fifo => '6',
        });
    }

    fn header(t: *TestTar, s: Spec, flag: u8) !void {
        var h: [512]u8 = @splat(0);
        @memcpy(h[0..s.path.len], s.path);
        _ = try std.fmt.bufPrint(h[100..107], "{o:0>7}", .{s.mode});
        _ = try std.fmt.bufPrint(h[108..115], "{o:0>7}", .{s.uid});
        _ = try std.fmt.bufPrint(h[116..123], "{o:0>7}", .{s.gid});
        _ = try std.fmt.bufPrint(h[124..135], "{o:0>11}", .{s.body.len});
        _ = try std.fmt.bufPrint(h[136..147], "{o:0>11}", .{s.mtime});
        h[156] = flag;
        @memcpy(h[157..][0..s.link.len], s.link);
        @memcpy(h[257..263], "ustar\x00");
        @memcpy(h[263..265], "00");
        @memset(h[148..156], ' ');
        var sum: u32 = 0;
        for (h) |c| sum += c;
        _ = try std.fmt.bufPrint(h[148..155], "{o:0>6}\x00", .{sum});
        try t.out.appendSlice(t.a, &h);
        try t.out.appendSlice(t.a, s.body);
        try t.out.appendNTimes(t.a, 0, (512 - s.body.len % 512) % 512);
    }

    pub fn paxRecord(a: Allocator, key: []const u8, value: []const u8) ![]const u8 {
        const body = key.len + value.len + 3;
        var len = body + 1;
        while (std.fmt.count("{d}", .{len}) + body != len) len += 1;
        return std.fmt.allocPrint(a, "{d} {s}={s}\n", .{ len, key, value });
    }

    pub fn finish(t: *TestTar) ![]const u8 {
        try t.out.appendNTimes(t.a, 0, 1024);
        return t.out.items;
    }
};

const testing = std.testing;
const paxRecord = TestTar.paxRecord;

/// `n` times `c`, at compile time.
pub fn repeat(comptime c: u8, comptime n: usize) *const [n]u8 {
    const S = struct {
        const out: [n]u8 = @splat(c);
    };
    return &S.out;
}

fn openRoot(io: std.Io, tmp: *testing.TmpDir, arena: Allocator) !linux.fd_t {
    _ = io;
    const path = try tmp.dir.realPathFileAlloc(testing.io, ".", arena);
    const rc = linux.open(try arena.dupeSentinel(u8, path, 0), .{ .ACCMODE = .RDONLY, .DIRECTORY = true, .CLOEXEC = true }, 0);
    try testing.expect(linux.errno(rc) == .SUCCESS);
    return @intCast(rc);
}

fn applyBytes(root: linux.fd_t, bytes: []const u8, diff_id: []const u8) !void {
    var r: std.Io.Reader = .fixed(bytes);
    var totals: Totals = .{};
    try apply(testing.allocator, testing.io, root, &r, diff_id, .{ .owners = false }, &totals);
}

fn readTmp(tmp: *testing.TmpDir, arena: Allocator, path: []const u8) ![]const u8 {
    return tmp.dir.readFileAlloc(testing.io, path, arena, .limited(1 << 20));
}

test "native oci layer: files, dirs, symlinks and hard links land in the rootfs, whiteouts remove what layers below had" {
    var a: std.heap.ArenaAllocator = .init(testing.allocator);
    defer a.deinit();
    const arena = a.allocator();
    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();
    const root = try openRoot(testing.io, &tmp, arena);
    defer _ = linux.close(root);

    var t1: TestTar = .{ .a = arena };
    try t1.add(.{ .path = "./", .kind = .directory, .mode = 0o755 });
    try t1.add(.{ .path = "usr/", .kind = .directory, .mode = 0o755 });
    try t1.add(.{ .path = "usr/bin/", .kind = .directory, .mode = 0o755 });
    try t1.add(.{ .path = "usr/bin/tool", .body = "#!/bin/sh\n", .mode = 0o4755 });
    try t1.add(.{ .path = "bin", .kind = .symlink, .link = "usr/bin" });
    try t1.add(.{ .path = "etc/gone", .body = "old" });
    try t1.add(.{ .path = "etc/keep", .body = "kept" });
    try t1.add(.{ .path = "opaque/old", .body = "old" });
    try t1.add(.{ .path = "usr/bin/tool2", .kind = .hard_link, .link = "usr/bin/tool" });
    try t1.add(.{ .path = "dev/null", .kind = .char });
    try t1.add(.{ .path = "fifo", .kind = .fifo });
    // A long name, through PAX.
    const long = "deep/" ++ repeat('d', 150) ++ "/file";
    try t1.add(.{ .path = "x", .body = "long", .pax = try paxRecord(arena, "path", long) });
    const tar1 = try t1.finish();
    var sum: [32]u8 = undefined;
    Sha256.hash(tar1, &sum, .{});
    try applyBytes(root, tar1, try std.fmt.allocPrint(arena, "sha256:{s}", .{&std.fmt.bytesToHex(sum, .lower)}));

    try testing.expectEqualStrings("#!/bin/sh\n", try readTmp(&tmp, arena, "usr/bin/tool"));
    // Through the symlink, inside the rootfs.
    try testing.expectEqualStrings("#!/bin/sh\n", try readTmp(&tmp, arena, "bin/tool2"));
    const st = try tmp.dir.statFile(testing.io, "usr/bin/tool", .{});
    try testing.expectEqual(@as(u32, 0o4755), @as(u32, @intCast(st.permissions.toMode() & 0o7777)));
    try testing.expectEqual(@as(u64, 2), st.nlink);
    try testing.expectError(error.FileNotFound, tmp.dir.statFile(testing.io, "dev/null", .{}));
    try testing.expectEqualStrings("long", try readTmp(&tmp, arena, long));

    // Layer 2: a whiteout, an opaque directory (its marker after the layer's own entry in it), a
    // file over a directory, and a file written through the usrmerge symlink.
    var t2: TestTar = .{ .a = arena };
    try t2.add(.{ .path = "etc/.wh.gone" });
    try t2.add(.{ .path = "opaque/new", .body = "new" });
    try t2.add(.{ .path = "opaque/.wh..wh..opq" });
    try t2.add(.{ .path = "deep", .body = "now a file" });
    try t2.add(.{ .path = "bin/added", .body = "via symlink" });
    try applyBytes(root, try t2.finish(), "");

    try testing.expectError(error.FileNotFound, tmp.dir.statFile(testing.io, "etc/gone", .{}));
    try testing.expectEqualStrings("kept", try readTmp(&tmp, arena, "etc/keep"));
    try testing.expectError(error.FileNotFound, tmp.dir.statFile(testing.io, "opaque/old", .{}));
    try testing.expectEqualStrings("new", try readTmp(&tmp, arena, "opaque/new"));
    try testing.expectEqualStrings("now a file", try readTmp(&tmp, arena, "deep"));
    try testing.expectEqualStrings("via symlink", try readTmp(&tmp, arena, "usr/bin/added"));
    try testing.expectError(error.FileNotFound, tmp.dir.statFile(testing.io, ".wh.gone", .{}));
}

test "native oci layer: no entry, link or symlink reaches outside the rootfs" {
    var a: std.heap.ArenaAllocator = .init(testing.allocator);
    defer a.deinit();
    const arena = a.allocator();
    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();
    try tmp.dir.createDirPath(testing.io, "rootfs");
    try tmp.dir.writeFile(testing.io, .{ .sub_path = "outside", .data = "host" });
    const base = try tmp.dir.realPathFileAlloc(testing.io, ".", arena);
    const rc = linux.open(try std.fmt.allocPrintSentinel(arena, "{s}/rootfs", .{base}, 0), .{ .ACCMODE = .RDONLY, .DIRECTORY = true, .CLOEXEC = true }, 0);
    const root: linux.fd_t = @intCast(rc);
    defer _ = linux.close(root);

    // `..` refuses the layer, in a path or a hard link's target.
    for ([_]TestTar.Spec{
        .{ .path = "../outside", .body = "x" },
        .{ .path = "a/../../outside", .body = "x" },
        .{ .path = "link", .kind = .hard_link, .link = "../outside" },
    }) |s| {
        var t: TestTar = .{ .a = arena };
        try t.add(s);
        try testing.expectError(error.PathEscapesRootfs, applyBytes(root, try t.finish(), ""));
    }
    // A symlink to the host's file, then a file written through it, and a hard link to it: both
    // stay inside (the symlink's target is taken inside the rootfs, where there is nothing).
    var t: TestTar = .{ .a = arena };
    try t.add(.{ .path = "esc", .kind = .symlink, .link = try std.fmt.allocPrint(arena, "{s}/outside", .{base}) });
    try t.add(.{ .path = "escdir", .kind = .symlink, .link = "/../../.." });
    try t.add(.{ .path = "escdir/outside", .body = "written inside" });
    try t.add(.{ .path = "esc", .body = "replaced the symlink" });
    try applyBytes(root, try t.finish(), "");
    try testing.expectEqualStrings("host", try readTmp(&tmp, arena, "outside"));
    try testing.expectEqualStrings("written inside", try readTmp(&tmp, arena, "rootfs/outside"));
    try testing.expectEqualStrings("replaced the symlink", try readTmp(&tmp, arena, "rootfs/esc"));

    var t3: TestTar = .{ .a = arena };
    try t3.add(.{ .path = "hostlink", .kind = .symlink, .link = try std.fmt.allocPrint(arena, "{s}/outside", .{base}) });
    try t3.add(.{ .path = "hard", .kind = .hard_link, .link = "hostlink" });
    try applyBytes(root, try t3.finish(), "");
    // The hard link is to the symlink itself, not to the host's file it names.
    var lst: linux.Statx = undefined;
    _ = linux.statx(root, "hard", linux.AT.SYMLINK_NOFOLLOW, .{ .TYPE = true }, &lst);
    try testing.expectEqual(@as(u32, linux.S.IFLNK), lst.mode & linux.S.IFMT);
    // A hard link to a directory is refused.
    var t4: TestTar = .{ .a = arena };
    try t4.add(.{ .path = "d/", .kind = .directory });
    try t4.add(.{ .path = "dl", .kind = .hard_link, .link = "d" });
    try testing.expectError(error.HardLinkTarget, applyBytes(root, try t4.finish(), ""));
}

test "native oci layer: gzip and zstd layers, and a diff id that does not match" {
    var a: std.heap.ArenaAllocator = .init(testing.allocator);
    defer a.deinit();
    const arena = a.allocator();
    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();
    const root = try openRoot(testing.io, &tmp, arena);
    defer _ = linux.close(root);

    // `printf 'zstd\n' > zstd.txt && tar --format=ustar -cf - zstd.txt | zstd -19`, and the
    // same with gzip -9 -n, made with GNU tar 1.35 and zstd 1.5.7 (external tools as oracles
    // only).
    try applyBytes(root, &test_zstd, "");
    try testing.expectEqualStrings("zstd\n", try readTmp(&tmp, arena, "zstd.txt"));
    try applyBytes(root, &test_gzip, "");
    try testing.expectEqualStrings("gzip\n", try readTmp(&tmp, arena, "gzip.txt"));

    var t: TestTar = .{ .a = arena };
    try t.add(.{ .path = "f", .body = "x" });
    try testing.expectError(error.DiffIdMismatch, applyBytes(root, try t.finish(), "sha256:" ++ repeat('0', 64)));
}

test "native oci layer: base-256 numbers and checksums in tar headers" {
    try testing.expectEqual(@as(u64, 0o755), try TarReader.number("0000755\x00"));
    try testing.expectEqual(@as(u64, 0), try TarReader.number("\x00\x00\x00"));
    try testing.expectEqual(@as(u64, 0x01020304), try TarReader.number("\x80\x00\x00\x00\x00\x00\x00\x00\x01\x02\x03\x04"));
    try testing.expectError(error.BadTarHeader, TarReader.number("0009"));
    var a: std.heap.ArenaAllocator = .init(testing.allocator);
    defer a.deinit();
    var t: TestTar = .{ .a = a.allocator() };
    try t.add(.{ .path = "f", .body = "x" });
    const bytes = try t.finish();
    var bad = try a.allocator().dupe(u8, bytes);
    bad[0] = 'g';
    var r: std.Io.Reader = .fixed(bad);
    var tr: TarReader = .{ .in = &r, .scratch = a.allocator() };
    try testing.expectError(error.BadTarHeader, tr.next());
}

test "allocation failures: a layer applied, with PAX headers, whiteouts and gzip" {
    var a: std.heap.ArenaAllocator = .init(testing.allocator);
    defer a.deinit();
    const arena = a.allocator();
    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();
    const root = try openRoot(testing.io, &tmp, arena);
    defer _ = linux.close(root);

    var t: TestTar = .{ .a = arena };
    try t.add(.{ .path = "./", .kind = .directory, .mode = 0o755 });
    try t.add(.{ .path = "d/", .kind = .directory, .mode = 0o755 });
    try t.add(.{ .path = "x", .body = "pax", .pax = try std.mem.concat(arena, u8, &.{
        try paxRecord(arena, "path", "d/" ++ repeat('p', 110)),
        try paxRecord(arena, "SCHILY.xattr.user.a", "1"),
    }) });
    try t.add(.{ .path = "d/gone", .body = "x" });
    try t.add(.{ .path = "d/.wh.gone" });
    try t.add(.{ .path = "o/old", .body = "x" });
    try t.add(.{ .path = "o/.wh..wh..opq" });
    try t.add(.{ .path = "l", .kind = .symlink, .link = "d" });
    const plain = try t.finish();

    // Every failure from one on, the layer's memory freed each time. A run may still succeed:
    // each entry's memory is an arena reset with `.retain_capacity`, which keeps what it has when
    // the larger block it tries for fails, on purpose (`checkNoLeaks`). Each run applies the
    // layer over the last one's rootfs, as a layer over a lower one.
    const S = struct {
        fn run(gpa: Allocator, fd: linux.fd_t, bytes: []const u8) !void {
            var r: std.Io.Reader = .fixed(bytes);
            var totals: Totals = .{};
            try apply(gpa, testing.io, fd, &r, "", .{ .owners = false }, &totals);
        }
    };
    const af = @import("../../alloc_failures.zig");
    try af.checkNoLeaks(S.run, .{ root, plain });
    try af.checkNoLeaks(S.run, .{ root, @as([]const u8, &test_gzip) });
}

/// The fixtures of the gzip and zstd test (see there).
pub const test_zstd = [_]u8{ 0x28, 0xb5, 0x2f, 0xfd, 0x04, 0x68, 0x6d, 0x02, 0x00, 0x72, 0x43, 0x0b, 0x10, 0xb0, 0xeb, 0x67, 0x14, 0xca, 0x57, 0xc3, 0x12, 0x09, 0x43, 0x5a, 0xe0, 0x5b, 0x89, 0x72, 0x0a, 0x05, 0x4d, 0xa5, 0x96, 0xdd, 0x85, 0x92, 0xb5, 0xd6, 0xa1, 0x78, 0x82, 0xe8, 0xda, 0xf7, 0x39, 0x1f, 0xe5, 0xd8, 0xe2, 0xde, 0x18, 0x37, 0x5d, 0x8a, 0x94, 0xec, 0x05, 0x0b, 0x20, 0x80, 0x19, 0x99, 0x07, 0xf7, 0x05, 0x18, 0x07, 0x64, 0xc3, 0x79, 0x0a, 0x63, 0x00, 0x84, 0xbf, 0x9f, 0xc3, 0x83, 0x39, 0xc1, 0xa0, 0x00, 0xc3, 0xa9, 0xca, 0x01, 0xd8, 0x22, 0x42, 0x6f };
pub const test_gzip = [_]u8{ 0x1f, 0x8b, 0x08, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02, 0x03, 0xed, 0xd1, 0x31, 0x0a, 0xc2, 0x40, 0x10, 0x05, 0xd0, 0xad, 0x3d, 0x85, 0x27, 0x90, 0xdd, 0xb8, 0xd9, 0x9c, 0xc7, 0x2a, 0x58, 0x45, 0xe2, 0x06, 0x82, 0xa7, 0x77, 0xb5, 0xb4, 0xd0, 0xca, 0x40, 0xe0, 0xbd, 0xe6, 0xc3, 0xfc, 0x66, 0x98, 0x19, 0x1f, 0xd7, 0xdb, 0xa9, 0xae, 0x35, 0xfc, 0x51, 0x6c, 0x4a, 0xc9, 0xef, 0x6c, 0x3e, 0xb3, 0xe9, 0x43, 0xca, 0x7d, 0x97, 0x87, 0x21, 0xe6, 0xd7, 0x3c, 0xa5, 0x73, 0x57, 0xc2, 0x31, 0x86, 0x0d, 0x2c, 0xf7, 0x7a, 0x99, 0xdb, 0x2a, 0xf3, 0x34, 0x7d, 0x3d, 0xc2, 0xaf, 0x7e, 0xa7, 0xc6, 0xf6, 0xff, 0x43, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x60, 0x6f, 0x9e, 0xdf, 0x2f, 0x78, 0xa5, 0x00, 0x28, 0x00, 0x00 };
