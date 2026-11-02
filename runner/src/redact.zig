//! Secret redaction for anything written to logs or stderr (SPEC §9).
const std = @import("std");

pub const mask = "***";

/// Writes `text` to `w` with every occurrence of any secret replaced by `***`.
pub fn write(
    w: *std.Io.Writer,
    text: []const u8,
    secrets: []const []const u8,
) std.Io.Writer.Error!void {
    var i: usize = 0;
    outer: while (i < text.len) {
        for (secrets) |s| {
            if (s.len > 0 and std.mem.startsWith(u8, text[i..], s)) {
                try w.writeAll(mask);
                i += s.len;
                continue :outer;
            }
        }
        try w.writeByte(text[i]);
        i += 1;
    }
}

/// `write` with `index` when there is one (the same result, faster), and `secrets` otherwise.
pub fn writeWith(
    w: *std.Io.Writer,
    text: []const u8,
    secrets: []const []const u8,
    index: ?*const Set,
) std.Io.Writer.Error!void {
    if (index) |ix| return ix.write(w, text);
    return write(w, text, secrets);
}

/// A job's secrets as it adds masks (`::add-mask::`): a list kept longest first without
/// duplicates, and a trie of them that `write` walks at each position of a line.
///
/// It replaces copying the whole list and sorting it again for each mask, then trying every secret
/// at every position of every line: 20000 masks cost 5.8 GB that way, quadratic in their number.
/// GitHub's runner sets no limit on masks, and neither does this, since a mask dropped is a secret
/// shown. Adding one is now a binary search and an insertion, and a position of a line costs as
/// many steps as the longest secret prefix found there, whatever the number of secrets. (Indexing
/// the list by first byte instead still cost 13 ms a line when every mask began alike.)
///
/// `write` gives what `redact.write` gives with `all`: the first match in a longest-first list is
/// the longest secret starting at the position, which is the deepest end the walk passes.
pub const Set = struct {
    /// Every secret, longest first: the list the sinks report as their secrets.
    all: std.ArrayList([]const u8) = .empty,
    /// The trie's first level, by byte: a node, or 0 for none.
    root: [256]u32 = @splat(0),
    /// The deeper levels: `node << 8 | byte` to the node it leads to.
    edges: std.AutoHashMapUnmanaged(u64, u32) = .empty,
    /// Whether a secret ends at each node (index 0 is the root, where none does).
    ends: std.ArrayList(bool) = .empty,

    /// Adds a copy of `secret`, owned by the set. An empty one, or one already present, is ignored.
    pub fn add(set: *Set, gpa: std.mem.Allocator, secret: []const u8) std.mem.Allocator.Error!void {
        if (secret.len == 0 or set.contains(secret)) return;
        // Everything that can fail first, so a secret is in both or in neither.
        try set.all.ensureUnusedCapacity(gpa, 1);
        try set.ends.ensureUnusedCapacity(gpa, secret.len + 1);
        try set.edges.ensureUnusedCapacity(gpa, @intCast(secret.len));
        const owned = try gpa.dupe(u8, secret);
        if (set.ends.items.len == 0) set.ends.appendAssumeCapacity(false);
        const first = &set.root[owned[0]];
        if (first.* == 0) first.* = set.newNode();
        var node = first.*;
        for (owned[1..]) |b| {
            const gop = set.edges.getOrPutAssumeCapacity(edge(node, b));
            if (!gop.found_existing) gop.value_ptr.* = set.newNode();
            node = gop.value_ptr.*;
        }
        set.ends.items[node] = true;
        set.all.insertAssumeCapacity(longestFirstAt(set.all.items, owned.len), owned);
    }

    fn newNode(set: *Set) u32 {
        set.ends.appendAssumeCapacity(false);
        return @intCast(set.ends.items.len - 1);
    }

    fn edge(node: u32, b: u8) u64 {
        return @as(u64, node) << 8 | b;
    }

    /// The length of the longest secret `text` starts with, or 0.
    fn longestAt(set: *const Set, text: []const u8) usize {
        var node = set.root[text[0]];
        var best: usize = 0;
        var j: usize = 1;
        while (node != 0) : (j += 1) {
            if (set.ends.items[node]) best = j;
            if (j == text.len) break;
            node = set.edges.get(edge(node, text[j])) orelse break;
        }
        return best;
    }

    fn contains(set: *const Set, secret: []const u8) bool {
        if (set.ends.items.len == 0) return false;
        var node = set.root[secret[0]];
        for (secret[1..]) |b| {
            if (node == 0) return false;
            node = set.edges.get(edge(node, b)) orelse return false;
        }
        return node != 0 and set.ends.items[node];
    }

    /// As `redact.write` with `all`.
    pub fn write(set: *const Set, w: *std.Io.Writer, text: []const u8) std.Io.Writer.Error!void {
        var plain: usize = 0; // the start of the text not written yet
        var i: usize = 0;
        while (i < text.len) {
            const n = set.longestAt(text[i..]);
            if (n == 0) {
                i += 1;
                continue;
            }
            try w.writeAll(text[plain..i]);
            try w.writeAll(mask);
            i += n;
            plain = i;
        }
        try w.writeAll(text[plain..]);
    }
};

/// Where a secret of length `len` goes in a longest-first list: after every one at least as long.
fn longestFirstAt(list: []const []const u8, len: usize) usize {
    var lo: usize = 0;
    var hi: usize = list.len;
    while (lo < hi) {
        const mid = lo + (hi - lo) / 2;
        if (list[mid].len >= len) lo = mid + 1 else hi = mid;
    }
    return lo;
}

/// `text` with every secret replaced by `***`, as a new string (`text` itself when nothing matched).
pub fn alloc(arena: std.mem.Allocator, text: []const u8, secrets: []const []const u8) std.mem.Allocator.Error![]const u8 {
    var found = false;
    for (secrets) |s| {
        if (s.len > 0 and std.mem.indexOf(u8, text, s) != null) {
            found = true;
            break;
        }
    }
    if (!found) return text;
    var aw: std.Io.Writer.Allocating = .init(arena);
    write(&aw.writer, text, secrets) catch return error.OutOfMemory; // Allocating: only OOM
    return aw.written();
}

/// The shortest line of a multi-line secret masked on its own. A JSON key file's `{` and `}` lines
/// would otherwise mask every brace of every log; the whole value and its longer lines still are.
pub const min_line = 4;

/// What one secret must be masked as, wherever it appears: its value without the whitespace around
/// it (a token saved with a trailing newline still matches), each line of a multi-line value (the
/// log is redacted line by line, so a whole multi-line value never matches there), and the whole
/// value as JSON (`toJSON(secrets)`), base64 and URL encoding write it.
pub fn forms(arena: std.mem.Allocator, value: []const u8) std.mem.Allocator.Error![]const []const u8 {
    var out: std.ArrayList([]const u8) = .empty;
    const whole = std.mem.trim(u8, value, " \t\r\n");
    if (whole.len == 0) return out.items;
    try out.append(arena, whole);
    if (std.mem.indexOfScalar(u8, whole, '\n') != null) {
        var lines = std.mem.splitScalar(u8, whole, '\n');
        while (lines.next()) |l| {
            const line = std.mem.trim(u8, l, " \t\r");
            if (line.len >= min_line) try out.append(arena, line);
        }
    }
    // As a JSON string's contents.
    var json: std.Io.Writer.Allocating = .init(arena);
    std.json.Stringify.encodeJsonStringChars(whole, .{}, &json.writer) catch return error.OutOfMemory;
    if (!std.mem.eql(u8, json.written(), whole)) try out.append(arena, json.written());
    // Base64, without padding, so it also matches inside a longer encoded text that starts with it.
    const enc = std.base64.standard_no_pad.Encoder;
    const b64 = try arena.alloc(u8, enc.calcSize(whole.len));
    try out.append(arena, enc.encode(b64, whole));
    // URL-encoded (every byte outside the unreserved set), when that differs.
    var url: std.ArrayList(u8) = .empty;
    for (whole) |ch| {
        if (std.ascii.isAlphanumeric(ch) or ch == '-' or ch == '.' or ch == '_' or ch == '~')
            try url.append(arena, ch)
        else
            try url.print(arena, "%{X:0>2}", .{ch});
    }
    if (!std.mem.eql(u8, url.items, whole)) try out.append(arena, url.items);
    return out.items;
}

/// `secrets`, each in all its `forms`, longest first: `write` takes the first match, so a secret
/// that begins with another is then masked whole (`abc` and `abcdef` would give `***def`).
pub fn expand(arena: std.mem.Allocator, secrets: []const []const u8) std.mem.Allocator.Error![]const []const u8 {
    var out: std.ArrayList([]const u8) = .empty;
    for (secrets) |s| try out.appendSlice(arena, try forms(arena, s));
    sortLongestFirst(out.items);
    return out.items;
}

pub fn sortLongestFirst(list: [][]const u8) void {
    std.mem.sort([]const u8, list, {}, struct {
        fn longer(_: void, a: []const u8, b: []const u8) bool {
            return a.len > b.len;
        }
    }.longer);
}

test "a secret is masked in every form it takes: trimmed, line by line, JSON, base64, URL" {
    var a: std.heap.ArenaAllocator = .init(std.testing.allocator);
    defer a.deinit();
    const ar = a.allocator();
    // A PEM key saved with a trailing newline, as `gh secret set < file` stores it.
    const pem = "-----BEGIN KEY-----\nMIIEabcdefgh\n}\n-----END KEY-----\n";
    const list = try expand(ar, &.{ pem, "abc", "abcdef" });
    // The log is redacted line by line: each line of the key is masked, the short `}` is not.
    try std.testing.expectEqualStrings("***", try alloc(ar, "MIIEabcdefgh", list));
    try std.testing.expectEqualStrings("***", try alloc(ar, "-----BEGIN KEY-----", list));
    try std.testing.expectEqualStrings("x } y", try alloc(ar, "x } y", list));
    // Longest first: `abcdef` is masked whole, not as `***def`.
    try std.testing.expectEqualStrings("*** ***", try alloc(ar, "abcdef abc", list));
    // As toJSON, base64 and a URL write it.
    try std.testing.expectEqualStrings("{\"k\":\"***\\n\"}", try alloc(ar, "{\"k\":\"-----BEGIN KEY-----\\nMIIEabcdefgh\\n}\\n-----END KEY-----\\n\"}", list));
    try std.testing.expectEqualStrings("auth ***", try alloc(ar, "auth YWJjZGVm", list));
    const spaced = try expand(ar, &.{"p@ss word"});
    try std.testing.expectEqualStrings("u=***", try alloc(ar, "u=p%40ss%20word", spaced));
}

test "redacts all occurrences" {
    var buf: [128]u8 = undefined;
    var w: std.Io.Writer = .fixed(&buf);
    try write(&w, "tok=abc123 url=pg://abc123@h", &.{ "abc123", "" });
    try std.testing.expectEqualStrings("tok=*** url=pg://***@h", w.buffered());
}

test "a set masks as write does with its list, longest first, whatever order masks arrive in" {
    var a: std.heap.ArenaAllocator = .init(std.testing.allocator);
    defer a.deinit();
    const ar = a.allocator();
    var set: Set = .{};
    // Secrets that begin with one another, one twice, and an empty one.
    for ([_][]const u8{ "ab", "abcd", "", "b", "abc", "ab", "xyz", "bcd" }) |s| try set.add(ar, s);
    try std.testing.expectEqual(@as(usize, 6), set.all.items.len);
    for (set.all.items[1..], set.all.items[0 .. set.all.items.len - 1]) |s, prev|
        try std.testing.expect(prev.len >= s.len);
    // Random text over the secrets' alphabet, against the plain loop.
    var prng: std.Random.DefaultPrng = .init(99);
    const r = prng.random();
    var text: [200]u8 = undefined;
    for (0..500) |_| {
        const len = r.uintAtMost(usize, text.len);
        for (text[0..len]) |*c| c.* = "abcdxyz "[r.uintLessThan(usize, 8)];
        var want: std.Io.Writer.Allocating = .init(ar);
        var got: std.Io.Writer.Allocating = .init(ar);
        try write(&want.writer, text[0..len], set.all.items);
        try set.write(&got.writer, text[0..len]);
        try std.testing.expectEqualStrings(want.written(), got.written());
    }
    var got: std.Io.Writer.Allocating = .init(ar);
    try set.write(&got.writer, "abcde bc abx");
    try std.testing.expectEqualStrings("***e ***c ***x", got.written());
}

test "a lone secret is masked by alloc, whatever its length, one byte too" {
    var a: std.heap.ArenaAllocator = .init(std.testing.allocator);
    defer a.deinit();
    const ar = a.allocator();
    // The only secret, and in the text: alloc's look for one before writing must find it.
    try std.testing.expectEqualStrings("tok=***", try alloc(ar, "tok=abc", &.{"abc"}));
    try std.testing.expectEqualStrings("a=*** b", try alloc(ar, "a=x b", &.{"x"}));
    // Through its forms too: a one-byte secret is a secret.
    try std.testing.expectEqualStrings("a=*** b", try alloc(ar, "a=x b", try expand(ar, &.{"x"})));
    // Nothing to mask (an empty secret is none): the text itself, not a copy.
    const text = "no secret here";
    try std.testing.expectEqual(text.ptr, (try alloc(ar, text, &.{ "", "abc" })).ptr);
}

test "a multi-line secret's lines of min_line bytes are masked on their own, shorter ones are not" {
    var a: std.heap.ArenaAllocator = .init(std.testing.allocator);
    defer a.deinit();
    const ar = a.allocator();
    const list = try expand(ar, &.{"head\nabcd\nxyz\nmore lines"});
    try std.testing.expectEqual(@as(usize, 4), min_line);
    try std.testing.expectEqualStrings("***", try alloc(ar, "abcd", list));
    try std.testing.expectEqualStrings("xyz", try alloc(ar, "xyz", list));
}

test "a secret's URL-encoded form keeps the unreserved -._~ and encodes the rest" {
    var a: std.heap.ArenaAllocator = .init(std.testing.allocator);
    defer a.deinit();
    const ar = a.allocator();
    const list = try expand(ar, &.{"a-b.c_d~e f/g"});
    try std.testing.expectEqualStrings("u=***", try alloc(ar, "u=a-b.c_d~e%20f%2Fg", list));
}

test "a set masks bytes past ASCII as write does, and keeps a secret once" {
    var a: std.heap.ArenaAllocator = .init(std.testing.allocator);
    defer a.deinit();
    const ar = a.allocator();
    var set: Set = .{};
    // UTF-8 secrets, whose bytes 0x80 and up share their low seven bits with ASCII ones.
    const alphabet = "a\xe1b\xe2\xc3\x83 ";
    for ([_][]const u8{ "x", "x", "a\xe1", "\xe1a", "aa\xe1b", "\xe2\xe2", "\xc3\x83a", "ba" }) |s|
        try set.add(ar, s);
    try std.testing.expectEqual(@as(usize, 7), set.all.items.len);
    var prng: std.Random.DefaultPrng = .init(7);
    const r = prng.random();
    var text: [64]u8 = undefined;
    for (0..2000) |_| {
        const len = r.uintAtMost(usize, text.len);
        for (text[0..len]) |*c| c.* = alphabet[r.uintLessThan(usize, alphabet.len)];
        var want: std.Io.Writer.Allocating = .init(ar);
        var got: std.Io.Writer.Allocating = .init(ar);
        try write(&want.writer, text[0..len], set.all.items);
        try set.write(&got.writer, text[0..len]);
        try std.testing.expectEqualStrings(want.written(), got.written());
    }
}
