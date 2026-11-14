//! Secret redaction for anything written to logs or stderr (SPEC §9).
const std = @import("std");

pub const mask = "***";

/// Writes `text` to `w` with every secret in it masked as GitHub's runner masks one
/// (`SecretMasker.MaskSecrets`): every occurrence of every secret is found, overlapping ones
/// included, the spans they cover are merged where they overlap or touch, and each merged span is
/// written as one `***`. Masking only the longest secret at each place and going on after it gave
/// `***cdef` for `abcdef` with the secrets `ab` and `bcdef`: most of the second secret, shown.
pub fn write(
    w: *std.Io.Writer,
    text: []const u8,
    secrets: []const []const u8,
) std.Io.Writer.Error!void {
    return maskSpans(w, text, List{ .secrets = secrets });
}

/// The longest of `secrets` a text starts with, by trying each.
const List = struct {
    secrets: []const []const u8,

    fn longestAt(l: List, text: []const u8) usize {
        var best: usize = 0;
        for (l.secrets) |s| {
            if (s.len > best and std.mem.startsWith(u8, text, s)) best = s.len;
        }
        return best;
    }
};

/// `write`'s masking, with `secrets.longestAt(rest)` the length of the longest secret `rest`
/// starts with (0 for none): the longest one at a place covers every shorter one there.
fn maskSpans(w: *std.Io.Writer, text: []const u8, secrets: anytype) std.Io.Writer.Error!void {
    var plain: usize = 0; // the start of the text not written yet
    var i: usize = 0;
    while (i < text.len) {
        if (comptime @TypeOf(secrets) == *const Set) i = secrets.nextStart(text, i);
        if (i == text.len) break;
        const n = secrets.longestAt(text[i..]);
        if (n == 0) {
            i += 1;
            continue;
        }
        // The span grows by every secret that starts inside it or where it ends.
        var end = i + n;
        var j = i + 1;
        while (j <= end and j < text.len) : (j += 1) end = @max(end, j + secrets.longestAt(text[j..]));
        try w.writeAll(text[plain..i]);
        try w.writeAll(mask);
        i = end;
        plain = end;
    }
    try w.writeAll(text[plain..]);
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
/// `write` gives what `redact.write` gives with `all`: the longest secret starting at a position
/// is the deepest end the walk passes.
pub const Set = struct {
    /// Every secret, longest first: the list the sinks report as their secrets.
    all: std.ArrayList([]const u8) = .empty,
    /// The trie's first level, by byte: a node, or 0 for none.
    root: [256]u32 = @splat(0),
    /// Which two bytes a secret can start with, one bit for each of the 65,536 pairs (a
    /// secret of one byte sets all 256 pairs it begins). A position of a log line is tried against
    /// the trie only when its pair is here: a secret's first byte alone is common in text (any
    /// letter of a base64 token), its first two rarely are, and testing a bit costs a load where
    /// the trie costs a hash lookup.
    starts: [1024]u64 = @splat(0),
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
        set.markStart(owned);
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

    fn markStart(set: *Set, secret: []const u8) void {
        const high = @as(usize, secret[0]) << 8;
        if (secret.len > 1) return set.setStart(high | secret[1]);
        for (0..256) |second| set.setStart(high | second);
    }

    fn setStart(set: *Set, pair: usize) void {
        set.starts[pair / 64] |= @as(u64, 1) << @truncate(pair);
    }

    fn newNode(set: *Set) u32 {
        set.ends.appendAssumeCapacity(false);
        return @intCast(set.ends.items.len - 1);
    }

    fn edge(node: u32, b: u8) u64 {
        return @as(u64, node) << 8 | b;
    }

    /// The first place at or after `from` that a secret could start at, by `starts`: `text.len`
    /// for none. The same test as `longestAt`'s, in a loop of its own, which is most of what a log
    /// line costs.
    fn nextStart(set: *const Set, text: []const u8, from: usize) usize {
        var i = from;
        while (i + 1 < text.len) : (i += 1) {
            const pair = @as(usize, text[i]) << 8 | text[i + 1];
            if (set.starts[pair / 64] >> @truncate(pair) & 1 != 0) return i;
        }
        // The last byte has no pair: a secret of one byte may be there.
        return if (i < text.len) i else text.len;
    }

    /// The length of the longest secret `text` starts with, or 0.
    fn longestAt(set: *const Set, text: []const u8) usize {
        if (text.len == 0) return 0;
        // The last byte of a text has no pair: a secret of one byte may be there.
        if (text.len > 1) {
            const pair = @as(usize, text[0]) << 8 | text[1];
            if (set.starts[pair / 64] >> @truncate(pair) & 1 == 0) return 0;
        }
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
        return maskSpans(w, text, set);
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

/// Where a line too long to hold whole is cut (`cut`): the first `at` bytes are logged as a line of
/// their own and the rest kept for the next; with `masked`, the first `at` bytes are one masked
/// span, logged as `***`.
pub const Cut = struct { at: usize, masked: bool = false };

/// Where to cut `text`, the start of a line too long to hold whole, so that the parts masked each
/// on its own show what the whole line masked would (`write`): the last place no occurrence of a
/// secret spans, at least the longest secret's length less one before the end, since the text
/// after the end, not here yet, could finish a secret begun before it. Null when there is no such
/// place, unless `force`: then the place a span of secrets reaching from the start ends, all of
/// it masked (only a run of overlapping secrets longer than the line gets there), or, when
/// `text` is shorter than a secret, all of it.
///
/// A cut anywhere else could split a secret between two lines, each part then shown.
pub fn cut(text: []const u8, secrets: []const []const u8, index: ?*const Set, force: bool) ?Cut {
    var longest: usize = 0;
    for (secrets) |s| longest = @max(longest, s.len);
    if (longest <= 1) return .{ .at = text.len };
    if (text.len < longest) return if (force) .{ .at = text.len } else null;
    const limit = text.len - (longest - 1);
    const list: List = .{ .secrets = secrets };
    // How far the secrets that start before each place reach.
    var reach: usize = 0;
    var best: ?usize = null;
    for (0..limit) |j| {
        const n = if (index) |ix| ix.longestAt(text[j..]) else list.longestAt(text[j..]);
        reach = @max(reach, j + n);
        if (reach <= j + 1) best = j + 1;
    }
    if (best) |at| return .{ .at = at };
    // Every place up to `limit` is inside a secret, so all of `text[0..reach]` is one span.
    return if (force) .{ .at = reach, .masked = true } else null;
}

test "a long line is cut where no secret spans the cut, so each part masks as the whole does" {
    var a: std.heap.ArenaAllocator = .init(std.testing.allocator);
    defer a.deinit();
    const ar = a.allocator();
    const secrets: []const []const u8 = &.{ "s3cret-value", "ab", "bcdef", "aaa" };
    var set: Set = .{};
    for (secrets) |s| try set.add(ar, s);
    // The cut never splits `s3cret-value`, however the line ends.
    try std.testing.expectEqual(Cut{ .at = 9 }, cut("xxxxxxxx s3cret-value", secrets, null, false).?);
    try std.testing.expectEqual(Cut{ .at = 9 }, cut("xxxxxxxx s3cret-value", secrets, &set, false).?);
    try std.testing.expectEqual(Cut{ .at = 6 }, cut("xxxxxxxx s3cret-v", secrets, &set, false).?);
    // No secrets: anywhere.
    try std.testing.expectEqual(Cut{ .at = 5 }, cut("hello", &.{}, null, false).?);
    // Too short to know: held, unless forced.
    try std.testing.expect(cut("s3cret", secrets, null, false) == null);
    try std.testing.expectEqual(Cut{ .at = 6 }, cut("s3cret", secrets, null, true).?);
    // Secrets that touch can be cut between; ones that overlap from the start cannot: held, and
    // forced, one masked span.
    try std.testing.expectEqual(Cut{ .at = 6 }, cut("ababababababababab", secrets, &set, false).?);
    const run = "aaaaaaaaaaaaaaaaaa";
    try std.testing.expect(cut(run, secrets, &set, false) == null);
    try std.testing.expectEqual(Cut{ .at = 9, .masked = true }, cut(run, secrets, &set, true).?);
    // Against masking the whole: random lines over a small alphabet.
    var prng: std.Random.DefaultPrng = .init(3);
    const r = prng.random();
    const small: []const []const u8 = &.{ "abc", "ca", "bcbcb" };
    for (0..3000) |_| {
        var text: [40]u8 = undefined;
        const len = r.uintAtMost(usize, text.len);
        for (text[0..len]) |*c| c.* = "abcd"[r.uintLessThan(usize, 4)];
        const c = cut(text[0..len], small, null, false) orelse continue;
        const whole = try alloc(ar, text[0..len], small);
        const parts = try std.mem.concat(ar, u8, &.{
            try alloc(ar, text[0..c.at], small),
            try alloc(ar, text[c.at..len], small),
        });
        // A part's last `***` and the next part's first are one span in the whole.
        const joined = try std.mem.replaceOwned(u8, ar, parts, mask ++ mask, mask);
        try std.testing.expectEqualStrings(whole, joined);
    }
}

/// The shortest line of a multi-line secret masked on its own. A JSON key file's `{` and `}` lines
/// would otherwise mask every brace of every log; the whole value and its longer lines still are.
pub const min_line = 4;

/// What one secret must be masked as, wherever it appears, as GitHub's runner masks a secret
/// (`InitializeSecretMasker` in Worker.cs, `AddMaskCommandExtension`, the encoders HostContext.cs
/// registers): its value without the whitespace around it (a token saved with a trailing newline
/// still matches), each line of a multi-line value, split at `\r` or `\n` (the log is masked line
/// by line, so a whole multi-line value never matches there), and each of those as GitHub's
/// `ValueEncoders` write it (`encodings`).
///
/// One difference: a line shorter than `min_line` is not masked on its own (GitHub masks every
/// line), or a JSON key file's `{` and `}` lines would mask every brace of every log.
pub fn forms(arena: std.mem.Allocator, value: []const u8) std.mem.Allocator.Error![]const []const u8 {
    var out: std.ArrayList([]const u8) = .empty;
    const whole = std.mem.trim(u8, value, &std.ascii.whitespace);
    if (whole.len == 0) return out.items;
    try encodings(arena, &out, whole);
    if (std.mem.indexOfAny(u8, whole, "\r\n") != null) {
        var lines = std.mem.tokenizeAny(u8, whole, "\r\n");
        while (lines.next()) |l| {
            const line = std.mem.trim(u8, l, &std.ascii.whitespace);
            if (line.len >= min_line) try encodings(arena, &out, line);
        }
    }
    return out.items;
}

/// The shortest base64 text masked as part of a longer one (`encodings`): six bytes of a secret.
const min_base64_part = 8;

/// `value` and what GitHub's `ValueEncoders` make of it, each that differs from `value` and is not
/// empty, appended to `out`:
///
///   - JSON, as `JsonConvert.ToString` writes a string's contents (`toJSON(secrets)`, a JSON
///     log line), and as std.json does where the two differ (U+0085, U+2028, U+2029);
///   - base64 (`Base64StringEscape`), and of the value without its first byte or two
///     (`Base64StringEscapeShift1`, `Shift2`): inside a longer encoded text, such as
///     `base64(user:password)`, the secret's bytes start one or two bytes into a group of three.
///     Each with its padding and without it, and, when it is at least `min_base64_part` long,
///     without the last characters that depend on the bytes after the secret, which GitHub's
///     forms keep, so the secret is masked whatever follows it;
///   - URL-encoded, every byte outside the unreserved set (`UriDataEscape`);
///   - `"` as `\"` (`CommandLineArgumentEscape`), `'` as `''` (`ExpressionStringEscape`), XML's
///     five entities (`XmlDataEscape`), without the double quotes around it (`TrimDoubleQuotes`),
///     and the parts PowerShell prints around a `&` (`PowerShellPreAmpersandEscape`, `Post`).
fn encodings(arena: std.mem.Allocator, out: *std.ArrayList([]const u8), value: []const u8) std.mem.Allocator.Error!void {
    try out.append(arena, value);
    const Add = struct {
        fn add(ar: std.mem.Allocator, o: *std.ArrayList([]const u8), v: []const u8, form: []const u8) !void {
            if (form.len > 0 and !std.mem.eql(u8, form, v)) try o.append(ar, form);
        }
    };
    const add = Add.add;

    // JSON.
    var json: std.Io.Writer.Allocating = .init(arena);
    std.json.Stringify.encodeJsonStringChars(value, .{}, &json.writer) catch return error.OutOfMemory;
    try add(arena, out, value, json.written());
    const newtonsoft = try replaceAll(arena, json.written(), &.{
        .{ "\u{85}", "\\u0085" }, .{ "\u{2028}", "\\u2028" }, .{ "\u{2029}", "\\u2029" },
    });
    try add(arena, out, value, newtonsoft);

    // Base64, of the value and of it shifted by one and two bytes.
    const enc = std.base64.standard.Encoder;
    for (0..3) |shift| {
        if (shift > 0 and value.len <= shift) break;
        const bytes = value[shift..];
        const padded = try arena.alloc(u8, enc.calcSize(bytes.len));
        _ = enc.encode(padded, bytes);
        try add(arena, out, value, padded);
        try add(arena, out, value, std.mem.trimEnd(u8, padded, "="));
        // Each character holds six bits: the first `len * 8 / 6` hold only the value's.
        const own = padded[0 .. bytes.len * 8 / 6];
        if (own.len >= min_base64_part) try add(arena, out, value, own);
    }

    // URL-encoded.
    var url: std.ArrayList(u8) = .empty;
    for (value) |ch| {
        if (std.ascii.isAlphanumeric(ch) or ch == '-' or ch == '.' or ch == '_' or ch == '~')
            try url.append(arena, ch)
        else
            try url.print(arena, "%{X:0>2}", .{ch});
    }
    try add(arena, out, value, url.items);

    try add(arena, out, value, try replaceAll(arena, value, &.{.{ "\"", "\\\"" }}));
    try add(arena, out, value, try replaceAll(arena, value, &.{.{ "'", "''" }}));
    try add(arena, out, value, try replaceAll(arena, value, &.{
        .{ "&", "&amp;" }, .{ "<", "&lt;" }, .{ ">", "&gt;" }, .{ "\"", "&quot;" }, .{ "'", "&apos;" },
    }));
    if (value.len > 8 and value[0] == '"' and value[value.len - 1] == '"')
        try add(arena, out, value, value[1 .. value.len - 1]);
    // PowerShell: up to and including the first `&+`, or else the last `&`; and after it (past
    // the one character it colours after `&+`). Each only from six bytes.
    if (std.mem.indexOf(u8, value, "&+")) |at| {
        const pre = value[0 .. at + 2];
        if (pre.len >= 6) try add(arena, out, value, pre);
        if (value.len > at + 3) {
            const post = value[at + 3 ..];
            if (post.len >= 6) try add(arena, out, value, post);
        }
    } else if (std.mem.lastIndexOfScalar(u8, value, '&')) |at| {
        const pre = value[0 .. at + 1];
        const post = value[at + 1 ..];
        if (pre.len >= 6) try add(arena, out, value, pre);
        if (post.len >= 6) try add(arena, out, value, post);
    }
}

/// `text` with each pair's first string replaced by its second, at each place, the first pair that
/// matches there winning.
fn replaceAll(arena: std.mem.Allocator, text: []const u8, pairs: []const [2][]const u8) std.mem.Allocator.Error![]const u8 {
    var out: std.ArrayList(u8) = .empty;
    var i: usize = 0;
    next: while (i < text.len) {
        for (pairs) |p| if (std.mem.startsWith(u8, text[i..], p[0])) {
            try out.appendSlice(arena, p[1]);
            i += p[0].len;
            continue :next;
        };
        try out.append(arena, text[i]);
        i += 1;
    }
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

test "a secret is masked in the forms GitHub's runner masks it in, base64 at any offset" {
    var a: std.heap.ArenaAllocator = .init(std.testing.allocator);
    defer a.deinit();
    const ar = a.allocator();
    const list = try expand(ar, &.{"pa\"ss'w<o>rd&+s3cret-x"});
    // base64(user:password): the password starts two bytes into a group of three, where the
    // plain base64 form never matched. And followed by more bytes, which change its last
    // character.
    const enc = std.base64.standard.Encoder;
    for ([_][]const u8{ "", "u", "us", "user:", "user:x" }) |before| {
        for ([_][]const u8{ "", "!", "!!", "\n--more--" }) |after| {
            const plain = try std.mem.concat(ar, u8, &.{ before, "pa\"ss'w<o>rd&+s3cret-x", after });
            const b64 = try ar.alloc(u8, enc.calcSize(plain.len));
            _ = enc.encode(b64, plain);
            const got = try alloc(ar, b64, list);
            try std.testing.expect(std.mem.indexOf(u8, got, mask) != null);
            // What is left are at most the characters that also hold the bytes around it.
            try std.testing.expect(got.len <= mask.len + 4 * (before.len + after.len + 2) / 3 + 4);
        }
    }
    // Escaped for a command line, an expression and XML; PowerShell's halves around `&+`.
    for ([_][]const u8{
        "pa\\\"ss'w<o>rd&+s3cret-x",
        "pa\"ss''w<o>rd&+s3cret-x",
        "pa&quot;ss&apos;w&lt;o&gt;rd&amp;+s3cret-x",
        "pa\"ss'w<o>rd&+",
        "3cret-x",
    }) |form| try std.testing.expectEqualStrings("<***>", try alloc(ar, try std.mem.concat(ar, u8, &.{ "<", form, ">" }), list));
    // In double quotes, the value inside them.
    const quoted = try expand(ar, &.{"\"quoted-value\""});
    try std.testing.expectEqualStrings("=***", try alloc(ar, "=quoted-value", quoted));
    // Lines split at a lone `\r` too, each masked in its forms.
    const cr = try expand(ar, &.{"first-line\rsecond-line"});
    try std.testing.expectEqualStrings("***", try alloc(ar, "second-line", cr));
    try std.testing.expectEqualStrings("***", try alloc(ar, "c2Vjb25kLWxpbmU", cr));
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

test "a set finds a secret of one byte at the end of a text, where no pair starts, and before any byte" {
    var a: std.heap.ArenaAllocator = .init(std.testing.allocator);
    defer a.deinit();
    const ar = a.allocator();
    var set: Set = .{};
    for ([_][]const u8{ "q", "\xff", "mn" }) |s| try set.add(ar, s);
    for ([_][2][]const u8{
        .{ "q", "***" },
        .{ "aq", "a***" },
        .{ "qz\xff", "***z***" },
        .{ "m", "m" },
        .{ "xm", "xm" },
        .{ "mn", "***" },
        .{ "amnq", "a***" }, // touching spans are one
    }) |case| {
        var got: std.Io.Writer.Allocating = .init(ar);
        try set.write(&got.writer, case[0]);
        try std.testing.expectEqualStrings(case[1], got.written());
    }
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

/// `text` masked as GitHub's `SecretMasker.MaskSecrets` does it, step by step: every position of
/// every secret (`ValueSecret.GetPositions`, which looks again one character after each match),
/// sorted by start, merged where one starts at or before the end of the last, each merged range
/// replaced by `***`. The model `write` is held to (the tests and fuzz.zig), not used to log.
pub fn modelGitHub(arena: std.mem.Allocator, text: []const u8, secrets: []const []const u8) std.mem.Allocator.Error![]const u8 {
    const Pos = struct { start: usize, end: usize };
    var found: std.ArrayList(Pos) = .empty;
    for (secrets) |s| {
        if (s.len == 0) continue;
        var from: usize = 0;
        while (std.mem.indexOfPos(u8, text, from, s)) |at| : (from = at + 1)
            try found.append(arena, .{ .start = at, .end = at + s.len });
    }
    // `OrderBy` sorts by start; the merge does not depend on the order of ties.
    std.mem.sort(Pos, found.items, {}, struct {
        fn less(_: void, a: Pos, b: Pos) bool {
            return a.start < b.start;
        }
    }.less);
    var out: std.ArrayList(u8) = .empty;
    var written: usize = 0;
    var k: usize = 0;
    while (k < found.items.len) {
        const start = found.items[k].start;
        var end = found.items[k].end;
        k += 1;
        while (k < found.items.len and found.items[k].start <= end) : (k += 1)
            end = @max(end, found.items[k].end);
        try out.appendSlice(arena, text[written..start]);
        try out.appendSlice(arena, mask);
        written = end;
    }
    try out.appendSlice(arena, text[written..]);
    return out.items;
}

test "overlapping and touching secrets are masked as one span, as GitHub's runner masks them" {
    var a: std.heap.ArenaAllocator = .init(std.testing.allocator);
    defer a.deinit();
    const ar = a.allocator();
    // `ab` is found first; `bcdef` starts inside it and is masked with it, not shown as `cdef`.
    try std.testing.expectEqualStrings("x***y", try alloc(ar, "xabcdefy", &.{ "ab", "bcdef" }));
    // Two that touch are one span, as are a secret's own overlapping occurrences.
    try std.testing.expectEqualStrings("***", try alloc(ar, "abab", &.{"ab"}));
    try std.testing.expectEqualStrings("-***-", try alloc(ar, "-aaaa-", &.{"aaa"}));
    try std.testing.expectEqualStrings("***c***", try alloc(ar, "abcab", &.{"ab"}));
    // Against GitHub's algorithm, over text and secrets from a small alphabet, so they overlap,
    // nest and repeat; the list and the set alike.
    var prng: std.Random.DefaultPrng = .init(7);
    const r = prng.random();
    for (0..2000) |_| {
        var secrets: [4][]const u8 = undefined;
        var set: Set = .{};
        for (&secrets) |*s| {
            const buf = try ar.alloc(u8, r.uintAtMost(usize, 5));
            for (buf) |*c| c.* = "abc"[r.uintLessThan(usize, 3)];
            s.* = buf;
            try set.add(ar, buf);
        }
        var text: [40]u8 = undefined;
        const len = r.uintAtMost(usize, text.len);
        for (text[0..len]) |*c| c.* = "abcd"[r.uintLessThan(usize, 4)];
        const want = try modelGitHub(ar, text[0..len], &secrets);
        try std.testing.expectEqualStrings(want, try alloc(ar, text[0..len], &secrets));
        var got: std.Io.Writer.Allocating = .init(ar);
        try set.write(&got.writer, text[0..len]);
        try std.testing.expectEqualStrings(want, got.written());
    }
}
