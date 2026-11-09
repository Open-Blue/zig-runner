//! Which jobs a runner will run. A runner on a machine that untrusted code must not reach (prod)
//! runs only jobs from trusted refs and events (`RUNNER_TRUSTED_REFS`, `RUNNER_TRUSTED_EVENTS`).
//! A pull request can name any runner's labels in `runs-on`, and a personal account's repository
//! has no runner groups to stop it, so the runner itself refuses: before any step runs, from the
//! github context that GitHub, not the workflow, wrote into the job.
//!
//! It fails closed (#105): no trusted refs trusts no job, and trusting every ref takes an explicit
//! `*`. An unset value used to trust every job, so a lost `EnvironmentFile` line or a typo turned
//! prod, still carrying the `prod` label, into a runner that took pull requests.

const std = @import("std");
const Allocator = std.mem.Allocator;
const Github = @import("job.zig").Github;

/// Why the job may not run here, or null when it may. `refs` and `events` are comma-separated, a
/// trailing `*` matching any rest (`refs/tags/v*`) and `*` alone matching anything. No refs trusts
/// no job. Both the run's ref and the ref its workflow file was read from must be trusted: an event
/// can run a workflow from another ref.
pub fn refusal(
    arena: Allocator,
    refs: []const u8,
    events: []const u8,
    g: Github,
) Allocator.Error!?[]const u8 {
    return switch (verdict(refs, events, g)) {
        .trusted => null,
        .no_refs => no_refs,
        .event => try std.fmt.allocPrint(
            arena,
            "This runner does not run jobs from '{s}' events (RUNNER_TRUSTED_EVENTS: {s}).",
            .{ g.event_name, events },
        ),
        .ref => try std.fmt.allocPrint(
            arena,
            "This runner does not run jobs for '{s}' (RUNNER_TRUSTED_REFS: {s}).",
            .{ g.ref, refs },
        ),
        .workflow => try std.fmt.allocPrint(
            arena,
            "This runner does not run workflows read from '{s}' (RUNNER_TRUSTED_REFS: {s}).",
            .{ workflowRef(g.workflow_ref), refs },
        ),
    };
}

/// Whether the runner vouches for the job: it passes the gate (`refusal`) on lists that name what
/// they trust. For what a job may share with the repository's trusted jobs, the package caches'
/// `repo` scope (#105). A `*` in either list lets every job through without vouching for any: such
/// a runner is where untrusted code runs (pre-prod), and none of its jobs may write what prod
/// reads, even on an engine the two share.
pub fn vouches(refs: []const u8, events: []const u8, g: Github) bool {
    return verdict(refs, events, g) == .trusted and !everything(refs) and !everything(events);
}

/// The gate's decision, before it is put into words: the one rule both `refusal` and `vouches`
/// apply.
const Verdict = enum { trusted, no_refs, event, ref, workflow };

fn verdict(refs: []const u8, events: []const u8, g: Github) Verdict {
    if (none(refs)) return .no_refs;
    if (!listed(events, g.event_name)) return .event;
    if (!listed(refs, g.ref)) return .ref;
    if (!listed(refs, workflowRef(g.workflow_ref))) return .workflow;
    return .trusted;
}

/// A job's refusal on a runner with no trusted refs: what to set, since nothing is wrong with the
/// job.
const no_refs = "This runner trusts no ref, so it runs no job: RUNNER_TRUSTED_REFS is not set. " ++
    "Set it to the refs whose jobs may run here (refs/heads/main,refs/tags/v*), or to * to run " ++
    "every job, on a machine untrusted code may reach (docs/OPERATIONS.md, \"Environments\").";

/// What the runner trusts, for its log at startup: which refs and events, every ref, or none.
pub fn mode(arena: Allocator, refs: []const u8, events: []const u8) Allocator.Error![]const u8 {
    if (none(refs)) return "trusting no ref: every job will fail before its first step; " ++
        "set RUNNER_TRUSTED_REFS (docs/OPERATIONS.md, \"Environments\")";
    const refs_text = if (everything(refs))
        "every ref (RUNNER_TRUSTED_REFS=*)"
    else
        try std.fmt.allocPrint(arena, "refs {s}", .{std.mem.trim(u8, refs, " ")});
    const events_text = if (none(events))
        "no event: every job will fail before its first step; set RUNNER_TRUSTED_EVENTS"
    else if (everything(events))
        "every event (RUNNER_TRUSTED_EVENTS=*)"
    else
        try std.fmt.allocPrint(arena, "events {s}", .{std.mem.trim(u8, events, " ")});
    return std.fmt.allocPrint(arena, "trusting {s} and {s}", .{ refs_text, events_text });
}

/// Whether `labels` (comma-separated, as `RUNNER_LABELS`) include `prod`, the label of the runner
/// untrusted code must not reach (docs/OPERATIONS.md, "Environments"). GitHub matches labels ignoring case.
pub fn prodLabel(labels: []const u8) bool {
    var it = std.mem.tokenizeScalar(u8, labels, ',');
    while (it.next()) |raw| {
        if (std.ascii.eqlIgnoreCase(std.mem.trim(u8, raw, " "), "prod")) return true;
    }
    return false;
}

/// Whether the comma-separated `list` has no entry: unset, empty, or only commas and spaces.
pub fn none(list: []const u8) bool {
    var it = std.mem.tokenizeAny(u8, list, ", ");
    return it.next() == null;
}

/// Whether the comma-separated `list` has the entry `*`, which matches anything.
pub fn everything(list: []const u8) bool {
    var it = std.mem.tokenizeScalar(u8, list, ',');
    while (it.next()) |raw| {
        if (std.mem.eql(u8, std.mem.trim(u8, raw, " "), "*")) return true;
    }
    return false;
}

/// `owner/repo/.github/workflows/ci.yml@refs/heads/main` -> `refs/heads/main`; empty without one.
fn workflowRef(workflow_ref: []const u8) []const u8 {
    const at = std.mem.lastIndexOfScalar(u8, workflow_ref, '@') orelse return "";
    return workflow_ref[at + 1 ..];
}

/// Whether `item` is in the comma-separated `list`, where an entry ending in `*` matches any rest
/// of a non-empty item, and `*` alone matches anything, even an empty item.
fn listed(list: []const u8, item: []const u8) bool {
    var entries = std.mem.tokenizeScalar(u8, list, ',');
    while (entries.next()) |raw| {
        const entry = std.mem.trim(u8, raw, " ");
        if (std.mem.eql(u8, entry, "*")) return true;
        if (entry.len == 0 or item.len == 0) continue;
        if (entry[entry.len - 1] == '*') {
            if (std.mem.startsWith(u8, item, entry[0 .. entry.len - 1])) return true;
        } else if (std.mem.eql(u8, entry, item)) return true;
    }
    return false;
}

const testing = std.testing;
const prod_refs = "refs/heads/main, refs/tags/v*";
const prod_events = "push,workflow_dispatch";

fn ctx(event: []const u8, ref: []const u8, workflow_ref: []const u8) Github {
    return .{ .event_name = event, .ref = ref, .workflow_ref = workflow_ref };
}

test "no trusted refs: no job runs, not even a push to main, and the refusal says what to set" {
    const wf = "o/r/.github/workflows/ci.yml@";
    const jobs = [_]Github{
        ctx("push", "refs/heads/main", wf ++ "refs/heads/main"),
        ctx("pull_request", "refs/pull/7/merge", wf ++ "refs/pull/7/merge"),
    };
    for (jobs) |g| for ([_][]const u8{ "", " ", ",", " , " }) |refs| {
        const why = (try refusal(testing.allocator, refs, "*", g)).?;
        try testing.expect(std.mem.indexOf(u8, why, "trusts no ref") != null);
        try testing.expect(std.mem.indexOf(u8, why, "Set it to") != null);
    };
}

test "* trusts every ref, even a missing one, and events are still checked" {
    const wf = "o/r/.github/workflows/ci.yml@";
    const pr = ctx("pull_request", "refs/pull/7/merge", wf ++ "refs/pull/7/merge");
    try testing.expectEqual(null, try refusal(testing.allocator, "*", "*", pr));
    const blank = ctx("", "", "");
    try testing.expectEqual(null, try refusal(testing.allocator, " * ", "push, *", blank));
    const push = ctx("push", "refs/heads/anything", wf ++ "refs/heads/anything");
    try testing.expectEqual(null, try refusal(testing.allocator, "*", prod_events, push));
    // The default events: every ref, but a pull request is still not trusted.
    var arena: std.heap.ArenaAllocator = .init(testing.allocator);
    defer arena.deinit();
    const why = (try refusal(arena.allocator(), "*", prod_events, pr)).?;
    try testing.expect(std.mem.indexOf(u8, why, "'pull_request' events") != null);
    // No events: no job.
    try testing.expect(try refusal(arena.allocator(), "*", "", push) != null);
}

test "the trust mode, as logged at startup" {
    var arena: std.heap.ArenaAllocator = .init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    try testing.expectEqualStrings(
        "trusting refs refs/heads/main, refs/tags/v* and events push,workflow_dispatch",
        try mode(a, prod_refs, prod_events),
    );
    try testing.expectEqualStrings(
        "trusting every ref (RUNNER_TRUSTED_REFS=*) and every event (RUNNER_TRUSTED_EVENTS=*)",
        try mode(a, "*", "*"),
    );
    try testing.expectEqualStrings(
        "trusting every ref (RUNNER_TRUSTED_REFS=*) and events push,workflow_dispatch",
        try mode(a, "*", prod_events),
    );
    for ([_][]const u8{ "", " , " }) |refs| try testing.expect(
        std.mem.startsWith(u8, try mode(a, refs, "*"), "trusting no ref: every job will fail"),
    );
    try testing.expect(std.mem.endsWith(
        u8,
        try mode(a, prod_refs, ""),
        "and no event: every job will fail before its first step; set RUNNER_TRUSTED_EVENTS",
    ));
}

test "the prod label, among others and in any case, but not pre-prod" {
    try testing.expect(prodLabel("self-hosted,linux,zig,prod"));
    try testing.expect(prodLabel("self-hosted, Prod"));
    try testing.expect(!prodLabel("self-hosted,linux,zig,pre-prod"));
    try testing.expect(!prodLabel("production,prod-like"));
    try testing.expect(!prodLabel(""));
}

test "a push to main, a dispatch and a version tag run" {
    const wf = "o/r/.github/workflows/ci.yml@";
    const ok = [_]Github{
        ctx("push", "refs/heads/main", wf ++ "refs/heads/main"),
        ctx("workflow_dispatch", "refs/heads/main", wf ++ "refs/heads/main"),
        ctx("push", "refs/tags/v1.2.3", wf ++ "refs/tags/v1.2.3"),
    };
    for (ok) |g| {
        try testing.expectEqual(null, try refusal(testing.allocator, prod_refs, prod_events, g));
    }
}

test "pull requests, other branches and workflows from elsewhere are refused" {
    var arena: std.heap.ArenaAllocator = .init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    const wf = "o/r/.github/workflows/ci.yml@";
    const refused = [_]Github{
        // A pull request's workflow file is the pull request's own.
        ctx("pull_request", "refs/pull/7/merge", wf ++ "refs/pull/7/merge"),
        // Runs on main's ref, but is not a trusted event.
        ctx("pull_request_target", "refs/heads/main", wf ++ "refs/heads/main"),
        // Anyone who can push a branch can dispatch on it.
        ctx("workflow_dispatch", "refs/heads/mine", wf ++ "refs/heads/mine"),
        ctx("push", "refs/heads/maintenance", wf ++ "refs/heads/maintenance"),
        ctx("push", "refs/tags/x1", wf ++ "refs/tags/x1"),
        // The ref is trusted, the workflow file's is not (or is missing).
        ctx("push", "refs/heads/main", wf ++ "refs/heads/mine"),
        ctx("push", "refs/heads/main", ""),
        ctx("", "", ""),
    };
    for (refused) |g| try testing.expect(try refusal(a, prod_refs, prod_events, g) != null);
    const why = (try refusal(a, prod_refs, prod_events, refused[0])).?;
    try testing.expect(std.mem.indexOf(u8, why, "'pull_request' events") != null);
}

test "vouched for (the caches' repo scope): what the gate trusts by name, never by *" {
    const wf = "o/r/.github/workflows/ci.yml@";
    const main = ctx("push", "refs/heads/main", wf ++ "refs/heads/main");
    const tag = ctx("push", "refs/tags/v1.2.3", wf ++ "refs/tags/v1.2.3");
    const same_repo_pr = ctx("pull_request", "refs/pull/7/merge", wf ++ "refs/pull/7/merge");
    // Both run on the default branch's ref and workflow, but a fork can set them off.
    const workflow_run = ctx("workflow_run", "refs/heads/main", wf ++ "refs/heads/main");
    const issue_comment = ctx("issue_comment", "refs/heads/main", wf ++ "refs/heads/main");
    // A fork's pull request whose head repository was deleted looks like any pull request.
    const orphan_pr = ctx("pull_request", "refs/pull/8/merge", wf ++ "refs/pull/8/merge");
    try testing.expect(vouches(prod_refs, prod_events, main));
    try testing.expect(vouches(prod_refs, prod_events, tag));
    for ([_]Github{ same_repo_pr, workflow_run, issue_comment, orphan_pr }) |g| {
        try testing.expect(!vouches(prod_refs, prod_events, g));
    }
    // A `*` in either list lets jobs through the gate but vouches for none, not even main's push.
    for ([_]Github{ main, same_repo_pr, workflow_run, orphan_pr }) |g| {
        try testing.expectEqual(null, try refusal(testing.allocator, "*", "*", g));
        try testing.expect(!vouches("*", "*", g));
        try testing.expect(!vouches("refs/heads/main,*", prod_events, g));
        try testing.expect(!vouches(prod_refs, "push, *", g));
    }
    // No refs: nothing passes, so nothing is vouched for.
    try testing.expect(!vouches("", prod_events, main));
    // Lists that name pull requests vouch for them; the caches still keep forks apart
    // (`packageCacheScope`).
    try testing.expect(vouches("refs/heads/main,refs/pull/*", "push,pull_request", same_repo_pr));
}
