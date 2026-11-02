//! The jobs' NAT and firewall rules over nftables netlink (docs/native-backend.md, P5): a native
//! port of what P1 made with `iptables`, with no `nft` or `iptables` binary at runtime.
//!
//! The rules live in a table of the runner's own, `ip zig_runner`, replaced whole and atomically
//! (one netlink batch) whenever they are made:
//!
//! - `postrouting` (nat): the jobs' subnet masqueraded on its way out, not towards the bridge.
//! - `input` (filter): from the bridge, replies only. A job reaches no service of the host's, at
//!   the bridge's address or any other.
//! - `forward` (filter): from the bridge, out through an uplink only (the interfaces of the host's
//!   default routes), so never to another job, to Docker's containers, or to another network the
//!   host routes to but does not leave by; to the bridge, replies only.
//! - `output` (filter): to the bridge, replies only. No process of the host's reaches a job, its
//!   services' ports included (P6's `not_asked`).
//!
//! nftables runs every base chain on a hook, and a packet must be accepted by all of them: a drop
//! in ours holds whatever the host's other tables say, but an accept in ours cannot overturn a
//! drop in theirs. Docker and ufw make their rules with iptables, which on current distributions
//! writes into nftables' `ip filter` table (iptables-nft), and both set its FORWARD policy to drop.
//! So the jobs' traffic is also accepted in that table's `FORWARD` chain, and in `DOCKER-USER` on a
//! Docker host (the chain Docker leaves for others' rules): `-i zr0 -j ACCEPT` and `-o zr0 -j
//! ACCEPT`, which say no more than "the runner's table decides", since ours drops everything else
//! of the bridge's. They are written exactly as iptables-nft writes those rules (meta, cmp,
//! counter, immediate), so iptables, Docker and ufw read and keep them as their own; any other
//! form would make iptables call the table incompatible and refuse to change it. Rules there that
//! name the bridge are the runner's (P1's too, made by `iptables`): they are removed and made again
//! in the same batch, so the rules are never doubled and P1's are replaced.

const std = @import("std");
const builtin = @import("builtin");
const linux = std.os.linux;
const net = @import("net.zig");

const Allocator = std.mem.Allocator;

/// The runner's table, in the `ip` family.
pub const table = "zig_runner";

/// The helper's subcommand that makes the rules in the caller's network namespace (`main.zig`
/// dispatches it): `zig-runner native-nft <subnet> [uplink...]`. The runner makes them itself
/// (`net.natRules`); this is for the tests, which make them in a namespace of their own, and for
/// an operator making them ahead of the runner.
pub const command = "native-nft";

pub fn main(args: []const []const u8) u8 {
    if (args.len < 1) return fail("native nft: usage: native-nft <subnet> [uplink...]");
    const subnet = net.Subnet.parse(args[0]) catch return fail("native nft: a subnet");
    for (args[1..]) |up| if (up.len == 0 or up.len >= 16) return fail("native nft: an uplink");
    if (apply(subnet, args[1..])) |why| {
        var buf: [512]u8 = undefined;
        return fail(std.fmt.bufPrint(&buf, "native nft: {s}", .{why}) catch "native nft: failed");
    }
    return 0;
}

fn fail(msg: []const u8) u8 {
    _ = linux.write(2, msg.ptr, msg.len);
    _ = linux.write(2, "\n", 1);
    return 1;
}

/// Makes the rules for `subnet` and the host's `uplinks` (see the file's comment). Null when they
/// were made, else why not. A batch that fails because another program changed a chain between
/// the rules being read and replaced (Docker starting, ufw reloading) is tried again.
pub fn apply(subnet: net.Subnet, uplinks: []const []const u8) ?[]const u8 {
    var sock = Socket.open() catch return "cannot open an nftables netlink socket";
    defer sock.close();
    var attempt: u32 = 0;
    while (true) : (attempt += 1) {
        const e = sock.replace(subnet, uplinks) catch |err| return @errorName(err);
        switch (e) {
            .SUCCESS => return null,
            // A rule removed or a chain made under us: read again.
            .NOENT, .EXIST, .BUSY, .AGAIN => if (attempt < 3) continue,
            else => {},
        }
        return explain(e);
    }
}

fn explain(e: linux.E) []const u8 {
    return switch (e) {
        .PERM, .ACCES => "nftables refused the rules (the runner needs CAP_NET_ADMIN)",
        .NOENT => "nftables lost a rule or chain while the rules were made, three times",
        .OPNOTSUPP => "the kernel lacks an nftables feature the rules need " ++
            "(nf_tables, nft_ct, nft_masq, nft_chain_nat)",
        .PROTONOSUPPORT, .AFNOSUPPORT => "the kernel has no nftables (nf_tables)",
        else => @tagName(e),
    };
}

/// What the host's `ip filter FORWARD` chain does with what no rule accepts, if it has the chain:
/// `accept` makes a host with IPv4 forwarding on route for its neighbours, and the runner warns.
pub const Policy = enum { none, accept, drop };

pub fn forwardPolicy() Policy {
    var sock = Socket.open() catch return .none;
    defer sock.close();
    const info = sock.chain("filter", "FORWARD") catch return .none;
    const c = info orelse return .none;
    return if (c.policy == nf_accept) .accept else if (c.policy == nf_drop) .drop else .none;
}

// --- the rules ---

const nfproto_ipv4 = 2;
const nf_drop = 0;
const nf_accept = 1;
const hook_input = 1;
const hook_forward = 2;
const hook_output = 3;
const hook_postrouting = 4;
const priority_filter = 0;
const priority_srcnat = 100;

/// The bridge's name as iptables-nft matches an interface exactly: with its terminating zero.
const bridge_name = net.bridge ++ "\x00";

/// `ip zig_runner` replaced, and the jobs' accepts in the iptables-nft chains made again, in one
/// batch: the kernel's errno for it (`.SUCCESS` when it was committed).
fn ruleBatch(b: *Batch, subnet: net.Subnet, uplinks: []const []const u8, host: HostChains) void {
    // Made if missing, then removed and made afresh: one batch is one transaction, so no packet
    // ever meets a half-made table.
    b.tableMsg(.NEWTABLE, linux.NLM_F_CREATE);
    b.tableMsg(.DELTABLE, 0);
    b.tableMsg(.NEWTABLE, linux.NLM_F_CREATE);
    b.baseChain("forward", "filter", hook_forward, priority_filter);
    b.baseChain("input", "filter", hook_input, priority_filter);
    b.baseChain("output", "filter", hook_output, priority_filter);
    b.baseChain("postrouting", "nat", hook_postrouting, priority_srcnat);

    // forward: from the bridge out through an uplink, nothing else from it; to it, replies only.
    for (uplinks) |up| {
        const r = b.rule(table, "forward", linux.NLM_F_APPEND);
        b.ifname(.iif, .eq, bridge_name);
        var name: [16]u8 = @splat(0);
        @memcpy(name[0..up.len], up);
        b.ifname(.oif, .eq, name[0 .. up.len + 1]);
        b.verdict(nf_accept);
        b.endRule(r);
    }
    var r = b.rule(table, "forward", linux.NLM_F_APPEND);
    b.ifname(.iif, .eq, bridge_name);
    b.verdict(nf_drop);
    b.endRule(r);
    r = b.rule(table, "forward", linux.NLM_F_APPEND);
    b.ifname(.oif, .eq, bridge_name);
    b.replies();
    b.verdict(nf_accept);
    b.endRule(r);
    r = b.rule(table, "forward", linux.NLM_F_APPEND);
    b.ifname(.oif, .eq, bridge_name);
    b.verdict(nf_drop);
    b.endRule(r);

    // input: from the bridge, replies only.
    r = b.rule(table, "input", linux.NLM_F_APPEND);
    b.ifname(.iif, .eq, bridge_name);
    b.replies();
    b.verdict(nf_accept);
    b.endRule(r);
    r = b.rule(table, "input", linux.NLM_F_APPEND);
    b.ifname(.iif, .eq, bridge_name);
    b.verdict(nf_drop);
    b.endRule(r);

    // output: to the bridge, replies only (P6): what the host's own processes send a job.
    r = b.rule(table, "output", linux.NLM_F_APPEND);
    b.ifname(.oif, .eq, bridge_name);
    b.replies();
    b.verdict(nf_accept);
    b.endRule(r);
    r = b.rule(table, "output", linux.NLM_F_APPEND);
    b.ifname(.oif, .eq, bridge_name);
    b.verdict(nf_drop);
    b.endRule(r);

    // postrouting: the subnet masqueraded, but towards the bridge.
    r = b.rule(table, "postrouting", linux.NLM_F_APPEND);
    b.sourceIn(subnet);
    b.ifname(.oif, .neq, bridge_name);
    b.expr("masq");
    b.endExpr(b.begin(nfta_expr_data));
    b.endRule(r);

    // The host's iptables-nft chains: the runner's old rules out, its accepts in at the head.
    for (host.stale) |s| b.deleteRule(s.table, s.chain, s.handle);
    for (host.accept_in) |chain| for ([_]Iface{ .oif, .iif }) |dir| {
        // Iptables' own form for `-i zr0 -j ACCEPT`: meta, cmp, a counter, an immediate.
        const h = b.rule("filter", chain, 0);
        b.ifname(dir, .eq, bridge_name);
        b.counter();
        b.verdict(nf_accept);
        b.endRule(h);
    };
}

/// The host's iptables-nft chains the batch touches: those to accept the jobs' traffic in, and
/// the runner's rules already there.
const HostChains = struct {
    accept_in: []const []const u8,
    stale: []const Stale,
};

const Stale = struct { table: []const u8, chain: []const u8, handle: u64 };

// --- netlink ---

const nfnl_subsys_nftables = 10;
const nfnl_msg_batch_begin = 0x10;
const nfnl_msg_batch_end = 0x11;

const Op = enum(u8) {
    NEWTABLE = 0,
    GETTABLE = 1,
    DELTABLE = 2,
    NEWCHAIN = 3,
    GETCHAIN = 4,
    NEWRULE = 6,
    GETRULE = 7,
    DELRULE = 8,
};

fn msgType(op: Op) u16 {
    return nfnl_subsys_nftables << 8 | @as(u16, @backingInt(op));
}

const nfta_table_name = 1;
const nfta_chain_table = 1;
const nfta_chain_name = 3;
const nfta_chain_hook = 4;
const nfta_chain_policy = 5;
const nfta_chain_type = 7;
const nfta_hook_hooknum = 1;
const nfta_hook_priority = 2;
const nfta_rule_table = 1;
const nfta_rule_chain = 2;
const nfta_rule_handle = 3;
const nfta_rule_expressions = 4;
const nfta_list_elem = 1;
const nfta_expr_name = 1;
const nfta_expr_data = 2;
const nfta_meta_dreg = 1;
const nfta_meta_key = 2;
const nft_meta_iifname = 6;
const nft_meta_oifname = 7;
const nfta_cmp_sreg = 1;
const nfta_cmp_op = 2;
const nfta_cmp_data = 3;
const nfta_data_value = 1;
const nfta_data_verdict = 2;
const nfta_verdict_code = 1;
const nfta_counter_bytes = 1;
const nfta_counter_packets = 2;
const nfta_immediate_dreg = 1;
const nfta_immediate_data = 2;
const nfta_payload_dreg = 1;
const nfta_payload_base = 2;
const nfta_payload_offset = 3;
const nfta_payload_len = 4;
const nft_payload_network_header = 1;
const nfta_bitwise_sreg = 1;
const nfta_bitwise_dreg = 2;
const nfta_bitwise_len = 3;
const nfta_bitwise_mask = 4;
const nfta_bitwise_xor = 5;
const nfta_ct_dreg = 1;
const nfta_ct_key = 2;
const nft_ct_state = 0;
/// conntrack's state bits as `ct state` loads them: ESTABLISHED and RELATED.
const ct_established_related: u32 = 0x2 | 0x4;
const nft_reg_verdict = 0;
const nft_reg_1 = 1;
const nla_f_nested = 0x8000;

const Iface = enum { iif, oif };
const CmpOp = enum(u32) { eq = 0, neq = 1 };

/// `struct nlmsghdr`, with the type a plain number: nftables' are not rtnetlink's.
const Header = extern struct { len: u32, type: u16, flags: u16, seq: u32, pid: u32 };
/// `struct nfgenmsg`: the family, version 0, and the resource id (big-endian).
const GenMsg = extern struct { family: u8, version: u8 = 0, res_id: u16 = 0 };
const Attr = extern struct { len: u16, type: u16 };

/// One batch of nftables messages being built: begin, the messages, end. Every message asks for
/// an acknowledgement, so the kernel answers each once, committed or not (`Socket.send`).
const Batch = struct {
    buf: []u8,
    len: usize = 0,
    seq: u32,
    first_seq: u32,
    /// Where the message being built starts.
    msg: usize = 0,
    acks: u32 = 0,
    overflow: bool = false,
    /// Where the expression being built starts (`expr`).
    elem: usize = 0,

    fn init(buf: []u8, seq: u32) Batch {
        var b: Batch = .{ .buf = buf, .seq = seq, .first_seq = seq };
        b.control(nfnl_msg_batch_begin);
        return b;
    }

    fn finish(b: *Batch) []const u8 {
        b.control(nfnl_msg_batch_end);
        return b.buf[0..b.len];
    }

    fn control(b: *Batch, t: u16) void {
        b.start(t, linux.NLM_F_REQUEST);
        b.put(GenMsg, .{ .family = 0, .res_id = std.mem.nativeToBig(u16, nfnl_subsys_nftables) });
        b.endMsg();
    }

    fn start(b: *Batch, t: u16, flags: u16) void {
        b.msg = b.len;
        b.seq += 1;
        b.put(Header, .{ .len = 0, .type = t, .flags = flags, .seq = b.seq, .pid = 0 });
    }

    fn message(b: *Batch, op: Op, flags: u16) void {
        b.start(msgType(op), linux.NLM_F_REQUEST | linux.NLM_F_ACK | flags);
        b.put(GenMsg, .{ .family = nfproto_ipv4 });
        b.acks += 1;
    }

    fn endMsg(b: *Batch) void {
        if (b.overflow) return;
        const len: u32 = @intCast(b.len - b.msg);
        @memcpy(b.buf[b.msg..][0..4], std.mem.asBytes(&len));
    }

    fn put(b: *Batch, comptime T: type, v: T) void {
        b.raw(std.mem.asBytes(&v));
    }

    fn raw(b: *Batch, bytes: []const u8) void {
        const stop = std.mem.alignForward(usize, b.len + bytes.len, 4);
        if (stop > b.buf.len) {
            b.overflow = true;
            return;
        }
        @memcpy(b.buf[b.len..][0..bytes.len], bytes);
        @memset(b.buf[b.len + bytes.len .. stop], 0);
        b.len = stop;
    }

    fn attr(b: *Batch, t: u16, data: []const u8) void {
        b.put(Attr, .{ .len = @intCast(@sizeOf(Attr) + data.len), .type = t });
        // The attribute's header is 4 bytes, so its data starts aligned; pad after it.
        b.raw(data);
    }

    fn attrStr(b: *Batch, t: u16, s: []const u8) void {
        var term: [64]u8 = @splat(0);
        @memcpy(term[0..s.len], s);
        b.attr(t, term[0 .. s.len + 1]);
    }

    fn attrBe32(b: *Batch, t: u16, v: u32) void {
        b.attr(t, std.mem.asBytes(&std.mem.nativeToBig(u32, v)));
    }

    fn attrBe64(b: *Batch, t: u16, v: u64) void {
        b.attr(t, std.mem.asBytes(&std.mem.nativeToBig(u64, v)));
    }

    fn begin(b: *Batch, t: u16) usize {
        const at = b.len;
        b.put(Attr, .{ .len = 0, .type = t | nla_f_nested });
        return at;
    }

    fn end(b: *Batch, at: usize) void {
        if (b.overflow) return;
        const len: u16 = @intCast(b.len - at);
        @memcpy(b.buf[at..][0..2], std.mem.asBytes(&len));
    }

    fn tableMsg(b: *Batch, op: Op, flags: u16) void {
        b.message(op, flags);
        b.attrStr(nfta_table_name, table);
        b.endMsg();
    }

    fn baseChain(b: *Batch, name: []const u8, kind: []const u8, hook: u32, priority: i32) void {
        b.message(.NEWCHAIN, linux.NLM_F_CREATE);
        b.attrStr(nfta_chain_table, table);
        b.attrStr(nfta_chain_name, name);
        const h = b.begin(nfta_chain_hook);
        b.attrBe32(nfta_hook_hooknum, hook);
        // A negative priority (NAT's -100) goes as its two's complement, which the kernel reads
        // back as the signed value (i32 to u32: the same bits, under any @bitCast definition).
        b.attrBe32(nfta_hook_priority, @bitCast(priority));
        b.end(h);
        b.attrBe32(nfta_chain_policy, nf_accept);
        b.attrStr(nfta_chain_type, kind);
        b.endMsg();
    }

    /// Starts a rule in `chain` of `ip <tbl>`: appended with `NLM_F_APPEND`, else at the chain's
    /// head. Its expressions follow, then `endRule` with what this returns.
    fn rule(b: *Batch, tbl: []const u8, chain: []const u8, flags: u16) usize {
        b.message(.NEWRULE, linux.NLM_F_CREATE | flags);
        b.attrStr(nfta_rule_table, tbl);
        b.attrStr(nfta_rule_chain, chain);
        return b.begin(nfta_rule_expressions);
    }

    fn endRule(b: *Batch, at: usize) void {
        b.end(at);
        b.endMsg();
    }

    fn deleteRule(b: *Batch, tbl: []const u8, chain: []const u8, handle: u64) void {
        b.message(.DELRULE, 0);
        b.attrStr(nfta_rule_table, tbl);
        b.attrStr(nfta_rule_chain, chain);
        b.attrBe64(nfta_rule_handle, handle);
        b.endMsg();
    }

    /// Opens an expression; its data follows, closed by `endExpr` on what `begin(data)` gave.
    fn expr(b: *Batch, name: []const u8) void {
        b.elem = b.begin(nfta_list_elem);
        b.attrStr(nfta_expr_name, name);
    }

    fn endExpr(b: *Batch, data: usize) void {
        b.end(data);
        b.end(b.elem);
    }

    /// `meta load iifname/oifname => reg 1; cmp <op> reg 1 <name>`.
    fn ifname(b: *Batch, dir: Iface, op: CmpOp, name: []const u8) void {
        b.expr("meta");
        const d = b.begin(nfta_expr_data);
        b.attrBe32(nfta_meta_key, if (dir == .iif) nft_meta_iifname else nft_meta_oifname);
        b.attrBe32(nfta_meta_dreg, nft_reg_1);
        b.endExpr(d);
        b.cmp(op, name);
    }

    fn cmp(b: *Batch, op: CmpOp, value: []const u8) void {
        b.expr("cmp");
        const d = b.begin(nfta_expr_data);
        b.attrBe32(nfta_cmp_sreg, nft_reg_1);
        b.attrBe32(nfta_cmp_op, @backingInt(op));
        const v = b.begin(nfta_cmp_data);
        b.attr(nfta_data_value, value);
        b.end(v);
        b.endExpr(d);
    }

    fn counter(b: *Batch) void {
        b.expr("counter");
        const d = b.begin(nfta_expr_data);
        b.attrBe64(nfta_counter_bytes, 0);
        b.attrBe64(nfta_counter_packets, 0);
        b.endExpr(d);
    }

    fn verdict(b: *Batch, code: u32) void {
        b.expr("immediate");
        const d = b.begin(nfta_expr_data);
        b.attrBe32(nfta_immediate_dreg, nft_reg_verdict);
        const data = b.begin(nfta_immediate_data);
        const v = b.begin(nfta_data_verdict);
        b.attrBe32(nfta_verdict_code, code);
        b.end(v);
        b.end(data);
        b.endExpr(d);
    }

    /// `ct state established,related`: the state's bits masked, not zero.
    fn replies(b: *Batch) void {
        b.expr("ct");
        const d = b.begin(nfta_expr_data);
        b.attrBe32(nfta_ct_key, nft_ct_state);
        b.attrBe32(nfta_ct_dreg, nft_reg_1);
        b.endExpr(d);
        b.bitwise(std.mem.asBytes(&ct_established_related));
        b.cmp(.neq, &.{ 0, 0, 0, 0 });
    }

    /// `reg 1 = reg 1 & mask` (xor zero), over the mask's length.
    fn bitwise(b: *Batch, mask: []const u8) void {
        b.expr("bitwise");
        const d = b.begin(nfta_expr_data);
        b.attrBe32(nfta_bitwise_sreg, nft_reg_1);
        b.attrBe32(nfta_bitwise_dreg, nft_reg_1);
        b.attrBe32(nfta_bitwise_len, @intCast(mask.len));
        var zeros: [16]u8 = @splat(0);
        const m = b.begin(nfta_bitwise_mask);
        b.attr(nfta_data_value, mask);
        b.end(m);
        const x = b.begin(nfta_bitwise_xor);
        b.attr(nfta_data_value, zeros[0..mask.len]);
        b.end(x);
        b.endExpr(d);
    }

    /// `ip saddr <subnet>`: the source address loaded, masked, compared.
    fn sourceIn(b: *Batch, subnet: net.Subnet) void {
        b.expr("payload");
        const d = b.begin(nfta_expr_data);
        b.attrBe32(nfta_payload_dreg, nft_reg_1);
        b.attrBe32(nfta_payload_base, nft_payload_network_header);
        b.attrBe32(nfta_payload_offset, 12);
        b.attrBe32(nfta_payload_len, 4);
        b.endExpr(d);
        var mask: [4]u8 = undefined;
        std.mem.writeInt(u32, &mask, ~@as(u32, 0) << @intCast(32 - @as(u32, subnet.prefix)), .big);
        b.bitwise(&mask);
        b.cmp(.eq, &subnet.base);
    }
};

/// An nftables netlink socket in the caller's network namespace.
const Socket = struct {
    fd: linux.fd_t,
    seq: u32 = 0,

    fn open() !Socket {
        const flags = linux.SOCK.RAW | linux.SOCK.CLOEXEC;
        const rc = linux.socket(linux.AF.NETLINK, flags, linux.NETLINK.NETFILTER);
        if (linux.errno(rc) != .SUCCESS) return error.NetlinkSocket;
        const fd: linux.fd_t = @intCast(rc);
        // Never wait forever on the kernel's answer.
        const tv: linux.timeval = .{ .sec = 10, .usec = 0 };
        const tv_bytes = std.mem.asBytes(&tv);
        _ = linux.setsockopt(fd, linux.SOL.SOCKET, linux.SO.RCVTIMEO, tv_bytes, tv_bytes.len);
        return .{ .fd = fd };
    }

    fn close(s: *Socket) void {
        _ = linux.close(s.fd);
    }

    /// Reads the host's chains, then replaces the rules in one batch: its errno.
    fn replace(s: *Socket, subnet: net.Subnet, uplinks: []const []const u8) !linux.E {
        var stale_buf: [64]Stale = undefined;
        var stale: std.ArrayList(Stale) = .initBuffer(&stale_buf);
        var accept_buf: [2][]const u8 = undefined;
        var accept: std.ArrayList([]const u8) = .initBuffer(&accept_buf);
        // The iptables-nft chains to accept the jobs' traffic in, where the host has them, and
        // the runner's rules in them and in the chains where P1 put its own.
        for ([_][]const u8{ "FORWARD", "DOCKER-USER" }) |name| {
            if (try s.chain("filter", name) != null) accept.appendBounded(name) catch {};
        }
        const scanned = [_][2][]const u8{
            .{ "filter", "FORWARD" }, .{ "filter", "DOCKER-USER" },
            .{ "filter", "INPUT" },   .{ "nat", "POSTROUTING" },
        };
        for (scanned) |tc| try s.bridgeRules(tc[0], tc[1], &stale);
        var buf: [32 * 1024]u8 align(4) = undefined;
        var b: Batch = .init(&buf, s.seq);
        ruleBatch(&b, subnet, uplinks, .{ .accept_in = accept.items, .stale = stale.items });
        const bytes = b.finish();
        if (b.overflow) return error.TooManyRules;
        s.seq = b.seq + 1;
        return s.send(bytes, b.first_seq, b.seq, b.acks);
    }

    /// Sends a batch and reads one answer per message that asked for one: the first error, or
    /// `.SUCCESS` when the batch was committed.
    fn send(s: *Socket, bytes: []const u8, first: u32, last: u32, acks: u32) !linux.E {
        const sent = linux.sendto(s.fd, bytes.ptr, bytes.len, 0, null, 0);
        if (linux.errno(sent) != .SUCCESS) return linux.errno(sent);
        var result: linux.E = .SUCCESS;
        var got: u32 = 0;
        var buf: [16 * 1024]u8 align(4) = undefined;
        while (got < acks) {
            const n = linux.recvfrom(s.fd, &buf, buf.len, 0, null, null);
            if (linux.errno(n) == .INTR) continue;
            if (linux.errno(n) != .SUCCESS) return error.NoAnswer;
            var it: Messages = .{ .buf = buf[0..n] };
            while (it.next()) |m| {
                if (m.hdr.seq < first or m.hdr.seq > last) continue;
                if (m.hdr.type != @backingInt(linux.NetlinkMessageType.ERROR)) continue;
                got += 1;
                const e = errorOf(m.body);
                if (result == .SUCCESS and e != .SUCCESS) result = e;
            }
        }
        return result;
    }

    const ChainInfo = struct { policy: ?u32 };

    /// The chain `name` of `ip <tbl>`, or null when the host has no such table or chain.
    fn chain(s: *Socket, tbl: []const u8, name: []const u8) !?ChainInfo {
        var buf: [256]u8 align(4) = undefined;
        var b: Batch = .{ .buf = &buf, .seq = s.seq, .first_seq = s.seq };
        b.start(msgType(.GETCHAIN), linux.NLM_F_REQUEST | linux.NLM_F_ACK);
        b.put(GenMsg, .{ .family = nfproto_ipv4 });
        b.attrStr(nfta_chain_table, tbl);
        b.attrStr(nfta_chain_name, name);
        b.endMsg();
        s.seq = b.seq + 1;
        const sent = linux.sendto(s.fd, &buf, b.len, 0, null, 0);
        if (linux.errno(sent) != .SUCCESS) return error.NetlinkSend;
        var info: ?ChainInfo = null;
        var rbuf: [16 * 1024]u8 align(4) = undefined;
        while (true) {
            const n = linux.recvfrom(s.fd, &rbuf, rbuf.len, 0, null, null);
            if (linux.errno(n) == .INTR) continue;
            if (linux.errno(n) != .SUCCESS) return error.NoAnswer;
            var it: Messages = .{ .buf = rbuf[0..n] };
            while (it.next()) |m| {
                if (m.hdr.seq != b.seq) continue;
                if (m.hdr.type == @backingInt(linux.NetlinkMessageType.ERROR)) {
                    return switch (errorOf(m.body)) {
                        .SUCCESS => info,
                        .NOENT => null,
                        else => |e| {
                            std.log.debug("nftables: get chain {s}: {s}", .{ name, @tagName(e) });
                            return error.Netlink;
                        },
                    };
                }
                var c: ChainInfo = .{ .policy = null };
                var attrs: Attrs = .{ .buf = m.body[@min(m.body.len, @sizeOf(GenMsg))..] };
                while (attrs.next()) |a| if (a.type == nfta_chain_policy and a.data.len == 4) {
                    c.policy = std.mem.readInt(u32, a.data[0..4], .big);
                };
                info = c;
            }
        }
    }

    /// Adds to `out` every rule of `ip <tbl> <chain>` that matches an interface named as the
    /// bridge: the runner's, made by this or by P1. Nothing when the host has no such chain.
    fn bridgeRules(
        s: *Socket,
        tbl: []const u8,
        name: []const u8,
        out: *std.ArrayList(Stale),
    ) !void {
        var buf: [256]u8 align(4) = undefined;
        var b: Batch = .{ .buf = &buf, .seq = s.seq, .first_seq = s.seq };
        b.start(msgType(.GETRULE), linux.NLM_F_REQUEST | linux.NLM_F_DUMP);
        b.put(GenMsg, .{ .family = nfproto_ipv4 });
        b.attrStr(nfta_rule_table, tbl);
        b.attrStr(nfta_rule_chain, name);
        b.endMsg();
        s.seq = b.seq + 1;
        const sent = linux.sendto(s.fd, &buf, b.len, 0, null, 0);
        if (linux.errno(sent) != .SUCCESS) return error.NetlinkSend;
        var rbuf: [64 * 1024]u8 align(4) = undefined;
        while (true) {
            const n = linux.recvfrom(s.fd, &rbuf, rbuf.len, 0, null, null);
            if (linux.errno(n) == .INTR) continue;
            if (linux.errno(n) != .SUCCESS) return error.NoAnswer;
            var it: Messages = .{ .buf = rbuf[0..n] };
            while (it.next()) |m| {
                if (m.hdr.seq != b.seq) continue;
                if (m.hdr.type == @backingInt(linux.NetlinkMessageType.DONE)) return;
                if (m.hdr.type == @backingInt(linux.NetlinkMessageType.ERROR)) {
                    return switch (errorOf(m.body)) {
                        .SUCCESS, .NOENT => {},
                        else => error.Netlink,
                    };
                }
                if (ruleNamesBridge(m.body)) |handle| out.appendBounded(.{
                    .table = tbl,
                    .chain = name,
                    .handle = handle,
                }) catch return error.TooManyRules;
            }
        }
    }
};

/// The handle of a dumped rule (a NEWRULE message's body) when one of its expressions compares
/// an interface name with the bridge's; null otherwise.
fn ruleNamesBridge(body: []const u8) ?u64 {
    var handle: ?u64 = null;
    var names = false;
    var attrs: Attrs = .{ .buf = body[@min(body.len, @sizeOf(GenMsg))..] };
    while (attrs.next()) |a| switch (a.type) {
        nfta_rule_handle => if (a.data.len == 8) {
            handle = std.mem.readInt(u64, a.data[0..8], .big);
        },
        nfta_rule_expressions => {
            var elems: Attrs = .{ .buf = a.data };
            while (elems.next()) |e| names = names or exprNamesBridge(e.data);
        },
        else => {},
    };
    return if (names) handle else null;
}

fn exprNamesBridge(elem: []const u8) bool {
    var name: []const u8 = "";
    var data: []const u8 = "";
    var attrs: Attrs = .{ .buf = elem };
    while (attrs.next()) |a| switch (a.type) {
        nfta_expr_name => name = std.mem.sliceTo(a.data, 0),
        nfta_expr_data => data = a.data,
        else => {},
    };
    if (!std.mem.eql(u8, name, "cmp")) return false;
    var cmp_attrs: Attrs = .{ .buf = data };
    while (cmp_attrs.next()) |a| if (a.type == nfta_cmp_data) {
        var values: Attrs = .{ .buf = a.data };
        while (values.next()) |v| if (v.type == nfta_data_value) {
            // iptables' exact match, or nft's whole IFNAMSIZ with zeros.
            if (v.data.len >= bridge_name.len and v.data.len <= 16 and
                std.mem.startsWith(u8, v.data, bridge_name) and
                std.mem.allEqual(u8, v.data[bridge_name.len..], 0)) return true;
        };
    };
    return false;
}

fn errorOf(body: []const u8) linux.E {
    if (body.len < 4) return .INVAL;
    const code = std.mem.readInt(i32, body[0..4], builtin.cpu.arch.endian());
    if (code == 0) return .SUCCESS;
    return @fromBackingInt(@intCast(@as(u16, @intCast(-code))));
}

const Message = struct { hdr: Header, body: []const u8 };

/// The messages in one read from a netlink socket.
const Messages = struct {
    buf: []const u8,
    off: usize = 0,

    fn next(it: *Messages) ?Message {
        if (it.off + @sizeOf(Header) > it.buf.len) return null;
        const hdr = std.mem.bytesToValue(Header, it.buf[it.off..][0..@sizeOf(Header)]);
        if (hdr.len < @sizeOf(Header) or it.off + hdr.len > it.buf.len) return null;
        const body = it.buf[it.off + @sizeOf(Header) .. it.off + hdr.len];
        it.off += std.mem.alignForward(usize, hdr.len, 4);
        return .{ .hdr = hdr, .body = body };
    }
};

/// The attributes in a netlink payload (nested ones are read the same way from `data`).
const Attrs = struct {
    buf: []const u8,
    off: usize = 0,

    fn next(it: *Attrs) ?struct { type: u16, data: []const u8 } {
        if (it.off + @sizeOf(Attr) > it.buf.len) return null;
        const a = std.mem.bytesToValue(Attr, it.buf[it.off..][0..@sizeOf(Attr)]);
        if (a.len < @sizeOf(Attr) or it.off + a.len > it.buf.len) return null;
        const data = it.buf[it.off + @sizeOf(Attr) .. it.off + a.len];
        it.off += std.mem.alignForward(usize, a.len, 4);
        return .{ .type = a.type & ~@as(u16, nla_f_nested), .data = data };
    }
};

// --- tests ---

test "a dumped rule that names the bridge is the runner's; others are left alone" {
    var buf: [2048]u8 align(4) = undefined;
    for ([_]struct { name: []const u8, ours: bool }{
        .{ .name = bridge_name, .ours = true },
        .{ .name = "zr0\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00", .ours = true },
        .{ .name = "docker0\x00", .ours = false },
        .{ .name = "xzr0\x00", .ours = false },
        .{ .name = "zr0", .ours = false },
        .{ .name = "zr01\x00", .ours = false },
    }) |case| {
        var b: Batch = .{ .buf = &buf, .seq = 0, .first_seq = 0 };
        b.put(GenMsg, .{ .family = nfproto_ipv4 });
        b.attrStr(nfta_rule_table, "filter");
        b.attrBe64(nfta_rule_handle, 42);
        const r = b.begin(nfta_rule_expressions);
        b.ifname(.iif, .eq, case.name);
        b.counter();
        b.verdict(nf_accept);
        b.end(r);
        try std.testing.expect(!b.overflow);
        const got = ruleNamesBridge(buf[0..b.len]);
        try std.testing.expectEqual(if (case.ours) @as(?u64, 42) else null, got);
    }
}

test "the batch: begin, every message acknowledged, end, within its buffer" {
    var buf: [32 * 1024]u8 align(4) = undefined;
    var b: Batch = .init(&buf, 100);
    const stale = [_]Stale{.{ .table = "filter", .chain = "FORWARD", .handle = 7 }};
    ruleBatch(&b, net.Subnet.default, &.{ "eth0", "wlp0s20f3" }, .{
        .accept_in = &.{ "FORWARD", "DOCKER-USER" },
        .stale = &stale,
    });
    const bytes = b.finish();
    try std.testing.expect(!b.overflow);
    var it: Messages = .{ .buf = bytes };
    var types: std.ArrayList(u16) = .empty;
    defer types.deinit(std.testing.allocator);
    while (it.next()) |m| try types.append(std.testing.allocator, m.hdr.type);
    try std.testing.expectEqual(@as(u16, nfnl_msg_batch_begin), types.items[0]);
    try std.testing.expectEqual(@as(u16, nfnl_msg_batch_end), types.getLast());
    // 3 table messages, 4 chains, 2 uplinks' accepts and 8 more rules of ours, 1 removal, and 2
    // accepts in each of the host's 2 chains.
    try std.testing.expectEqual(@as(u32, 3 + 4 + 10 + 1 + 4), b.acks);
    try std.testing.expectEqual(@as(usize, b.acks + 2), types.items.len);
}
