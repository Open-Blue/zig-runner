//! TLS over an `Io.Reader` and `Io.Writer` pair, by the network library's sans-IO rustls
//! (`rust/zr-net/src/tls.rs`, docs/rust-net.md): this file keeps the socket, so the reads and
//! writes below are std.Io's, and a cancelled or timed-out one ends the connection where it blocks.
//! Rust only turns ciphertext into plaintext and back. Used by `pg.zig` after its SSLRequest.
const std = @import("std");
const Io = std.Io;

const Handle = opaque {};

const CConfig = extern struct {
    host: [*]const u8,
    host_len: usize,
    roots: [*]const u8,
    roots_len: usize,
    cert: [*]const u8,
    cert_len: usize,
    key: [*]const u8,
    key_len: usize,
    flags: u32,
};

extern fn zr_net_tls_new(cfg: *const CConfig, out: *?*Handle, msg: [*]u8, msg_cap: usize) i32;
extern fn zr_net_tls_free(t: ?*Handle) void;
extern fn zr_net_tls_wants_write(t: *Handle) i32;
extern fn zr_net_tls_is_handshaking(t: *Handle) i32;
extern fn zr_net_tls_take_cipher(t: *Handle, out: [*]u8, cap: usize) isize;
extern fn zr_net_tls_give_cipher(t: *Handle, inp: [*]const u8, len: usize) isize;
extern fn zr_net_tls_read(t: *Handle, out: [*]u8, cap: usize) isize;
extern fn zr_net_tls_write(t: *Handle, inp: [*]const u8, len: usize) isize;
extern fn zr_net_tls_close_notify(t: *Handle) void;
extern fn zr_net_tls_error(t: *Handle, msg: [*]u8, msg_cap: usize) i32;

/// What went wrong, as the library classifies it (`tls::Kind`).
pub const Kind = enum(i32) {
    none = 0,
    config = 1,
    unknown_issuer = 2,
    expired = 3,
    name_mismatch = 4,
    certificate = 5,
    alert = 6,
    protocol = 7,
    eof = 8,
    _,
};

pub const Config = struct {
    host: []const u8,
    /// Check the server's certificate (chain and name). False: encrypt only.
    verify: bool = true,
    /// PEM roots that replace the system's; empty: the system's (`SSL_CERT_FILE`, `SSL_CERT_DIR`).
    roots_pem: []const u8 = "",
    /// The client's certificate chain and key, PEM; empty: none (a server that asks is told so).
    cert_pem: []const u8 = "",
    key_pem: []const u8 = "",
};

pub const Error = error{
    /// The configuration: bad PEM, no roots, a key that does not match its certificate.
    TlsConfig,
    /// The handshake or the records failed; `Stream.kind` and `message()` say why.
    TlsFailed,
    /// The socket ended, failed or was cancelled.
    ConnectionClosed,
};

/// The size of the ciphertext moved at once: a TLS record and its overhead.
const chunk_len = 17 * 1024;

pub const Stream = struct {
    handle: *Handle,
    sock_r: *Io.Reader,
    sock_w: *Io.Writer,
    kind: Kind = .none,
    msg_buf: [256]u8 = @splat(0),
    reader: Reader = undefined,
    writer: Writer = undefined,

    /// The plaintext side: what the caller reads and writes, with `plain_r` and `plain_w` as buffers.
    /// Runs the handshake first. `s` must not move afterwards (the reader and writer point into it).
    pub fn open(s: *Stream, sock_r: *Io.Reader, sock_w: *Io.Writer, cfg: Config, plain_r: []u8, plain_w: []u8) Error!void {
        var c: CConfig = .{
            .host = cfg.host.ptr,
            .host_len = cfg.host.len,
            .roots = cfg.roots_pem.ptr,
            .roots_len = cfg.roots_pem.len,
            .cert = cfg.cert_pem.ptr,
            .cert_len = cfg.cert_pem.len,
            .key = cfg.key_pem.ptr,
            .key_len = cfg.key_pem.len,
            .flags = if (cfg.verify) 1 else 0,
        };
        var handle: ?*Handle = null;
        var msg: [256]u8 = @splat(0);
        const rc = zr_net_tls_new(&c, &handle, &msg, msg.len);
        if (rc != 0) {
            s.* = undefined;
            s.kind = std.enums.fromInt(Kind, rc) orelse .protocol;
            s.msg_buf = msg;
            return error.TlsConfig;
        }
        s.* = .{ .handle = handle.?, .sock_r = sock_r, .sock_w = sock_w };
        errdefer zr_net_tls_free(s.handle);
        s.reader = .{ .stream = s, .interface = .{
            .vtable = &.{ .stream = Reader.streamFn },
            .buffer = plain_r,
            .seek = 0,
            .end = 0,
        } };
        s.writer = .{ .stream = s, .interface = .{
            .vtable = &.{ .drain = Writer.drain },
            .buffer = plain_w,
            .end = 0,
        } };
        try s.handshake();
    }

    pub fn close(s: *Stream) void {
        zr_net_tls_close_notify(s.handle);
        s.sendCipher() catch |e| std.log.debug("tls: the close was not sent: {t}", .{e});
        zr_net_tls_free(s.handle);
    }

    /// The text of the last error, for the log.
    pub fn message(s: *const Stream) []const u8 {
        return std.mem.sliceTo(&s.msg_buf, 0);
    }

    fn fail(s: *Stream) Error {
        s.kind = std.enums.fromInt(Kind, zr_net_tls_error(s.handle, &s.msg_buf, s.msg_buf.len)) orelse .protocol;
        // The alert the library owes the peer, best effort.
        s.sendCipher() catch |e| std.log.debug("tls: the alert was not sent: {t}", .{e});
        return error.TlsFailed;
    }

    fn handshake(s: *Stream) Error!void {
        while (true) {
            try s.sendCipher();
            if (zr_net_tls_is_handshaking(s.handle) == 0) return;
            try s.receiveCipher();
        }
    }

    /// Ciphertext the library has ready, to the socket, flushed.
    fn sendCipher(s: *Stream) Error!void {
        var buf: [chunk_len]u8 = undefined;
        var sent = false;
        while (zr_net_tls_wants_write(s.handle) != 0) {
            const n = zr_net_tls_take_cipher(s.handle, &buf, buf.len);
            if (n < 0) return s.fail();
            if (n == 0) break;
            s.sock_w.writeAll(buf[0..@abs(n)]) catch return error.ConnectionClosed;
            sent = true;
        }
        if (sent) s.sock_w.flush() catch return error.ConnectionClosed;
    }

    /// Waits for ciphertext from the socket and gives it to the library: what it took is consumed.
    fn receiveCipher(s: *Stream) Error!void {
        const data = s.sock_r.peekGreedy(1) catch return error.ConnectionClosed;
        const n = zr_net_tls_give_cipher(s.handle, data.ptr, data.len);
        if (n < 0) return s.fail();
        // Nothing taken from a full buffer is a library that will not read more until its plaintext
        // is read: the callers read plaintext first, so this is a stuck state, not progress.
        if (n == 0) return s.fail();
        s.sock_r.toss(@abs(n));
    }

    fn readPlain(s: *Stream, out: []u8) Error!usize {
        while (true) {
            const n = zr_net_tls_read(s.handle, out.ptr, out.len);
            if (n > 0) return @abs(n);
            if (n == -2) return 0;
            if (n < 0) return s.fail();
            // Nothing yet: what the library owes the peer (key updates, alerts) goes first.
            try s.sendCipher();
            try s.receiveCipher();
        }
    }

    fn writePlain(s: *Stream, bytes: []const u8) Error!void {
        var off: usize = 0;
        while (off < bytes.len) {
            const n = zr_net_tls_write(s.handle, bytes.ptr + off, bytes.len - off);
            if (n < 0) return s.fail();
            off += @abs(n);
            // Every record is written through as it is sealed, as the caller's flush expects.
            try s.sendCipher();
        }
    }

    pub const Reader = struct {
        stream: *Stream,
        interface: Io.Reader,
        err: ?Error = null,

        fn streamFn(r: *Io.Reader, w: *Io.Writer, limit: Io.Limit) Io.Reader.StreamError!usize {
            const self: *Reader = @fieldParentPtr("interface", r);
            const buf = limit.slice(try w.writableSliceGreedy(1));
            const n = self.stream.readPlain(buf) catch |e| {
                self.err = e;
                return error.ReadFailed;
            };
            if (n == 0) return error.EndOfStream;
            w.advance(n);
            return n;
        }
    };

    pub const Writer = struct {
        stream: *Stream,
        interface: Io.Writer,
        err: ?Error = null,

        fn writeAll(self: *Writer, bytes: []const u8) Io.Writer.Error!void {
            self.stream.writePlain(bytes) catch |e| {
                self.err = e;
                return error.WriteFailed;
            };
        }

        fn drain(w: *Io.Writer, data: []const []const u8, splat: usize) Io.Writer.Error!usize {
            const self: *Writer = @fieldParentPtr("interface", w);
            try self.writeAll(w.buffered());
            w.end = 0;
            if (data.len == 0) return 0;
            var n: usize = 0;
            for (data[0 .. data.len - 1]) |bytes| {
                try self.writeAll(bytes);
                n += bytes.len;
            }
            const pattern = data[data.len - 1];
            for (0..splat) |_| {
                try self.writeAll(pattern);
                n += pattern.len;
            }
            return n;
        }
    };
};

/// A client connection whose server is the fuzz target ("TLS records", fuzz.zig): bytes go in as the
/// server's, in any chunks, and nothing comes out but whether the library kept going.
pub const Probe = struct {
    handle: *Handle,

    pub fn init(cfg: Config) ?Probe {
        var c: CConfig = .{
            .host = cfg.host.ptr,
            .host_len = cfg.host.len,
            .roots = cfg.roots_pem.ptr,
            .roots_len = cfg.roots_pem.len,
            .cert = cfg.cert_pem.ptr,
            .cert_len = cfg.cert_pem.len,
            .key = cfg.key_pem.ptr,
            .key_len = cfg.key_pem.len,
            .flags = if (cfg.verify) 1 else 0,
        };
        var handle: ?*Handle = null;
        var msg: [64]u8 = undefined;
        if (zr_net_tls_new(&c, &handle, &msg, msg.len) != 0) return null;
        return .{ .handle = handle.? };
    }

    pub fn deinit(p: Probe) void {
        zr_net_tls_free(p.handle);
    }

    /// The client's own bytes out (its hello, alerts), what a peer would read; and the plaintext, if
    /// any. Returns false once the library has reported an error: the connection is over.
    pub fn drain(p: Probe) bool {
        var buf: [chunk_len]u8 = undefined;
        while (zr_net_tls_wants_write(p.handle) != 0) {
            const n = zr_net_tls_take_cipher(p.handle, &buf, buf.len);
            if (n <= 0) break;
        }
        while (true) {
            const n = zr_net_tls_read(p.handle, &buf, buf.len);
            if (n > 0) continue;
            return n >= 0 or n == -2;
        }
    }

    /// Gives `bytes` as the server's, taking what the library does not hold back in as many calls as
    /// it takes. False: an error, or a library that stopped taking input without saying why.
    pub fn feed(p: Probe, bytes: []const u8) bool {
        var rest = bytes;
        while (rest.len > 0) {
            const n = zr_net_tls_give_cipher(p.handle, rest.ptr, rest.len);
            if (n < 0) return false;
            if (n == 0) {
                // Plaintext is waiting to be read first.
                if (!p.drain()) return false;
                const again = zr_net_tls_give_cipher(p.handle, rest.ptr, rest.len);
                if (again <= 0) return false;
                rest = rest[@abs(again)..];
                continue;
            }
            rest = rest[@abs(n)..];
        }
        return p.drain();
    }
};
