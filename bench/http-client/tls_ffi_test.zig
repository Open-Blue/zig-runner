//! Drives the sans-IO rustls shim over a raw socket the way pg.zig would after its SSLRequest:
//! tls_ffi_test <port> <ca.pem> [client.pem client-key.pem]  -> prints the HTTP status line.
const std = @import("std");
const linux = std.os.linux;
const Tls = opaque {};
extern fn zr_tls_new(h: [*]const u8, hl: usize, ca: [*]const u8, cal: usize, c: [*]const u8, cl: usize, k: [*]const u8, kl: usize) ?*Tls;
extern fn zr_tls_free(t: *Tls) void;
extern fn zr_tls_wants_write(t: *Tls) i32;
extern fn zr_tls_is_handshaking(t: *Tls) i32;
extern fn zr_tls_take_cipher(t: *Tls, out: [*]u8, cap: usize) isize;
extern fn zr_tls_give_cipher(t: *Tls, inp: [*]const u8, len: usize) isize;
extern fn zr_tls_read(t: *Tls, out: [*]u8, cap: usize) isize;
extern fn zr_tls_write(t: *Tls, inp: [*]const u8, len: usize) isize;

fn readFile(io: std.Io, gpa: std.mem.Allocator, path: []const u8) ![]u8 {
    return std.Io.Dir.cwd().readFileAlloc(io, path, gpa, .limited(1 << 20));
}
fn flushCipher(t: *Tls, fd: i32) !void {
    var b: [16 * 1024]u8 = undefined;
    while (zr_tls_wants_write(t) != 0) {
        const n = zr_tls_take_cipher(t, &b, b.len);
        if (n <= 0) return;
        var off: usize = 0;
        while (off < @as(usize, @intCast(n))) {
            const w = linux.write(fd, b[off..].ptr, @as(usize, @intCast(n)) - off);
            if (@as(isize, @bitCast(w)) < 0) return error.Write;
            off += w;
        }
    }
}
fn pump(t: *Tls, fd: i32) !void { // read one chunk of ciphertext from the socket into rustls
    var b: [16 * 1024]u8 = undefined;
    const r = linux.read(fd, &b, b.len);
    const n: isize = @bitCast(r);
    if (n <= 0) return error.Eof;
    if (zr_tls_give_cipher(t, &b, @intCast(n)) < 0) return error.TlsError;
}

pub fn main(init: std.process.Init) !void {
    const gpa = init.gpa;
    const io = init.io;
    var args = try init.minimal.args.iterateAllocator(gpa);
    _ = args.next();
    const port = try std.fmt.parseInt(u16, args.next().?, 10);
    const ca = try readFile(io, gpa, args.next().?);
    var cert: []u8 = &.{};
    var key: []u8 = &.{};
    if (args.next()) |c| {
        cert = try readFile(io, gpa, c);
        key = try readFile(io, gpa, args.next().?);
    }
    const fd: i32 = @intCast(linux.socket(linux.AF.INET, linux.SOCK.STREAM, 0));
    var addr: linux.sockaddr.in = .{ .port = std.mem.nativeToBig(u16, port), .addr = std.mem.nativeToBig(u32, 0x7f000001) };
    if (linux.connect(fd, @ptrCast(&addr), @sizeOf(@TypeOf(addr))) != 0) return error.Connect;
    // pg.zig would send SSLRequest and read 'S' here, in plaintext, on the same fd.
    const t = zr_tls_new("localhost", 9, ca.ptr, ca.len, cert.ptr, cert.len, key.ptr, key.len) orelse return error.TlsConfig;
    defer zr_tls_free(t);
    const req = "GET /json HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n";
    _ = zr_tls_write(t, req, req.len); // queued: sent after the handshake
    var out: [4096]u8 = undefined;
    var got: usize = 0;
    while (true) {
        try flushCipher(t, fd);
        pump(t, fd) catch |e| if (got > 0) break else return e;
        const n = zr_tls_read(t, &out, out.len);
        if (n > 0) got += @intCast(n);
        if (got >= 12) break;
    }
    std.debug.print("ok: {s}\n", .{out[0..@min(got, 15)]});
}
