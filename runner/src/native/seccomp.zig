//! A step's seccomp filter (docs/native-backend.md, P5): Docker's default profile as Docker applies
//! it to a container with its default capabilities, an allow list. A call it does not name fails
//! with EPERM, and a call newer than any it names fails with ENOSYS, as runc makes it, so a C
//! library falls back to an older one. Its argument conditions are kept: `clone` without namespace
//! flags, `clone3` as ENOSYS (its flags are in memory, out of a filter's reach, so the C library
//! falls back to `clone`), `personality` with Docker's five values only, and `socket` with the
//! address families Docker allows.
//!
//! The profile is moby/profiles' `seccomp/default.json` at 6fe7deb1b9fb (2026-09-17). Its
//! capability-gated rules are applied as for Docker's default capabilities (`sandbox.docker_caps`):
//! of them only `chroot` (CAP_SYS_CHROOT) is allowed; `ptrace` and `process_vm_*` are allowed as
//! Docker allows them on Linux 4.8 and later. Calls are named here and numbered per architecture
//! from std's tables (`std.os.linux.syscalls`), for x86_64 and aarch64, so the filter of each is
//! built and tested on either.
//!
//! The filter runs on the step's every system call, so it is built as ranges: the allowed numbers,
//! sorted, make a few dozen runs, and a call is two comparisons per run until its own.

const std = @import("std");
const builtin = @import("builtin");
const linux = std.os.linux;

pub const Arch = enum { x86_64, aarch64 };

/// The names in `text`, split at whitespace: the profile's lists, kept as compact as Docker's.
fn words(comptime text: []const u8) []const []const u8 {
    @setEvalBranchQuota(100_000);
    comptime var out: []const []const u8 = &.{};
    comptime var it = std.mem.tokenizeAny(u8, text, " \n");
    inline while (comptime it.next()) |w| out = out ++ .{w};
    return out;
}

pub const native: Arch = switch (builtin.cpu.arch) {
    .x86_64 => .x86_64,
    .aarch64 => .aarch64,
    else => @compileError("the native backend's seccomp filter knows x86_64 and aarch64"),
};

/// Installs the filter for this machine's architecture in the calling thread: the result of
/// `prctl(PR_SET_SECCOMP)`, for the caller to check.
pub fn install() usize {
    const prog = comptime program(native);
    const fprog: extern struct { len: u16, filter: [*]const SockFilter } = .{
        .len = @intCast(prog.len),
        .filter = prog.ptr,
    };
    return linux.prctl(
        @backingInt(linux.PR.SET_SECCOMP),
        linux.SECCOMP.MODE.FILTER,
        @intFromPtr(&fprog),
        0,
        0,
    );
}

/// The calls Docker's profile allows unconditionally (its first rule, verbatim). Names an
/// architecture does not have are skipped.
const allowed = words(
    \\accept accept4 access adjtimex alarm bind brk cachestat capget capset chdir chmod chown
    \\chown32 clock_adjtime clock_adjtime64 clock_getres clock_getres_time64 clock_gettime
    \\clock_gettime64 clock_nanosleep clock_nanosleep_time64 close close_range connect
    \\copy_file_range creat dup dup2 dup3 epoll_create epoll_create1 epoll_ctl epoll_ctl_old
    \\epoll_pwait epoll_pwait2 epoll_wait epoll_wait_old eventfd eventfd2 execve execveat exit
    \\exit_group faccessat faccessat2 fadvise64 fadvise64_64 fallocate fanotify_mark fchdir fchmod
    \\fchmodat fchmodat2 fchown fchown32 fchownat fcntl fcntl64 fdatasync fgetxattr flistxattr
    \\flock fork fremovexattr fsetxattr fstat fstat64 fstatat64 fstatfs fstatfs64 fsync ftruncate
    \\ftruncate64 futex futex_requeue futex_time64 futex_wait futex_waitv futex_wake futimesat
    \\getcpu getcwd getdents getdents64 getegid getegid32 geteuid geteuid32 getgid getgid32
    \\getgroups getgroups32 getitimer getpeername getpgid getpgrp getpid getppid getpriority
    \\getrandom getresgid getresgid32 getresuid getresuid32 getrlimit get_robust_list getrusage
    \\getsid getsockname getsockopt get_thread_area gettid gettimeofday getuid getuid32 getxattr
    \\getxattrat inotify_add_watch inotify_init inotify_init1 inotify_rm_watch io_cancel ioctl
    \\io_destroy io_getevents io_pgetevents io_pgetevents_time64 ioprio_get ioprio_set io_setup
    \\io_submit ipc kill landlock_add_rule landlock_create_ruleset landlock_restrict_self lchown
    \\lchown32 lgetxattr link linkat listen listmount listxattr listxattrat llistxattr _llseek
    \\lremovexattr lseek lsetxattr lstat lstat64 madvise map_shadow_stack membarrier memfd_create
    \\memfd_secret mincore mkdir mkdirat mknod mknodat mlock mlock2 mlockall mmap mmap2 mprotect
    \\mq_getsetattr mq_notify mq_open mq_timedreceive mq_timedreceive_time64 mq_timedsend
    \\mq_timedsend_time64 mq_unlink mremap mseal msgctl msgget msgrcv msgsnd msync munlock
    \\munlockall munmap name_to_handle_at nanosleep newfstatat _newselect open openat openat2
    \\pause pidfd_open pidfd_send_signal pipe pipe2 pkey_alloc pkey_free pkey_mprotect poll ppoll
    \\ppoll_time64 prctl pread64 preadv preadv2 prlimit64 process_mrelease pselect6
    \\pselect6_time64 pwrite64 pwritev pwritev2 read readahead readlink readlinkat readv recv
    \\recvfrom recvmmsg recvmmsg_time64 recvmsg remap_file_pages removexattr removexattrat rename
    \\renameat renameat2 restart_syscall riscv_hwprobe rmdir rseq rt_sigaction rt_sigpending
    \\rt_sigprocmask rt_sigqueueinfo rt_sigreturn rt_sigsuspend rt_sigtimedwait
    \\rt_sigtimedwait_time64 rt_tgsigqueueinfo sched_getaffinity sched_getattr sched_getparam
    \\sched_get_priority_max sched_get_priority_min sched_getscheduler sched_rr_get_interval
    \\sched_rr_get_interval_time64 sched_setaffinity sched_setattr sched_setparam
    \\sched_setscheduler sched_yield seccomp select semctl semget semop semtimedop
    \\semtimedop_time64 send sendfile sendfile64 sendmmsg sendmsg sendto setfsgid setfsgid32
    \\setfsuid setfsuid32 setgid setgid32 setgroups setgroups32 setitimer setpgid setpriority
    \\setregid setregid32 setresgid setresgid32 setresuid setresuid32 setreuid setreuid32
    \\setrlimit set_robust_list setsid setsockopt set_thread_area set_tid_address setuid setuid32
    \\setxattr setxattrat shmat shmctl shmdt shmget shutdown sigaltstack signalfd signalfd4
    \\sigprocmask sigreturn socketcall socketpair splice stat stat64 statfs statfs64 statmount
    \\statx symlink symlinkat sync sync_file_range syncfs sysinfo tee tgkill time timer_create
    \\timer_delete timer_getoverrun timer_gettime timer_gettime64 timer_settime timer_settime64
    \\timerfd_create timerfd_gettime timerfd_gettime64 timerfd_settime timerfd_settime64 times
    \\tkill truncate truncate64 ugetrlimit umask uname unlink unlinkat uretprobe utime utimensat
    \\utimensat_time64 utimes vfork vmsplice wait4 waitid waitpid write writev
);

/// Allowed besides, from the profile's other rules: what Linux 4.8 and later may have
/// (`ptrace`, made safe by seccomp's recheck after a tracer's change), what Docker's default
/// capabilities allow (`chroot`, CAP_SYS_CHROOT), and each architecture's own calls.
const allowed_also = [_][]const u8{ "ptrace", "process_vm_readv", "process_vm_writev", "chroot" };
const allowed_x86_64 = [_][]const u8{ "arch_prctl", "modify_ldt" };
const allowed_aarch64 = [_][]const u8{
    "arm_fadvise64_64", "arm_sync_file_range", "sync_file_range2", "breakpoint", "cacheflush",
    "set_tls",
};

/// Every other call the profile names: those behind a capability a default container lacks, and
/// those with conditions (below). With `allowed`, they set the number past which a call is newer
/// than the profile (`max_known`).
const named_otherwise = words(
    \\acct arch_prctl arm_fadvise64_64 arm_sync_file_range bpf breakpoint cacheflush chroot
    \\clock_settime clock_settime64 clone clone3 delete_module fanotify_init finit_module fsconfig
    \\fsmount fsopen fspick get_mempolicy init_module ioperm iopl kcmp lookup_dcookie
    \\lsm_get_self_attr lsm_list_modules lsm_set_self_attr mbind modify_ldt mount mount_setattr
    \\move_mount open_by_handle_at open_tree perf_event_open personality pidfd_getfd
    \\process_madvise process_vm_readv process_vm_writev ptrace quotactl quotactl_fd reboot
    \\riscv_flush_icache s390_pci_mmio_read s390_pci_mmio_write s390_runtime_instr set_mempolicy
    \\set_mempolicy_home_node set_tls setdomainname sethostname setns settimeofday socket stime
    \\swapcontext sync_file_range2 syslog umount umount2 unshare vhangup
);

/// `personality`'s arguments Docker's profile allows: PER_LINUX, PER_LINUX32, UNAME26,
/// UNAME26 | PER_LINUX32, and 0xffffffff, which asks for the current one.
pub const allowed_personalities = [_]u32{ 0x0, 0x8, 0x20000, 0x20008, 0xffffffff };

/// `socket`'s address families Docker's profile allows: below 3 (AF_UNSPEC, AF_UNIX, AF_INET),
/// and these. Not AF_AX25, AF_IPX, AF_APPLETALK, AF_NETROM, AF_ROSE, AF_DECnet, AF_NETBEUI,
/// AF_SECURITY, AF_KEY's neighbours, AF_ALG, AF_NFC, AF_VSOCK and the like.
pub const allowed_families = [_]u32{
    7,  8,  9,  10, 13, 14, 15, 16, 17, 18, 21, 22, 24, 26, 27, 28, 29, 30, 31, 32, 33, 35, 36,
    39, 41, 42, 43, 44, 45,
};

/// clone's flags that make namespaces (NEWNS, NEWCGROUP, NEWUTS, NEWIPC, NEWUSER, NEWPID, NEWNET):
/// the profile allows `clone` only without any of them.
pub const clone_namespace_flags: u32 = 0x7E020000;

/// What the filter answers: allow, or fail with an errno.
pub const ret_allow: u32 = 0x7fff0000;
pub const ret_errno: u32 = 0x00050000;
pub const ret_eperm: u32 = ret_errno | 1;
pub const ret_enosys: u32 = ret_errno | 38;

/// `AUDIT_ARCH_X86_64` and `AUDIT_ARCH_AARCH64` (std's `AUDIT.ARCH` does not compile in 0.17).
pub fn auditArch(arch: Arch) u32 {
    return switch (arch) {
        .x86_64 => 0xC000003E,
        .aarch64 => 0xC00000B7,
    };
}

fn Table(comptime arch: Arch) type {
    return switch (arch) {
        .x86_64 => linux.syscalls.X64,
        .aarch64 => linux.syscalls.Arm64,
    };
}

/// `name`'s number on `arch`, or null when it has no such call.
pub fn number(comptime arch: Arch, comptime name: []const u8) ?u32 {
    const T = Table(arch);
    if (!@hasField(T, name)) return null;
    return @intCast(@backingInt(@field(T, name)));
}

/// The highest number of any call the profile names on `arch`: one above it is newer than the
/// profile, and gets ENOSYS.
pub fn maxKnown(comptime arch: Arch) u32 {
    return comptime max: {
        @setEvalBranchQuota(200_000);
        var max: u32 = 0;
        for (allowed ++ named_otherwise) |name| {
            if (number(arch, name)) |nr| max = @max(max, nr);
        }
        break :max max;
    };
}

/// The allowed numbers on `arch` (the conditional calls left out: they have blocks of their own),
/// sorted.
fn allowedNumbers(comptime arch: Arch) []const u32 {
    @setEvalBranchQuota(200_000);
    const own = switch (arch) {
        .x86_64 => &allowed_x86_64,
        .aarch64 => &allowed_aarch64,
    };
    const names = allowed ++ allowed_also ++ own.*;
    var out: [names.len]u32 = undefined;
    var n: usize = 0;
    for (names) |name| if (number(arch, name)) |nr| {
        if (std.mem.indexOfScalar(u32, out[0..n], nr) != null) continue;
        out[n] = nr;
        n += 1;
    };
    std.mem.sortUnstable(u32, out[0..n], {}, std.sort.asc(u32));
    const final = out[0..n].*;
    return &final;
}

pub const SockFilter = extern struct { code: u16, jt: u8, jf: u8, k: u32 };
const bpf_ld_w_abs = 0x20;
const bpf_jeq = 0x15;
const bpf_jgt = 0x25;
const bpf_jge = 0x35;
const bpf_jset = 0x45;
const bpf_ret = 0x06;
/// `struct seccomp_data`: the call's number, its architecture, and its first argument's low word
/// (little-endian on both architectures).
const off_nr = 0;
const off_arch = 4;
const off_arg0 = 16;

/// The filter for `arch`. Every jump is short and forward: each block ends in its own returns.
pub fn program(comptime arch: Arch) []const SockFilter {
    @setEvalBranchQuota(400_000);
    const nums = allowedNumbers(arch);
    var ins: [nums.len * 4 + 128]SockFilter = undefined;
    var n: usize = 0;
    const P = struct {
        fn op(list: []SockFilter, len: *usize, code: u16, k: u32, jt: usize, jf: usize) void {
            if (jt > 255 or jf > 255) @compileError("a seccomp jump is too long");
            list[len.*] = .{ .code = code, .jt = jt, .jf = jf, .k = k };
            len.* += 1;
        }
    };
    const op = P.op;
    // A foreign architecture's numbers mean other calls.
    op(&ins, &n, bpf_ld_w_abs, off_arch, 0, 0);
    op(&ins, &n, bpf_jeq, auditArch(arch), 1, 0);
    op(&ins, &n, bpf_ret, ret_eperm, 0, 0);
    op(&ins, &n, bpf_ld_w_abs, off_nr, 0, 0);
    // x32's calls, numbered from 0x40000000 on x86_64.
    if (arch == .x86_64) {
        op(&ins, &n, bpf_jset, 0x40000000, 0, 1);
        op(&ins, &n, bpf_ret, ret_eperm, 0, 0);
    }
    op(&ins, &n, bpf_jgt, maxKnown(arch), 0, 1);
    op(&ins, &n, bpf_ret, ret_enosys, 0, 0);

    // clone: only without namespace flags.
    op(&ins, &n, bpf_jeq, number(arch, "clone").?, 0, 4);
    op(&ins, &n, bpf_ld_w_abs, off_arg0, 0, 0);
    op(&ins, &n, bpf_jset, clone_namespace_flags, 1, 0);
    op(&ins, &n, bpf_ret, ret_allow, 0, 0);
    op(&ins, &n, bpf_ret, ret_eperm, 0, 0);
    op(&ins, &n, bpf_jeq, number(arch, "clone3").?, 0, 1);
    op(&ins, &n, bpf_ret, ret_enosys, 0, 0);

    // personality: Docker's values only.
    const pers = allowed_personalities;
    op(&ins, &n, bpf_jeq, number(arch, "personality").?, 0, pers.len + 3);
    op(&ins, &n, bpf_ld_w_abs, off_arg0, 0, 0);
    for (pers, 0..) |p, i| op(&ins, &n, bpf_jeq, p, pers.len - i, 0);
    op(&ins, &n, bpf_ret, ret_eperm, 0, 0);
    op(&ins, &n, bpf_ret, ret_allow, 0, 0);

    // socket: Docker's address families only.
    const fams = allowed_families;
    op(&ins, &n, bpf_jeq, number(arch, "socket").?, 0, fams.len + 4);
    op(&ins, &n, bpf_ld_w_abs, off_arg0, 0, 0);
    op(&ins, &n, bpf_jge, 3, 0, fams.len + 1);
    for (fams, 0..) |f, i| op(&ins, &n, bpf_jeq, f, fams.len - i, 0);
    op(&ins, &n, bpf_ret, ret_eperm, 0, 0);
    op(&ins, &n, bpf_ret, ret_allow, 0, 0);

    // The rest, by runs of consecutive numbers, ascending: past this run's end, on to the next;
    // within it, allowed; below its start (in the gap after the run before), refused.
    var i: usize = 0;
    while (i < nums.len) {
        var j = i;
        while (j + 1 < nums.len and nums[j + 1] == nums[j] + 1) j += 1;
        op(&ins, &n, bpf_jgt, nums[j], 3, 0);
        op(&ins, &n, bpf_jge, nums[i], 0, 1);
        op(&ins, &n, bpf_ret, ret_allow, 0, 0);
        op(&ins, &n, bpf_ret, ret_eperm, 0, 0);
        i = j + 1;
    }
    op(&ins, &n, bpf_ret, ret_eperm, 0, 0);
    const final = ins[0..n].*;
    return &final;
}

// --- tests ---

/// Runs `prog` as the kernel would on one call: the action it returns.
fn evaluate(prog: []const SockFilter, arch: u32, nr: u32, arg0: u64) u32 {
    var data: [64]u8 = @splat(0);
    std.mem.writeInt(u32, data[off_nr..][0..4], nr, .little);
    std.mem.writeInt(u32, data[off_arch..][0..4], arch, .little);
    std.mem.writeInt(u64, data[off_arg0..][0..8], arg0, .little);
    var acc: u32 = 0;
    var pc: usize = 0;
    while (pc < prog.len) {
        const i = prog[pc];
        pc += 1;
        switch (i.code) {
            bpf_ld_w_abs => acc = std.mem.readInt(u32, data[i.k..][0..4], .little),
            bpf_ret => return i.k,
            bpf_jeq, bpf_jgt, bpf_jge, bpf_jset => {
                const taken = switch (i.code) {
                    bpf_jeq => acc == i.k,
                    bpf_jgt => acc > i.k,
                    bpf_jge => acc >= i.k,
                    else => acc & i.k != 0,
                };
                pc += if (taken) i.jt else i.jf;
            },
            else => unreachable,
        }
    }
    unreachable;
}

fn expectArch(comptime arch: Arch) !void {
    const prog = comptime program(arch);
    const a = auditArch(arch);
    const t = std.testing;
    try t.expect(prog.len < 4096);
    // Every call the profile allows, and nothing it does not name.
    inline for (allowed ++ allowed_also) |name| if (comptime number(arch, name)) |nr| {
        try t.expectEqual(ret_allow, evaluate(prog, a, nr, 0));
    };
    const refused = [_][]const u8{
        "keyctl",            "add_key",         "request_key",    "bpf",
        "perf_event_open",   "userfaultfd",     "unshare",        "setns",
        "mount",             "umount2",         "pivot_root",     "open_tree",
        "move_mount",        "fsopen",          "fsmount",        "mount_setattr",
        "kexec_load",        "kexec_file_load", "init_module",    "finit_module",
        "delete_module",     "reboot",          "swapon",         "swapoff",
        "settimeofday",      "clock_settime",   "acct",           "quotactl",
        "syslog",            "io_uring_setup",  "io_uring_enter", "io_uring_register",
        "open_by_handle_at", "kcmp",            "pidfd_getfd",    "process_madvise",
        "migrate_pages",     "move_pages",      "mbind",          "set_mempolicy",
        "get_mempolicy",     "sethostname",     "setdomainname",  "vhangup",
        "lookup_dcookie",    "fanotify_init",   "nfsservctl",     "lsm_list_modules",
    };
    inline for (refused) |name| if (comptime number(arch, name)) |nr|
        try t.expectEqual(ret_eperm, evaluate(prog, a, nr, 0));
    // Calls Docker refuses by leaving them out, which P1's deny list allowed.
    inline for (.{ "migrate_pages", "lsm_list_modules" }) |name|
        try t.expect(number(arch, name) != null);
    // clone: plain threads and forks, never a namespace.
    const clone = number(arch, "clone").?;
    try t.expectEqual(ret_allow, evaluate(prog, a, clone, 0x3d0f00));
    try t.expectEqual(ret_allow, evaluate(prog, a, clone, 0x01200011));
    for ([_]u64{ 0x10000000, 0x20000, 0x40000000, 0x20000000, 0x8000000, 0x4000000, 0x2000000 }) |f|
        try t.expectEqual(ret_eperm, evaluate(prog, a, clone, f | 0x11));
    try t.expectEqual(ret_enosys, evaluate(prog, a, number(arch, "clone3").?, 0));
    const pers = number(arch, "personality").?;
    for (allowed_personalities) |p| try t.expectEqual(ret_allow, evaluate(prog, a, pers, p));
    try t.expectEqual(ret_eperm, evaluate(prog, a, pers, 0x0040000));
    try t.expectEqual(ret_eperm, evaluate(prog, a, pers, 0x0400000));
    const socket = number(arch, "socket").?;
    for ([_]u64{ 0, 1, 2, 10, 16, 17 }) |f|
        try t.expectEqual(ret_allow, evaluate(prog, a, socket, f));
    for ([_]u64{ 3, 4, 5, 6, 38, 40, 46 }) |f|
        try t.expectEqual(ret_eperm, evaluate(prog, a, socket, f));
    // Newer than the profile: ENOSYS, so a C library falls back.
    try t.expectEqual(ret_enosys, evaluate(prog, a, maxKnown(arch) + 1, 0));
    try t.expectEqual(ret_enosys, evaluate(prog, a, 100_000, 0));
    // Another architecture's numbers.
    try t.expectEqual(ret_eperm, evaluate(prog, 0x40000003, 0, 0));
}

test "the seccomp filter is Docker's allow list, on x86_64 and on aarch64" {
    try expectArch(.x86_64);
    try expectArch(.aarch64);
    // x32's calls, on x86_64.
    const prog = comptime program(.x86_64);
    try std.testing.expectEqual(ret_eperm, evaluate(prog, auditArch(.x86_64), 0x40000000, 0));
}

test "each architecture's calls the profile does not name are those Docker refuses" {
    // A name std spells otherwise would be quietly left out of the filter, so every call of each
    // architecture is either named by the profile or known to be refused by it.
    const known_refused = [_][]const u8{
        "uselib",           "ustat",          "sysfs",           "sysctl",
        "swapon",           "swapoff",        "create_module",   "get_kernel_syms",
        "query_module",     "nfsservctl",     "getpmsg",         "putpmsg",
        "afs_syscall",      "tuxcall",        "security",        "vserver",
        "kexec_load",       "add_key",        "request_key",     "keyctl",
        "migrate_pages",    "move_pages",     "kexec_file_load", "userfaultfd",
        "uprobe",           "io_uring_setup", "io_uring_enter",  "io_uring_register",
        "open_tree_attr",   "file_getattr",   "file_setattr",    "listns",
        "rseq_slice_yield", "pivot_root",
    };
    const named = allowed ++ allowed_also ++ named_otherwise ++ allowed_x86_64 ++ allowed_aarch64;
    inline for (.{ Arch.x86_64, Arch.aarch64 }) |arch| {
        for (std.meta.fieldNames(Table(arch))) |call| {
            const in = struct {
                fn f(list: []const []const u8, name: []const u8) bool {
                    for (list) |x| if (std.mem.eql(u8, x, name)) return true;
                    return false;
                }
            }.f;
            if (in(named, call) or in(&known_refused, call)) continue;
            std.debug.print("{s}: {s} is neither in Docker's profile nor known refused\n", .{
                @tagName(arch), call,
            });
            return error.TestUnexpectedResult;
        }
    }
}
