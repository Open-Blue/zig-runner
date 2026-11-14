//! Counts the bytes Rust holds, so the runner's memory accounting (`proc_stats.heap` sees only Zig's
//! allocator) can add them: bytes in use now, the most there ever were, and the allocations made.
//! The allocator itself is the system's (musl's malloc), with one addition: freed blocks of 32-512 KiB
//! are kept (a few, per exact size) and handed out again. musl maps and unmaps every block that big,
//! and a download reads into a fresh one each time (hyper's read buffers, the bodies' chunks): the page
//! faults and system calls of that cost about as much CPU as the transfer itself did (R4, measured).
use std::alloc::{GlobalAlloc, Layout, System};
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering::Relaxed};

pub struct Counting;

const CACHE_MIN: usize = 32 * 1024;
const CACHE_MAX: usize = 512 * 1024;
const CACHE_SLOTS: usize = 16;
static LOCK: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(false);
static mut CACHE: [(usize, usize); CACHE_SLOTS] = [(0, 0); CACHE_SLOTS];

fn cacheable(l: &Layout) -> bool {
    (CACHE_MIN..=CACHE_MAX).contains(&l.size()) && l.align() <= 16
}

fn locked<T>(f: impl FnOnce(&mut [(usize, usize); CACHE_SLOTS]) -> T) -> T {
    use std::sync::atomic::Ordering::{Acquire, Release};
    while LOCK.compare_exchange_weak(false, true, Acquire, Relaxed).is_err() {
        std::hint::spin_loop();
    }
    // SAFETY: LOCK is held, so this is the only reference.
    let r = f(unsafe { &mut *std::ptr::addr_of_mut!(CACHE) });
    LOCK.store(false, Release);
    r
}

fn take(size: usize) -> *mut u8 {
    locked(|c| {
        for slot in c.iter_mut() {
            if slot.1 == size && slot.0 != 0 {
                let p = slot.0;
                *slot = (0, 0);
                return p as *mut u8;
            }
        }
        std::ptr::null_mut()
    })
}

/// True when the block was kept.
fn keep(p: *mut u8, size: usize) -> bool {
    locked(|c| match c.iter_mut().find(|s| s.0 == 0) {
        Some(slot) => {
            *slot = (p as usize, size);
            true
        }
        None => false,
    })
}

static IN_USE: AtomicUsize = AtomicUsize::new(0);
static PEAK: AtomicUsize = AtomicUsize::new(0);
static ALLOCS: AtomicU64 = AtomicU64::new(0);

fn grew(by: usize) {
    let now = IN_USE.fetch_add(by, Relaxed) + by;
    PEAK.fetch_max(now, Relaxed);
}

unsafe impl GlobalAlloc for Counting {
    unsafe fn alloc(&self, l: Layout) -> *mut u8 {
        let kept = if cacheable(&l) { take(l.size()) } else { std::ptr::null_mut() };
        let p = if kept.is_null() { System.alloc(l) } else { kept };
        if !p.is_null() {
            ALLOCS.fetch_add(1, Relaxed);
            grew(l.size());
        }
        p
    }
    unsafe fn alloc_zeroed(&self, l: Layout) -> *mut u8 {
        let p = System.alloc_zeroed(l);
        if !p.is_null() {
            ALLOCS.fetch_add(1, Relaxed);
            grew(l.size());
        }
        p
    }
    unsafe fn dealloc(&self, p: *mut u8, l: Layout) {
        if !(cacheable(&l) && keep(p, l.size())) {
            System.dealloc(p, l);
        }
        IN_USE.fetch_sub(l.size(), Relaxed);
    }
    unsafe fn realloc(&self, p: *mut u8, l: Layout, new: usize) -> *mut u8 {
        let q = System.realloc(p, l, new);
        if !q.is_null() {
            if new >= l.size() {
                grew(new - l.size());
            } else {
                IN_USE.fetch_sub(l.size() - new, Relaxed);
            }
        }
        q
    }
}

pub fn in_use() -> usize {
    IN_USE.load(Relaxed)
}
pub fn peak() -> usize {
    PEAK.load(Relaxed)
}
pub fn allocations() -> u64 {
    ALLOCS.load(Relaxed)
}
