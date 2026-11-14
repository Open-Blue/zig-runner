//! Counts the bytes Rust holds, so the runner's memory accounting (`proc_stats.heap` sees only Zig's
//! allocator) can add them: bytes in use now, the most there ever were, and the allocations made.
//! The allocator itself is the system's (musl's malloc): this only counts.
use std::alloc::{GlobalAlloc, Layout, System};
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering::Relaxed};

pub struct Counting;

static IN_USE: AtomicUsize = AtomicUsize::new(0);
static PEAK: AtomicUsize = AtomicUsize::new(0);
static ALLOCS: AtomicU64 = AtomicU64::new(0);

fn grew(by: usize) {
    let now = IN_USE.fetch_add(by, Relaxed) + by;
    PEAK.fetch_max(now, Relaxed);
}

unsafe impl GlobalAlloc for Counting {
    unsafe fn alloc(&self, l: Layout) -> *mut u8 {
        let p = System.alloc(l);
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
        System.dealloc(p, l);
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
