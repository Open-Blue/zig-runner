//! The process's one tokio runtime: started on first use, stopped at exit.
use std::sync::Mutex;
use tokio::runtime::{Builder, Runtime};

static RUNTIME: Mutex<Option<Runtime>> = Mutex::new(None);

pub fn start(threads: u32) -> i32 {
    let mut slot = RUNTIME.lock().unwrap_or_else(|e| e.into_inner());
    if slot.is_some() {
        return 0;
    }
    let workers = if threads == 0 { 2 } else { threads as usize };
    match Builder::new_multi_thread()
        .worker_threads(workers)
        .thread_name("zr-net")
        .enable_time()
        .build()
    {
        Ok(rt) => {
            *slot = Some(rt);
            0
        }
        Err(e) => -(e.raw_os_error().unwrap_or(5)),
    }
}

pub fn selftest(n: u32) -> i64 {
    let slot = RUNTIME.lock().unwrap_or_else(|e| e.into_inner());
    let Some(rt) = slot.as_ref() else { return -1 };
    let (tx, rx) = std::sync::mpsc::channel();
    rt.spawn(async move {
        tokio::time::sleep(std::time::Duration::from_millis(1)).await;
        let _ = tx.send(n as i64 + 1);
    });
    rx.recv().unwrap_or(-2)
}

pub fn stop() {
    let rt = RUNTIME.lock().unwrap_or_else(|e| e.into_inner()).take();
    if let Some(rt) = rt {
        rt.shutdown_timeout(std::time::Duration::from_secs(5));
    }
}

#[cfg(test)]
mod tests {
    #[test]
    fn start_selftest_stop() {
        assert_eq!(super::selftest(1), -1);
        assert_eq!(super::start(1), 0);
        assert_eq!(super::start(1), 0);
        assert_eq!(super::selftest(41), 42);
        super::stop();
        super::stop();
        assert_eq!(super::selftest(1), -1);
    }
}
