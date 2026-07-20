//! Single-process timing and peak-RSS sampling.
//!
//! Each generate/tsc invocation is spawned, then reaped with `wait4(2)` so the child's peak RSS
//! (`ru_maxrss`) is captured alongside wall time in one syscall. The std `Child` is deliberately not
//! `wait`ed — that would reap the process first and lose the rusage — so this module owns the reap.
//! Both output streams are piped and drained on threads before the reap to avoid a full-pipe deadlock
//! on the large diagnostics a corpus spec can produce.

use std::io;
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

/// The result of one timed child invocation.
pub struct SampleOutcome {
    pub wall: Duration,
    pub peak_rss_bytes: u64,
    pub exit_code: i32,
    pub stdout: String,
    pub stderr: String,
}

/// Spawns `cmd`, times it end-to-end, and reaps it with `wait4` to capture peak RSS.
///
/// `exit_code` is the child's exit status, or `-1` when it was terminated by a signal rather than
/// exiting normally. `peak_rss_bytes` is `ru_maxrss` (Linux reports it in KiB) converted to bytes.
pub fn timed_sample(mut cmd: Command) -> io::Result<SampleOutcome> {
    cmd.stdin(Stdio::null());
    cmd.stdout(Stdio::piped());
    cmd.stderr(Stdio::piped());

    let start = Instant::now();
    let mut child = cmd.spawn()?;
    let pid = libc::pid_t::try_from(child.id())
        .map_err(|_| io::Error::other("child pid does not fit pid_t"))?;

    // Drain both pipes on threads started before the reap, so a child that fills a pipe buffer can
    // still exit instead of blocking on write forever.
    let stdout_reader = child.stdout.take().map(drain_on_thread);
    let stderr_reader = child.stderr.take().map(drain_on_thread);

    let mut status: libc::c_int = 0;
    let mut usage: libc::rusage = unsafe { std::mem::zeroed() };
    let reaped = unsafe { libc::wait4(pid, &mut status, 0, &mut usage) };
    let wall = start.elapsed();
    if reaped == -1 {
        return Err(io::Error::last_os_error());
    }

    let stdout = join_reader(stdout_reader);
    let stderr = join_reader(stderr_reader);

    let peak_rss_bytes = u64::try_from(usage.ru_maxrss)
        .unwrap_or(0)
        .saturating_mul(1024);
    let exit_code = if libc::WIFEXITED(status) {
        libc::WEXITSTATUS(status)
    } else {
        -1
    };

    Ok(SampleOutcome {
        wall,
        peak_rss_bytes,
        exit_code,
        stdout,
        stderr,
    })
}

fn drain_on_thread<R: io::Read + Send + 'static>(
    mut reader: R,
) -> std::thread::JoinHandle<Vec<u8>> {
    std::thread::spawn(move || {
        let mut buffer = Vec::new();
        let _ = reader.read_to_end(&mut buffer);
        buffer
    })
}

fn join_reader(handle: Option<std::thread::JoinHandle<Vec<u8>>>) -> String {
    let bytes = handle
        .map(|handle| handle.join().unwrap_or_default())
        .unwrap_or_default();
    String::from_utf8_lossy(&bytes).into_owned()
}

/// The nearest-rank percentile in milliseconds: sort ascending, take the value at 1-based index
/// `ceil(p * n)` clamped to `[1, n]`. Returns `0.0` for an empty slice.
pub fn nearest_rank_ms(samples: &mut [f64], p: f64) -> f64 {
    if samples.is_empty() {
        return 0.0;
    }
    samples.sort_by(|left, right| left.partial_cmp(right).unwrap_or(std::cmp::Ordering::Equal));
    let count = samples.len();
    let rank = (p * count as f64).ceil().clamp(1.0, count as f64);
    let index = rank as usize;
    samples[index - 1]
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn nearest_rank_over_known_distributions() {
        let mut odd = [3.0, 1.0, 2.0];
        assert_eq!(nearest_rank_ms(&mut odd, 0.5), 2.0);

        let mut ten: Vec<f64> = (1..=10).map(f64::from).collect();
        assert_eq!(nearest_rank_ms(&mut ten, 0.5), 5.0);
        assert_eq!(nearest_rank_ms(&mut ten, 1.0), 10.0);

        let mut single = [42.0];
        assert_eq!(nearest_rank_ms(&mut single, 0.5), 42.0);

        let mut empty: [f64; 0] = [];
        assert_eq!(nearest_rank_ms(&mut empty, 0.5), 0.0);
    }

    #[test]
    fn true_exits_zero_with_nonzero_rss() {
        let outcome = timed_sample(Command::new("/bin/true")).expect("sample /bin/true");
        assert_eq!(outcome.exit_code, 0);
        assert!(outcome.peak_rss_bytes > 0, "expected nonzero peak RSS");
    }

    #[test]
    fn false_exits_one() {
        let outcome = timed_sample(Command::new("/bin/false")).expect("sample /bin/false");
        assert_eq!(outcome.exit_code, 1);
    }

    #[test]
    fn repeated_spawns_do_not_misbehave_on_drop() {
        // The std Child is dropped without wait() after our wait4 reap; confirm no ECHILD/panic
        // across many iterations.
        for _ in 0..200 {
            let outcome = timed_sample(Command::new("/bin/true")).expect("sample");
            assert_eq!(outcome.exit_code, 0);
        }
    }

    #[test]
    fn captures_child_stdout() {
        let mut command = Command::new("/bin/sh");
        command.arg("-c").arg("printf hello");
        let outcome = timed_sample(command).expect("sample sh");
        assert_eq!(outcome.exit_code, 0);
        assert_eq!(outcome.stdout, "hello");
    }
}
