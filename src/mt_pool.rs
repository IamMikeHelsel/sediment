// SPDX-License-Identifier: MIT OR Apache-2.0
//! A tiny std-only scoped worker pool for compressing independent pieces in
//! parallel while keeping the output order (and therefore the bytes)
//! deterministic.
//!
//! [`map_ordered`] runs `f` over a slice on up to `threads` scoped workers
//! (`std::thread::scope`). Work is handed out by an atomic counter in index
//! order; results land in per-index slots and are returned in input order, so
//! the result never depends on scheduling. The first error in index order is
//! returned and stops the hand-out of further items. No `unsafe`, no
//! dependencies.
//!
//! [`resolve_threads`] turns a 7-Zip style `-mmt` value (0 = "all cores") into
//! a concrete worker count, and [`parse_mmt`] parses the switch itself.
//!
//! Spec source: 7-Zip's documented `-mmt[N|on|off]` switch semantics (public
//! command-line help); the pool design is original.

use std::sync::Mutex;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};

/// Upper bound on workers (also the largest accepted `-mmt=N`).
pub const MAX_THREADS: usize = 256;

/// Concrete worker count for a requested value: 0 means
/// `std::thread::available_parallelism()` (1 if unknown); the result is
/// clamped to `1..=MAX_THREADS`.
pub fn resolve_threads(requested: usize) -> usize {
    let n = if requested == 0 { std::thread::available_parallelism().map(|n| n.get()).unwrap_or(1) } else { requested };
    n.clamp(1, MAX_THREADS)
}

/// Parse the part of a `-mmt` switch after `-mmt` (`""`, `"=on"`, `"=off"`,
/// `"=N"`, `"N"`, `"on"`, `"off"`, `"+"`, `"-"`). Returns the requested thread
/// count (0 = all cores) or `None` when malformed or out of `1..=256`.
pub fn parse_mmt(rest: &str) -> Option<usize> {
    let v = rest.strip_prefix('=').unwrap_or(rest);
    match v.to_ascii_lowercase().as_str() {
        "" | "on" | "+" => Some(0),
        "off" | "-" => Some(1),
        s if !s.is_empty() && s.len() <= 3 && s.bytes().all(|b| b.is_ascii_digit()) => {
            let n: usize = s.parse().ok()?;
            if (1..=MAX_THREADS).contains(&n) { Some(n) } else { None }
        }
        _ => None,
    }
}

/// Apply `f` to every item on up to `threads` workers and return the results
/// in input order. `threads <= 1` (or a single item) runs inline on the
/// calling thread. The first `Err` in index order is returned; `lost` is
/// returned if result slots cannot be allocated or a slot is unexpectedly
/// empty (never happens without an earlier error).
pub fn map_ordered<T, R, E, F>(items: &[T], threads: usize, lost: E, f: F) -> Result<Vec<R>, E>
where
    T: Sync,
    R: Send,
    E: Send + Copy,
    F: Fn(&T) -> Result<R, E> + Sync,
{
    let workers = threads.clamp(1, MAX_THREADS).min(items.len().max(1));
    if workers <= 1 {
        let mut out = Vec::new();
        out.try_reserve_exact(items.len()).map_err(|_| lost)?;
        for it in items {
            out.push(f(it)?);
        }
        return Ok(out);
    }
    let mut init: Vec<Option<Result<R, E>>> = Vec::new();
    init.try_reserve_exact(items.len()).map_err(|_| lost)?;
    init.resize_with(items.len(), || None);
    let slots = Mutex::new(init);
    let next = AtomicUsize::new(0);
    let failed = AtomicBool::new(false);
    std::thread::scope(|s| {
        for _ in 0..workers {
            s.spawn(|| {
                loop {
                    if failed.load(Ordering::Relaxed) {
                        break;
                    }
                    let i = next.fetch_add(1, Ordering::Relaxed);
                    let Some(item) = items.get(i) else { break };
                    let r = f(item);
                    if r.is_err() {
                        failed.store(true, Ordering::Relaxed);
                    }
                    if let Ok(mut g) = slots.lock() {
                        if let Some(slot) = g.get_mut(i) {
                            *slot = Some(r);
                        }
                    }
                }
            });
        }
    });
    let slots = slots.into_inner().map_err(|_| lost)?;
    let mut out = Vec::new();
    out.try_reserve_exact(slots.len()).map_err(|_| lost)?;
    // Items are claimed in index order, so every slot before the first
    // failure is filled; an empty slot can only follow an error.
    for s in slots {
        match s {
            Some(Ok(r)) => out.push(r),
            Some(Err(e)) => return Err(e),
            None => return Err(lost),
        }
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ordered_results() {
        let v: Vec<u32> = (0..1000).collect();
        for t in [1, 2, 3, 8, 64] {
            let r = map_ordered(&v, t, (), |x| Ok::<u32, ()>(x * 2)).unwrap();
            assert_eq!(r, v.iter().map(|x| x * 2).collect::<Vec<_>>());
        }
    }

    #[test]
    fn first_error_in_order() {
        let v: Vec<u32> = (0..200).collect();
        for t in [1, 4] {
            let r = map_ordered(&v, t, 0u32, |&x| if x == 50 || x == 150 { Err(x) } else { Ok(x) });
            assert_eq!(r, Err(50));
        }
    }

    #[test]
    fn empty_and_mmt() {
        let v: Vec<u8> = Vec::new();
        assert_eq!(map_ordered(&v, 8, (), |&x| Ok::<u8, ()>(x)).unwrap(), Vec::<u8>::new());
        assert_eq!(parse_mmt(""), Some(0));
        assert_eq!(parse_mmt("=4"), Some(4));
        assert_eq!(parse_mmt("2"), Some(2));
        assert_eq!(parse_mmt("=off"), Some(1));
        assert_eq!(parse_mmt("=0"), None);
        assert_eq!(parse_mmt("=257"), None);
        assert_eq!(parse_mmt("=x"), None);
        assert!(resolve_threads(0) >= 1);
        assert_eq!(resolve_threads(1000), MAX_THREADS);
    }
}
