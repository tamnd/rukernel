//! Raw synchronization primitives.
//!
//! These are the lowest locks of the kernel, per spec/03-architecture.md section 3.5. The kernel
//! runs with interrupts off, so a lock does not turn interrupts off. The CPUs run kernel code at
//! the same time, so a lock can be held by another CPU.
//!
//! A CPU that spins on a lock does the TLB requests of the other CPUs while it waits. The CPU that
//! holds the lock can wait for such a request, for example after it changed a page table, and the
//! waiting CPU has interrupts off, so it would not see the interrupt of the request.

use core::cell::UnsafeCell;
use core::mem::MaybeUninit;
use core::ops::{Deref, DerefMut};
use core::sync::atomic::{AtomicBool, AtomicU8, Ordering};

/// A spin lock that protects a value of type `T`.
pub struct SpinLock<T> {
    locked: AtomicBool,
    value: UnsafeCell<T>,
}

// SAFETY: the lock gives one `&mut T` at a time, so a `SpinLock<T>` can be shared between CPUs
// when `T` can be sent between them.
unsafe impl<T: Send> Sync for SpinLock<T> {}

impl<T> SpinLock<T> {
    /// Makes an unlocked lock.
    pub const fn new(value: T) -> Self {
        Self { locked: AtomicBool::new(false), value: UnsafeCell::new(value) }
    }

    /// Takes the lock. The CPU spins until the lock is free, and does the TLB requests of the
    /// other CPUs while it spins.
    pub fn lock(&self) -> SpinLockGuard<'_, T> {
        while self
            .locked
            .compare_exchange_weak(false, true, Ordering::Acquire, Ordering::Relaxed)
            .is_err()
        {
            while self.locked.load(Ordering::Relaxed) {
                wait_hint();
            }
        }
        SpinLockGuard { lock: self }
    }

    /// Gives the value and drops the lock. The caller owns the lock, so no other CPU holds it.
    pub fn into_inner(self) -> T {
        self.value.into_inner()
    }

    /// Takes the lock if it is free.
    pub fn try_lock(&self) -> Option<SpinLockGuard<'_, T>> {
        self.locked
            .compare_exchange(false, true, Ordering::Acquire, Ordering::Relaxed)
            .ok()
            .map(|_| SpinLockGuard { lock: self })
    }
}

/// One step of a spin loop. On the kernel, the CPU also does the TLB requests of the other CPUs,
/// as the wait of `smp_call_function` of Linux does with interrupts on. Each spin loop of the
/// kernel must use it: the CPU that the loop waits for can wait for a TLB request of this CPU.
#[inline]
pub fn wait_hint() {
    #[cfg(all(target_os = "none", any(target_arch = "x86_64", target_arch = "aarch64")))]
    crate::arch::imp::smp::poll();
    core::hint::spin_loop();
}

/// The guard of a held `SpinLock`. The lock is released when the guard is dropped.
pub struct SpinLockGuard<'a, T> {
    lock: &'a SpinLock<T>,
}

impl<T> Deref for SpinLockGuard<'_, T> {
    type Target = T;
    fn deref(&self) -> &T {
        // SAFETY: the guard exists only while this CPU holds the lock.
        unsafe { &*self.lock.value.get() }
    }
}

impl<T> DerefMut for SpinLockGuard<'_, T> {
    fn deref_mut(&mut self) -> &mut T {
        // SAFETY: the guard exists only while this CPU holds the lock, and `&mut self` makes sure
        // that there is one mutable reference.
        unsafe { &mut *self.lock.value.get() }
    }
}

impl<T> Drop for SpinLockGuard<'_, T> {
    fn drop(&mut self) {
        self.lock.locked.store(false, Ordering::Release);
    }
}

const EMPTY: u8 = 0;
const RUNNING: u8 = 1;
const DONE: u8 = 2;

/// A value that is set one time and then only read.
pub struct Once<T> {
    state: AtomicU8,
    value: UnsafeCell<MaybeUninit<T>>,
}

// SAFETY: the value is written one time before `DONE` is published with release ordering, and then
// it is only read. Thus a `&Once<T>` can be shared when `T` can be shared and sent.
unsafe impl<T: Send + Sync> Sync for Once<T> {}

impl<T> Once<T> {
    /// Makes an empty value.
    pub const fn new() -> Self {
        Self { state: AtomicU8::new(EMPTY), value: UnsafeCell::new(MaybeUninit::uninit()) }
    }

    /// Sets the value with `f` if it is empty, and gives the value. A second caller waits until
    /// the first caller finishes.
    pub fn call_once(&self, f: impl FnOnce() -> T) -> &T {
        if self.state.compare_exchange(EMPTY, RUNNING, Ordering::Acquire, Ordering::Acquire).is_ok()
        {
            // SAFETY: only the caller that moved the state from EMPTY to RUNNING writes the value,
            // and no reader reads it before the state is DONE.
            unsafe { (*self.value.get()).write(f()) };
            self.state.store(DONE, Ordering::Release);
        }
        while self.state.load(Ordering::Acquire) != DONE {
            wait_hint();
        }
        // SAFETY: the state is DONE.
        unsafe { self.value_ref() }
    }

    /// Gives the value if it is set.
    pub fn get(&self) -> Option<&T> {
        if self.state.load(Ordering::Acquire) == DONE {
            // SAFETY: the state is DONE.
            Some(unsafe { self.value_ref() })
        } else {
            None
        }
    }
}

impl<T> Once<T> {
    /// Gives the value.
    ///
    /// # Safety
    ///
    /// The state must be DONE. Then the value is initialized and is never written again.
    unsafe fn value_ref(&self) -> &T {
        // SAFETY: the caller makes sure that no writer exists, so a shared reference is valid.
        let slot = unsafe { &*self.value.get() };
        // SAFETY: the caller makes sure that the value is initialized.
        unsafe { slot.assume_init_ref() }
    }
}

impl<T> Default for Once<T> {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn lock_gives_one_guard_at_a_time() {
        let lock = SpinLock::new(1);
        let mut guard = lock.lock();
        *guard += 1;
        assert!(lock.try_lock().is_none());
        drop(guard);
        assert_eq!(*lock.lock(), 2);
    }

    #[test]
    fn once_sets_the_value_one_time() {
        let once = Once::new();
        assert!(once.get().is_none());
        assert_eq!(*once.call_once(|| 7), 7);
        assert_eq!(*once.call_once(|| 8), 7);
        assert_eq!(once.get(), Some(&7));
    }
}
