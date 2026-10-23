//! Raw synchronization primitives.
//!
//! These are the lowest locks of the kernel, per spec/03-architecture.md section 3.5. In R0 there
//! is one CPU and no interrupt handler takes a lock, so a lock does not turn interrupts off yet.
//! The `IrqGuard` and the lock levels come with SMP in R2.

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

    /// Takes the lock. The CPU spins until the lock is free.
    pub fn lock(&self) -> SpinLockGuard<'_, T> {
        while self
            .locked
            .compare_exchange_weak(false, true, Ordering::Acquire, Ordering::Relaxed)
            .is_err()
        {
            while self.locked.load(Ordering::Relaxed) {
                core::hint::spin_loop();
            }
        }
        SpinLockGuard { lock: self }
    }

    /// Takes the lock if it is free.
    pub fn try_lock(&self) -> Option<SpinLockGuard<'_, T>> {
        self.locked
            .compare_exchange(false, true, Ordering::Acquire, Ordering::Relaxed)
            .ok()
            .map(|_| SpinLockGuard { lock: self })
    }
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
            core::hint::spin_loop();
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
