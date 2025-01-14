use core::{sync::atomic::AtomicU64, task::Waker};
use parking_lot::Mutex;
use std::vec::Vec;

#[derive(Debug, Default)]
pub struct MockDriverInner {}
impl MockDriver {
    /// Poll the driver to increment time by `dt` and handle alarm callbacks.
    // # Note
    // Don't call in the same thread as any of the [`embassy_time_driver::Driver`] methods to avoid deadlock/panic.
    pub fn advance(&self, dt: embassy_time::Duration) {
        let dt = dt.as_ticks();
        // Probably going to set `Duration` to something too small and get ticks rounded to 0 at some point in the future.
        // The assert will save future me some time when I make the mistake.
        assert_ne!(dt, 0, "dt=0");

        let tick = self
            .tick
            .fetch_add(dt, core::sync::atomic::Ordering::SeqCst)
            + dt;

        let alarms = &mut *self.alarms.lock();
        let taken_alarms = core::mem::take(alarms);
        *alarms = taken_alarms
            .into_iter()
            .filter_map(|alarm| {
                // Fire alarm if timestamp past.
                if alarm.0 <= tick {
                    log::trace!("fire alarm at {}", tick);
                    alarm.1.wake();
                    None
                } else {
                    Some(alarm)
                }
            })
            .collect();
    }
}
#[derive(Debug, Default)]
pub struct MockDriver {
    alarms: Mutex<Vec<(u64, Waker)>>,
    pub tick: AtomicU64,
}
impl MockDriver {
    const INIT: Self = MockDriver {
        alarms: Mutex::new(Vec::new()),
        tick: AtomicU64::new(0),
    };
    /// Get global instance (used by `embassy_time`) of the [`MockDriver`]
    pub const fn get() -> &'static MockDriver {
        &DRIVER
    }
    /// Reset the driver.
    pub fn reset(&self) {
        self.alarms.lock().clear();
        self.tick.store(0, core::sync::atomic::Ordering::SeqCst);
    }
    /// Return if any alarms are pending and not disabled. Useful for ending the test if nothing further will happen.
    pub fn alarm_pending(&self) -> bool {
        !self.alarms.lock().is_empty()
    }
}
impl embassy_time_driver::Driver for MockDriver {
    fn now(&self) -> u64 {
        self.tick.load(core::sync::atomic::Ordering::SeqCst)
    }
    fn schedule_wake(&self, at: u64, waker: &core::task::Waker) {
        let mut alarms = self.alarms.lock();
        let idx = alarms.len();
        log::trace!("allocated alarm {idx}");
        alarms.push((at, waker.clone()));
    }
}
embassy_time_driver::time_driver_impl! {static DRIVER: MockDriver = MockDriver::INIT}
