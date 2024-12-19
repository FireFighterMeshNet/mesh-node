use core::{ptr, sync::atomic::AtomicU64};
use parking_lot::Mutex;

/// Unsafely mark as Send. This way the unsafety is contained.
#[derive(Debug, Clone, Copy, Default, Hash, PartialEq, Eq, PartialOrd, Ord)]
struct UnsafeSendCell<T>(T);
unsafe impl<T> Send for UnsafeSendCell<T> {}

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

        for alarm in &mut *self.alarms.lock() {
            // Fire alarm if timestamp past.
            if alarm.2 <= tick {
                let alarm_fn = alarm.0;
                let alarm_data = alarm.1;
                alarm.2 = u64::MAX;

                log::trace!("fire alarm at {}", tick);
                alarm_fn(alarm_data.0);
            }
        }
    }
}
#[derive(Debug, Default)]
pub struct MockDriver {
    alarms: Mutex<Vec<(fn(*mut ()), UnsafeSendCell<*mut ()>, u64)>>,
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
        self.alarms.lock().iter().any(|x| x.2 != u64::MAX)
    }
}
impl embassy_time_driver::Driver for MockDriver {
    fn now(&self) -> u64 {
        self.tick.load(core::sync::atomic::Ordering::SeqCst)
    }

    unsafe fn allocate_alarm(&self) -> Option<embassy_time_driver::AlarmHandle> {
        let mut alarms = self.alarms.lock();
        let idx = alarms.len();
        log::trace!("allocated alarm {idx}");
        alarms.push((drop, UnsafeSendCell(ptr::null_mut()), u64::MAX));
        Some(embassy_time_driver::AlarmHandle::new(idx as _))
    }

    fn set_alarm_callback(
        &self,
        alarm: embassy_time_driver::AlarmHandle,
        callback: fn(*mut ()),
        ctx: *mut (),
    ) {
        log::trace!("setting alarm callback: {}", alarm.id());
        let mut alarms = self.alarms.lock();
        alarms[alarm.id() as usize] = (callback, UnsafeSendCell(ctx), u64::MAX);
    }

    fn set_alarm(&self, alarm: embassy_time_driver::AlarmHandle, timestamp: u64) -> bool {
        log::trace!("setting alarm: {} at {}", alarm.id(), timestamp);
        let mut alarms = self.alarms.lock();
        alarms[alarm.id() as usize].2 = timestamp;
        true
    }
}
embassy_time_driver::time_driver_impl! {static DRIVER: MockDriver = MockDriver::INIT}
