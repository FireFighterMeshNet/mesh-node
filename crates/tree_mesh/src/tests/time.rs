use core::{ptr, sync::atomic::AtomicU64};
use parking_lot::Mutex;
use std::sync::{Arc, OnceLock};

/// Unsafely mark as Sync + Send. This way the unsafety of marking something Send + Sync is contained.
#[derive(Debug, Clone, Copy, Default, Hash, PartialEq, Eq, PartialOrd, Ord)]
struct UnsafeSyncSendCell<T>(T);
unsafe impl<T> Sync for UnsafeSyncSendCell<T> {}
unsafe impl<T> Send for UnsafeSyncSendCell<T> {}

#[derive(Debug, Default)]
pub struct TestTimeDriverInner {
    alarms: Mutex<Vec<(fn(*mut ()), UnsafeSyncSendCell<*mut ()>, u64)>>,
    pub tick: AtomicU64,
}
impl TestTimeDriverInner {
    /// Poll the driver to increment time by `dt` and handle alarm callbacks.
    /// # Note
    /// Don't call in the same thread as any of the [`embassy_time_driver::Driver`] methods to avoid deadlock/panic.
    pub fn poll(&self, dt: embassy_time::Duration) {
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

                eprintln!("fire alarm at {}", tick);
                alarm_fn(alarm_data.0);
            }
        }
    }
}
#[derive(Debug, Default)]
pub struct TestTimeDriver {
    pub inner: OnceLock<Arc<TestTimeDriverInner>>,
}
impl TestTimeDriver {
    const INIT: Self = TestTimeDriver {
        inner: OnceLock::new(),
    };
}
impl embassy_time_driver::Driver for TestTimeDriver {
    fn now(&self) -> u64 {
        self.inner
            .get_or_init(Default::default)
            .tick
            .load(core::sync::atomic::Ordering::SeqCst)
    }

    unsafe fn allocate_alarm(&self) -> Option<embassy_time_driver::AlarmHandle> {
        let mut alarms = self.inner.get_or_init(Default::default).alarms.lock();
        let idx = alarms.len();
        log::trace!("allocated alarm {idx}");
        alarms.push((drop, UnsafeSyncSendCell(ptr::null_mut()), u64::MAX));
        Some(embassy_time_driver::AlarmHandle::new(idx as _))
    }

    fn set_alarm_callback(
        &self,
        alarm: embassy_time_driver::AlarmHandle,
        callback: fn(*mut ()),
        ctx: *mut (),
    ) {
        log::trace!("setting alarm callback: {}", alarm.id());
        let mut alarms = self.inner.get_or_init(Default::default).alarms.lock();
        alarms[alarm.id() as usize] = (callback, UnsafeSyncSendCell(ctx), u64::MAX);
    }

    fn set_alarm(&self, alarm: embassy_time_driver::AlarmHandle, timestamp: u64) -> bool {
        log::trace!("setting alarm: {} at {}", alarm.id(), timestamp);
        let mut alarms = self.inner.get_or_init(Default::default).alarms.lock();
        alarms[alarm.id() as usize].2 = timestamp;
        true
    }
}
embassy_time_driver::time_driver_impl! {static _DRIVER: TestTimeDriver = TestTimeDriver::INIT}
/// Public export of the `embassy_time_driver` implementation.
pub static DRIVER: &TestTimeDriver = &_DRIVER;
