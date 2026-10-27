//! The files of /proc/net. A protocol adds the text of a file with `register`, and procfs shows
//! each file that is there. This crate gives `dev`, as net/core/net-procfs.c of Linux.

use crate::dev;
use alloc::format;
use alloc::string::String;
use alloc::vec::Vec;
use rk_frame::sync::SpinLock;

/// A function that makes the text of a file of /proc/net.
pub type Show = fn() -> String;

/// The files of /proc/net, in the order of `register`.
static FILES: SpinLock<Vec<(&'static str, Show)>> = SpinLock::new(Vec::new());

/// Adds the file /proc/net/`name`, or changes the function of a file that is there.
pub fn register(name: &'static str, show: Show) {
    let mut files = FILES.lock();
    match files.iter_mut().find(|(n, _)| *n == name) {
        Some(f) => f.1 = show,
        None => files.push((name, show)),
    }
}

/// The files of /proc/net: `dev`, then the files of `register`.
pub fn files() -> Vec<(&'static str, Show)> {
    let mut out: Vec<(&'static str, Show)> = Vec::from([("dev", show_dev as Show)]);
    out.extend(FILES.lock().iter().copied());
    out
}

/// The text of /proc/net/dev, as `dev_seq_show` of Linux. The device layer does not count the
/// FIFO, frame, compressed, multicast, collision and carrier errors, so they are 0.
pub fn show_dev() -> String {
    let mut out = String::from(
        "Inter-|   Receive                                                |  Transmit\n \
         face |bytes    packets errs drop fifo frame compressed multicast|bytes    packets \
         errs drop fifo colls carrier compressed\n",
    );
    for d in dev::devices() {
        let s = d.stats();
        out.push_str(&format!(
            "{:>6}:{:>8} {:>7} {:>4} {:>4} {:>4} {:>5} {:>10} {:>9} {:>8} {:>7} {:>4} {:>4} {:>4} \
             {:>5} {:>7} {:>10}\n",
            d.name(),
            s.rx_bytes,
            s.rx_packets,
            s.rx_errors,
            s.rx_dropped,
            0,
            0,
            0,
            0,
            s.tx_bytes,
            s.tx_packets,
            s.tx_errors,
            s.tx_dropped,
            0,
            0,
            0,
            0,
        ));
    }
    out
}
