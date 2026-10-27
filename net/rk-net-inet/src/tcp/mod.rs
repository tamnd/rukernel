//! TCP, as net/ipv4/tcp*.c of Linux.
//!
//! The module `seg` has the header, `conn` has the state machine of one connection, and `cc`
//! has the congestion control. These three do no I/O, so that the host tests drive them. The
//! module `sock` has the sockets, the tables of the connections and the timers.

pub mod cc;
pub mod conn;
pub mod seg;
mod sock;

pub use sock::Stream;
pub(crate) use sock::{input, tick};
