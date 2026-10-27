//! The parts of the IPC objects that the system calls and procfs share: the limits of the
//! sysctl files, the text of `/proc/sysvipc`, and the queues of the message queues.
//!
//! The system calls of System V and of POSIX are in a higher layer. Procfs cannot call them, so
//! the limits are here, and the system calls give the text of `/proc/sysvipc` through a hook.
//!
//! `MsgQueue` is the queue of a System V message queue, from ipc/msg.c of Linux. It keeps the
//! messages in the order of `msgsnd`, and a receive selects a message by its type. `PrioQueue` is
//! the queue of a POSIX message queue, from ipc/mqueue.c of Linux. It gives the message with the
//! highest priority first, and the oldest one of equal priorities.

use alloc::collections::VecDeque;
use alloc::vec::Vec;
use core::sync::atomic::{AtomicI32, Ordering};
use rk_abi::Errno;
use rk_frame::sync::Once;

/// A limit that a sysctl file reads and writes.
pub struct Tunable {
    value: AtomicI32,
    min: i32,
    max: i32,
}

impl Tunable {
    /// Makes a limit with the first value `value` and the range `min..=max`.
    pub const fn new(value: i32, min: i32, max: i32) -> Self {
        Self { value: AtomicI32::new(value), min, max }
    }

    /// The value.
    pub fn get(&self) -> i32 {
        self.value.load(Ordering::Relaxed)
    }

    /// Changes the value.
    ///
    /// # Errors
    ///
    /// Gives `EINVAL` if the value is not in the range, as `proc_dointvec_minmax` of Linux.
    pub fn set(&self, value: i32) -> Result<(), Errno> {
        if !(self.min..=self.max).contains(&value) {
            return Err(Errno::EINVAL);
        }
        self.value.store(value, Ordering::Relaxed);
        Ok(())
    }

    /// Gives the value and sets it to -1, for the `*_next_id` files that one new object uses.
    pub fn take(&self) -> i32 {
        self.value.swap(-1, Ordering::Relaxed)
    }
}

/// The largest number of System V objects of one kind, as `IPCMNI` of Linux.
pub const IPCMNI: i32 = 32768;

/// The largest size of one System V message, `kernel.msgmax`.
pub static MSGMAX: Tunable = Tunable::new(8192, 0, i32::MAX);
/// The size in bytes of a new System V message queue, `kernel.msgmnb`.
pub static MSGMNB: Tunable = Tunable::new(16384, 0, i32::MAX);
/// The largest number of System V message queues, `kernel.msgmni`.
pub static MSGMNI: Tunable = Tunable::new(32000, 0, IPCMNI);
/// The ID of the next new System V message queue, or -1, `kernel.msg_next_id`.
pub static MSG_NEXT_ID: Tunable = Tunable::new(-1, -1, i32::MAX);
/// The ID of the next new semaphore set, or -1, `kernel.sem_next_id`.
pub static SEM_NEXT_ID: Tunable = Tunable::new(-1, -1, i32::MAX);
/// The ID of the next new shared memory segment, or -1, `kernel.shm_next_id`.
pub static SHM_NEXT_ID: Tunable = Tunable::new(-1, -1, i32::MAX);

/// The largest number of POSIX message queues, `fs.mqueue.queues_max`.
pub static MQ_QUEUES_MAX: Tunable = Tunable::new(256, 0, i32::MAX);
/// The largest number of messages in a POSIX message queue, `fs.mqueue.msg_max`.
pub static MQ_MSG_MAX: Tunable = Tunable::new(10, 1, MQ_HARD_MSG_MAX);
/// The largest size of a POSIX message, `fs.mqueue.msgsize_max`.
pub static MQ_MSGSIZE_MAX: Tunable = Tunable::new(8192, 128, MQ_HARD_MSGSIZE_MAX);
/// The number of messages of a new queue without attributes, `fs.mqueue.msg_default`.
pub static MQ_MSG_DEFAULT: Tunable = Tunable::new(10, 1, MQ_HARD_MSG_MAX);
/// The message size of a new queue without attributes, `fs.mqueue.msgsize_default`.
pub static MQ_MSGSIZE_DEFAULT: Tunable = Tunable::new(8192, 128, MQ_HARD_MSGSIZE_MAX);

/// The limit of `fs.mqueue.msg_max` that a privileged process cannot pass, as `HARD_MSGMAX`.
pub const MQ_HARD_MSG_MAX: i32 = 65536;
/// The limit of `fs.mqueue.msgsize_max` that a privileged process cannot pass.
pub const MQ_HARD_MSGSIZE_MAX: i32 = 16 * 1024 * 1024;

/// Finds the limit of the sysctl file `name`, a path below `/proc/sys`.
pub fn sysctl(name: &str) -> Option<&'static Tunable> {
    Some(match name {
        "kernel/msgmax" => &MSGMAX,
        "kernel/msgmnb" => &MSGMNB,
        "kernel/msgmni" => &MSGMNI,
        "kernel/msg_next_id" => &MSG_NEXT_ID,
        "kernel/sem_next_id" => &SEM_NEXT_ID,
        "kernel/shm_next_id" => &SHM_NEXT_ID,
        "fs/mqueue/queues_max" => &MQ_QUEUES_MAX,
        "fs/mqueue/msg_max" => &MQ_MSG_MAX,
        "fs/mqueue/msgsize_max" => &MQ_MSGSIZE_MAX,
        "fs/mqueue/msg_default" => &MQ_MSG_DEFAULT,
        "fs/mqueue/msgsize_default" => &MQ_MSGSIZE_DEFAULT,
        _ => return None,
    })
}

/// The names of the sysctl files of `sysctl`.
pub const SYSCTL_NAMES: &[&str] = &[
    "fs/mqueue/msg_default",
    "fs/mqueue/msg_max",
    "fs/mqueue/msgsize_default",
    "fs/mqueue/msgsize_max",
    "fs/mqueue/queues_max",
    "kernel/msg_next_id",
    "kernel/msgmax",
    "kernel/msgmnb",
    "kernel/msgmni",
    "kernel/sem_next_id",
    "kernel/shm_next_id",
];

/// Gives the first ID for a new object that is not in use: the value of the `*_next_id` file
/// `next_id` if it is set, and else `next`. `used` tells if an ID is in use. The value of the
/// file goes back to -1, as `ipc_idr_alloc` of Linux.
pub fn alloc_id(next_id: &Tunable, next: i32, used: impl Fn(i32) -> bool) -> i32 {
    let want = next_id.take();
    let mut id = if want >= 0 { want } else { next };
    while used(id) {
        id = id.wrapping_add(1) & i32::MAX;
    }
    id
}

/// The kinds of System V objects that `/proc/sysvipc` shows.
pub const SYSVIPC_FILES: &[&str] = &["msg", "sem", "shm"];

static SYSVIPC: Once<fn(&str) -> Vec<u8>> = Once::new();

/// Sets the function that gives the text of `/proc/sysvipc/<name>`. Only the first call has an
/// effect.
pub fn set_sysvipc(f: fn(&str) -> Vec<u8>) {
    SYSVIPC.call_once(|| f);
}

/// The text of `/proc/sysvipc/<name>`.
pub fn sysvipc(name: &str) -> Vec<u8> {
    SYSVIPC.get().map_or(Vec::new(), |f| f(name))
}

/// One message of a System V message queue.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Msg {
    /// The type, which is 1 or more.
    pub mtype: i64,
    /// The text.
    pub text: Vec<u8>,
}

/// The way that `msgrcv` selects a message, as `SEARCH_*` of Linux.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Search {
    /// The first message.
    Any,
    /// The first message of the type.
    Equal(i64),
    /// The first message that does not have the type, for `MSG_EXCEPT`.
    NotEqual(i64),
    /// The first message of the lowest type that is not more than the value, for a negative
    /// type.
    LessEqual(i64),
    /// The message at the index, for `MSG_COPY`.
    Number(i64),
}

impl Search {
    /// The search for the type argument `msgtyp` of `msgrcv` and its flags, as `convert_mode`
    /// of Linux.
    pub fn new(msgtyp: i64, except: bool, copy: bool) -> Self {
        if copy {
            return Search::Number(msgtyp);
        }
        if msgtyp == 0 {
            Search::Any
        } else if msgtyp < 0 {
            Search::LessEqual(if msgtyp == i64::MIN { i64::MAX } else { -msgtyp })
        } else if except {
            Search::NotEqual(msgtyp)
        } else {
            Search::Equal(msgtyp)
        }
    }
}

/// The messages of a System V message queue and the limit of their bytes.
#[derive(Clone, Debug, Default)]
pub struct MsgQueue {
    msgs: VecDeque<Msg>,
    cbytes: usize,
    qbytes: usize,
}

impl MsgQueue {
    /// Makes an empty queue that holds at most `qbytes` bytes.
    pub fn new(qbytes: usize) -> Self {
        Self { msgs: VecDeque::new(), cbytes: 0, qbytes }
    }

    /// The number of bytes in the queue.
    pub fn cbytes(&self) -> usize {
        self.cbytes
    }

    /// The number of messages in the queue.
    pub fn qnum(&self) -> usize {
        self.msgs.len()
    }

    /// The largest number of bytes.
    pub fn qbytes(&self) -> usize {
        self.qbytes
    }

    /// Changes the largest number of bytes. The messages in the queue stay.
    pub fn set_qbytes(&mut self, qbytes: usize) {
        self.qbytes = qbytes;
    }

    /// Tells if a message of `len` bytes fits, as `msg_fits_inqueue` of Linux. The number of
    /// messages also cannot be more than the limit of bytes.
    pub fn fits(&self, len: usize) -> bool {
        self.cbytes + len <= self.qbytes && self.msgs.len() < self.qbytes
    }

    /// Adds a message at the end. The caller checks `fits` first.
    pub fn push(&mut self, msg: Msg) {
        self.cbytes += msg.text.len();
        self.msgs.push_back(msg);
    }

    /// Finds the index of the message that `search` selects, as `find_msg` of Linux.
    pub fn find(&self, search: Search) -> Option<usize> {
        match search {
            Search::Any => (!self.msgs.is_empty()).then_some(0),
            Search::Equal(t) => self.msgs.iter().position(|m| m.mtype == t),
            Search::NotEqual(t) => self.msgs.iter().position(|m| m.mtype != t),
            Search::Number(n) => usize::try_from(n).ok().filter(|&n| n < self.msgs.len()),
            Search::LessEqual(t) => {
                let mut found: Option<usize> = None;
                for (i, m) in self.msgs.iter().enumerate() {
                    if m.mtype > t || found.is_some_and(|f| self.msgs[f].mtype <= m.mtype) {
                        continue;
                    }
                    found = Some(i);
                    if m.mtype == 1 {
                        break;
                    }
                }
                found
            }
        }
    }

    /// The message at the index.
    pub fn get(&self, index: usize) -> Option<&Msg> {
        self.msgs.get(index)
    }

    /// Removes the message at the index.
    pub fn remove(&mut self, index: usize) -> Option<Msg> {
        let msg = self.msgs.remove(index)?;
        self.cbytes -= msg.text.len();
        Some(msg)
    }
}

/// The messages of a POSIX message queue and its limits.
#[derive(Clone, Debug, Default)]
pub struct PrioQueue {
    /// The messages and their priorities, from the first one that a receive gives.
    msgs: VecDeque<(u32, Vec<u8>)>,
    bytes: usize,
    maxmsg: usize,
    msgsize: usize,
}

impl PrioQueue {
    /// Makes an empty queue of at most `maxmsg` messages of at most `msgsize` bytes.
    pub fn new(maxmsg: usize, msgsize: usize) -> Self {
        Self { msgs: VecDeque::new(), bytes: 0, maxmsg, msgsize }
    }

    /// The largest number of messages.
    pub fn maxmsg(&self) -> usize {
        self.maxmsg
    }

    /// The largest size of a message.
    pub fn msgsize(&self) -> usize {
        self.msgsize
    }

    /// The number of messages.
    pub fn len(&self) -> usize {
        self.msgs.len()
    }

    /// Tells if the queue has no message.
    pub fn is_empty(&self) -> bool {
        self.msgs.is_empty()
    }

    /// Tells if the queue cannot take one more message.
    pub fn is_full(&self) -> bool {
        self.msgs.len() >= self.maxmsg
    }

    /// The number of bytes of the messages, as `QSIZE` of the status text.
    pub fn bytes(&self) -> usize {
        self.bytes
    }

    /// Adds a message after the messages of the same or a higher priority.
    ///
    /// # Errors
    ///
    /// Gives `EMSGSIZE` if the message is too large and `EAGAIN` if the queue is full.
    pub fn push(&mut self, prio: u32, data: Vec<u8>) -> Result<(), Errno> {
        if data.len() > self.msgsize {
            return Err(Errno::EMSGSIZE);
        }
        if self.is_full() {
            return Err(Errno::EAGAIN);
        }
        let at = self.msgs.iter().position(|(p, _)| *p < prio).unwrap_or(self.msgs.len());
        self.bytes += data.len();
        self.msgs.insert(at, (prio, data));
        Ok(())
    }

    /// Takes the message with the highest priority, and the oldest one of these.
    pub fn pop(&mut self) -> Option<(u32, Vec<u8>)> {
        let msg = self.msgs.pop_front()?;
        self.bytes -= msg.1.len();
        Some(msg)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::vec;

    fn msg(mtype: i64, len: usize) -> Msg {
        Msg { mtype, text: vec![mtype as u8; len] }
    }

    fn queue(types: &[i64]) -> MsgQueue {
        let mut q = MsgQueue::new(1024);
        for &t in types {
            q.push(msg(t, 1));
        }
        q
    }

    #[test]
    fn byte_limit() {
        let mut q = MsgQueue::new(10);
        assert!(q.fits(10));
        assert!(!q.fits(11));
        q.push(msg(1, 6));
        assert!(q.fits(4));
        assert!(!q.fits(5));
        q.push(msg(2, 4));
        assert_eq!((q.cbytes(), q.qnum()), (10, 2));
        // A message of 0 bytes still fits in a queue that is full of bytes, as in Linux.
        assert!(q.fits(0));
        assert!(!q.fits(1));
        assert_eq!(q.remove(0), Some(msg(1, 6)));
        assert_eq!((q.cbytes(), q.qnum()), (4, 1));
        assert!(q.fits(6));
    }

    #[test]
    fn message_count_limit() {
        // Each message counts as one byte for the number of messages.
        let mut q = MsgQueue::new(2);
        q.push(msg(1, 0));
        q.push(msg(1, 0));
        assert!(!q.fits(0));
        q.set_qbytes(3);
        assert!(q.fits(0));
    }

    #[test]
    fn search_modes() {
        assert_eq!(Search::new(0, false, false), Search::Any);
        assert_eq!(Search::new(0, true, false), Search::Any);
        assert_eq!(Search::new(5, false, false), Search::Equal(5));
        assert_eq!(Search::new(5, true, false), Search::NotEqual(5));
        assert_eq!(Search::new(-5, true, false), Search::LessEqual(5));
        assert_eq!(Search::new(i64::MIN, false, false), Search::LessEqual(i64::MAX));
        assert_eq!(Search::new(3, false, true), Search::Number(3));
    }

    #[test]
    fn type_selection() {
        let q = queue(&[3, 5, 2, 5, 4]);
        assert_eq!(q.find(Search::Any), Some(0));
        assert_eq!(q.find(Search::Equal(5)), Some(1));
        assert_eq!(q.find(Search::Equal(7)), None);
        assert_eq!(q.find(Search::NotEqual(3)), Some(1));
        // The lowest type that is not more than the value, and the first of that type.
        assert_eq!(q.find(Search::LessEqual(5)), Some(2));
        assert_eq!(q.find(Search::LessEqual(4)), Some(2));
        assert_eq!(q.find(Search::LessEqual(1)), None);
        assert_eq!(q.find(Search::Number(4)), Some(4));
        assert_eq!(q.find(Search::Number(5)), None);
        assert_eq!(q.find(Search::Number(-1)), None);
        assert_eq!(MsgQueue::new(8).find(Search::Any), None);
    }

    #[test]
    fn less_equal_takes_first_of_lowest() {
        let q = queue(&[2, 1, 3, 1]);
        assert_eq!(q.find(Search::LessEqual(i64::MAX)), Some(1));
        let q = queue(&[4, 2, 2]);
        assert_eq!(q.find(Search::LessEqual(3)), Some(1));
    }

    #[test]
    fn prio_order() {
        let mut q = PrioQueue::new(4, 8);
        q.push(1, vec![b'a']).unwrap();
        q.push(5, vec![b'b', b'b']).unwrap();
        q.push(1, vec![b'c']).unwrap();
        q.push(5, vec![b'd']).unwrap();
        assert!(q.is_full());
        assert_eq!(q.bytes(), 5);
        assert_eq!(q.push(9, vec![]), Err(Errno::EAGAIN));
        assert_eq!(q.pop(), Some((5, vec![b'b', b'b'])));
        assert_eq!(q.pop(), Some((5, vec![b'd'])));
        assert_eq!(q.pop(), Some((1, vec![b'a'])));
        assert_eq!(q.pop(), Some((1, vec![b'c'])));
        assert_eq!(q.pop(), None);
        assert_eq!(q.bytes(), 0);
    }

    #[test]
    fn prio_size_limit() {
        let mut q = PrioQueue::new(2, 4);
        assert_eq!(q.push(0, vec![0; 5]), Err(Errno::EMSGSIZE));
        q.push(0, vec![0; 4]).unwrap();
        assert_eq!(q.len(), 1);
    }

    #[test]
    fn tunable_range_and_next_id() {
        let t = Tunable::new(-1, -1, 100);
        assert_eq!(t.set(101), Err(Errno::EINVAL));
        assert_eq!(t.set(-2), Err(Errno::EINVAL));
        t.set(7).unwrap();
        assert_eq!(alloc_id(&t, 0, |id| id == 7 || id == 8), 9);
        assert_eq!(t.get(), -1);
        assert_eq!(alloc_id(&t, 3, |_| false), 3);
        assert!(sysctl("kernel/msgmni").is_some());
        assert!(SYSCTL_NAMES.iter().all(|n| sysctl(n).is_some()));
    }
}
