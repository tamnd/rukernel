use crate::buf::NetBuf;
use crate::dev;
use crate::ns::{self, PerNet};
use crate::veth;
use alloc::vec::Vec;
use rk_abi::Errno;
use rk_frame::sync::SpinLock;

static VALUE: PerNet<SpinLock<u32>> = PerNet::new(|| SpinLock::new(7));

/// The names of the devices of the current namespace.
fn names() -> Vec<alloc::string::String> {
    dev::devices().iter().map(|d| d.name()).collect()
}

// The namespaces and the devices are global, so one test does all of the checks.
#[test]
fn namespaces_have_their_own_devices_and_values() {
    let _serial = crate::TEST_DEVICES.lock();
    dev::init();
    let first = ns::init_ns();
    assert!(first.is_init());
    assert_eq!(ns::current_index(), 0);

    // Each namespace has its own value, and a new namespace starts with the value of `make`.
    *VALUE.lock() = 1;
    let a = ns::new().unwrap();
    let b = ns::new().unwrap();
    assert_ne!(a.index(), b.index());
    assert_ne!(a.id(), b.id());
    assert_eq!(ns::by_id(b.id()).map(|n| n.index()), Some(b.index()));
    assert_eq!(ns::by_id(0).map(|n| n.index()), Some(0));
    assert_eq!(ns::count(), 3);
    {
        let _in = ns::enter(&a);
        assert_eq!(ns::current_index(), a.index());
        assert_eq!(*VALUE.lock(), 7);
        *VALUE.lock() = 2;
        // A new namespace has a loopback device that is down.
        assert_eq!(names(), ["lo"]);
        assert_eq!(dev::by_name("lo").unwrap().ifindex(), 1);
        {
            let _in = ns::enter(&b);
            assert_eq!(*VALUE.lock(), 7);
        }
        assert_eq!(*VALUE.lock(), 2);
    }
    assert_eq!(*VALUE.lock(), 1);

    // A pair joins two namespaces. The peer is made first, in its namespace.
    let (va, vb) = {
        let _in = ns::enter(&a);
        veth::create(Some(b"va"), Some(b"vb"), Some(&b)).unwrap()
    };
    assert_eq!((va.net(), vb.net()), (a.index(), b.index()));
    assert_eq!(va.link_kind(), Some(veth::KIND));
    assert!(alloc::sync::Arc::ptr_eq(&va.peer().unwrap(), &vb));
    assert!(!names().iter().any(|n| n == "va" || n == "vb"));
    {
        let _in = ns::enter(&b);
        assert_eq!(names(), ["lo", "vb"]);
        assert_eq!(vb.ifindex(), 2);
    }

    // A frame goes to the other end only when both ends are up.
    let frame = || NetBuf::from_slice(&[0xff; 60]);
    va.set_up(true);
    assert!(!va.driver().link_up());
    va.driver().transmit(frame()).unwrap();
    let mut got = 0;
    vb.driver().poll(8, &mut |_| got += 1);
    assert_eq!(got, 0);
    vb.set_up(true);
    assert!(va.driver().link_up());
    va.driver().transmit(frame()).unwrap();
    vb.driver().poll(8, &mut |_| got += 1);
    assert_eq!(got, 1);

    // A move takes the device out of its namespace, and it goes down.
    {
        let _in = ns::enter(&b);
        dev::move_to(&vb, &first).unwrap();
        assert_eq!(names(), ["lo"]);
    }
    assert_eq!(vb.net(), 0);
    assert!(!vb.is_up());
    assert!(names().iter().any(|n| n == "vb"));
    let lo = dev::by_name("lo").unwrap();
    assert_eq!(dev::move_to(&lo, &a).err(), Some(Errno::EINVAL));
    {
        let _in = ns::enter(&a);
        let other = veth::create(Some(b"vb"), None, None).unwrap();
        assert_eq!(dev::move_to(&vb, &a).err(), Some(Errno::EEXIST));
        dev::unregister(&other.0);
        assert!(dev::by_name(&other.1.name()).is_none());
    }

    // The end of a namespace takes its virtual devices, and the other end of a pair goes too.
    let first_index = a.index();
    drop(a);
    assert!(!names().iter().any(|n| n == "vb"));
    assert_eq!(ns::count(), 2);

    // A new namespace with the index of an old one gets a fresh value.
    drop(b);
    let c = ns::new().unwrap();
    assert_eq!(c.index(), first_index);
    {
        let _in = ns::enter(&c);
        assert_eq!(*VALUE.lock(), 7);
        assert_eq!(names(), ["lo"]);
    }
    drop(c);
    assert_eq!(ns::count(), 1);
    assert_eq!(ns::current_index(), 0);
}

/// A socket that records the calls of `poll_wait`.
struct Waits(core::sync::atomic::AtomicU32);

impl crate::Socket for Waits {
    fn family(&self) -> u32 {
        2
    }
    fn kind(&self) -> u32 {
        1
    }
    fn ino(&self) -> u64 {
        1
    }
    fn send(
        &self,
        _paths: &dyn crate::PathOps,
        _msg: crate::Message,
        _flags: u32,
        _nonblock: bool,
    ) -> rk_vfs::inode::Result<usize> {
        Err(Errno::EOPNOTSUPP)
    }
    fn recv(
        &self,
        _len: usize,
        _flags: u32,
        _nonblock: bool,
    ) -> rk_vfs::inode::Result<crate::Received> {
        Err(Errno::EOPNOTSUPP)
    }
    fn name(&self) -> Vec<u8> {
        Vec::new()
    }
    fn get_option(&self, _level: u32, _name: u32) -> rk_vfs::inode::Result<Vec<u8>> {
        Err(Errno::ENOPROTOOPT)
    }
    fn set_option(&self, _level: u32, _name: u32, _value: &[u8]) -> rk_vfs::inode::Result<()> {
        Err(Errno::ENOPROTOOPT)
    }
    fn poll(&self) -> u32 {
        0
    }
    fn poll_wait(&self, _table: &mut rk_vfs::wait::PollTable) {
        self.0.fetch_add(1, core::sync::atomic::Ordering::Relaxed);
    }
    fn as_any(&self) -> &dyn core::any::Any {
        self
    }
}

// The wrapper of the namespace gives `poll_wait` to the socket in it. Else `select` without a
// timeout does not wake when a TCP connection comes, as in recvmsg01 of LTP (#470).
#[test]
fn namespace_socket_adds_the_queues_of_its_socket() {
    let _serial = crate::TEST_DEVICES.lock();
    let inner = alloc::sync::Arc::new(Waits(core::sync::atomic::AtomicU32::new(0)));
    let sock = ns::NsSocket::wrap(ns::init_ns(), inner.clone());
    let mut table = rk_vfs::wait::PollTable::new();
    sock.poll_wait(&mut table);
    assert_eq!(inner.0.load(core::sync::atomic::Ordering::Relaxed), 1);
}
