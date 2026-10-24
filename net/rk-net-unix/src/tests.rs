use super::*;
use rk_net::NoPaths;

fn abstract_addr(name: &[u8]) -> Vec<u8> {
    let mut a = (AF_UNIX as u16).to_ne_bytes().to_vec();
    a.push(0);
    a.extend_from_slice(name);
    a
}

fn msg(data: &[u8]) -> Message {
    Message { data: data.to_vec(), ..Message::default() }
}

#[test]
fn stream_pair_moves_bytes() {
    let (a, b) = Unix::pair(SOCK_STREAM).unwrap();
    assert_eq!(a.send(&NoPaths, msg(b"hello"), 0, true), Ok(5));
    assert_eq!(a.send(&NoPaths, msg(b" world"), 0, true), Ok(6));
    assert_eq!(b.readable(), Ok(11));
    let r = b.recv(4, MSG_PEEK, true).unwrap();
    assert_eq!(r.data, b"hell");
    let r = b.recv(100, 0, true).unwrap();
    assert_eq!(r.data, b"hello world");
    assert_eq!(b.recv(100, 0, true).err(), Some(Errno::EAGAIN));
    a.release();
    assert_eq!(b.recv(100, 0, true).unwrap().data.len(), 0);
    assert_eq!(b.send(&NoPaths, msg(b"x"), 0, true), Err(Errno::EPIPE));
}

#[test]
fn seqpacket_keeps_boundaries() {
    let (a, b) = Unix::pair(SOCK_SEQPACKET).unwrap();
    assert_eq!(a.send(&NoPaths, msg(b"one"), 0, true), Ok(3));
    assert_eq!(a.send(&NoPaths, msg(b"two!"), 0, true), Ok(4));
    let r = b.recv(2, 0, true).unwrap();
    assert_eq!((r.data.as_slice(), r.len, r.flags), (&b"on"[..], 3, MSG_TRUNC));
    assert_eq!(b.recv(10, 0, true).unwrap().data, b"two!");
}

#[test]
fn dgram_bind_and_send() {
    let server = Unix::new(SOCK_DGRAM).unwrap();
    let client = Unix::new(SOCK_DGRAM).unwrap();
    let addr = abstract_addr(b"rk-test-dgram");
    assert_eq!(server.bind(&NoPaths, &addr), Ok(()));
    assert_eq!(server.bind(&NoPaths, &addr), Err(Errno::EINVAL));
    assert_eq!(client.bind(&NoPaths, &addr), Err(Errno::EADDRINUSE));
    assert_eq!(server.name(), addr);
    let m = Message { addr: Some(addr.clone()), ..msg(b"ping") };
    assert_eq!(client.send(&NoPaths, m, 0, true), Ok(4));
    let r = server.recv(10, 0, true).unwrap();
    assert_eq!(r.data, b"ping");
    assert_eq!(r.addr, None);
    assert_eq!(client.send(&NoPaths, msg(b"x"), 0, true), Err(Errno::ENOTCONN));
    // The queue holds at most 11 datagrams from a sender that is not the peer.
    for _ in 0..=MAX_DGRAM_QLEN {
        let m = Message { addr: Some(addr.clone()), ..msg(b"x") };
        assert_eq!(client.send(&NoPaths, m, 0, true), Ok(1));
    }
    let m = Message { addr: Some(addr.clone()), ..msg(b"x") };
    assert_eq!(client.send(&NoPaths, m, 0, true), Err(Errno::EAGAIN));
    server.release();
    let m = Message { addr: Some(addr), ..msg(b"x") };
    assert_eq!(client.send(&NoPaths, m, 0, true), Err(Errno::ECONNREFUSED));
}

#[test]
fn stream_listen_connect_accept() {
    let server = Unix::new(SOCK_STREAM).unwrap();
    let client = Unix::new(SOCK_STREAM).unwrap();
    let addr = abstract_addr(b"rk-test-stream");
    assert_eq!(server.listen(1), Err(Errno::EINVAL));
    assert_eq!(client.connect(&NoPaths, &addr, true), Err(Errno::ECONNREFUSED));
    server.bind(&NoPaths, &addr).unwrap();
    assert_eq!(server.accept(true).err(), Some(Errno::EINVAL));
    server.listen(0).unwrap();
    assert_eq!(server.accept(true).err(), Some(Errno::EAGAIN));
    assert_eq!(client.connect(&NoPaths, &addr, true), Ok(()));
    assert_eq!(client.connect(&NoPaths, &addr, true), Err(Errno::EISCONN));
    // A backlog of 0 takes one connection.
    let other = Unix::new(SOCK_STREAM).unwrap();
    assert_eq!(other.connect(&NoPaths, &addr, true), Err(Errno::EAGAIN));
    let dgram = Unix::new(SOCK_DGRAM).unwrap();
    assert_eq!(dgram.connect(&NoPaths, &addr, true), Err(Errno::EPROTOTYPE));
    let conn = server.accept(true).unwrap();
    assert_eq!(client.peer_name(), Ok(addr.clone()));
    assert_eq!(conn.name(), addr);
    client.send(&NoPaths, msg(b"abc"), 0, true).unwrap();
    assert_eq!(conn.recv(10, 0, true).unwrap().data, b"abc");
    assert_eq!(conn.shutdown(SHUT_WR), Ok(()));
    assert_eq!(client.recv(10, 0, true).unwrap().data.len(), 0);
    assert_eq!(client.shutdown(3), Err(Errno::EINVAL));
}

#[test]
fn autobind_gives_abstract_name() {
    let s = Unix::new(SOCK_DGRAM).unwrap();
    s.bind(&NoPaths, &(AF_UNIX as u16).to_ne_bytes()).unwrap();
    let name = s.name();
    assert_eq!(name.len(), 8);
    assert_eq!(name[2], 0);
}

#[test]
fn options() {
    let (a, _b) = Unix::pair(SOCK_STREAM).unwrap();
    assert_eq!(a.get_option(SOL_SOCKET, SO_TYPE), Ok(int(SOCK_STREAM as i32)));
    assert_eq!(a.get_option(SOL_SOCKET, SO_PEERCRED).unwrap().len(), 12);
    assert_eq!(a.get_option(0, SO_TYPE), Err(Errno::EOPNOTSUPP));
    assert_eq!(a.set_option(SOL_SOCKET, SO_PASSCRED, &1_i32.to_ne_bytes()), Ok(()));
    assert_eq!(a.get_option(SOL_SOCKET, SO_PASSCRED), Ok(int(1)));
    assert_eq!(Unix::new(9).err(), Some(Errno::ESOCKTNOSUPPORT));
    assert_eq!(Unix::new(SOCK_RAW).unwrap().kind(), SOCK_DGRAM);
}
