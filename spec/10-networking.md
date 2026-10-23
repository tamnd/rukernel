# Networking

Networking is the second largest body of ABI after the VFS: the socket families, socket options, ioctls, netlink families and `/proc/net` files. It is also the part of a kernel where performance is most often judged in public. A web server benchmark is a networking benchmark. The stack is designed to look like Linux from user space and to be as fast as Linux's on the paths that matter, which are TCP request and response, bulk TCP, UDP, loopback, and virtio-net.

## 10.1 The socket layer

Every address family a distribution or container runtime opens on a normal system:

- `AF_UNIX`: stream, datagram and seqpacket, abstract names, `SCM_RIGHTS`, `SCM_CREDENTIALS`, `SCM_PIDFD`, `SO_PEERCRED`, `SO_PEERPIDFD`, `SO_PASSCRED`, `SO_PASSPIDFD`, and garbage collection of in flight descriptors.
- `AF_INET` and `AF_INET6`.
- `AF_NETLINK`.
- `AF_PACKET`, with `TPACKET_V3` rings and fanout.
- `AF_VSOCK`, for VMs and for Firecracker's and Kata's agents.
- `AF_ALG`, which cryptsetup and iwd use.
- `AF_XDP`.
- `AF_KEY` only for legacy IPsec tools, with XFRM through netlink as the real interface.
- `AF_BLUETOOTH` and `AF_CAN`, with their drivers (document 12).
- `AF_TIPC`, `AF_RDS`, `AF_SMC`, `AF_MCTP` and the other rare families: post 1.0, each listed in the compat register until done.

The socket system calls in full: `socket`, `socketpair`, `bind`, `listen`, `accept4`, `connect`, `getsockname`, `getpeername`, `sendto`, `recvfrom`, `sendmsg`, `recvmsg`, `sendmmsg`, `recvmmsg`, `shutdown`, `getsockopt` and `setsockopt`.

Socket options are generated. `rk-abigen` extracts every `SOL_*` level and option constant from the uAPI, and the kernel has a table that maps each one to an implementation or to `ENOPROTOOPT` as the reference does. `SO_*` options with subtle semantics are tested individually by the gVisor and kselftest suites: `SO_REUSEPORT` with BPF steering, `SO_BINDTODEVICE`, `SO_MARK`, `SO_TIMESTAMPING` and its full flag set, `SO_BUSY_POLL`, `SO_PREFER_BUSY_POLL`, `SO_INCOMING_CPU`, `SO_ZEROCOPY`, `SO_TXTIME`, `SO_RCVLOWAT` and `SO_DEVMEM_*`.

## 10.2 TCP and UDP

TCP is the most consequential piece of software in the stack, because its behaviour is observable from the other end of a connection. An implementation that is correct by the RFCs but differs from Linux in a timer or a window change shows up as different throughput, different latency under loss, and different results in every network benchmark. So rukernel's TCP follows Linux's TCP, not the RFCs. Where Linux and the RFCs differ, the RFC is read for understanding and Linux is followed for behaviour. The parts:

- **Congestion control:** CUBIC by default, BBR (v1 and v3), Reno, DCTCP, and the `tcp_congestion_ops` struct_ops interface so BPF congestion controllers load (document 11).
- **Loss recovery:** RACK-TLP, PRR, SACK, D-SACK, F-RTO, and the same RTO computation with its minimum and its backoff.
- **Options:** timestamps, window scaling, ECN and AccECN, TCP Fast Open with cookies, MD5 and TCP-AO signatures, MPTCP (a separate protocol number on the same sockets, used by iOS clients and some proxies), and `TCP_ULP` for kTLS.
- **Small packets and timing:** autocorking, small queues (TSQ), pacing through the `fq` qdisc or internal pacing, and delayed ACK and quick ACK with the same heuristics.
- **Introspection:** `TCP_INFO` with every field filled the same way (load balancers and monitoring read it), `TCP_ZEROCOPY_RECEIVE`, `TCP_REPAIR` for CRIU, and the `tcp_*` sysctls with the same defaults.

**kTLS.** TLS 1.2 and 1.3 record offload in software and to NICs that support it, used by nginx, HAProxy, OpenSSL 3 and the Go and Rust TLS stacks when enabled.

**UDP.** GSO and GRO for UDP (QUIC stacks depend on both for performance), `UDP_SEGMENT`, `UDP_GRO`, `IP_PKTINFO`, `IP_RECVERR` and the error queue, and SO_REUSEPORT groups.

The **socket buffers and memory accounting** follow Linux: `tcp_mem`, `tcp_rmem` and `tcp_wmem`, autotuning, memcg socket accounting, and `net.core.*` limits.

## 10.3 Packets inside the kernel

The packet representation is Linux's `sk_buff` in spirit, not in layout:

- A head buffer with headroom.
- Page fragments for payload.
- A shared info area with GSO metadata.
- Clone and copy on write semantics.

It is written as a safe Rust type over `rk-frame`'s page and DMA primitives. The page pool and netmem abstractions (Linux 6.x) are where receive buffers come from. They are also what makes devmem TCP and zcrx possible: receive payload lands in device memory or in user mapped pages and never touches a kernel copy.

**The receive path:**

1. NAPI polling with the same weight and budget semantics, and threaded NAPI as an option.
2. GRO.
3. RPS and RFS steering.
4. XDP at the driver.
5. The tc ingress hook.
6. netfilter prerouting.
7. Routing, and local delivery or forwarding.

**The transmit path:**

1. The socket.
2. TSQ, then the qdisc layer.
3. The tc egress hook.
4. XPS.
5. GSO, then driver offload (TSO, checksum).

Every hook point that user space can attach to exists at the same place in the path, because BPF programs and nftables rules written for Linux assume Linux's order.

The stack uses async Rust internally where it simplifies protocol state machines (connection establishment, timers), as document 03.4 allows. User facing blocking calls are on the stackful side and wait on the socket's wait queue like any other blocking call.

## 10.4 Netlink and the control plane

Netlink is how every modern network tool talks to the kernel: `ip`, `ss`, `nft`, `ethtool`, `iw`, NetworkManager, systemd-networkd, `tc`, `bridge`, `devlink`, WireGuard's `wg`, and the container network plugins.

- **rtnetlink:** links, addresses, routes, neighbours, rules, qdiscs and classes and filters, netconf, nexthop objects, and multicast. This includes every link kind containers and VMs create: veth, bridge, vlan, macvlan, ipvlan, vxlan, geneve, gre, ipip, sit, tun and tap, wireguard, bond, team, dummy, ifb, vrf, netkit (6.7, the BPF programmable veth replacement Cilium uses), and macsec.
- **Generic netlink families with YNL specs** in `Documentation/netlink/specs`: ethtool, devlink, netdev, wireguard, mptcp, handshake, nl80211, team, ovs, and dpll. The YNL specs describe each family's messages and attributes in YAML. `rk-abigen` generates the parsing and the reply construction from them (document 04.3). That turns most of the control plane from hand written code into data, the way Linux itself is moving.
- **sock_diag** (`ss`), **audit**, **connector** (the process events connector), **uevent**, and the `NETLINK_ROUTE` multicast groups that daemons subscribe to.

The rule for netlink is that replies are byte identical to the reference: the same attributes in the same order with the same padding. Some tools parse positionally, and the trace differential (document 18.2) compares messages, not just status codes.

## 10.5 Packet filtering

**nftables** is the interface: the `nf_tables` netlink family, the expression VM (payload, meta, ct, lookup, set, map, verdict, nat, masq, redirect, reject, limit, quota, counter, log, queue, fib, socket, tproxy, synproxy, flow offload, inner), sets with intervals and concatenations, flowtables, and the transaction semantics. Rules are compiled to a validated bytecode interpreted per hook, as Linux does. A JIT through the BPF backend is an R10 performance item if measurement shows the interpreter is the bottleneck.

**iptables** in 2026 is `iptables-nft` on every major distribution, which speaks nftables. Legacy `ip_tables` sockopts (the `iptables-legacy` path) are supported for old containers that bundle it, by translating the legacy blob into nftables rules, which is how Linux's own compat layer works.

**conntrack** with every helper distributions enable (ftp, sip, tftp, h323 and pptp behind their sysctls), `nf_conntrack` netlink for `conntrack-tools`, NAT, and the `/proc/sys/net/netfilter/*` tunables.

**IPVS** for kube-proxy's IPVS mode, and **xfrm** IPsec for strongSwan and libreswan.

## 10.6 tc, XDP and AF_XDP

**tc:**

- The qdiscs distributions and Kubernetes use: `fq_codel` (the default), `fq`, `cake`, `htb`, `tbf`, `prio`, `mq`, `netem` (fault injection in tests), `ingress` and `clsact`.
- The classifiers `flower`, `u32`, `matchall` and `bpf`.
- The actions `mirred`, `gact`, `pedit`, `skbedit`, `vlan`, `tunnel_key`, `police` and `bpf`.
- tcx, the BPF link based attachment from 6.6.

**XDP** in native mode on the drivers that support it, and generic mode everywhere. **AF_XDP** with the fill, completion, RX and TX rings, zero copy on supporting drivers, and copy mode otherwise. These come with document 11's BPF and document 12's drivers.

## 10.7 Devmem TCP and zero copy

- **TX:** `MSG_ZEROCOPY` with completion notifications.
- **RX:** `TCP_ZEROCOPY_RECEIVE` by page remapping, and devmem TCP (6.12 receive, 6.13 transmit) with dmabuf bound queues for GPU to NIC transfers in AI training clusters.
- io_uring zcrx (document 09.3).

All of these depend on driver features (header split, flow steering) and arrive per driver.

## 10.8 Namespaces and virtual networking

Network namespaces own:

- Interfaces, routes, rules, netfilter state, sysctls, sockets, and the `/proc/net` view.
- `/sys/class/net` as seen from inside.

veth, netkit, macvlan and ipvlan connect them. The container network plugins (the CNI bridge plugin, Cilium, Calico, Flannel), Docker's and Podman's networking (Podman uses `pasta` from passt by default since 5.0), and Kubernetes' kube-proxy in iptables, IPVS and nftables modes are all L4 corpus scenarios (document 18.6).

## 10.9 Wireless and other link layers

nl80211 and cfg80211 with mac80211 for the Wi-Fi drivers in document 12's laptop list, and `iwd` and `wpa_supplicant` as the tests. Bluetooth through the HCI socket interface with BlueZ. CAN through SocketCAN. All of them are post 1.0 except where a supported laptop needs them, as document 22 orders it.

## 10.10 Performance targets

From document 19.1: within 5% on throughput and 10% on p99 for `netperf` and `neper` TCP_RR and TCP_STREAM, `sockperf` UDP latency, and `iperf3`, over loopback, virtio-net and a real 100 GbE NIC. Also nginx with `wrk`, Redis and Valkey with `memtier`, and memcached in the application class.

Document 21 explains where loopback TCP_RR spends its time on Linux:

- About 5 µs per round trip.
- Most of it in the two socket wakeups and the stack traversal.
- Almost none in copies.

The targets come from that breakdown.
