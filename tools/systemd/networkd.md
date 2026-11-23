# The network tests of systemd on rukernel

This file tells how to run the network tests of systemd on rukernel and on a Linux reference kernel, and gives the results. The tests are:

- test/test-network/systemd-networkd-tests.py, the test of systemd-networkd, systemd-networkd-wait-online and networkctl (TEST-85-NETWORK in the integration tests of systemd).
- TEST-75-RESOLVED, the integration test of systemd-resolved.

The two tests come from the package systemd-tests of Debian trixie (systemd 257.13). The work is item "networkd and resolved tests" of #538.

## The image

tools/systemd/build.sh makes the tree. The tests need these packages more than the default packages of build.sh:

```sh
RK_SYSTEMD_PACKAGES="systemd-tests iputils-ping python3 python3-packaging iproute2 \
  dnsmasq-base nftables wireguard-tools systemd-timesyncd knot knot-dnsutils knot-dnssecutils \
  bind9-dnsutils jq lsof procps isc-dhcp-server radvd passwd libnss-resolve libnss-myhostname \
  libnss-systemd" sh tools/systemd/build.sh tree-amd64.tar.gz amd64
```

- systemd-tests has the two tests and test-ndisc-send.
- python3, python3-packaging, iproute2, iputils-ping, procps and jq are the tools of systemd-networkd-tests.py.
- dnsmasq-base, isc-dhcp-server and radvd are the DHCP and RA servers of the tests. wireguard-tools, nftables and systemd-timesyncd are for the tests that use them.
- knot, knot-dnsutils, knot-dnssecutils and bind9-dnsutils are the DNS server and the DNS tools of TEST-75. TEST-75 uses lsof to find the sockets of resolved. The libnss packages are for the NSS cases of TEST-75. passwd has useradd for the test user 4711.

For the Linux reference on arm64, add linux-image-arm64 to the packages. `nettest.py cpio --modules` takes the network modules from that package.

`nettest.py cpio` writes an initramfs of the tree with an init script. The init script:

- adds a service rk-nettest that runs the tests of the kernel command line, writes the output to the console with the prefix `rk-nettest:`, and stops the machine,
- on rukernel, which has no loadable modules, writes a modules.builtin with the drivers that are in the kernel (veth, dummy, tun, nf_tables), so that `modprobe` of these drivers succeeds,
- sets DefaultTimeoutStartSec to 900 s and SYSTEMD_BUS_TIMEOUT to 600 s, because under QEMU without KVM a unit or a D-Bus call can take more than the default time,
- adds the user 4711 and /usr/lib/tests/test-ndisc-send, as the image of the integration tests of systemd.

## How to run the tests

```sh
python3 tools/systemd/nettest.py cpio --tree tree-amd64.tar.gz --out x86.cpio
python3 tools/systemd/nettest.py run --kernel target/x86_64-unknown-none/debug/rukernel \
  --initrd x86.cpio --classes all --t75 --log rk-x86.log --timeout 14400 --mem 2G
python3 tools/systemd/nettest.py report rk-x86.log
```

- For the Linux reference, give the Linux kernel with --kernel and add --linux. Make the cpio with `--modules /lib/modules/VERSION` of that kernel.
- On arm64, give the arm64 `Image` with --kernel and add `--arch aarch64`.
- The run of all the classes takes about 3 hours under QEMU without KVM. Give a list of classes with --classes to run a part.
- TEST-75 stops at its first test case that fails. `--t75-skip` gives the test cases to skip in a second run.
- `--journal N` writes the journal of networkd and udevd at the end of each class, and the journal of resolved after a failure of TEST-75.
- `report --col rukernel=LOG1,LOG2 --col Linux=LOG3` gives a markdown table with one column for each kernel. `--diff` keeps only the tests with different results.

QEMU runs with one CPU and TCG, without KVM.

## Results

All runs are on x86_64, on server1, one machine at a time.

- rukernel: 0.5.36 at 557e553 (#796), on 2026-11-18. The run of all the classes took 9423 s. NetworkdIPv6PrefixTests and NetworkdL2TPTests ran in a second run with the same kernel, because the first version of nettest.py did not find the classes with a digit in their names.
- Linux: 6.8.0-147-generic. NetworkdNetDevTests, NetworkdNetworkTests, NetworkdRATests, NetworkdDHCPClientTests, NetworkdSRIOVTests and NetworkdL2TPTests are from 2026-11-18 (8953 s). The other classes are from 2026-11-13.

A test "passes" when unittest gives "ok". "xfail" is an expected failure: the test itself sees that the kernel does not have the feature, and does not fail. For TEST-75, the numbers are the test cases. TEST-75 stops at its first test case that fails, so on rukernel 6 of its 10 test cases ran.

| Class | Tests | Linux pass | rukernel pass |
| --- | --- | --- | --- |
| NetworkctlTests | 12 | 12 | 12 |
| NetworkdBondTests | 4 | 4 | 0 |
| NetworkdBridgeTests | 9 | 9 | 0 |
| NetworkdDHCPClientTests | 21 | 19 | 18 |
| NetworkdDHCPPDTests | 4 | 4 | 2 |
| NetworkdDHCPServerRelayAgentTests | 2 | 2 | 1 |
| NetworkdDHCPServerTests | 7 | 7 | 7 |
| NetworkdIPv6PrefixTests | 2 | 2 | 2 |
| NetworkdL2TPTests | 2 | 0 | 0 |
| NetworkdLLDPTests | 1 | 1 | 1 |
| NetworkdMTUTests | 8 | 8 | 8 |
| NetworkdMatchTests | 2 | 2 | 2 |
| NetworkdNetDevTests | 44 | 33 | 4 |
| NetworkdNetworkTests | 42 | 39 | 27 |
| NetworkdRATests | 11 | 9 | 3 |
| NetworkdSRIOVTests | 2 | 0 | 0 |
| NetworkdStateFileTests | 2 | 2 | 2 |
| NetworkdTCTests | 21 | 21 | 0 |
| WaitOnlineTests | 1 | 1 | 0 |
| TEST-75-RESOLVED | 10 | 10 | 5 |
| All | 207 | 185 | 94 |

NetworkdSysctlTest of systemd 257.13 has no test method (its only method is check_sysctl_watch), so it runs no test and is not in the table.

These tests do not pass on Linux either. rukernel gives the same result for each one:

- NetworkdDHCPClientTests: test_dhcp_client_ipv4_dbus_status fails. test_dhcp_client_vrf is xfail.
- NetworkdNetDevTests: test_macsec, test_nlmon and test_vxlan give an error. test_bareudp, test_batadv, test_vcan, test_vxcan and test_vrf are xfail. The three test_rps_cpu tests are skipped.
- NetworkdNetworkTests: test_prefix_route and test_route_vrf are xfail.
- NetworkdRATests: test_ndisc_mtu and test_ndisc_redirect fail.
- NetworkdSRIOVTests and NetworkdL2TPTests: all xfail.

test_nexthop gives an error on Linux, because `ip -0 nexthop list id 21` exits with 2. On rukernel it gave an error too, but for another cause: networkd stopped at the first wait_online with "IPv4 routes through IPv6 gateways are not supported". Before #809, networkd failed veth99 earlier, with "No route to host" for the nexthop with ID 2. With RTA_VIA (see "The kernel fixes"), test_nexthop passes on rukernel.

The tests that pass on Linux and not on rukernel are in "Exceptions".

## The kernel fixes

These pull requests of #538 fixed the kernel for these tests:

- #738: the file queues/rx-0/rps_cpus in sysfs of a network interface.
- #747: a veth device tells of the new carrier of the other end of the pair.
- #754: CAP_NET_ADMIN gives the access of root to /proc/sys/net.
- #760, #767 and #770: TUN devices. The ioctls of a detached file act on its device, a detached file can be written, and the sysfs files and IFLA_INFO_DATA of a TUN device.
- #764: arm64. SCTLR_EL1 lets EL0 read CTR_EL0 and use DC ZVA and the cache instructions.
- #773: an IPv6 reject route goes on the loopback device.
- #774: a secondary IPv4 address becomes the primary address when its primary address goes.
- #775: the labels of the IPv6 addresses, as addrlabel.c of Linux.
- #777: the IPv6 MTU follows the MTU of the device.
- #778: a link local gateway on another device is not local.
- #779: a link local address of another interface is reached through the link of the socket.
- #781: no ARP answer to a sender with a local address.
- #783: router advertisements follow accept_ra and forwarding.
- #786: an IPv4 address with a peer gets the route to the peer.
- #788: IFLA_CARRIER sets the carrier of a dummy device.
- #789: MSG_FASTOPEN connects a TCP socket.
- #792: IP_PKTINFO of a local packet gives the device of the address.
- #794: the dump of RTM_GETLINK for AF_INET6.
- #796: IPV6_MULTICAST_IF and IPV6_UNICAST_IF give the interface of a send.
- #806: `getsockopt` of IP_PKTOPTIONS and IPV6_2292PKTOPTIONS on a TCP socket. systemd-resolved closed each TCP connection to its stub resolver without them, so `dig +tcp` and `dig AXFR` got "connection reset" and TEST-75 stopped at testcase_08_resolved on rukernel 0.5.36 at 557e553.
- #808: IFLA_INET6_ADDR_GEN_MODE in RTM_SETLINK and the AF_INET6 attributes in IFLA_AF_SPEC of each link. A device with addr_gen_mode 1 (none) gets no link local address. With this, test_link_local_addressing_ipv6ll passes.
- #809: the IPv6 gateway of a new nexthop or route is on the link while each address of the interface is tentative. Before, networkd got "No route to host" for the nexthop `id 2 via 2001:1234:5:8f63::2 dev veth99` in test_nexthop.
- RTA_VIA: an IPv4 route or nexthop through an IPv6 gateway, as Linux 5.2 and later. With this, test_route_via_ipv6 and test_nexthop pass on rukernel (the run of NetworkdNetworkTests on 2026-11-21 gave 31 passes of 42, and 29 before).
- RTA_MULTIPATH: multipath routes for IPv4 and IPv6, with a weight for each path and the IPv6 siblings. With this, test_route_static passes on rukernel, and `ip route show` gives the same paths in the same order as Linux 6.8 (the run of NetworkdNetworkTests on 2026-11-21 gave 32 passes of 42, and 31 before). Before, networkd failed dummy98 with "Could not set static route: No such device".

## Exceptions

These tests pass on Linux and do not pass on rukernel. Most of them need a device kind or a feature that rukernel does not have yet.

- Device kinds that rukernel does not have:
  - bond: all of NetworkdBondTests, test_bond and test_vlan_on_bond, and test_ip_route_ipv6_src_route (it uses a bond device).
  - bridge: all of NetworkdBridgeTests, test_bridge, WaitOnlineTests.test_wait_online_any, test_relay_agent_on_bridge, and the RA tests test_captive_portal, test_invalid_captive_portal, test_router_hop_limit and test_router_preference (these use bridge99).
  - Tunnels: gre, gretap, ip6gre, ip6gretap, erspan, ipip, sit, isatap, 6rd, vti, vti6, ip6tnl and fou, and test_tunnel_independent and test_tunnel_independent_loopback. test_neighbor uses gre and ip6gre devices. test_dhcp_client_ipv4_only uses a sit device, and test_dhcp4_6rd uses a 6rd device.
  - geneve, macvlan, macvtap, ipvlan, ipvtap, ifb, wireguard and xfrm.
  - VLAN: test_vlan and test_activation_policy (vlan99) failed in this run. VLAN devices came in #797, after this run.
- Queueing disciplines: all of NetworkdTCTests. rukernel has no qdisc other than the default.
- Network features that rukernel does not have yet:
  - An IPv6 address with a peer address: test_address_static.
  - Proxy NDP entries: test_ipv6_proxy_ndp.
  - The files retrans_time_ms and base_reachable_time_ms in /proc/sys/net/ipv6/neigh/DEV: test_ipv6_neigh_retrans_time and test_ipv6_prefix_delegation.
  - addr_gen_mode none: networkd sets IFLA_INET6_ADDR_GEN_MODE with RTM_SETLINK, and reads it from IFLA_AF_SPEC. rukernel did not take it, so with LinkLocalAddressing=no the device still had an fe80 address, and test_link_local_addressing_ipv6ll did not get a new fe80 address after the change of its .network file. #808 came after this run, and with it test_link_local_addressing_ipv6ll passes. test_link_local_addressing also needs stable_secret and the mode stable privacy (IPv6StableSecretAddress), which rukernel does not have.
  - Temporary IPv6 addresses: test_dhcp6pd.
  - DAD: in test_ipv6_token_prefixstable the address from the router advertisement gets the flag dadfailed.
  - TCP_CONGESTION of a route: test_route_congctl is xfail.
  - L3 master devices (VRF): test_routing_policy_rule_l3mdev is xfail.
