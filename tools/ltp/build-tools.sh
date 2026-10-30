#!/bin/sh
# Copies the network programs that the LTP net tests need from the packages of Alpine Linux, with
# the shared libraries that they use.
#
# Usage: tools/ltp/build-tools.sh OUT_DIR
#
# The script needs docker. It installs the packages in PACKAGES in an Alpine container, and puts
# the programs in PROGRAMS in OUT_DIR/root/bin. The libraries and the dynamic linker of musl go in
# OUT_DIR/root with their paths, as the linker finds them in /lib and /usr/lib. tools/ltp/run.py
# takes the directory with `--tools OUT_DIR/root` and puts its files in the initramfs. A program
# in /bin comes before the applet of BusyBox with the same name, because `busybox --install -s`
# does not replace a file. The tests need these programs:
#
# - netstat of net-tools (netstat01 and the multicast tests use `netstat -s`, `-i` and `-g`).
# - traceroute of Dmitry Butskoy (traceroute01 and traceroute601 use `-T` and `-V`). The program
#   uses IPv6 when its name ends in 6, so traceroute6 is a copy of it.
# - ss of iproute2 (sendfile01 and sendfile601), ethtool (busy_poll01 to busy_poll03),
#   tcpdump (tcpdump01 and tcpdump601) and tracepath of iputils (tracepath01 and tracepath601).
#   tracepath01 gives the option `-l` after the address. The getopt of musl stops at the first
#   operand, so a small script puts the options first and runs the program in /usr/libexec.
# - ps of procps (mc_commo uses `ps -ewf`).
# - ping of iputils (tcpdump01 and tcpdump601 use `ping -f` and `ping6 -f`, and the ping of
#   BusyBox has no `-f`). ipneigh01 gives `-I` after the address, so a script puts the options
#   first, as for tracepath. iputils has no ping6, so ping6 is a script that runs `ping -6`.
# - dhcpd and dhclient of ISC DHCP, and dnsmasq (dhcpd, dhcpd6, dnsmasq and dnsmasq6). dhcpd_tests
#   needs a file /etc/dhcp/dhcpd.conf, which it replaces during the test.
# - rpcbind and rpcinfo (runtest/net.rpc_tests and net.tirpc_tests). The init script of run.py
#   starts rpcbind. libtirpc reads /etc/netconfig, and rpcinfo reads the names of the programs
#   in /etc/rpc. Alpine has no /etc/rpc, so the script writes the first lines of the file of
#   glibc.
set -eu

ALPINE=alpine:3.20
PACKAGES="net-tools traceroute iproute2-ss ethtool tcpdump iputils-tracepath iputils-ping
dhcp-server-vanilla dhclient dnsmasq rpcbind procps-ng"
PROGRAMS="netstat traceroute ss ethtool tcpdump tracepath ping dhcpd dhclient dnsmasq rpcbind rpcinfo
ps"

out=${1:?usage: tools/ltp/build-tools.sh OUT_DIR}
mkdir -p "$out"
out=$(cd "$out" && pwd)

docker run --rm --platform linux/amd64 -v "$out:/out" -e PACKAGES="$PACKAGES" \
	-e PROGRAMS="$PROGRAMS" "$ALPINE" sh -euc '
apk add --no-cache $PACKAGES >/dev/null
rm -rf /out/root
mkdir -p /out/root/bin
libs=""
for p in $PROGRAMS; do
	f=$(command -v "$p")
	cp "$f" "/out/root/bin/$p"
	libs="$libs $(ldd "$f" | awk "/=>/ { print \$3; next } { print \$1 }")"
done
cp /out/root/bin/traceroute /out/root/bin/traceroute6
mkdir -p /out/root/usr/libexec
mv /out/root/bin/tracepath /out/root/usr/libexec/
cat > /out/root/bin/tracepath <<"EOF"
#!/bin/sh
# Puts the options before the address, for the getopt of musl.
opts=""
args=""
while [ $# -gt 0 ]; do
	case $1 in
	-l|-m|-p) opts="$opts $1 $2"; shift 2 ;;
	-*) opts="$opts $1"; shift ;;
	*) args="$args $1"; shift ;;
	esac
done
exec /usr/libexec/tracepath $opts $args
EOF
chmod +x /out/root/bin/tracepath
mv /out/root/bin/ping /out/root/usr/libexec/
cat > /out/root/bin/ping <<"EOF"
#!/bin/sh
# Puts the options before the address, for the getopt of musl.
opts=""
args=""
while [ $# -gt 0 ]; do
	case $1 in
	-[ceiIlmMpQsStwWTFN]) opts="$opts $1 $2"; shift 2 ;;
	-*) opts="$opts $1"; shift ;;
	*) args="$args $1"; shift ;;
	esac
done
exec /usr/libexec/ping $opts $args
EOF
chmod +x /out/root/bin/ping
printf "#!/bin/sh\nexec /bin/ping -6 \"\$@\"\n" > /out/root/bin/ping6
chmod +x /out/root/bin/ping6
# dhclient runs this script to set the address that it gets. The script runs /sbin/ip, which is
# the ip of BusyBox, and that ip does not take the address options of DHCPv6. run.py puts the ip
# of iproute2 in /bin/ip.
mkdir -p /out/root/sbin
sed "s|^ip=.*|ip=/bin/ip|" /sbin/dhclient-script > /out/root/sbin/dhclient-script
chmod +x /out/root/sbin/dhclient-script
mkdir -p /out/root/etc/dhcp
cp /etc/netconfig /out/root/etc/
touch /out/root/etc/dhcp/dhcpd.conf
printf "%s\n" "portmapper	100000	portmap sunrpc rpcbind" "rstatd		100001	rstat rup perfmeter" \
	"rusersd		100002	rusers" "nfs		100003	nfsprog" "ypserv		100004	ypprog" \
	"mountd		100005	mount showmount" "ypbind		100007" "walld		100008	rwall shutdown" \
	"yppasswdd	100009	yppasswd" "sprayd		100012	spray" "nlockmgr	100021" \
	"status		100024" > /out/root/etc/rpc
# tar -h copies the file of each link with the name of the link, as the linker looks for it.
cd /
tar -chf - $(echo "$libs" | tr " " "\n" | sed "s|^/||" | sort -u) | tar -xf - -C /out/root
'
echo "tools: the files are in $out/root"
