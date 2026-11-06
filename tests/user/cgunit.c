/*
 * The program of the IP accounting unit and of the device unit of the systemd boot test. It is a
 * dynamic glibc program.
 *
 * rk-cgunit ping: sets the address 10.0.2.15/24 on the first interface that is not lo, and sends
 * ICMP echo requests to the gateway 10.0.2.2 of the user network of QEMU until a reply comes. It
 * exits with 0 after a reply.
 *
 * rk-cgunit open PATH: opens PATH. It exits with 0 if the open gives EPERM.
 */
#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <net/if.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/ip_icmp.h>
#include <stdio.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <unistd.h>

/* The name of the first interface that is not lo. udev can give eth0 a new name. */
static char dev[IFNAMSIZ];

static int find_dev(void)
{
	struct if_nameindex *list = if_nameindex(), *i;

	if (!list)
		return -1;
	for (i = list; i->if_name; i++) {
		if (strcmp(i->if_name, "lo")) {
			snprintf(dev, sizeof(dev), "%s", i->if_name);
			break;
		}
	}
	if_freenameindex(list);
	return dev[0] ? 0 : -1;
}

static int set_addr(int fd, unsigned long req, const char *addr)
{
	struct ifreq ifr;
	struct sockaddr_in *sin = (struct sockaddr_in *)&ifr.ifr_addr;

	memset(&ifr, 0, sizeof(ifr));
	memcpy(ifr.ifr_name, dev, IFNAMSIZ);
	sin->sin_family = AF_INET;
	inet_pton(AF_INET, addr, &sin->sin_addr);
	return ioctl(fd, req, &ifr);
}

/* The checksum of RFC 1071. */
static unsigned short csum(const void *data, int len)
{
	const unsigned short *p = data;
	unsigned long sum = 0;

	for (; len > 1; len -= 2)
		sum += *p++;
	if (len)
		sum += *(const unsigned char *)p;
	sum = (sum >> 16) + (sum & 0xffff);
	sum += sum >> 16;
	return (unsigned short)~sum;
}

static int ping(void)
{
	struct timeval tv = { 1, 0 };
	struct sockaddr_in to = { .sin_family = AF_INET };
	struct ifreq ifr;
	int cfg, fd, seq;

	if (find_dev() < 0) {
		printf("rk-cgunit: no network interface\n");
		return 1;
	}
	cfg = socket(AF_INET, SOCK_DGRAM, 0);
	memset(&ifr, 0, sizeof(ifr));
	memcpy(ifr.ifr_name, dev, IFNAMSIZ);
	if (cfg < 0 || set_addr(cfg, SIOCSIFADDR, "10.0.2.15") < 0 ||
	    set_addr(cfg, SIOCSIFNETMASK, "255.255.255.0") < 0 || ioctl(cfg, SIOCGIFFLAGS, &ifr) < 0) {
		printf("rk-cgunit: the address of %s: %s\n", dev, strerror(errno));
		return 1;
	}
	ifr.ifr_flags |= IFF_UP;
	if (ioctl(cfg, SIOCSIFFLAGS, &ifr) < 0) {
		printf("rk-cgunit: %s up: %s\n", dev, strerror(errno));
		return 1;
	}
	close(cfg);
	fd = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP);
	if (fd < 0) {
		printf("rk-cgunit: socket: %s\n", strerror(errno));
		return 1;
	}
	setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
	inet_pton(AF_INET, "10.0.2.2", &to.sin_addr);
	for (seq = 1; seq <= 10; seq++) {
		unsigned char pkt[64] = { 0 }, buf[256];
		struct icmphdr *icmp = (struct icmphdr *)pkt;
		ssize_t n;

		icmp->type = ICMP_ECHO;
		icmp->un.echo.id = htons(0x524b);
		icmp->un.echo.sequence = htons(seq);
		icmp->checksum = csum(pkt, sizeof(pkt));
		if (sendto(fd, pkt, sizeof(pkt), 0, (struct sockaddr *)&to, sizeof(to)) < 0) {
			printf("rk-cgunit: sendto: %s\n", strerror(errno));
			continue;
		}
		while ((n = recv(fd, buf, sizeof(buf), 0)) > 0) {
			struct iphdr *ip = (struct iphdr *)buf;
			struct icmphdr *r = (struct icmphdr *)(buf + ip->ihl * 4);

			if (n < ip->ihl * 4 + 8)
				continue;
			if (r->type == ICMP_ECHOREPLY && r->un.echo.id == htons(0x524b)) {
				printf("rk-cgunit: reply %d from 10.0.2.2\n", seq);
				return 0;
			}
		}
	}
	printf("rk-cgunit: no reply from 10.0.2.2\n");
	return 1;
}

int main(int argc, char **argv)
{
	int fd;

	if (argc == 2 && !strcmp(argv[1], "ping"))
		return ping();
	if (argc == 3 && !strcmp(argv[1], "open")) {
		fd = open(argv[2], O_RDONLY);
		if (fd >= 0) {
			printf("rk-cgunit: open %s gives a descriptor\n", argv[2]);
			return 1;
		}
		printf("rk-cgunit: open %s: %s\n", argv[2], strerror(errno));
		return errno == EPERM ? 0 : 1;
	}
	fprintf(stderr, "usage: rk-cgunit ping | open PATH\n");
	return 2;
}
