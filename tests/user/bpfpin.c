// The bpffs check of the systemd boot test. It makes an array map, writes a value, pins the map
// in /sys/fs/bpf, closes it, gets it again with BPF_OBJ_GET and reads the value. Then it does
// the same with a program of BPF_PROG_TYPE_CGROUP_SKB and with a link of the program to the
// root cgroup, as systemd pins the programs of IPAccounting= and of BPFProgram=.

#include <errno.h>
#include <fcntl.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <sys/syscall.h>
#include <unistd.h>

enum {
    BPF_MAP_CREATE = 0,
    BPF_MAP_LOOKUP_ELEM = 1,
    BPF_MAP_UPDATE_ELEM = 2,
    BPF_PROG_LOAD = 5,
    BPF_OBJ_PIN = 6,
    BPF_OBJ_GET = 7,
    BPF_OBJ_GET_INFO_BY_FD = 15,
    BPF_PROG_QUERY = 16,
    BPF_LINK_CREATE = 28,
    BPF_MAP_TYPE_ARRAY = 2,
    BPF_PROG_TYPE_CGROUP_SKB = 8,
    BPF_CGROUP_INET_EGRESS = 1,
    BPF_LINK_TYPE_CGROUP = 3,
};

static const char map_path[] = "/sys/fs/bpf/rk-bpfpin";
static const char prog_path[] = "/sys/fs/bpf/rk-bpfpin-prog";
static const char link_path[] = "/sys/fs/bpf/rk-bpfpin-link";

static long bpf(int cmd, uint32_t *attr, unsigned size) {
    return syscall(SYS_bpf, cmd, attr, size);
}

static void put64(uint32_t *attr, int word, uint64_t v) {
    memcpy(&attr[word], &v, 8);
}

static int fail(const char *what) {
    printf("rk-bpfpin: %s: %s\n", what, strerror(errno));
    unlink(map_path);
    unlink(prog_path);
    unlink(link_path);
    return 1;
}

static int elem(int cmd, int fd, uint32_t key, uint64_t *value) {
    uint32_t attr[8] = {0};
    attr[0] = (uint32_t)fd;
    put64(attr, 2, (uintptr_t)&key);
    put64(attr, 4, (uintptr_t)value);
    return (int)bpf(cmd, attr, sizeof(attr));
}

static int obj(int cmd, const char *path, int fd) {
    uint32_t attr[4] = {0};
    put64(attr, 0, (uintptr_t)path);
    attr[2] = (uint32_t)fd;
    return (int)bpf(cmd, attr, sizeof(attr));
}

// BPF_OBJ_GET_INFO_BY_FD: the first three words of the info, the type, the ID and, for a link,
// the ID of the program.
static int info(int fd, uint32_t out[3]) {
    uint32_t data[64] = {0}, attr[4] = {0};
    attr[0] = (uint32_t)fd;
    attr[1] = sizeof(data);
    put64(attr, 2, (uintptr_t)data);
    if (bpf(BPF_OBJ_GET_INFO_BY_FD, attr, sizeof(attr)) < 0)
        return -1;
    memcpy(out, data, 12);
    return 0;
}

// BPF_PROG_QUERY of the egress programs of the cgroup: 1 if the program ID is there, else 0.
static int attached(int cg, uint32_t id) {
    uint32_t ids[64] = {0}, attr[10] = {0};
    attr[0] = (uint32_t)cg;
    attr[1] = BPF_CGROUP_INET_EGRESS;
    put64(attr, 4, (uintptr_t)ids);
    attr[6] = 64;
    if (bpf(BPF_PROG_QUERY, attr, sizeof(attr)) < 0)
        return -1;
    for (uint32_t i = 0; i < attr[6] && i < 64; i++)
        if (ids[i] == id)
            return 1;
    return 0;
}

static int check_map(void) {
    uint32_t create[4] = {BPF_MAP_TYPE_ARRAY, 4, 8, 4};
    int fd = (int)bpf(BPF_MAP_CREATE, create, sizeof(create));
    if (fd < 0)
        return fail("BPF_MAP_CREATE");
    uint64_t value = 0x5250424650494eULL;
    if (elem(BPF_MAP_UPDATE_ELEM, fd, 2, &value) < 0)
        return fail("BPF_MAP_UPDATE_ELEM");
    unlink(map_path);
    if (obj(BPF_OBJ_PIN, map_path, fd) < 0)
        return fail("BPF_OBJ_PIN of the map");
    close(fd);
    fd = obj(BPF_OBJ_GET, map_path, 0);
    if (fd < 0)
        return fail("BPF_OBJ_GET of the map");
    uint64_t got = 0;
    if (elem(BPF_MAP_LOOKUP_ELEM, fd, 2, &got) < 0)
        return fail("BPF_MAP_LOOKUP_ELEM");
    close(fd);
    unlink(map_path);
    if (got != value) {
        printf("rk-bpfpin: the value is %#llx, not %#llx\n", (unsigned long long)got,
               (unsigned long long)value);
        return 1;
    }
    printf("rk-bpfpin: map pass\n");
    return 0;
}

static int check_prog_link(void) {
    // r0 = 1; exit: the program lets each packet go.
    uint64_t insns[] = {0x00000001000000b7ULL, 0x0000000000000095ULL};
    uint32_t load[30] = {0}, got[3], id;
    load[0] = BPF_PROG_TYPE_CGROUP_SKB;
    load[1] = 2;
    put64(load, 2, (uintptr_t)insns);
    put64(load, 4, (uintptr_t)"GPL");
    load[17] = BPF_CGROUP_INET_EGRESS;
    int prog = (int)bpf(BPF_PROG_LOAD, load, sizeof(load));
    if (prog < 0)
        return fail("BPF_PROG_LOAD");
    if (info(prog, got) < 0)
        return fail("BPF_OBJ_GET_INFO_BY_FD of the program");
    id = got[1];
    unlink(prog_path);
    if (obj(BPF_OBJ_PIN, prog_path, prog) < 0)
        return fail("BPF_OBJ_PIN of the program");
    close(prog);
    prog = obj(BPF_OBJ_GET, prog_path, 0);
    if (prog < 0)
        return fail("BPF_OBJ_GET of the program");
    if (info(prog, got) < 0 || got[0] != BPF_PROG_TYPE_CGROUP_SKB || got[1] != id) {
        printf("rk-bpfpin: the pinned program has the type %u and the ID %u, not %u\n", got[0],
               got[1], id);
        return 1;
    }
    unlink(prog_path);
    printf("rk-bpfpin: program pass\n");

    int cg = open("/sys/fs/cgroup", O_RDONLY | O_DIRECTORY);
    if (cg < 0)
        return fail("open /sys/fs/cgroup");
    uint32_t create[4] = {(uint32_t)prog, (uint32_t)cg, BPF_CGROUP_INET_EGRESS, 0};
    int link = (int)bpf(BPF_LINK_CREATE, create, sizeof(create));
    if (link < 0)
        return fail("BPF_LINK_CREATE");
    close(prog);
    unlink(link_path);
    if (obj(BPF_OBJ_PIN, link_path, link) < 0)
        return fail("BPF_OBJ_PIN of the link");
    close(link);
    link = obj(BPF_OBJ_GET, link_path, 0);
    if (link < 0)
        return fail("BPF_OBJ_GET of the link");
    if (info(link, got) < 0 || got[0] != BPF_LINK_TYPE_CGROUP || got[2] != id) {
        printf("rk-bpfpin: the pinned link has the type %u and the program %u, not %u\n",
               got[0], got[2], id);
        return 1;
    }
    close(link);
    if (attached(cg, id) != 1) {
        printf("rk-bpfpin: the program of the pinned link is not attached\n");
        unlink(link_path);
        return 1;
    }
    // The pin holds the last reference: unlink releases the link and detaches the program.
    unlink(link_path);
    if (attached(cg, id) != 0) {
        printf("rk-bpfpin: the program is attached after the unlink of the link\n");
        return 1;
    }
    close(cg);
    printf("rk-bpfpin: link pass\n");
    return 0;
}

int main(void) {
    if (check_map() || check_prog_link())
        return 1;
    printf("rk-bpfpin: pass\n");
    return 0;
}
