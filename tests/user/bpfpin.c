// The bpffs check of the systemd boot test. It makes an array map, writes a value, pins the map
// in /sys/fs/bpf, closes it, gets it again with BPF_OBJ_GET and reads the value.

#include <errno.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <sys/syscall.h>
#include <unistd.h>

enum {
    BPF_MAP_CREATE = 0,
    BPF_MAP_LOOKUP_ELEM = 1,
    BPF_MAP_UPDATE_ELEM = 2,
    BPF_OBJ_PIN = 6,
    BPF_OBJ_GET = 7,
    BPF_MAP_TYPE_ARRAY = 2,
};

static const char path[] = "/sys/fs/bpf/rk-bpfpin";

static long bpf(int cmd, uint32_t *attr, unsigned size) {
    return syscall(SYS_bpf, cmd, attr, size);
}

static int fail(const char *what) {
    printf("rk-bpfpin: %s: %s\n", what, strerror(errno));
    unlink(path);
    return 1;
}

static int elem(int cmd, int fd, uint32_t key, uint64_t *value) {
    uint32_t attr[8] = {0};
    attr[0] = (uint32_t)fd;
    uint64_t k = (uintptr_t)&key, v = (uintptr_t)value;
    memcpy(&attr[2], &k, 8);
    memcpy(&attr[4], &v, 8);
    return (int)bpf(cmd, attr, sizeof(attr));
}

static int obj(int cmd, int fd) {
    uint32_t attr[4] = {0};
    uint64_t p = (uintptr_t)path;
    memcpy(&attr[0], &p, 8);
    attr[2] = (uint32_t)fd;
    return (int)bpf(cmd, attr, sizeof(attr));
}

int main(void) {
    uint32_t create[4] = {BPF_MAP_TYPE_ARRAY, 4, 8, 4};
    int fd = (int)bpf(BPF_MAP_CREATE, create, sizeof(create));
    if (fd < 0)
        return fail("BPF_MAP_CREATE");
    uint64_t value = 0x5250424650494eULL;
    if (elem(BPF_MAP_UPDATE_ELEM, fd, 2, &value) < 0)
        return fail("BPF_MAP_UPDATE_ELEM");
    unlink(path);
    if (obj(BPF_OBJ_PIN, fd) < 0)
        return fail("BPF_OBJ_PIN");
    close(fd);
    fd = obj(BPF_OBJ_GET, 0);
    if (fd < 0)
        return fail("BPF_OBJ_GET");
    uint64_t got = 0;
    if (elem(BPF_MAP_LOOKUP_ELEM, fd, 2, &got) < 0)
        return fail("BPF_MAP_LOOKUP_ELEM");
    close(fd);
    unlink(path);
    if (got != value) {
        printf("rk-bpfpin: the value is %#llx, not %#llx\n", (unsigned long long)got,
               (unsigned long long)value);
        return 1;
    }
    printf("rk-bpfpin: pass\n");
    return 0;
}
