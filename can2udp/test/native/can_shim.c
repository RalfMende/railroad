/*
 * LD_PRELOAD shim for testing the real can2lan binary without a CAN interface.
 *
 * can2lan opens a PF_CAN raw socket. The shim hands out an inherited
 * AF_UNIX datagram socket instead (fd number in $CAN_SHIM_FD). A datagram of
 * 16 bytes is exactly one struct can_frame, which is what SocketCAN
 * delivers, so the test acts as the CAN bus on the other end of the pair.
 */
#define _GNU_SOURCE
#include <dlfcn.h>
#include <net/if.h>
#include <stdarg.h>
#include <stdlib.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <unistd.h>

static int shim_fd = -1;

int socket(int domain, int type, int protocol) {
    static int (*real_socket)(int, int, int);
    const char *env;

    if (domain == PF_CAN) {
	env = getenv("CAN_SHIM_FD");
	if (!env)
	    return -1;
	shim_fd = dup(atoi(env));
	return shim_fd;
    }
    if (!real_socket)
	real_socket = dlsym(RTLD_NEXT, "socket");
    return real_socket(domain, type, protocol);
}

int ioctl(int fd, unsigned long request, ...) {
    static int (*real_ioctl)(int, unsigned long, ...);
    va_list ap;
    void *arg;

    va_start(ap, request);
    arg = va_arg(ap, void *);
    va_end(ap);
    if ((fd == shim_fd) && (request == SIOCGIFINDEX)) {
	((struct ifreq *)arg)->ifr_ifindex = 1;
	return 0;
    }
    if (!real_ioctl)
	real_ioctl = dlsym(RTLD_NEXT, "ioctl");
    return real_ioctl(fd, request, arg);
}

int bind(int fd, const struct sockaddr *addr, socklen_t len) {
    static int (*real_bind)(int, const struct sockaddr *, socklen_t);

    if (fd == shim_fd)
	return 0;
    if (!real_bind)
	real_bind = dlsym(RTLD_NEXT, "bind");
    return real_bind(fd, addr, len);
}

/*
 * On loopback the kernel gives every TCP socket a send buffer of more than a
 * megabyte, so a stuck client would swallow a lot of data before can2lan
 * sees EAGAIN. $CAN_SHIM_SNDBUF shrinks the send buffer of accepted
 * connections to make slow clients reproducible, like on a real network.
 */
int accept(int fd, struct sockaddr *addr, socklen_t *len) {
    static int (*real_accept)(int, struct sockaddr *, socklen_t *);
    const char *env = getenv("CAN_SHIM_SNDBUF");
    int conn, size;

    if (!real_accept)
	real_accept = dlsym(RTLD_NEXT, "accept");
    conn = real_accept(fd, addr, len);
    if ((conn >= 0) && env) {
	size = atoi(env);
	setsockopt(conn, SOL_SOCKET, SO_SNDBUF, &size, sizeof(size));
    }
    return conn;
}
