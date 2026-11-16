/* ----------------------------------------------------------------------------
 * "THE BEER-WARE LICENSE" (Revision 42):
 * <info@gerhard-bertelsmann.de> wrote this file. As long as you retain this
 * notice you can do whatever you want with this stuff. If we meet some day,
 * and you think this stuff is worth it, you can buy me a beer in return
 * Gerhard Bertelsmann
 * ----------------------------------------------------------------------------
 */

#include "can2lan.h"

/* it seems Gleisbox needs a short break after every CAN message */
/* use 10ms delay between two consequences CAN frames */
#define TIME_WAIT_US	10 * 1000
/* a shorter break for updates */
#define TIME_WAIT_US_SH	2 * 1000

extern struct filter_t filter[2];

/*
 * return string with CRLF removed from end
 */
char *rmcrlf(char *s, int slen) {
    int l;

    s[slen - 1] = '\0';
    l = strlen(s) - 1;

    while (l >= 0 && (s[l] == '\r' || s[l] == '\n'))
	s[l--] = '\0';

    return s;
}

void print_pages(char **page_name) {
    int i = 0;
    printf("track pages:\n");
    while (page_name[i]) {
	printf("track %2d -> %s\n", i, page_name[i]);
	i++;
    }
}

int time_stamp(char *timestamp) {
    /* char *timestamp = (char *)malloc(sizeof(char) * 16); */
    struct timeval tv;
    struct tm *tm;

    gettimeofday(&tv, NULL);
    tm = localtime(&tv.tv_sec);

    sprintf(timestamp, "%02d:%02d:%02d.%03d", tm->tm_hour, tm->tm_min, tm->tm_sec, (int)tv.tv_usec / 1000);
    return 0;
}

void free_track_file(char **page_name) {
    int i = 0;

    while (page_name[i]) {
	free(page_name[i]);
	i++;
    }
}

void print_can_frame(char *format_string, unsigned char *netframe, int verbose) {
    uint32_t canid;
    int i, dlc;
    char timestamp[16];

    if (!verbose)
	return;

    memcpy(&canid, netframe, 4);
    dlc = netframe[4];
    time_stamp(timestamp);
    printf("%s   ", timestamp);
    printf(format_string, ntohl(canid) & CAN_EFF_MASK, netframe[4]);
    for (i = 5; i < 5 + dlc; i++) {
	printf(" %02x", netframe[i]);
    }
    if (dlc < 8) {
	printf("(%02x", netframe[i]);
	for (i = 6 + dlc; i < CAN_ENCAP_SIZE; i++) {
	    printf(" %02x", netframe[i]);
	}
	printf(")");
    } else {
	printf(" ");
    }
    printf("  ");
    for (i = 5; i < CAN_ENCAP_SIZE; i++) {
	if (isprint(netframe[i]))
	    printf("%c", netframe[i]);
	else
	    putchar('.');
    }

    printf("\n");
}

/*
 * Non-blocking transmit paths
 *
 * can2lan is a single threaded select() loop. Blocking in a send (slow TCP
 * client) or sleeping to pace CAN frames would stall every other path and
 * make the kernel drop received frames silently. Therefore:
 *
 * - every TCP client has its own send queue (tcp_tx), flushed with
 *   MSG_DONTWAIT. A client which cannot keep up is marked dead and closed by
 *   the main loop instead of blocking the gateway.
 * - frames for the CAN bus go through one queue (can_txq). The pacing the
 *   gateway box needs between two frames is done with a timer:
 *   can_tx_service() returns the time until the next frame is due.
 *
 * Memory is bounded: static CAN queue, TCP queues grow on demand up to
 * TCP_TX_QUEUE_MAX and are released when empty (Omega2+ has 128 MB RAM).
 */
struct tcp_tx {
    int used;
    int fd;
    int dead;
    uint8_t *buf;
    size_t head;
    size_t len;
    size_t cap;
};

static struct tcp_tx tcp_tx[MAX_TCP_CONN];
static struct can_frame can_txq[CAN_TX_QUEUE_LEN];
static unsigned int can_tx_head, can_tx_count;
/* monotonic: wall clock jumps (NTP after boot) must not stall the CAN queue */
static struct timespec can_last_sent;

static struct tcp_tx *tcp_tx_lookup(int fd) {
    int i;

    for (i = 0; i < MAX_TCP_CONN; i++) {
	if (tcp_tx[i].used && (tcp_tx[i].fd == fd))
	    return &tcp_tx[i];
    }
    return NULL;
}

static void tcp_tx_release(struct tcp_tx *q) {
    free(q->buf);
    q->buf = NULL;
    q->head = 0;
    q->len = 0;
    q->cap = 0;
}

static void tcp_tx_kill(struct tcp_tx *q) {
    q->dead = 1;
    tcp_tx_release(q);
}

int tcp_tx_register(int fd) {
    int i, on = 1;

    for (i = 0; i < MAX_TCP_CONN; i++) {
	if (!tcp_tx[i].used) {
	    memset(&tcp_tx[i], 0, sizeof(tcp_tx[i]));
	    tcp_tx[i].used = 1;
	    tcp_tx[i].fd = fd;
	    /* queued frames are already coalesced, don't let Nagle delay them */
	    setsockopt(fd, IPPROTO_TCP, TCP_NODELAY, &on, sizeof(on));
	    return 0;
	}
    }
    syslog(LOG_ERR, "%s: no free send queue for TCP client fd %d\n", __func__, fd);
    return -1;
}

void tcp_tx_unregister(int fd) {
    struct tcp_tx *q = tcp_tx_lookup(fd);

    if (q) {
	tcp_tx_release(q);
	memset(q, 0, sizeof(*q));
    }
}

/* make room for add more bytes: compact first, grow (bounded) if still needed */
static int tcp_tx_reserve(struct tcp_tx *q, size_t add) {
    size_t ncap;
    uint8_t *nbuf;

    if (q->len + add > TCP_TX_QUEUE_MAX)
	return -1;
    if (q->head + q->len + add <= q->cap)
	return 0;
    if (q->head) {
	memmove(q->buf, q->buf + q->head, q->len);
	q->head = 0;
    }
    if (q->len + add <= q->cap)
	return 0;
    ncap = q->cap ? q->cap : TCP_TX_QUEUE_MIN;
    while (ncap < q->len + add)
	ncap *= 2;
    if (ncap > TCP_TX_QUEUE_MAX)
	ncap = TCP_TX_QUEUE_MAX;
    nbuf = realloc(q->buf, ncap);
    if (nbuf == NULL)
	return -1;
    q->buf = nbuf;
    q->cap = ncap;
    return 0;
}

/* all or nothing: a queue never holds a partial write of one call */
static int tcp_tx_enqueue(struct tcp_tx *q, const unsigned char *data, size_t length) {
    if (q->dead)
	return -1;
    if (tcp_tx_reserve(q, length) < 0) {
	syslog(LOG_ERR, "%s: send queue of TCP client fd %d is full - closing client\n", __func__, q->fd);
	tcp_tx_kill(q);
	return -1;
    }
    memcpy(q->buf + q->head + q->len, data, length);
    q->len += length;
    return 0;
}

static void tcp_tx_flush(struct tcp_tx *q) {
    ssize_t n;
    int err;

    while (q->len && !q->dead) {
	n = send(q->fd, q->buf + q->head, q->len, MSG_DONTWAIT | MSG_NOSIGNAL);
	if (n < 0) {
	    err = errno;
	    if (err == EINTR)
		continue;
	    if ((err != EAGAIN) && (err != EWOULDBLOCK)) {
		syslog(LOG_NOTICE, "%s: sending to TCP client fd %d failed: %s\n", __func__, q->fd, strerror(err));
		tcp_tx_kill(q);
	    }
	    break;
	}
	q->head += n;
	q->len -= n;
	/* short write: socket buffer is full, wait until select() reports it writable */
	if (q->len)
	    break;
    }
    if (!q->len && !q->dead) {
	q->head = 0;
	if (q->cap > TCP_TX_QUEUE_KEEP)
	    tcp_tx_release(q);
    }
}

void tcp_tx_flush_all(void) {
    int i;

    for (i = 0; i < MAX_TCP_CONN; i++) {
	if (tcp_tx[i].used && tcp_tx[i].len)
	    tcp_tx_flush(&tcp_tx[i]);
    }
}

void tcp_tx_flush_fd(int fd) {
    struct tcp_tx *q = tcp_tx_lookup(fd);

    if (q)
	tcp_tx_flush(q);
}

/* add all clients with queued data to wfds, returns how many */
int tcp_tx_fill_wfds(fd_set *wfds) {
    int i, count = 0;

    for (i = 0; i < MAX_TCP_CONN; i++) {
	if (tcp_tx[i].used && tcp_tx[i].len && !tcp_tx[i].dead) {
	    FD_SET(tcp_tx[i].fd, wfds);
	    count++;
	}
    }
    return count;
}

int tcp_tx_dead(int fd) {
    struct tcp_tx *q = tcp_tx_lookup(fd);

    return q && q->dead;
}

size_t tcp_tx_pending(int fd) {
    struct tcp_tx *q = tcp_tx_lookup(fd);

    return q ? q->len : 0;
}

/*
 * Send to a TCP client (queued) or UDP (datagram, dropped when the socket
 * buffer is full - there is nobody to retry for).
 */
static int net_send(int net_socket, struct sockaddr *net_addr, const unsigned char *data, int length) {
    struct tcp_tx *q = tcp_tx_lookup(net_socket);
    int s;

    if (q)
	return tcp_tx_enqueue(q, data, length);
    s = sendto(net_socket, data, length, MSG_DONTWAIT | MSG_NOSIGNAL, net_addr, sizeof(*net_addr));
    if (s != length) {
	fprint_syslog_wc(stderr, LOG_ERR, "error sending TCP/UDP data:", strerror(errno));
	return -1;
    }
    return 0;
}

int net_to_net(int net_socket, struct sockaddr *net_addr, unsigned char *netframe, int length) {
    return net_send(net_socket, net_addr, netframe, length);
}

int frame_to_net(int net_socket, struct sockaddr *net_addr, struct can_frame *frame) {
    uint32_t canid;
    extern unsigned char netframe[MAXDG];

    if (filter[0].use) {
	if ((frame->can_id & filter[0].mask) == filter[0].id)
	    return 0;
    }
    if (filter[1].use) {
	if ((frame->can_id & filter[1].mask) == filter[1].id)
	    return 0;
    }

    memset(netframe, 0, CAN_ENCAP_SIZE);
    frame->can_id &= CAN_EFF_MASK;
    canid = htonl(frame->can_id);
    memcpy(netframe, &canid, 4);
    netframe[4] = frame->can_dlc;
    memcpy(&netframe[5], &frame->data, frame->can_dlc);

    /* send TCP/UDP frame */
    return net_send(net_socket, net_addr, netframe, CAN_ENCAP_SIZE);
}

/* Maerklin TCP/UDP Format: always 13 (CAN_ENCAP_SIZE) bytes
 *   byte 0 - 3  CAN ID
 *   byte 4      DLC
 *   byte 5 - 12 CAN data
 */
static void netframe_to_canframe(const unsigned char *netframe, struct can_frame *frame) {
    uint32_t canid;

    memset(frame, 0, sizeof(*frame));
    memcpy(&canid, netframe, 4);
    /* CAN uses (network) big endian format */
    frame->can_id = ntohl(canid);
    frame->can_id &= CAN_EFF_MASK;
    frame->can_id |= CAN_EFF_FLAG;
    frame->can_dlc = netframe[4];
    memcpy(&frame->data, &netframe[5], 8);
}

/* it seems Gleisbox needs a short break after every CAN message, shorter for updates */
static long can_pace_us(canid_t can_id) {
    if (((can_id & 0x00FE0000) == 0x00360000) ||
	((can_id & 0x00FE0000) == 0x00420000) ||
	((can_id & 0x00FE0000) == 0x00800000))
	return TIME_WAIT_US_SH;
    return TIME_WAIT_US;
}

/* 64 bit: a 32 bit long (MIPS) overflows after 2147 seconds */
static long long can_elapsed_us(const struct timespec *now) {
    return (long long)(now->tv_sec - can_last_sent.tv_sec) * 1000000LL + (now->tv_nsec - can_last_sent.tv_nsec) / 1000;
}

/* blocking variant, only used for the start sequence before the main loop runs */
int frame_to_can(int can_socket, unsigned char *netframe) {
    struct can_frame frame;
    struct timespec now, to_wait;
    long long usec;
    long wait_usec;

    netframe_to_canframe(netframe, &frame);
    wait_usec = can_pace_us(frame.can_id);
    clock_gettime(CLOCK_MONOTONIC, &now);
    usec = can_elapsed_us(&now);
    if (usec < wait_usec) {
	to_wait.tv_sec = 0;
	to_wait.tv_nsec = (wait_usec - usec) * 1000;
	nanosleep(&to_wait, NULL);
    }

    /* send CAN frame */
    if (write(can_socket, &frame, sizeof(frame)) != sizeof(frame)) {
	fprint_syslog_wc(stderr, LOG_ERR, "error CAN frame:", strerror(errno));
	return -1;
    }

    clock_gettime(CLOCK_MONOTONIC, &can_last_sent);
    return 0;
}

/* queue a 13 byte network frame for the CAN bus, -1 if the queue is full */
int can_tx_enqueue(unsigned char *netframe) {
    if (can_tx_count >= CAN_TX_QUEUE_LEN)
	return -1;
    netframe_to_canframe(netframe, &can_txq[(can_tx_head + can_tx_count) % CAN_TX_QUEUE_LEN]);
    can_tx_count++;
    return 0;
}

int can_tx_free(void) {
    return CAN_TX_QUEUE_LEN - can_tx_count;
}

/*
 * Write the next queued frame to the CAN bus if the pacing time has elapsed.
 * Never blocks. Returns the time in microseconds after which this function
 * should be called again, or -1 if the queue is empty.
 */
long can_tx_service(int can_socket) {
    struct timespec now;
    long long elapsed;
    long wait_usec;
    ssize_t n;
    int err;

    if (!can_tx_count)
	return -1;
    wait_usec = can_pace_us(can_txq[can_tx_head].can_id);
    clock_gettime(CLOCK_MONOTONIC, &now);
    elapsed = can_elapsed_us(&now);
    if (elapsed < wait_usec)
	return wait_usec - (long)elapsed;

    n = send(can_socket, &can_txq[can_tx_head], sizeof(struct can_frame), MSG_DONTWAIT | MSG_NOSIGNAL);
    if (n != (ssize_t)sizeof(struct can_frame)) {
	err = (n < 0) ? errno : EIO;
	/* TX queue of the CAN interface is full: keep the frame and try again later */
	if ((err == EAGAIN) || (err == EWOULDBLOCK) || (err == ENOBUFS) || (err == EINTR))
	    return CAN_TX_RETRY_US;
	syslog(LOG_ERR, "%s: error CAN frame: %s - frame dropped\n", __func__, strerror(err));
    }
    can_last_sent = now;
    can_tx_head = (can_tx_head + 1) % CAN_TX_QUEUE_LEN;
    can_tx_count--;
    return can_tx_count ? can_pace_us(can_txq[can_tx_head].can_id) : -1;
}

char *search_interface(char *search) {
    struct sockaddr_in *bsa;
    struct ifaddrs *ifap, *ifa;
    char *s;

    /* trying to get the broadcast address */
    if (getifaddrs(&ifap) == -1) {
	perror("getifaddrs");
	exit(EXIT_FAILURE);
    }
    for (ifa = ifap; ifa; ifa = ifa->ifa_next) {
	if (ifa->ifa_addr == NULL)
	    continue;
	if (ifa->ifa_addr) {
	    if (ifa->ifa_addr->sa_family == AF_INET) {
		bsa = (struct sockaddr_in *)ifa->ifa_broadaddr;
		if (strncmp(ifa->ifa_name, search, strlen(search)) == 0) {
		    s = strdup(inet_ntoa(bsa->sin_addr));
		    freeifaddrs(ifap);
		    return s;
		}
	    }
	}
    }
    freeifaddrs(ifap);
    return NULL;
}

/*
  CS2 CAN hash generation

  hash' = highword ^ lowword

  xxxxxxx11 0xxxxxxxx
  ^^^^^^^    ^^^^^^^^
   \\\\\\\   ||||||||
    \\\\\\-- ||||||||
     \\\\\\ \||||||||
  000xxxxxx xxxxxxxxx
 */

uint16_t generateHash(uint32_t uid) {
    uint16_t hash, highword, lowword;

    highword = uid >> 16;
    lowword = uid & 0xFFFF;
    hash = highword ^ lowword;
    hash = (((hash << 3) & 0xFF00) | 0x0300) | (hash & 0x7F);
    return hash;
}
