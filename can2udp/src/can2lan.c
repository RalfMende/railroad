/* ----------------------------------------------------------------------------
 * "THE BEER-WARE LICENSE" (Revision 42):
 * <info@gerhard-bertelsmann.de> wrote this file. As long as you retain this
 * notice you can do whatever you want with this stuff. If we meet some day,
 * and you think this stuff is worth it, you can buy me a beer in return
 * Gerhard Bertelsmann
 * ----------------------------------------------------------------------------
 */

/* Thanks to Stefan Krauss and the SocketCAN team
 *
 * With contributions from Rainer Mueller
 */

#include "can2lan.h"
#include "cs2-core.h"
#include "ascii-frame.h"
#include "read-cs2-config.h"

extern struct track_page_t *track_page;
extern struct track_data_t *track_data;
extern struct loco_data_t *loco_data;
extern struct magnet_data_t *magnet_data;

static char *UDP_FORMAT_STRG      = "->CAN>UDP     0x%08X   [%d]";
static char *TCP_FORMAT_STRG      = "->TCP>CAN     0x%08X   [%d]";
static char *TCP_FORMATS_STRG     = "->TCP>CAN*    0x%08X   [%d]";
static char *CAN_TCP_FORMAT_STRG  = "->CAN>TCP     0x%08X   [%d]";
static char *UDP_TCP_FORMAT_STRG  = "->UDP>TCP     0x%08X   [%d]";
static char *UDP_UDP_FORMAT_STRG  = "->UDP>UDP     0x%08X   [%d]";
static char *NET_UDP_FORMAT_STRG  = "      UDP->   0x%08X   [%d]";

static char *PIDFILE = "/var/run/can2lan.pid";

char config_dir[MAXLINE];
char config_file[MAXLINE];
char **page_name;
char **cs2_page_name;
int pidfd, do_loop = 1;

static const int MAXPENDING = 16;       /* max outstanding tcp connections */
unsigned char netframe[MAXDG];

struct filter_t filter[2];

/* pending (incomplete) frame bytes of one TCP connection */
struct tcp_rx_buf {
    uint8_t data[CAN_ENCAP_SIZE];
    uint8_t len;
};

static void tcp_rx_reset(struct tcp_rx_buf *rx) {
    rx->len = 0;
}

/*
 * TCP is a byte stream and does not preserve packet boundaries: a read()
 * may return a partial 13-byte CAN frame or several frames at once.
 * Append received data to the per-connection reassembly buffer and copy
 * every complete 13-byte frame into frames (max_frames capacity).
 * Returns the number of complete frames. Bytes of an incomplete trailing
 * frame stay pending in rx until the next call.
 */
static int tcp_rx_feed(struct tcp_rx_buf *rx, const uint8_t *data, size_t len, uint8_t *frames, int max_frames) {
    size_t pos = 0;
    int count = 0;

    while (pos < len) {
	if (rx->len) {
	    /* complete the pending frame first */
	    size_t need = CAN_ENCAP_SIZE - rx->len;
	    size_t take = (need < len - pos) ? need : len - pos;
	    memcpy(&rx->data[rx->len], &data[pos], take);
	    rx->len += take;
	    pos += take;
	    if (rx->len < CAN_ENCAP_SIZE)
		break;
	    if (count < max_frames) {
		memcpy(&frames[count * CAN_ENCAP_SIZE], rx->data, CAN_ENCAP_SIZE);
		count++;
	    }
	    rx->len = 0;
	} else if (len - pos >= CAN_ENCAP_SIZE) {
	    if (count < max_frames) {
		memcpy(&frames[count * CAN_ENCAP_SIZE], &data[pos], CAN_ENCAP_SIZE);
		count++;
	    }
	    pos += CAN_ENCAP_SIZE;
	} else {
	    /* keep the incomplete trailing frame for the next call */
	    memcpy(rx->data, &data[pos], len - pos);
	    rx->len = len - pos;
	    pos = len;
	}
    }
    return count;
}

/* close a TCP client connection and release all per client state */
static void close_tcp_client(int *client, struct tcp_rx_buf *rx, fd_set *all_fds, unsigned int *connections) {
    if (rx && rx->len) {
	syslog(LOG_NOTICE, "%s: discarding %d bytes of incomplete CAN frame\n", __func__, rx->len);
	tcp_rx_reset(rx);
    }
    tcp_tx_unregister(*client);
    close(*client);
    FD_CLR(*client, all_fds);
    *client = -1;
    (*connections)--;
}

/* I/O context handed to the CS2 core (cs2-core.c): the core never touches
   sockets itself, all CAN/UDP/TCP transmission happens here in the gateway */
struct gw_io_ctx {
    int udp_socket;		/* UDP broadcast sending socket */
    struct sockaddr *udp_baddr;	/* UDP broadcast destination */
    int can_socket;		/* CAN socket */
    int *tcp_clients;		/* TCP client socket array */
    int *tcp_client_max;	/* index of the last used entry in tcp_clients */
};

static int gw_udp_send(void *arg, unsigned char *frame, int len) {
    struct gw_io_ctx *io = (struct gw_io_ctx *)arg;
    return net_to_net(io->udp_socket, io->udp_baddr, frame, len);
}

static int gw_tcp_send(void *arg, int tcp_socket, unsigned char *frame, int len) {
    (void)arg;
    return net_to_net(tcp_socket, NULL, frame, len);
}

static int gw_tcp_send_all(void *arg, unsigned char *frame, int len) {
    struct gw_io_ctx *io = (struct gw_io_ctx *)arg;
    int i, ret = 0;

    for (i = 0; i <= *io->tcp_client_max; i++) {
	if (io->tcp_clients[i] < 0)
	    continue;
	if (net_to_net(io->tcp_clients[i], NULL, frame, len) < 0)
	    ret = -1;
    }
    return ret;
}

static int gw_can_send(void *arg, unsigned char *frame) {
    struct gw_io_ctx *io = (struct gw_io_ctx *)arg;
    return frame_to_can(io->can_socket, frame);
}

static int gw_can_enqueue(void *arg, unsigned char *frame) {
    (void)arg;
    return can_tx_enqueue(frame);
}

static int gw_tcp_config_send(void *arg, char *name, uint32_t canid, int *tcp_socket_list, int socket_nmbr, int flags, uint8_t fill) {
    (void)arg;
    return send_tcp_config_data(name, config_dir, canid, tcp_socket_list, socket_nmbr, flags, fill);
}

static int gw_tcp_config_send_all(void *arg, char *name, uint32_t canid, int flags, uint8_t fill) {
    struct gw_io_ctx *io = (struct gw_io_ctx *)arg;
    return send_tcp_config_data(name, config_dir, canid, io->tcp_clients, *io->tcp_client_max + 1, flags, fill);
}

void signal_handler(int sig) {
    syslog(LOG_WARNING, "got signal %s\n", strsignal(sig));
    do_loop = 0;
}

void print_usage(char *prg) {
    fprintf(stderr, "\nUsage: %s -c <config_dir> -u <udp_port> -t <tcp_port> -d <udp_dest_port> -i <can interface>\n", prg);
    fprintf(stderr, "   Version 1.85\n\n");
    fprintf(stderr, "         -c <config_dir>     set the config directory\n");
    fprintf(stderr, "         -u <port>           listening UDP port for the server - default 15731\n");
    fprintf(stderr, "         -t <port>           listening TCP port for the server - default 15731\n");
    fprintf(stderr, "         -s <port>           second listening TCP server port - default 15732\n");
    fprintf(stderr, "         -d <port>           destination UDP port for the server - default 15730\n");
    fprintf(stderr, "         -b <bcast_addr/int> broadcast address or interface - default 255.255.255.255/br-lan\n");
    fprintf(stderr, "         -i <can int>        CAN interface - default can0\n");
    fprintf(stderr, "         -k                  use a connected CAN member as config source\n");
    fprintf(stderr, "         -g                  obsolete: use -S for slave mode)\n");
    fprintf(stderr, "         -S                  cs2-core acts like a central station in slave mode (default: master mode)\n");
    fprintf(stderr, "         -T                  timeout starting %s in sec - default %d sec\n", prg, MAX_UDP_BCAST_RETRY);
    fprintf(stderr, "         -m                  doing MS1 workaround - default: don't do it\n");
    fprintf(stderr, "         -x                  excluding mask/filter CAN->LAN e.g. \"0x00FF0000 0x00170000\"\n");
    fprintf(stderr, "         -f                  running in foreground\n");
    fprintf(stderr, "         -v                  verbose output (in foreground)\n\n");
}

int main(int argc, char **argv) {
	int n, i, j, max_fds, opt, max_tcp_i, nready, conn_fd, timeout, ret, tcp_client[MAX_TCP_CONN], tcp_client2[MAX_TCP_CONN];
    struct sigaction sigact;
    sigset_t blockset, emptyset;
    struct can_frame frame;
    char timestamp[16];
    /* per TCP client reassembly buffer for incomplete 13-byte frames */
    struct tcp_rx_buf tcp_rx[MAX_TCP_CONN];
    unsigned char tcp_frames[MAXDG + CAN_ENCAP_SIZE];
    /* UDP incoming socket, CAN socket, UDP broadcast socket, TCP socket */
    int sa, sc, sb, st, st2, tcp_socket;
    struct sockaddr_in saddr, baddr, tcp_addr, tcp_addr2;
    /* vars for determing broadcast address */
    struct sockaddr_can caddr;
    struct ifreq ifr;
    socklen_t caddrlen = sizeof(caddr);
    socklen_t tcp_client_length = sizeof(tcp_addr);
    fd_set all_fds, read_fds, write_fds;
    int free_slots, rdlen, short_wait;
    long can_wait;
    int s = 0;
    unsigned int tcp_connections = 0;
    struct timespec ts;
    char *udp_dst_address;
    char *bcast_interface;
    char *searchif;
    char *tempsp;
    char *loco_file;
    struct cs2_core_t core = { 0 };	/* cs2_core_init() preserves the options parsed before it runs */
    struct cs2_core_io core_io;
    struct gw_io_ctx gw_io;
    uint32_t id, mask;

    pidfd = 0;
    int local_udp_port = 15731;
    int local_tcp_port = 15731;
    int local2_tcp_port = 15732;
    int destination_port = 15730;
    int background = 1;
    /* const int off = 0; */
    const int on = 1;
    uint32_t canid;
    char buffer[64];

    memset(&filter, 0, sizeof(filter));

    /* the CS2 core delegates all CAN/UDP/TCP transmission to the gateway */
    gw_io.udp_socket = -1;
    gw_io.udp_baddr = NULL;
    gw_io.can_socket = -1;
    gw_io.tcp_clients = tcp_client;
    gw_io.tcp_client_max = &max_tcp_i;
    core_io.arg = &gw_io;
    core_io.udp_send = gw_udp_send;
    core_io.tcp_send = gw_tcp_send;
    core_io.tcp_send_all = gw_tcp_send_all;
    core_io.can_send = gw_can_send;
    core_io.can_enqueue = gw_can_enqueue;
    core_io.tcp_config_send = gw_tcp_config_send;
    core_io.tcp_config_send_all = gw_tcp_config_send_all;

    page_name = calloc(MAX_TRACK_PAGE, sizeof(char *));
    if (!page_name) {
	fprintf(stderr, "can't alloc memory for page_name: %s\n", strerror(errno));
	exit(EXIT_FAILURE);
    };

    cs2_page_name = calloc(MAX_TRACK_PAGE, sizeof(char *));
    if (!cs2_page_name) {
	fprintf(stderr, "can't alloc memory for cs2_page_name: %s\n", strerror(errno));
	exit(EXIT_FAILURE);
    };

    core.cfg.page_name = cs2_page_name;

    memset(ifr.ifr_name, 0, sizeof(ifr.ifr_name));
    strcpy(ifr.ifr_name, "can0");
    memset(config_dir, 0, sizeof(config_dir));

    udp_dst_address = (char *)calloc(MAXIFLEN, 1);
    if (!udp_dst_address) {
	fprintf(stderr, "can't alloc memory for udp_dst_address: %s\n", strerror(errno));
	exit(EXIT_FAILURE);
    };

    bcast_interface = (char *)calloc(MAXIFLEN, 1);
    if (!bcast_interface) {
	fprintf(stderr, "can't alloc memory for bcast_interface: %s\n", strerror(errno));
	exit(EXIT_FAILURE);
    };

    timeout = MAX_UDP_BCAST_RETRY;
    strcpy(udp_dst_address, "255.255.255.255");
    strcpy(bcast_interface, "br-lan");

    config_file[0] = '\0';

    while ((opt = getopt(argc, argv, "c:u:s:t:d:b:i:kT:x:gSmvhf?")) != -1) {
	switch (opt) {
	case 'c':
	    if (strnlen(optarg, MAXLINE) < MAXLINE) {
		strncpy(config_dir, optarg, sizeof(config_dir) - 1);
	    } else {
		fprintf(stderr, "config file dir to long\n");
		exit(EXIT_FAILURE);
	    }
	    break;
	case 'u':
	    local_udp_port = strtoul(optarg, (char **)NULL, 10);
	    break;
	case 't':
	    local_tcp_port = strtoul(optarg, (char **)NULL, 10);
	    break;
	case 's':
	    local2_tcp_port = strtoul(optarg, (char **)NULL, 10);
	    break;
	case 'd':
	    destination_port = strtoul(optarg, (char **)NULL, 10);
	    break;
	case 'b':
	    if (strnlen(optarg, MAXIFLEN) <= MAXIFLEN - 1) {
		/* IP address begins with a number */
		if ((optarg[0] >= '0') && (optarg[0] <= '9')) {
		    strncpy(udp_dst_address, optarg, MAXIFLEN - 1);
		} else {
		    memset(udp_dst_address, 0, MAXIFLEN);
		    strncpy(bcast_interface, optarg, MAXIFLEN - 1);
		}
	    } else {
		fprintf(stderr, "UDP broadcast address or interface error: %s\n", optarg);
		exit(EXIT_FAILURE);
	    }
	    break;
	case 'i':
	    strncpy(ifr.ifr_name, optarg, sizeof(ifr.ifr_name) - 1);
	    break;
	case 'k':
	    core.cfg.cs2_config_copy = 1;
	    break;
	case 'T':
	    timeout = strtoul(optarg, (char **)NULL, 10);
	    break;
	case 'g':
	    /* kept for backward compatibility, no effect: the periodic ping is
	       now sent by default (master mode); use -S for the old behaviour */
	    fprintf(stderr, "warning: option -g is obsolete and ignored (use -S for slave mode)\n");
	    syslog(LOG_WARNING, "option -g is obsolete and ignored (use -S for slave mode)");
	    break;
	case 'S':
	    core.slave = 1;
	    break;
	case 'm':
	    core.ms1_workaround = 1;
	    break;
	case 'v':
	    core.cfg.verbose = 1;
	    break;
	case 'f':
	    background = 0;
	    break;
	case 'x':
	    if (sscanf(optarg, "%x %x", &mask, &id) != 2) {
		fprintf(stderr, "error scanning filter mask/id%s\n", optarg);
		exit(EXIT_FAILURE);
	    }
	    if (filter[0].use) {
		filter[1].mask = mask;
		filter[1].id = id;
		filter[1].use = 1;
	    } else {
		filter[0].mask = mask;
		filter[0].id = id;
		filter[0].use = 1;
	    }
	    break;
	case 'h':
	case '?':
	    print_usage(basename(argv[0]));
	    exit(EXIT_SUCCESS);
	default:
	    fprintf(stderr, "Unknown option %c\n", opt);
	    print_usage(basename(argv[0]));
	    exit(EXIT_FAILURE);
	}
    }

    /* read track file */
    if (config_dir[0] == 0) {
	strcat(config_file, ".");
    }

    strcat(config_file, config_dir);
    if (config_dir[strlen(config_dir) - 1] != '/') {
	strcat(config_file, "/");
    }
    strncpy(config_dir, config_file, sizeof(config_dir) - 1);
    strcat(config_file, "gleisbild.cs2");

    core.cfg.dir = config_dir;

    page_name = read_track_file(config_file, page_name);

    /* read loco data */
    if (asprintf(&loco_file, "%s%s", config_dir, "lokomotive.cs2") < 0)
	fprintf(stderr, "can't alloc buffer for loco_name: %s\n", strerror(errno));
    else
	read_loco_data(loco_file, CONFIG_FILE);
    free(loco_file);

    /* we are trying to setup a UDP socket */
    if (udp_dst_address[0]) {
	memset(&baddr, 0, sizeof(baddr));
	baddr.sin_family = AF_INET;
	baddr.sin_port = htons(destination_port);
	s = inet_pton(AF_INET, udp_dst_address, &baddr.sin_addr);
    } else {
	for (i = 0; i < timeout; i++) {
	    /* trying to get the broadcast address */
	    tempsp = strdup(bcast_interface);
	    /* storing pointer for freeing memory */
	    char *sf = tempsp;
	    while ((searchif = strsep(&tempsp, ","))) {
		free(udp_dst_address);
		udp_dst_address = search_interface(searchif);
		if (udp_dst_address)
		    break;
	    }
	    free(sf);
	    /* try to prepare UDP sending socket struct */
	    if (udp_dst_address) {
		memset(&baddr, 0, sizeof(baddr));
		baddr.sin_family = AF_INET;
		baddr.sin_port = htons(destination_port);
		s = inet_pton(AF_INET, udp_dst_address, &baddr.sin_addr);
		if (s > 0)
		    break;
	    }
	    sleep(1);
	}
    }
    /* check if we got a real UDP socket after MAX_UDP_BCAST_TRY seconds */
    if (s <= 0) {
	if (s == 0) {
	    fprintf(stderr, "UDP IP address invalid\n");
	} else {
	    fprintf(stderr, "invalid address family\n");
	}
	exit(EXIT_FAILURE);
    }

    if (core.cfg.verbose && !background)
	printf("using broadcast address %s\n", udp_dst_address);

    /* prepare UDP sending socket */
    sb = socket(AF_INET, SOCK_DGRAM, 0);
    if (sb < 0) {
	fprintf(stderr, "error creating UDP sending socket: %s\n", strerror(errno));
	exit(EXIT_FAILURE);
    }
    if (setsockopt(sb, SOL_SOCKET, SO_BROADCAST, &on, sizeof(on)) < 0) {
	fprintf(stderr, "error setup UDP broadcast option: %s\n", strerror(errno));
	exit(EXIT_FAILURE);
    }
    gw_io.udp_socket = sb;
    gw_io.udp_baddr = (struct sockaddr *)&baddr;
    free(udp_dst_address);
    free(bcast_interface);

    /* prepare reading UDP socket */
    memset(&saddr, 0, sizeof(saddr));
    saddr.sin_family = AF_INET;
    saddr.sin_addr.s_addr = htonl(INADDR_ANY);
    saddr.sin_port = htons(local_udp_port);
    sa = socket(PF_INET, SOCK_DGRAM, 0);
    if (sa < 0) {
	fprintf(stderr, "creating UDP reading socket error: %s\n", strerror(errno));
	exit(EXIT_FAILURE);
    }
    if (bind(sa, (struct sockaddr *)&saddr, sizeof(saddr)) < 0) {
	fprintf(stderr, "binding UDP reading socket error: %s\n", strerror(errno));
	exit(EXIT_FAILURE);
    }

    /* prepare TCP socket */
    st = socket(PF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (st < 0) {
	fprintf(stderr, "creating TCP socket error: %s\n", strerror(errno));
	exit(EXIT_FAILURE);
    }

    tcp_addr.sin_family = AF_INET;
    tcp_addr.sin_addr.s_addr = htonl(INADDR_ANY);
    tcp_addr.sin_port = htons(local_tcp_port);
    if (bind(st, (struct sockaddr *)&tcp_addr, sizeof(tcp_addr)) < 0) {
	fprintf(stderr, "binding TCP socket error: %s\n", strerror(errno));
	exit(EXIT_FAILURE);
    }
    if (listen(st, MAXPENDING) < 0) {
	fprintf(stderr, "starting TCP listener error: %s\n", strerror(errno));
	exit(EXIT_FAILURE);
    }
    /* prepare TCP clients array */
    max_tcp_i = -1;		/* index into tcp_client[] array */
    memset(tcp_client, -1, sizeof(tcp_client));
    memset(tcp_client2, -1, sizeof(tcp_client2));
    memset(tcp_rx, 0, sizeof(tcp_rx));

    /* prepare second TCP socket */
    st2 = socket(PF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (st2 < 0) {
	fprintf(stderr, "creating second TCP socket error: %s\n", strerror(errno));
	exit(EXIT_FAILURE);
    }
    tcp_addr2.sin_family = AF_INET;
    tcp_addr2.sin_addr.s_addr = htonl(INADDR_ANY);
    tcp_addr2.sin_port = htons(local2_tcp_port);
    if (bind(st2, (struct sockaddr *)&tcp_addr2, sizeof(tcp_addr2)) < 0) {
	fprintf(stderr, "binding second TCP socket error: %s\n", strerror(errno));
	exit(EXIT_FAILURE);
    }
    if (listen(st2, MAXPENDING) < 0) {
	fprintf(stderr, "starting TCP listener error: %s\n", strerror(errno));
	exit(EXIT_FAILURE);
    }

    /* prepare CAN socket */
    memset(&caddr, 0, sizeof(caddr));
    sc = socket(PF_CAN, SOCK_RAW, CAN_RAW);
    if (sc < 0) {
	fprintf(stderr, "creating CAN socket error: %s\n", strerror(errno));
	exit(EXIT_FAILURE);
    }
    caddr.can_family = AF_CAN;
    if (ioctl(sc, SIOCGIFINDEX, &ifr) < 0) {
	fprintf(stderr, "setup CAN error: %s\n", strerror(errno));
	exit(EXIT_FAILURE);
    }
    caddr.can_ifindex = ifr.ifr_ifindex;

    if (bind(sc, (struct sockaddr *)&caddr, caddrlen) < 0) {
	fprintf(stderr, "binding CAN socket error: %s\n", strerror(errno));
	exit(EXIT_FAILURE);
    }

    gw_io.can_socket = sc;

    /* init the CS2 core: in master mode this sends the 60113 start sequence
       and arms the periodic CAN member ping timer */
    if (cs2_core_init(&core, &core_io))
	exit(EXIT_FAILURE);

    /* daemonize the process if requested */
    if (background) {
	/* normally only root can write PID file */
	if (getuid() == 0) {
	    pidfd = open(PIDFILE, O_RDWR | O_CREAT | O_EXCL | O_NOCTTY, S_IRUSR | S_IWUSR | S_IRGRP | S_IROTH);
	    if (pidfd < 0) {
		fprintf(stderr, "Cannot open PID file %s\n", PIDFILE);
		exit(EXIT_FAILURE);
	    }
	}
	if (daemon(0, 0) < 0) {
	    fprintf(stderr, "Going into background failed: %s\n", strerror(errno));
	    exit(EXIT_FAILURE);
	}
	if (dprintf(pidfd, "%d\n", getpid()) < 0) {
	    syslog(LOG_ERR, "Cannot write to PID file %s\n", PIDFILE);
	    exit(EXIT_FAILURE);
	}
	if (close(pidfd) == -1) {
	    syslog(LOG_ERR, "Cannot close PID file %s\n", PIDFILE);
	    exit(EXIT_FAILURE);
	}
    }
    setlogmask(LOG_UPTO(LOG_NOTICE));
    openlog("can2lan", LOG_CONS | LOG_NDELAY, LOG_DAEMON);

    sigemptyset(&blockset);
    sigaddset(&sigact.sa_mask, SIGHUP);
    sigaddset(&sigact.sa_mask, SIGINT);
    sigaddset(&sigact.sa_mask, SIGTERM);
    if (sigprocmask(SIG_BLOCK, &blockset, NULL) < 0) {
	fprint_syslog(stderr, LOG_ERR, "cannot set SIGNAL block mask\n");
	return (EXIT_FAILURE);
    }

    sigact.sa_handler = signal_handler;
    sigact.sa_flags = 0;
    sigemptyset(&sigact.sa_mask);
    sigaction(SIGHUP, &sigact, NULL);
    sigaction(SIGINT, &sigact, NULL);
    sigaction(SIGTERM, &sigact, NULL);
    /* writing to a disconnected TCP client must not kill the process -
       sendto() then fails with EPIPE and the client is cleaned up on the
       next read */
    sigact.sa_handler = SIG_IGN;
    sigaction(SIGPIPE, &sigact, NULL);
    sigemptyset(&emptyset);

    /* the select() timeout is set in the loop: 1 sec for the core's periodic
       CAN member ping, shorter while CAN frames are waiting for their pacing time */
    FD_ZERO(&all_fds);
    FD_SET(sc, &all_fds);
    FD_SET(sa, &all_fds);
    FD_SET(st, &all_fds);
    FD_SET(st2, &all_fds);
    max_fds = MAX(MAX(MAX(sc, sa), st), st2);

    while (do_loop) {
	/* send what the clients couldn't take yet, close clients which can't keep up */
	tcp_tx_flush_all();
	for (i = 0; i <= max_tcp_i; i++) {
	    if ((tcp_client[i] >= 0) && tcp_tx_dead(tcp_client[i])) {
		syslog(LOG_NOTICE, "%s: closing TCP client fd %d - can't keep up with the CAN traffic\n", __func__, tcp_client[i]);
		close_tcp_client(&tcp_client[i], &tcp_rx[i], &all_fds, &tcp_connections);
	    }
	}

	/* write the next CAN frame if its pacing time has elapsed, otherwise wake up in time */
	can_wait = can_tx_service(sc);
	if ((can_wait >= 0) && (can_wait < 1000000)) {
	    ts.tv_sec = 0;
	    ts.tv_nsec = can_wait * 1000;
	    short_wait = 1;
	} else {
	    ts.tv_sec = 1;
	    ts.tv_nsec = 0;
	    short_wait = 0;
	}

	read_fds = all_fds;
	FD_ZERO(&write_fds);
	tcp_tx_fill_wfds(&write_fds);
	/* back pressure: don't read more than the CAN queue can take. TCP data stays in the
	   kernel buffer and slows the sender down, UDP is only lost if the kernel buffer overflows */
	free_slots = can_tx_free();
	if (free_slots < 1)
	    FD_CLR(sa, &read_fds);
	if (free_slots < 2) {
	    for (i = 0; i <= max_tcp_i; i++) {
		if (tcp_client[i] >= 0)
		    FD_CLR(tcp_client[i], &read_fds);
	    }
	}
	/* a read of rdlen bytes yields at most free_slots - 1 complete frames, even with a pending partial frame */
	rdlen = MIN((free_slots - 1) * CAN_ENCAP_SIZE, MAXDG);

	nready = pselect(max_fds + 1, &read_fds, &write_fds, NULL, &ts, &emptyset);
	if (nready == 0) {
	    /* woke up only because the next CAN frame is due */
	    if (short_wait)
		continue;
	    /* 1-second tick: services the core's master-mode ping timer */
	    cs2_core_tick(&core);
	    continue;
	} else if (nready < 0) {
	    if (!background)
		fprintf(stderr, "select exception: [%d] %s\n", nready, strerror(errno));
	    syslog(LOG_WARNING, "select exception: [%d] %s\n", nready, strerror(errno));
	    continue;
	}

	/* TCP clients which can take more of their queued data */
	for (i = 0; i <= max_tcp_i; i++) {
	    if ((tcp_client[i] >= 0) && FD_ISSET(tcp_client[i], &write_fds)) {
		tcp_tx_flush_fd(tcp_client[i]);
		nready--;
	    }
	}

	/* received a CAN frame */
	if (FD_ISSET(sc, &read_fds)) {
	    /* reading via SockatCAN */
	    n = read(sc, &frame, sizeof(struct can_frame));
	    if (n < 0) {
		fprintf(stderr, "reading CAN frame error: %s\n", strerror(errno));
		syslog(LOG_ERR, "%s: reading CAN frame error: %s\n", __func__, strerror(errno));
	    }
	    /* if CAN Frame is EFF do it - but never forward the previous frame again after a failed read */
	    if ((n == (int)sizeof(struct can_frame)) && (frame.can_id & CAN_EFF_FLAG)) {	/* only EFF frames are valid */
		/* the core sees every frame on the CAN bus and may consume it (config change broadcast) */
		if (!cs2_core_handle_can_frame(&core, &frame)) {
		    /* send UDP frame */
		    frame_to_net(sb, (struct sockaddr *)&baddr, (struct can_frame *)&frame);
		    print_can_frame(UDP_FORMAT_STRG, netframe, core.cfg.verbose && !background);
		    /* send CAN frame to all connected TCP clients */
		    /* TODO: need all clients the packets ? */
		    for (i = 0; i <= max_tcp_i; i++) {	/* check all clients for data */
			tcp_socket = tcp_client[i];
			if (tcp_socket < 0)
			    continue;
			frame_to_net(tcp_socket, (struct sockaddr *)&tcp_addr, (struct can_frame *)&frame);
			print_can_frame(CAN_TCP_FORMAT_STRG, netframe, core.cfg.verbose && !background);
		    }
		}
	    }
	}
	/* received a UDP packet */
	if (FD_ISSET(sa, &read_fds)) {
	    if (read(sa, netframe, MAXDG) == CAN_ENCAP_SIZE) {
		/* check for S88 events on send them to TCP connected clients */
		memcpy(&canid, netframe, 4);
		canid = ntohl(canid);
		if ((canid & 0x00230000) == 0x00230000) {
		    for (i = 0; i <= max_tcp_i; i++) {
			tcp_socket = tcp_client[i];
			if (tcp_socket < 0)
			    continue;
			net_to_net(tcp_socket, NULL, netframe, CAN_ENCAP_SIZE);
			print_can_frame(UDP_TCP_FORMAT_STRG, netframe, core.cfg.verbose && !background);
		    }
		    net_to_net(sb, (struct sockaddr *)&baddr, netframe, CAN_ENCAP_SIZE);
		    print_can_frame(UDP_UDP_FORMAT_STRG, netframe, core.cfg.verbose && !background);
		} else {
		    /* queue the packet for the CAN bus (the queue has room: sa isn't read when it is full) */
		    ret = can_tx_enqueue(netframe);
		    print_can_frame(NET_UDP_FORMAT_STRG, netframe, core.cfg.verbose && !background);
		    cs2_core_handle_frame(&core, CS2_SRC_UDP, -1, netframe);
		}
	    }
	}
	/* received a TCP packet */
	if (FD_ISSET(st, &read_fds)) {
	    conn_fd = accept(st, (struct sockaddr *)&tcp_addr, &tcp_client_length);
	    if (conn_fd < 0) {
		syslog(LOG_ERR, "%s: accept on TCP port failed: %s\n", __func__, strerror(errno));
		if (--nready <= 0)
		    continue;
	    } else {
	    if (core.cfg.verbose && !background) {
		printf("new client request: %s, port %d conn fd: %d max fds: %d active tcp_cons: %d\n", inet_ntop(AF_INET, &(tcp_addr.sin_addr),
			buffer, sizeof(buffer)), ntohs(tcp_addr.sin_port), conn_fd, max_fds, tcp_connections);
	    }
	    syslog(LOG_NOTICE, "%s: new client request: %s port %d conn fd: %d max fds: %d active tcp_cons: %d\n", __func__,
			 inet_ntop(AF_INET, &(tcp_addr.sin_addr), buffer, sizeof(buffer)), ntohs(tcp_addr.sin_port), conn_fd, max_fds, tcp_connections);

	    if (tcp_connections == MAX_TCP_CONN) {
		shutdown(conn_fd, SHUT_RDWR);
		close(conn_fd);
		fprintf(stderr, "too many TCP clients\n");
		syslog(LOG_ERR, "%s: too many TCP clients\n", __func__);
	    } else {
		tcp_connections++;
		for (i = 0; i < MAX_TCP_CONN; i++) {
		    if (tcp_client[i] < 0) {
			tcp_client[i] = conn_fd;	/* save new TCP client descriptor */
			break;
		    }
		}
		FD_SET(conn_fd, &all_fds);		/* add new descriptor to set */
		max_fds = MAX(conn_fd, max_fds);	/* for select */
		max_tcp_i = MAX(i, max_tcp_i);		/* max index in tcp_client[] array */
		tcp_tx_register(conn_fd);		/* send queue of the new client */
		/* send embedded CAN member ping */
		memcpy(netframe, M_CAN_MEMBER_PING, CAN_ENCAP_SIZE);
		net_to_net(conn_fd, NULL, netframe, CAN_ENCAP_SIZE);
		if (core.cfg.verbose && !background)
		    printf("send embedded CAN ping\n");
	    }
	    }

	    if (--nready <= 0)
		continue;	/* no more readable descriptors */
	}
	/* received a packet on second TCP port */
	if (FD_ISSET(st2, &read_fds)) {
	    conn_fd = accept(st2, (struct sockaddr *)&tcp_addr2, &tcp_client_length);
	    if (conn_fd < 0) {
		syslog(LOG_ERR, "%s: accept on second TCP port failed: %s\n", __func__, strerror(errno));
		if (--nready <= 0)
		    continue;
	    } else {
	    if (core.cfg.verbose && !background) {
		printf("new client request: %s, port %d conn fd: %d max fds: %d active tcp_cons:%d\n", inet_ntop(AF_INET, &(tcp_addr2.sin_addr),
			buffer, sizeof(buffer)), ntohs(tcp_addr2.sin_port), conn_fd, max_fds, tcp_connections);
	    }
	    syslog(LOG_NOTICE, "%s: new client request: %s port %d conn fd: %d max fds: %d active tcp_cons:%d\n", __func__,
			 inet_ntop(AF_INET, &(tcp_addr2.sin_addr), buffer, sizeof(buffer)), ntohs(tcp_addr2.sin_port), conn_fd, max_fds, tcp_connections);
	    if (tcp_connections == MAX_TCP_CONN) {
		shutdown(conn_fd, SHUT_RDWR);
		close(conn_fd);
		fprintf(stderr, "too many TCP clients\n");
		syslog(LOG_ERR, "%s: too many TCP clients\n", __func__);
	    } else {
		tcp_connections++;
		for (i = 0; i < MAX_TCP_CONN; i++) {
		    if (tcp_client2[i] < 0) {
			tcp_client2[i] = conn_fd;	/* save new TCP client descriptor */
			break;
		    }
		}
		FD_SET(conn_fd, &all_fds);		/* add new descriptor to set */
		max_fds = MAX(conn_fd, max_fds);	/* for select */
		max_tcp_i = MAX(i, max_tcp_i);	/* max index in tcp_client[] array */
	    }
	    }

	    if (--nready <= 0)
		continue;	/* no more readable descriptors */
	}

	/* check for already connected TCP clients */
	for (i = 0; i <= max_tcp_i; i++) {	/* check all clients for data */
	    tcp_socket = tcp_client[i];
	    if (tcp_socket < 0)
		continue;
	    /* printf("%s tcp packet received from client #%d  max_tcp_i:%d todo:%d\n", time_stamp(timestamp), i, max_tcp_i,nready); */
	    if (FD_ISSET(tcp_socket, &read_fds)) {
		if (core.cfg.verbose && !background) {
		    time_stamp(timestamp);
		    printf("%s packet from: %s\n", timestamp, inet_ntop(AF_INET, &tcp_addr.sin_addr, buffer, sizeof(buffer)));
		}
		n = read(tcp_socket, netframe, rdlen);
		if ((n < 0) && ((errno == EINTR) || (errno == EAGAIN) || (errno == EWOULDBLOCK))) {
		    /* nothing to read after all - try again with the next select() */
		} else if (n <= 0) {
		    /* connection closed by client or read error (e.g. ECONNRESET) */
		    if (n < 0)
			syslog(LOG_ERR, "%s: reading TCP data error: %s\n", __func__, strerror(errno));
		    if (core.cfg.verbose && !background) {
			time_stamp(timestamp);
			printf("%s client %s closed connection\n", timestamp, inet_ntop(AF_INET, &tcp_addr.sin_addr, buffer, sizeof(buffer)));
		    }
		    syslog(LOG_NOTICE, "%s: client %s closed connection\n", __func__, inet_ntop(AF_INET, &tcp_addr.sin_addr, buffer, sizeof(buffer)));
		    close_tcp_client(&tcp_client[i], &tcp_rx[i], &all_fds, &tcp_connections);
		} else {
		    /* TCP is a byte stream: reassemble complete 13-byte CAN frames per connection */
		    int nframes = tcp_rx_feed(&tcp_rx[i], netframe, n, tcp_frames, sizeof(tcp_frames) / CAN_ENCAP_SIZE);
		    for (j = 0; j < nframes; j++) {
			if (!cs2_core_handle_frame(&core, CS2_SRC_TCP, tcp_socket, &tcp_frames[j * CAN_ENCAP_SIZE])) {
			    ret = can_tx_enqueue(&tcp_frames[j * CAN_ENCAP_SIZE]);
			    if (!ret) {
				if (j > 0)
				    print_can_frame(TCP_FORMATS_STRG, &tcp_frames[j * CAN_ENCAP_SIZE], core.cfg.verbose && !background);
				else
				    print_can_frame(TCP_FORMAT_STRG, &tcp_frames[j * CAN_ENCAP_SIZE], core.cfg.verbose && !background);
			    }
			    net_to_net(sb, (struct sockaddr *)&baddr, &tcp_frames[j * CAN_ENCAP_SIZE], CAN_ENCAP_SIZE);
			    print_can_frame(UDP_FORMAT_STRG, &tcp_frames[j * CAN_ENCAP_SIZE], core.cfg.verbose && !background);
			}
		    }
		}
		if (--nready <= 0)
		    break;	/* no more readable descriptors */
	    }
	}
	/* packet on the second TCP port */
	for (i = 0; i <= max_tcp_i; i++) {	/* check all clients for data */
	    tcp_socket = tcp_client2[i];
	    if (tcp_socket < 0)
		continue;
	    if (FD_ISSET(tcp_socket, &read_fds)) {
		if (core.cfg.verbose && !background) {
		    time_stamp(timestamp);
		    printf("%s TCP2 socket packet from: %s\n", timestamp, inet_ntop(AF_INET, &tcp_addr2.sin_addr, buffer, sizeof(buffer)));
		}
		n = read(tcp_socket, netframe, MAXDG);
		if ((n < 0) && ((errno == EINTR) || (errno == EAGAIN) || (errno == EWOULDBLOCK))) {
		    /* nothing to read after all - try again with the next select() */
		} else if (n <= 0) {
		    /* connection closed by client or read error (e.g. ECONNRESET) */
		    if (n < 0)
			syslog(LOG_ERR, "%s: reading TCP2 data error: %s\n", __func__, strerror(errno));
		    if (core.cfg.verbose && !background) {
			time_stamp(timestamp);
			printf("%s client %s closed connection\n", timestamp, inet_ntop(AF_INET, &tcp_addr2.sin_addr, buffer, sizeof(buffer)));
		    }
		    syslog(LOG_NOTICE, "%s: client %s closed connection\n", __func__, inet_ntop(AF_INET, &tcp_addr2.sin_addr, buffer, sizeof(buffer)));
		    close_tcp_client(&tcp_client2[i], NULL, &all_fds, &tcp_connections);
		} else {
		    decode_ascii_frame(tcp_socket, netframe, n);
		}
		if (--nready <= 0)
		    break;	/* no more readable descriptors */
	    }
	}
    }
    free_track_file(page_name);
    free(page_name);
    /* free(udp_dst_address); */
    free(cs2_page_name);
    closelog();
    close(sc);
    close(sa);
    close(sb);
    close(st);
    close(st2);
    if (pidfd) {
	if (unlink(PIDFILE) == -1) {
	    syslog(LOG_ERR, "Cannot remove pidfile '%s'\n", PIDFILE);
	    exit(EXIT_FAILURE);
	}
    }
    return (EXIT_SUCCESS);
}
