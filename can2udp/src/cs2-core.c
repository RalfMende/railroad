/* ----------------------------------------------------------------------------
 * "THE BEER-WARE LICENSE" (Revision 42):
 * <info@gerhard-bertelsmann.de> wrote this file. As long as you retain this
 * notice you can do whatever you want with this stuff. If we meet some day,
 * and you think this stuff is worth it, you can buy me a beer in return
 * Gerhard Bertelsmann
 * ----------------------------------------------------------------------------
 */

/* CS2 protocol emulation core (split out of can2lan.c):
 * CAN member ping handling, config data requests/streams and the config
 * clone state machine. The core never touches sockets itself - all
 * CAN/UDP/TCP transmission is delegated to the gateway (can2lan.c)
 * through the struct cs2_core_io callbacks.
 */

#include "cs2-core.h"

static char *CAN_FORMAT_STRG     = "      CAN->   0x%08X R [%d]";
static char *NET_UDP_FORMAT_STRG = "      UDP->   0x%08X   [%d]";
static char *NET_TCP_FORMAT_STRG = "      TCP->   0x%08X   [%d]";

static char *BROADCAST_C0NFIG_UPDATE = "broadcast_update.cs2";

/* Gleisbox (60113) start sequence: magic frame + enable all loco protocols */
static unsigned char M_GLEISBOX_MAGIC_START_SEQUENCE[] =
    { 0x00, 0x36, 0x03, 0x01, 0x05, 0x00, 0x00, 0x00, 0x00, 0x11, 0x00, 0x00, 0x00 };
static unsigned char M_GLEISBOX_ALL_PROTO_ENABLE[] =
    { 0x00, 0x00, 0x03, 0x01, 0x06, 0x00, 0x00, 0x00, 0x00, 0x08, 0x07, 0x00, 0x00 };
/* CAN member ping (also sent by the gateway to new TCP clients) */
unsigned char M_CAN_PING[] =
    { 0x00, 0x30, 0x47, 0x11, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 };
/* fake CS2 ping answers of further bus members, sent in slave mode */
static unsigned char M_CAN_PING_CS2_1[] =
    { 0x00, 0x31, 0x63, 0x4A, 0x08, 0x00, 0x00, 0x00, 0x00, 0x04, 0x02, 0xFF, 0xF0 };
static unsigned char M_CAN_PING_CS2_2[] =
    { 0x00, 0x31, 0x63, 0x4B, 0x08, 0x00, 0x00, 0x00, 0x00, 0x03, 0x44, 0x00, 0x00 };
/* our CAN member ping answer (slave mode): response bit set, DLC 8,
   SW version 0x0402, device id 0xFFFF (CS2-GUI) */
static unsigned char M_CAN_PING_CS2_3[] =
    { 0x00, 0x31, 0x03, 0x00, 0x08, 0x00, 0x00, 0x00, 0x00, 0x04, 0x02, 0xFF, 0xFF };
static unsigned char M_PING_RESPONSE[] =
    { 0x00, 0x30, 0x00, 0x00, 0x00 };

/* config data stream commands (GETCONFIG_DATA is also used by gio.c) */
unsigned char GETCONFIG[]      = { 0x00, 0x40, 0xaf, 0x7e, 0x08 };
unsigned char GETCONFIG_DATA[] = { 0x00, 0x42, 0x03, 0x00, 0x08 };

/* config request name -> local config file (also used by gio.c) */
char *cs2_configs[][2] = {
    { "loks", "lokomotive.cs2" },
    { "mags", "magnetartikel.cs2" },
    { "fs", "fahrstrassen.cs2" },
    { "gbs", "gleisbild.cs2" },
    { "lokstat", "lokomotive.sr2" },
    { "magstat", "magnetartikel.sr2" },
    { "gbsstat", "gleisbild.sr2" },
    { "fsstat", "fahrstrassen.sr2" },
    { NULL, NULL },
};

char *ms2_configs[] = {
    "lokinfo",
    "loknamen",
    "maginfo",
    "lokdb",
    "lang",
    "ldbver",
    "langver",
    NULL
};

/* track pages of the local gleisbild.cs2, owned by the gateway */
extern char **page_name;

/*
 * Initialize the core context and store the gateway I/O callbacks.
 * The config clone state machine starts inactive.
 */
void cs2_core_init(struct cs2_core_t *core, const struct cs2_core_io *io) {
    memset(core, 0, sizeof(*core));
    core->io = *io;
    core->cfg.state = CS2_STATE_INACTIVE;
    core->cfg.track_index = MAX_TRACK_PAGE;
}

/*
 * Send the Gleisbox (60113) start sequence to the CAN bus: the magic start
 * frame followed by the frame enabling all loco protocols. Returns -1 if a
 * frame could not be sent.
 */
int cs2_core_send_start_frames(struct cs2_core_t *core) {
    if (core->io.can_send(core->io.arg, M_GLEISBOX_MAGIC_START_SEQUENCE) < 0) {
	fprint_syslog(stderr, LOG_ERR, "can't send CAN magic 60113 start sequence");
	return -1;
    } else {
	if (core->cfg.verbose) {
	    printf("                CAN magic 60113 start written\n");
	    print_can_frame(CAN_FORMAT_STRG, M_GLEISBOX_MAGIC_START_SEQUENCE, core->cfg.verbose);
	}
    }
    if (core->io.can_send(core->io.arg, M_GLEISBOX_ALL_PROTO_ENABLE) < 0) {
	fprint_syslog(stderr, LOG_ERR, "can't enable all loco protos");
	return -1;
    } else {
	if (core->cfg.verbose) {
	    printf("                CAN enabled all loco protos\n");
	    print_can_frame(CAN_FORMAT_STRG, M_GLEISBOX_ALL_PROTO_ENABLE, core->cfg.verbose);
	}
    }

    return 0;
}

/* Send a CAN member ping to the CAN bus. Returns -1 on send error. */
int cs2_core_send_ping(struct cs2_core_t *core) {
    if (core->io.can_send(core->io.arg, M_CAN_PING) < 0) {
	fprint_syslog(stderr, LOG_ERR, "can't send CAN Ping");
	return -1;
    } else {
	if (core->cfg.verbose) {
	    /* printf("                CAN Ping sent\n"); */
	    print_can_frame(CAN_FORMAT_STRG, M_CAN_PING, core->cfg.verbose);
	}
    }
    return 0;
}

/*
 * Answer a CAN member ping in slave mode: the answer carries the response
 * bit, DLC 8, SW version 0x0402 and the device id 0xFFFF (CS2-GUI). It is
 * queued for the CAN bus (paced, non-blocking) and sent to the UDP broadcast
 * destination and all connected TCP clients. Returns -1 if a frame could
 * not be sent.
 */
int cs2_core_answer_ping(struct cs2_core_t *core) {
    unsigned char netframe[CAN_ENCAP_SIZE];
    int ret = 0;

    memcpy(netframe, M_CAN_PING_CS2_3, CAN_ENCAP_SIZE);
    if (core->io.can_enqueue(core->io.arg, netframe) < 0) {
	fprint_syslog(stderr, LOG_ERR, "can't queue CAN ping answer");
	ret = -1;
    } else {
	print_can_frame(CAN_FORMAT_STRG, netframe, core->cfg.verbose);
    }
    if (core->io.udp_send(core->io.arg, netframe, CAN_ENCAP_SIZE)) {
	fprint_syslog_wc(stderr, LOG_ERR, "sending UDP data (CAN ping answer) error:", strerror(errno));
	ret = -1;
    } else {
	print_can_frame(NET_UDP_FORMAT_STRG, netframe, core->cfg.verbose);
    }
    if (core->io.tcp_send_all(core->io.arg, netframe, CAN_ENCAP_SIZE) < 0) {
	fprint_syslog(stderr, LOG_ERR, "can't send TCP ping answer");
	ret = -1;
    } else {
	print_can_frame(NET_TCP_FORMAT_STRG, netframe, core->cfg.verbose);
    }
    if (core->cfg.verbose)
	printf("                replied CAN ping (slave)\n");
    return ret;
}

/*
 * Start cloning the config from a connected CAN member: request the first
 * config file (lokomotive.cs2) via its TCP connection; the answer is
 * received as config data stream by reassemble_data() (gio.c), which then
 * walks through the remaining cs2_configs entries. Does nothing if no CAN
 * member TCP connection is known yet.
 */
int cs2_core_copy_config(struct cs2_core_t *core) {
    char *ptr;
    unsigned char newframe[CAN_ENCAP_SIZE];

    syslog(LOG_NOTICE, "%s %d: copy config request\n", __func__, __LINE__);
    if (core->cfg.cs2_tcp_socket) {
	/* strip old subdir if needed */
	ptr = strstr(core->cfg.dir, "gleisbilder/");
	if (ptr)
	    *ptr = 0;
	memset(newframe, 0, CAN_ENCAP_SIZE);
	memcpy(newframe, GETCONFIG, 5);
	/* TODO */

	if (core->cfg.verbose)
	    printf("getting %s filename %s\n", cs2_configs[0][0], cs2_configs[0][1]);

	core->cfg.name = cs2_configs[0][1];
	memcpy(&newframe[5], cs2_configs[0][0], strlen(cs2_configs[0][0]));
	core->cfg.next = 1;

	if (core->cfg.verbose)
	    printf("send to CAN member ...\n");
	core->io.tcp_send(core->io.arg, core->cfg.cs2_tcp_socket, newframe, CAN_ENCAP_SIZE);
	/* done - don't copy again */
	core->cfg.cs2_config_copy = 0;
	core->cfg.state = CS2_STATE_NORMAL_CONFIG;
    } else {
	if (core->cfg.verbose)
	    fprintf(stderr, "can't clone CAN member config - no CAN member TCP connection yet\n");
	syslog(LOG_ERR, "%s: can't clone CAN member config - no CAN member TCP connection yet\n", __func__);
    }
    return 0;
}

/*
 * Handle a frame received from the CAN bus: convert it to the 13-byte
 * network format and let cs2_core_handle_frame() decide what to do with it.
 * Returns 0 if the frame has to be forwarded to UDP/TCP, 1 if it was
 * consumed locally.
 */
int cs2_core_handle_can_frame(struct cs2_core_t *core, struct can_frame *frame) {
    unsigned char netframe[CAN_ENCAP_SIZE];
    uint32_t canid;

    memset(netframe, 0, CAN_ENCAP_SIZE);
    canid = htonl(frame->can_id & CAN_EFF_MASK);
    memcpy(netframe, &canid, 4);
    netframe[4] = frame->can_dlc;
    memcpy(&netframe[5], frame->data, 8);
    return cs2_core_handle_frame(core, CS2_SRC_CAN, -1, netframe);
}

/*
 * Handle a received 13-byte frame, regardless of whether it arrived via UDP,
 * TCP or the CAN bus: answer CAN member pings (in slave mode, faked as CS2),
 * serve config file requests (loks/mags/gbs/fs and the *stat files) from the
 * local config directory, feed config data streams to reassemble_data()
 * (gio.c), distribute config change broadcasts and apply the MS1 workaround.
 * Replies are routed to the UDP broadcast destination (src = CS2_SRC_UDP) or
 * back to the sending TCP client (src = CS2_SRC_TCP, tcp_socket). Returns 0
 * if the frame has to be forwarded (UDP/TCP frames: to the CAN bus, CAN
 * frames: to UDP/TCP), 1 if it was consumed locally.
 */
int cs2_core_handle_frame(struct cs2_core_t *core, enum cs2_core_source src, int tcp_socket, unsigned char *netframe) {
    uint32_t canid;
    char config_name[9];
    char gbs_name[MAXLINE];
    int ret;
    gbs_name[0] = '\0';

    ret = 0;
    memcpy(&canid, netframe, 4);
    canid = ntohl(canid);

    /* frames from the CAN bus: a config change broadcast from a CAN member
       triggers a config data stream to all TCP clients and is consumed;
       every other frame is just forwarded by the gateway */
    if (src == CS2_SRC_CAN) {
	if (((canid & 0x1FFFF00UL) == 0x0434700UL) && (netframe[4] == 8)) {
	    uint8_t fill = canid & 0xFF;
	    strncpy(config_name, (char *)&netframe[5], 8);
	    config_name[8] = '\0';
	    syslog(LOG_NOTICE, "%s: config request >%s<\n", __func__, config_name);
	    core->io.tcp_config_send_all(core->io.arg, config_name, canid, CRC | COMPRESSED | BCCHANGE, fill);
	    return 1;
	}
	/* slave mode: answer CAN member pings from the bus; the request
	   itself is still forwarded to UDP/TCP by the gateway */
	if (core->slave && ((canid & 0xFFFF0000UL) == 0x00300000UL)) {
	    if (core->cfg.verbose)
		printf("                received CAN ping\n");
	    cs2_core_answer_ping(core);
	}
	return 0;
    }

    switch (canid & 0xFFFF0000UL) {
    case (0x00300000UL):
	/* slave mode: answer CAN member pings on CAN, UDP and all TCP clients */
	if (core->slave) {
	    if (core->cfg.verbose)
		printf("                received CAN ping\n");
	    cs2_core_answer_ping(core);
	}
	break;
    case (0x00310000UL):	/* CAN ping */
	if (src == CS2_SRC_TCP) {
	    ret = 0;
	    /* looking for CAN member ping answer */
	    print_can_frame(NET_TCP_FORMAT_STRG, netframe, core->cfg.verbose);
	    if ((netframe[11] == 0xFF) && (netframe[12] == 0xFF)) {
		if (core->cfg.verbose)
		    printf("got CAN member TCP ping - copy config var: %d\n", core->cfg.cs2_config_copy);
		syslog(LOG_NOTICE, "%s: got CAN member TCP ping - copy config var: %d\n", __func__, core->cfg.cs2_config_copy);
		core->cfg.cs2_tcp_socket = tcp_socket;
		if (core->cfg.cs2_config_copy)
		    cs2_core_copy_config(core);
	    }
	} else {
	    if ((netframe[11] == 0xEE) && (netframe[12] == 0xEE)) {
		if (core->cfg.verbose)
		    printf("                received CAN ping\n");
		memcpy(netframe, M_PING_RESPONSE, 5);
		if (core->io.udp_send(core->io.arg, netframe, CAN_ENCAP_SIZE)) {
		    fprint_syslog_wc(stderr, LOG_ERR, "sending UDP data (CAN Ping) error:", strerror(errno));
		} else {
		    print_can_frame(NET_UDP_FORMAT_STRG, netframe, core->cfg.verbose);
		    if (core->cfg.verbose)
			printf("                replied CAN ping\n");
		}
		if (core->cfg.cs2_config_copy)
		    cs2_core_copy_config(core);
	    }
	    if (core->slave) {
		if (core->cfg.verbose)
		    printf("                received CAN ping\n");
		memcpy(netframe, M_CAN_PING_CS2_1, 13);
		if (core->io.udp_send(core->io.arg, netframe, CAN_ENCAP_SIZE)) {
		    fprint_syslog_wc(stderr, LOG_ERR, "sending UDP data (CAN Ping fake memeber) error:", strerror(errno));
		} else {
		    print_can_frame(NET_UDP_FORMAT_STRG, netframe, core->cfg.verbose);
		    if (core->cfg.verbose)
			printf("                replied CAN ping (fake member)\n");
		}
		memcpy(netframe, M_CAN_PING_CS2_2, 13);
		if (core->io.udp_send(core->io.arg, netframe, CAN_ENCAP_SIZE)) {
		    fprint_syslog_wc(stderr, LOG_ERR, "sending UDP data (CAN Ping fake member) error:", strerror(errno));
		} else {
		    print_can_frame(NET_UDP_FORMAT_STRG, netframe, core->cfg.verbose);
		    if (core->cfg.verbose)
			printf("                replied CAN ping (fake GFP)\n");
		}
	    }
	}
	break;
    case (0x00400000UL):	/* config data */
	if (src == CS2_SRC_UDP) {
	    /* check for initiated config request */
	    if (canid == 0x0040af7e) {
		if (core->cfg.verbose)
		    printf("copy config request\n");
		syslog(LOG_NOTICE, "%s %d: copy config request\n", __func__, __LINE__);
		core->cfg.cs2_config_copy = 1;
		cs2_core_copy_config(core);
	    }
	    break;
	}
	/* mark frame to send over CAN */
	ret = 0;
	/* check for special copy request */
	if (canid == 0x0040af7e) {
	    ret = 1;
	    netframe[1] |= 1;
	    netframe[4] = 4;
	    strcpy((char *)&netframe[5], "copy");
	    core->io.tcp_send(core->io.arg, tcp_socket, netframe, CAN_ENCAP_SIZE);
	    if (core->cfg.verbose)
		printf("CAN member copy request\n");
	    syslog(LOG_NOTICE, "%s: CAN member copy request\n", __func__);
	    core->cfg.cs2_config_copy = 1;
	} else {
	    strncpy(config_name, (char *)&netframe[5], 8);
	    config_name[8] = '\0';
	    syslog(LOG_NOTICE, "%s: config request >%s<\n", __func__, config_name);
	    if (core->cfg.verbose)
		printf("%s ID 0x%08x %s\n", __func__, canid, (char *)&netframe[5]);
	    netframe[1] |= 1;
	    core->io.tcp_send(core->io.arg, tcp_socket, netframe, CAN_ENCAP_SIZE);
	    if (strcmp("loks", config_name) == 0) {
		ret = 1;
		syslog(LOG_NOTICE, "%s: sending lokomotive.cs2\n", __func__);
		core->io.tcp_config_send(core->io.arg, "lokomotive.cs2", canid, &tcp_socket, 1, CRC | COMPRESSED, 0);
		break;
	    } else if (strcmp("mags", config_name) == 0) {
		ret = 1;
		syslog(LOG_NOTICE, "%s: sending magnetartikel.cs2\n", __func__);
		core->io.tcp_config_send(core->io.arg, "magnetartikel.cs2", canid, &tcp_socket, 1, CRC | COMPRESSED, 0);
		break;
	    } else if (strncmp("gbs-", config_name, 4) == 0) {
		int page_number;
		ret = 1;
		page_number = atoi(&config_name[4]);
		if ((page_number >= 0) && (page_number < MAX_TRACK_PAGE) && page_name[page_number]) {
		    syslog(LOG_NOTICE, "%s: sending %s\n", __func__, gbs_name);
		    core->io.tcp_config_send(core->io.arg, gbs_name, canid, &tcp_socket, 1, CRC | COMPRESSED, 0);
		    break;
		}
		syslog(LOG_NOTICE, "%s: cant't send gbs-%d\n", __func__, page_number);
		break;
	    } else if (strcmp("gbs", config_name) == 0) {
		ret = 1;
		syslog(LOG_NOTICE, "%s: sending gleisbild.cs2\n", __func__);
		core->io.tcp_config_send(core->io.arg, "gleisbild.cs2", canid, &tcp_socket, 1, CRC | COMPRESSED, 0);
		break;
	    } else if (strcmp("fs", config_name) == 0) {
		ret = 1;
		syslog(LOG_NOTICE, "%s: sending fahrstrassen.cs2\n", __func__);
		core->io.tcp_config_send(core->io.arg, "fahrstrassen.cs2", canid, &tcp_socket, 1, CRC | COMPRESSED, 0);
		break;
	    }
	    /* TODO : these files depends on different internal states */
	    else if (strcmp("lokstat", config_name) == 0) {
		ret = 1;
		/* fprintf(stderr, "%s: lokstat (lokomotive.sr2) not implemented yet\n", __func__); */
		syslog(LOG_NOTICE, "%s: sending lokomotive.sr2\n", __func__);
		core->io.tcp_config_send(core->io.arg, "lokomotive.sr2", canid, &tcp_socket, 1, CRC | COMPRESSED, 0);
		break;
	    } else if (strcmp("magstat", config_name) == 0) {
		ret = 1;
		/* fprintf(stderr, "%s: magstat (magnetartikel.sr2) not implemented yet\n\n", __func__); */
		syslog(LOG_NOTICE, "%s: sending magnetartikel.sr2\n", __func__);
		core->io.tcp_config_send(core->io.arg, "magnetartikel.sr2", canid, &tcp_socket, 1, CRC | COMPRESSED, 0);
		break;
	    } else if (strcmp("gbsstat", config_name) == 0) {
		ret = 1;
		/* fprintf(stderr, "%s: gbsstat (gleisbild.sr2) not implemented yet\n\n", __func__); */
		syslog(LOG_NOTICE, "%s: sending gleisbild.sr2\n", __func__);
		core->io.tcp_config_send(core->io.arg, "gleisbild.sr2", canid, &tcp_socket, 1, CRC | COMPRESSED, 0);
		break;
	    } else if (strcmp("fsstat", config_name) == 0) {
		ret = 1;
		/* fprintf(stderr, "%s: fsstat (fahrstrassen.sr2) not implemented yet\n\n", __func__); */
		syslog(LOG_NOTICE, "%s: sending fahrstrassen.sr2\n", __func__);
		core->io.tcp_config_send(core->io.arg, "fahrstrassen.sr2", canid, &tcp_socket, 1, CRC | COMPRESSED, 0);
		break;
	    }
	    break;
	}
	break;
    case (0x00420000UL):
	if (src == CS2_SRC_TCP) {
	    /* check for bordcast config change: DLC = 7 */
	    if (netframe[4] == 7) {
		/* TODO */
		syslog(LOG_NOTICE, "%s: broadcast config change", __func__);
		core->cfg.name = BROADCAST_C0NFIG_UPDATE;
		core->cfg.state = CS2_STATE_BROADCAST_UPDATE;
	    }
	    /* check for initiated copy request or brodcast update */
	    reassemble_data(&core->cfg, netframe);
	    print_can_frame(NET_TCP_FORMAT_STRG, netframe, core->cfg.verbose);
	    /* none CAN member copy request needs to be send over CAN */
	    if (canid & 0x0000fcff)
		ret = 0;
	    else
		ret = 1;
	}
	break;
	/* fake cyclic MS1 slave monitoring response */
    case (0x0C000000UL):
	if (src == CS2_SRC_TCP) {
	    /* mark CAN frame to send */
	    ret = 0;
	    if (core->ms1_workaround)
		netframe[5] = 0x03;
	}
	break;
    default:
	break;
    }
    return ret;
}
