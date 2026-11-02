/* ----------------------------------------------------------------------------
 * "THE BEER-WARE LICENSE" (Revision 42):
 * <info@gerhard-bertelsmann.de> wrote this file. As long as you retain this
 * notice you can do whatever you want with this stuff. If we meet some day,
 * and you think this stuff is worth it, you can buy me a beer in return
 * Gerhard Bertelsmann
 * ----------------------------------------------------------------------------
 */

/* CS2 protocol emulation core: CAN member ping handling, config data
 * requests/streams and the config clone state machine.
 *
 * The core never touches sockets itself - all CAN/UDP/TCP transmission
 * is delegated to the gateway (can2lan.c) through struct cs2_core_io.
 */

#ifndef _CS2_CORE_H_
#define _CS2_CORE_H_

#include "can2lan.h"

/* I/O callbacks implemented by the gateway (can2lan.c) */
struct cs2_core_io {
    void *arg;
    /* send a 13-byte CAN frame to the UDP broadcast destination */
    int (*udp_send)(void *arg, unsigned char *frame, int len);
    /* send a 13-byte CAN frame to a single TCP client */
    int (*tcp_send)(void *arg, int tcp_socket, unsigned char *frame, int len);
    /* send a 13-byte CAN frame to the CAN bus (blocking, paced) */
    int (*can_send)(void *arg, unsigned char *frame);
    /* send a config file as (compressed) config data stream to TCP clients */
    int (*tcp_config_send)(void *arg, char *name, uint32_t canid, int *tcp_socket_list, int socket_nmbr, int flags,
			   uint8_t fill);
    /* send a config file as (compressed) config data stream to all connected TCP clients */
    int (*tcp_config_send_all)(void *arg, char *name, uint32_t canid, int flags, uint8_t fill);
};

/* where a frame was received from / where replies are routed to */
enum cs2_core_source {
    CS2_SRC_UDP,	/* frame from UDP, replies go to the UDP broadcast destination */
    CS2_SRC_TCP,	/* frame from a TCP client, replies go to that client */
    CS2_SRC_CAN		/* frame from the CAN bus */
};

struct cs2_core_t {
    struct cs2_config_data_t cfg;	/* config clone/stream state */
    struct cs2_core_io io;
    int cs2fake_ping;			/* -g: answer CAN member pings ourselves */
    int ms1_workaround;			/* -m: fake cyclic MS1 slave monitoring response */
};

/* shared with the gateway (can2lan.c) and gio.c */
extern unsigned char M_CAN_PING[];
extern unsigned char GETCONFIG[];
extern unsigned char GETCONFIG_DATA[];
extern char *cs2_configs[][2];

void cs2_core_init(struct cs2_core_t *core, const struct cs2_core_io *io);
int cs2_core_send_start_frames(struct cs2_core_t *core);
int cs2_core_send_ping(struct cs2_core_t *core);
int cs2_core_copy_config(struct cs2_core_t *core);
/* handle a received 13-byte frame; returns 0 if it has to be forwarded, 1 if consumed locally */
int cs2_core_handle_frame(struct cs2_core_t *core, enum cs2_core_source src, int tcp_socket, unsigned char *netframe);
/* handle a frame received from the CAN bus; returns 0 if it has to be forwarded to UDP/TCP, 1 if consumed locally */
int cs2_core_handle_can_frame(struct cs2_core_t *core, struct can_frame *frame);

#endif /* _CS2_CORE_H_ */
