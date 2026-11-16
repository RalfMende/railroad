#include "cs2-core.c"

static int test_tcp_send(void *arg, int socket, unsigned char *data, int length) {
    (void)arg;
    return net_to_net(socket, NULL, data, length);
}

int test_config_send_stream(char *filename, char *dir, uint32_t canid, int *sockets,
			    int count, int flags, uint8_t fill) {
    return cs2_config_send_stream(filename, dir, canid, sockets, count, flags, fill,
				  MAX_PACKETS, test_tcp_send, NULL);
}

int test_config_reassemble(struct cs2_config_data_t *config_data, unsigned char *frame) {
    return cs2_config_reassemble(config_data, frame, test_tcp_send, NULL);
}

struct test_start_fds {
    int can;
    int udp;
    int tcp;
};

static int test_start_can(void *arg, unsigned char *frame) {
    struct test_start_fds *fds = arg;
    return net_to_net(fds->can, NULL, frame, CAN_ENCAP_SIZE);
}

static int test_start_udp(void *arg, unsigned char *frame, int length) {
    struct test_start_fds *fds = arg;
    return net_to_net(fds->udp, NULL, frame, length);
}

static int test_start_tcp(void *arg, unsigned char *frame, int length) {
    struct test_start_fds *fds = arg;
    return net_to_net(fds->tcp, NULL, frame, length);
}

int test_core_send_start_frames(int can, int udp, int tcp) {
    struct test_start_fds fds = { can, udp, tcp };
    struct cs2_core_t core = { 0 };
    core.io.arg = &fds;
    core.io.can_enqueue = test_start_can;
    core.io.udp_send = test_start_udp;
    core.io.tcp_send_all = test_start_tcp;
    return cs2_core_send_start_frames(&core);
}
