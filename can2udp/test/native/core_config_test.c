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
