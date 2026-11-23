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

struct test_loco_core {
    struct cs2_core_t core;
    char dir[MAXLINE];
};

static int test_loco_can(void *arg, unsigned char *frame) {
    (void)arg;
    (void)frame;
    return 0;
}

static int test_loco_net(void *arg, unsigned char *frame, int length) {
    (void)arg;
    (void)frame;
    (void)length;
    return 0;
}

struct test_loco_core *test_loco_create(const char *dir, int slave) {
    struct test_loco_core *test = calloc(1, sizeof(*test));
    struct cs2_core_io io = { 0 };
    if (!test)
	return NULL;
    if (snprintf(test->dir, sizeof(test->dir), "%s", dir) >= (int)sizeof(test->dir)) {
	free(test);
	return NULL;
    }
    test->core.slave = slave;
    io.can_enqueue = test_loco_can;
    io.udp_send = test_loco_net;
    io.tcp_send_all = test_loco_net;
    if (cs2_core_init(&test->core, &io, test->dir) < 0) {
	cs2_core_close(&test->core);
	free(test->core.cfg.page_name);
	free(test);
	return NULL;
    }
    return test;
}

void test_loco_destroy(struct test_loco_core *test) {
    cs2_core_close(&test->core);
    free(test->core.cfg.page_name);
    if (page_name)
	free_track_file(page_name);
    free(page_name);
    page_name = NULL;
    delete_all_loco_data();
    free(test);
}

size_t test_loco_count(struct test_loco_core *test) {
    return test->core.loco_count;
}

const char *test_loco_name(struct test_loco_core *test, size_t index) {
    return test->core.locos[index].name;
}

unsigned int test_loco_velocity(struct test_loco_core *test, size_t index) {
    return test->core.locos[index].velocity;
}

unsigned int test_loco_direction(struct test_loco_core *test, size_t index) {
    return test->core.locos[index].direction;
}

void test_loco_handle_can(struct test_loco_core *test, unsigned char *frame) {
    cs2_core_handle_frame(&test->core, CS2_SRC_CAN, -1, frame);
}
