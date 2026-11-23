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
#include "ascii-frame.h"
#include "read-cs2-config.h"
#include <sys/timerfd.h>
#include <zlib.h>

static char *CAN_FORMAT_STRG     = "      CAN->   0x%08X R [%d]";
static char *NET_UDP_FORMAT_STRG = "      UDP->   0x%08X   [%d]";
static char *NET_TCP_FORMAT_STRG = "      TCP->   0x%08X   [%d]";

static char *BROADCAST_C0NFIG_UPDATE = "broadcast_update.cs2";

/* master mode: interval of the periodic CAN member ping in seconds */
#define PING_TIME 10

/* command 0x1B "Bootloader CAN gebunden" (service), here with DLC 5 - sent
   before every CAN member ping (the CS is observed sending it with DLC 0) */
static unsigned char M_BOOTLOADER_CAN_BOUND[] =
    { 0x00, 0x36, 0x03, 0x01, 0x05, 0x00, 0x00, 0x00, 0x00, 0x11, 0x00, 0x00, 0x00 };
/* Gleisbox (60113) start frame: enable all loco protocols */
static unsigned char M_GLEISBOX_ALL_PROTO_ENABLE[] =
    { 0x00, 0x00, 0x03, 0x01, 0x06, 0x00, 0x00, 0x00, 0x00, 0x08, 0x07, 0x00, 0x00 };
/* command 0x18 "Softwarestand Anfrage / Teilnehmer Ping", DLC 0: query all
   CAN bus members (also sent to TCP clients with the periodic master ping) */
unsigned char M_SOFTWARE_VERSION_REQUEST_MEMBER_PING[] =
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

/* config data stream commands */
static unsigned char GETCONFIG[]      = { 0x00, 0x40, 0xaf, 0x7e, 0x08 };
static unsigned char GETCONFIG_DATA[] = { 0x00, 0x42, 0x03, 0x00, 0x08 };

/* config request name -> local config file */
static char *cs2_configs[][2] = {
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

struct cs2_core_loco {
    char *name;
    uint32_t uid;
    unsigned int velocity;
    unsigned int direction;
};

struct cs2_loknamen_request {
    uint16_t hash;
    struct cs2_loknamen_request *next;
};

struct cs2_loknamen_stream {
    unsigned char *data;
    size_t length;
    size_t offset;
    uint32_t canid;
    uint16_t crc;
    int header_sent;
    struct cs2_loknamen_stream *next;
};

static int cs2_core_add_loco(const struct loco_data_t *config, void *arg) {
    struct cs2_core_t *core = arg;
    struct cs2_core_loco *locos, *loco;
    char *name = strdup(config->name);

    if (!name) {
	fprint_syslog_wc(stderr, LOG_ERR, "can't allocate locomotive name:", strerror(errno));
	return -1;
    }
    if (core->loco_count == SIZE_MAX / sizeof(*core->locos)) {
	free(name);
	fprint_syslog(stderr, LOG_ERR, "too many locomotives");
	return -1;
    }
    locos = realloc(core->locos, (core->loco_count + 1) * sizeof(*core->locos));
    if (!locos) {
	free(name);
	fprint_syslog_wc(stderr, LOG_ERR, "can't allocate locomotive state:", strerror(errno));
	return -1;
    }
    core->locos = locos;
    loco = &core->locos[core->loco_count++];
    loco->name = name;
    loco->uid = config->uid;
    loco->velocity = 0;
    loco->direction = 1;
    return 0;
}

static int cs2_core_load_locos(struct cs2_core_t *core, char *filename) {
    delete_all_loco_data();
    if (read_loco_data_with_callback(filename, CONFIG_FILE, cs2_core_add_loco, core) != 0) {
	syslog(LOG_ERR, "%s: can't read locomotive data from %s\n", __func__, filename);
	delete_all_loco_data();
	return -1;
    }
    return 0;
}

static void cs2_core_update_loco(struct cs2_core_t *core, uint32_t canid, unsigned char *frame) {
    uint32_t uid;
    unsigned int command = (canid >> 17) & 0xFF;
    size_t i;

    if (!(canid & 0x10000) || !((command == 0x04 && frame[4] == 6) ||
				 (command == 0x05 && frame[4] == 5)))
	return;
    memcpy(&uid, &frame[5], sizeof(uid));
    uid = ntohl(uid);
    for (i = 0; i < core->loco_count; i++) {
	struct cs2_core_loco *loco = &core->locos[i];
	if (loco->uid != uid)
	    continue;
	if (command == 0x04) {
	    unsigned int velocity = ((unsigned int)frame[9] << 8) | frame[10];
	    if (velocity <= 1023)
		loco->velocity = velocity;
	} else if (frame[9] >= 1 && frame[9] <= 3) {
	    unsigned int direction = frame[9] == 3 ? 3 - loco->direction : frame[9];
	    if (loco->direction != direction)
		loco->velocity = 0;
	    loco->direction = direction;
	}
    }
}

typedef int (*cs2_config_send_fn)(void *arg, int destination, unsigned char *data, int length);

#define CHUNK 0x8000
#define windowBits 15
#define MAX_CONFIG_STREAM_SIZE (4 * 1024 * 1024)

static unsigned char GETCONFIG_RESPONSE[] = { 0x00, 0x42, 0x03, 0x00, 0x06 };
char *rmcrlf(char *s, int slen);
void print_pages(char **page_name);

#define CALL_ZLIB(x) do { \
    int status = (x); \
    if (status < 0) { \
        fprintf(stderr, "%s:%d: zlib error %d\n", __FILE__, __LINE__, status); \
        exit(EXIT_FAILURE); \
    } \
} while (0)

static char **cs2_config_read_track_file(char *filename, char **page_name) {
    FILE *fp;
    int id = 0;
    int page = 0;
    char line[MAXLINE];

    syslog(LOG_NOTICE, "%s: read %s", __func__, filename);

    if ((fp = fopen(filename, "r")) != NULL) {
	while (fgets(line, MAXLINE, fp) != NULL) {
	    if (strstr(line, "seite") == line) {
		page = 1;
	    } else if (strstr(line, " .id=") == line) {
		id = strtoul(&line[5], NULL, 0);
	    } else if (strstr(line, " .name=") == line) {
		rmcrlf(line, MAXLINE);
		if (page) {
		    page_name[id] = calloc(strlen(&line[7]) + 5, 1);
		    if (page_name[id] == NULL) {
			fprint_syslog_wc(stderr, LOG_ERR, "error calloc failed creating config buffer for", filename);
			return NULL;
		    }
		    strcpy(page_name[id], &line[7]);
		    strcat(page_name[id], ".cs2");
		}
	    }
	}
	fclose(fp);
	/* EOF found, normal exit */
	return page_name;
    } else {
	fprintf(stderr, "%s: error reading file %s: %s\n", __func__, filename, strerror(errno));
	syslog(LOG_ERR, "%s: error reading file %s: %s\n", __func__, filename, strerror(errno));
	return NULL;
    }
}

static int cs2_config_inflate(struct cs2_config_data_t *config_data) {
    int ret;
    z_stream strm;

    if (config_data->deflated_size < 4)
	return Z_DATA_ERROR;

    strm.zalloc = Z_NULL;
    strm.zfree = Z_NULL;
    strm.opaque = Z_NULL;
    strm.avail_in = 0;
    strm.next_in = Z_NULL;
    ret = inflateInit(&strm);
    if (ret != Z_OK)
	return ret;
    strm.avail_in = config_data->deflated_size - 4;
    strm.avail_out = config_data->inflated_size ? config_data->inflated_size : 1;
    strm.next_in = config_data->deflated_data + 4;
    strm.next_out = config_data->inflated_data;
    ret = inflate(&strm, Z_FINISH);
    if (ret == Z_STREAM_END && strm.total_out == (unsigned int)config_data->inflated_size &&
	strm.total_in == (unsigned int)(config_data->deflated_size - 4))
	ret = Z_OK;
    else if (ret >= Z_OK)
	ret = Z_DATA_ERROR;
    (void)inflateEnd(&strm);
    return ret;
}

static int cs2_config_write(struct cs2_config_data_t *config_data) {
    FILE *config_fp;
    uint16_t crc;
    int i, write_error = 0, saved_errno = 0;
    size_t written;
    char *filename;

    if (config_data->name == NULL) {
	fprintf(stderr, "\nunexpected config data stream received\n");
	syslog(LOG_ERR, "%s: unexpected config data stream received\n", __func__);
	free(config_data->deflated_data);
	config_data->deflated_data = NULL;
	free(config_data->inflated_data);
	config_data->inflated_data = NULL;
	return 0;
    }

    filename = calloc(MAXLINE, 1);
    if (filename == NULL) {
	fprint_syslog_wc(stderr, LOG_ERR, "can't calloc:", strerror(errno));
	exit(EXIT_FAILURE);
    }
    strcpy(filename, config_data->dir);
    strcat(filename, config_data->name);

    crc = CRCCCITT(config_data->deflated_data, config_data->deflated_stream_size, 0xFFFF);

    if (config_data->verbose)
	printf("\n  writing to %s - size 0x%04x crc exp 0x%04x calc 0x%04x\n", config_data->name,
	       config_data->deflated_stream_size, config_data->crc, crc);

    if (crc != config_data->crc) {
	fprintf(stderr, "\n%s: CRC mismatch for %s - expected 0x%04x calculated 0x%04x, not writing file\n",
		__func__, config_data->name, config_data->crc, crc);
	syslog(LOG_ERR, "%s: CRC mismatch for %s - expected 0x%04x calculated 0x%04x, not writing file\n",
	       __func__, config_data->name, config_data->crc, crc);
	free(filename);
	free(config_data->deflated_data);
	config_data->deflated_data = NULL;
	free(config_data->inflated_data);
	config_data->inflated_data = NULL;
	return 0;
    }

    i = cs2_config_inflate(config_data);
    if (config_data->verbose)
	printf("inflate returned code %i\n", i);
    if (i != 0) {
	fprintf(stderr, "\n%s: inflate failed for %s - error %d, not writing file\n", __func__, config_data->name, i);
	syslog(LOG_ERR, "%s: inflate failed for %s - error %d, not writing file\n", __func__, config_data->name, i);
	free(filename);
	free(config_data->deflated_data);
	config_data->deflated_data = NULL;
	free(config_data->inflated_data);
	config_data->inflated_data = NULL;
	return 0;
    }

    config_fp = fopen(filename, "wb");
    if (!config_fp) {
	fprintf(stderr, "\ncan't open file %s for writing - error: %s\n", filename, strerror(errno));
	syslog(LOG_ERR, "%s: can't open file %s for writing - error: %s\n", __func__, filename, strerror(errno));
	free(filename);
	free(config_data->deflated_data);
	config_data->deflated_data = NULL;
	free(config_data->inflated_data);
	config_data->inflated_data = NULL;
	return 0;
    } else if (config_data->verbose) {
	for (i = 0; i < config_data->deflated_stream_size; i++) {
	    if ((i % 8) == 0)
		printf("\n");
	    printf("%02x ", config_data->deflated_data[i]);
	}
	printf("\n");
    }
    errno = 0;
    written = fwrite(config_data->inflated_data, 1, config_data->inflated_size, config_fp);
    if (written != (size_t)config_data->inflated_size || ferror(config_fp)) {
	write_error = 1;
	saved_errno = errno ? errno : EIO;
    }
    if (fclose(config_fp) != 0 && !write_error) {
	write_error = 1;
	saved_errno = errno ? errno : EIO;
    }
    if (write_error) {
	fprintf(stderr, "\n%s: can't write file %s: %s\n", __func__, filename, strerror(saved_errno));
	syslog(LOG_ERR, "%s: can't write file %s: %s\n", __func__, filename, strerror(saved_errno));
    }
    free(filename);
    free(config_data->deflated_data);
    config_data->deflated_data = NULL;
    free(config_data->inflated_data);
    config_data->inflated_data = NULL;
    return !write_error;
}

static int cs2_config_reassemble(struct cs2_config_data_t *config_data, unsigned char *netframe,
			  cs2_config_send_fn send, void *arg) {
    unsigned int state, temp;
    uint16_t hash;
    unsigned char newframe[CAN_ENCAP_SIZE];
    char *filename;
    char *ptr;

    if (memcmp(netframe, GETCONFIG_DATA, 2) != 0)
	return 1;
    memcpy(&hash, &netframe[2], sizeof(hash));
    hash = ntohs(hash);
    if ((config_data->start || config_data->stream) && hash != config_data->stream_hash) {
	syslog(LOG_DEBUG, "%s: ignoring config stream frame with another hash 0x%04x\n", __func__, hash);
	return 1;
    }

    if ((memcmp(netframe, GETCONFIG_RESPONSE, 5) == 0) || netframe[4] == 7) {
	memcpy(&temp, &netframe[5], 4);
	temp = ntohl(temp);
	if (temp > MAX_CONFIG_STREAM_SIZE) {
	    syslog(LOG_ERR, "%s: abort config data stream - announced deflated size 0x%08x exceeds limit\n",
		   __func__, temp);
	    config_data->start = 0;
	    config_data->stream = 0;
	    config_data->state = CS2_STATE_INACTIVE;
	    free(config_data->deflated_data);
	    config_data->deflated_data = NULL;
	    free(config_data->inflated_data);
	    config_data->inflated_data = NULL;
	    return 0;
	}
	config_data->deflated_size = temp;
	config_data->deflated_size_counter = config_data->deflated_size;

	memcpy(&temp, &netframe[9], 2);
	config_data->crc = ntohs(temp);
	if (config_data->verbose)
	    printf("\nstart of config - deflated size: 0x%08x crc 0x%04x\n", config_data->deflated_size, config_data->crc);

	config_data->start = 1;
	config_data->stream = 0;
	config_data->stream_hash = hash;
	/* we alloc 8 bytes more to be sure that it fits */
	config_data->deflated_data = realloc(config_data->deflated_data, config_data->deflated_size + 16);
	if (config_data->deflated_data == NULL) {
	    fprintf(stderr, "can't malloc deflated config data buffer - size 0x%04x\n", config_data->deflated_size + 8);
	    exit(EXIT_FAILURE);
	}
	/* deflated data index */
	config_data->ddi = 0;

    } else if (netframe[4] == 8) {
	if (config_data->start) {
	    memcpy(&temp, &netframe[5], 4);
	    temp = ntohl(temp);
	    if (temp > MAX_CONFIG_STREAM_SIZE) {
		syslog(LOG_ERR, "%s: abort config data stream - announced inflated size 0x%08x exceeds limit\n",
		       __func__, temp);
		config_data->start = 0;
		config_data->stream = 0;
		config_data->state = CS2_STATE_INACTIVE;
		free(config_data->deflated_data);
		config_data->deflated_data = NULL;
		free(config_data->inflated_data);
		config_data->inflated_data = NULL;
		return 0;
	    }
	    config_data->inflated_size = temp;
	    config_data->inflated_data = realloc(config_data->inflated_data,
						 config_data->inflated_size ? config_data->inflated_size : 1);
	    if (config_data->inflated_data == NULL) {
		fprintf(stderr, "can't malloc inflated config data buffer - size 0x%04x\n", config_data->inflated_size);
		exit(EXIT_FAILURE);
	    }
	    config_data->start = 0;
	    config_data->stream = 1;
	    memcpy(&config_data->deflated_data[0], &netframe[5], 8);
	    config_data->ddi = 8;
	    config_data->deflated_size_counter -= 8;
	} else if (config_data->stream) {
	    if (config_data->ddi + 8 > config_data->deflated_size + 16) {
		syslog(LOG_ERR, "%s: abort config data stream - received more data than announced\n", __func__);
		config_data->start = 0;
		config_data->stream = 0;
		config_data->state = CS2_STATE_INACTIVE;
		free(config_data->deflated_data);
		config_data->deflated_data = NULL;
		free(config_data->inflated_data);
		config_data->inflated_data = NULL;
		return 0;
	    }
	    memcpy(&config_data->deflated_data[config_data->ddi], &netframe[5], 8);
	    config_data->ddi += 8;
	    if (config_data->deflated_size_counter <= 8) {
		config_data->stream = 0;
		config_data->deflated_stream_size = config_data->ddi;
		if (!cs2_config_write(config_data)) {
		    syslog(LOG_ERR, "%s: abort config copy after stream processing failed\n", __func__);
		    config_data->state = CS2_STATE_INACTIVE;
		    return 0;
		}
		/* TODO next */
		state = config_data->state;
		switch (state) {
		case CS2_STATE_INACTIVE:
		    break;
		case CS2_STATE_NORMAL_CONFIG:
		    if (cs2_configs[config_data->next][0]) {
			memset(newframe, 0, CAN_ENCAP_SIZE);
			memcpy(newframe, GETCONFIG, 5);
			if (config_data->verbose)
			    printf("getting %s filename %s\n", cs2_configs[config_data->next][0], cs2_configs[config_data->next][1]);
			config_data->name = cs2_configs[config_data->next][1];
			syslog(LOG_NOTICE, "%s: getting %s filename %s\n", __func__, cs2_configs[config_data->next][0], config_data->name);
			memcpy(&newframe[5], cs2_configs[config_data->next][0], strlen(cs2_configs[config_data->next][0]));
			/* print_can_frame(NET_TCP_FORMAT_STRG, newframe, 1); */
			if (send(arg, config_data->cs2_tcp_socket, newframe, CAN_ENCAP_SIZE) < 0) {
			    syslog(LOG_ERR, "%s: can't send next config request\n", __func__);
			    config_data->state = CS2_STATE_INACTIVE;
			    return 0;
			}
			config_data->next++;
			break;
		    } else {
			/* list is done if no entry is left */
			config_data->state = CS2_STATE_TRACK_SUM;
		    }
		    /* falls through */
		case CS2_STATE_TRACK_SUM:
		    filename = calloc(MAXLINE, 1);
		    if (filename == NULL) {
			fprintf(stderr, "can't calloc in %s: %s\n", __func__, strerror(errno));
			config_data->state = CS2_STATE_INACTIVE;
			return (EXIT_FAILURE);
		    }
		    strcpy(filename, config_data->dir);
		    strcat(filename, "gleisbild.cs2");
		    if (config_data->verbose)
			printf("read track file %s dir %s\n", filename, config_data->dir);
		    syslog(LOG_NOTICE, "%s: read track file %s dir %s\n", __func__, filename, config_data->dir);
		    config_data->page_name = cs2_config_read_track_file(filename, config_data->page_name);
		    if (config_data->page_name == NULL) {
			fprint_syslog(stderr, LOG_ERR, "can't finish CAN member copy config request");
			config_data->state = CS2_STATE_INACTIVE;
			return (EXIT_FAILURE);
		    }
		    if (config_data->verbose)
			printf("copy track file %s dir %s\n", filename, config_data->dir);
		    syslog(LOG_NOTICE, "%s: track track file %s dir %s (global)\n", __func__, filename, config_data->dir);
		    page_name = cs2_config_read_track_file(filename, config_data->page_name);

		    strcat(config_data->dir, "gleisbilder/");
		    if (config_data->verbose)
			print_pages(config_data->page_name);
		    free(filename);
		    config_data->track_index = 0;
		    config_data->state = CS2_STATE_GET_TRACKS;
		    /* falls through */
		case CS2_STATE_GET_TRACKS:
		    if (config_data->page_name[config_data->track_index]) {
			memset(newframe, 0, CAN_ENCAP_SIZE);
			memcpy(newframe, GETCONFIG, 5);
			config_data->name = config_data->page_name[config_data->track_index];
			sprintf((char *)&newframe[5], "gbs-%d", config_data->track_index);
			if (config_data->verbose)
			    printf("getting track %s filename %s\n", &newframe[5], config_data->name);
			syslog(LOG_NOTICE, "%s: getting track %s filename %s\n", __func__, &newframe[5], config_data->name);
			if (send(arg, config_data->cs2_tcp_socket, newframe, CAN_ENCAP_SIZE) < 0) {
			    syslog(LOG_ERR, "%s: can't send track config request\n", __func__);
			    config_data->state = CS2_STATE_INACTIVE;
			    return 0;
			}
			config_data->track_index++;
		    } else {
			/* reset dir */
			ptr = strstr(config_data->dir, "gleisbilder/");
			if (ptr)
			    *ptr = 0;
			config_data->state = CS2_STATE_INACTIVE;
		    }
		    break;
		case CS2_STATE_BROADCAST_UPDATE:
		default:
		    config_data->state = CS2_STATE_INACTIVE;
		    break;
		}
	    } else {
		config_data->deflated_size_counter -= 8;
	    }
	}
    } else if ((config_data->start || config_data->stream) &&
	       (netframe[4] != 6) && (netframe[4] != 7) && (netframe[4] != 8)) {
	/* spec: only DLC 6/7 (stream start) and 8 (data) are valid - any other
	   DLC within a config data stream aborts the reception */
	syslog(LOG_ERR, "%s: abort config data stream - unexpected DLC %d\n", __func__, netframe[4]);
	config_data->start = 0;
	config_data->stream = 0;
	config_data->state = CS2_STATE_INACTIVE;
	free(config_data->deflated_data);
	config_data->deflated_data = NULL;
	free(config_data->inflated_data);
	config_data->inflated_data = NULL;
	return 0;
    }
    return 1;
}

static uint8_t *cs2_config_read_file(char *filename, char *config_dir, uint32_t * nbytes) {
    int rc;
    struct stat st;
    FILE *fp;
    uint8_t *config;
    char *file_name;

    file_name = calloc(MAXLINE, 1);
    if (!file_name)
	return NULL;

    strncat(file_name, config_dir, MAXLINE - 1);
    strcat(file_name, filename);

    /* printf("%s: try reading file %s\n", __func__, file_name); */

    rc = stat(file_name, &st);
    if (rc < 0) {
	fprintf(stderr, "%s: error stat failed for file %s\n", __func__, filename);
	syslog(LOG_ERR, "%s: error stat failed for file %s\n", __func__, filename);
	goto read_error1;
    }
    fp = fopen(file_name, "rb");
    if (fp == NULL) {
	fprintf(stderr, "%s: error fopen failed for file %s\n", __func__, filename);
	syslog(LOG_ERR, "%s: error fopen failed for file %s\n", __func__, filename);
	goto read_error1;
    }
    *nbytes = st.st_size;
    config = (uint8_t *) calloc(*nbytes, 1);
    if (config == NULL) {
	fprintf(stderr, "%s: error calloc failed creating config buffer for %s\n", __func__, filename);
	syslog(LOG_ERR, "%s: error calloc failed creating config buffer for %s\n", __func__, filename);
	goto read_error2;
    }
    rc = fread((void *)config, 1, *nbytes, fp);
    if (((unsigned int)rc != *nbytes)) {
	fprintf(stderr, "%s: error fread failed reading %s\n", __func__, filename);
	syslog(LOG_ERR, "%s: error fread failed reading %s\n", __func__, filename);
	free(config);
	goto read_error2;
    }
    fclose(fp);
    free(file_name);
    return config;

read_error2:
    fclose(fp);
read_error1:
    free(file_name);
    return NULL;
}

static void strm_init(z_stream * strm) {
    strm->zalloc = Z_NULL;
    strm->zfree = Z_NULL;
    strm->opaque = Z_NULL;
    CALL_ZLIB(deflateInit2(strm, Z_DEFAULT_COMPRESSION, Z_DEFLATED, windowBits, 8, Z_DEFAULT_STRATEGY));
}

static int cs2_config_send_stream(char *filename, char *config_dir, uint32_t canid,
			   int *socket_list, int socket_nmbr, int flags, uint8_t fill,
			   int packets_per_write, cs2_config_send_fn send, void *arg) {
    uint32_t temp32, canid_be, nbytes = 0;
    uint8_t *config;
    uint8_t *out;
    z_stream strm;
    int inflated_size, deflated_size, padded_nbytes, i, src_i, n_packets;
    uint16_t crc, temp16;
    uint8_t netframe[MAXMTU];
    int rc = 0;

    config = cs2_config_read_file(filename, config_dir, &nbytes);
    if (config == NULL) {
	fprintf(stderr, "%s: error reading config %s\n", __func__, filename);
	syslog(LOG_ERR, "%s: error reading config %s\n", __func__, filename);
	return -1;
    }

    if (flags & COMPRESSED) {
	/* we need some more bytes to prepare send data (includes inflated file size and padding)    */
	/* assuming that out[CHUNK] is large enough to compress the whole file, otherwise don't send */
	out = (uint8_t *) calloc(CHUNK + 12, 1);
	if (out == NULL) {
	    fprintf(stderr, "%s: error calloc failed creating deflation buffer\n", __func__);
	    syslog(LOG_ERR, "%s: error calloc failed creating deflation buffer\n", __func__);
	    free(config);
	    return -1;
	}
	strm_init(&strm);
	strm.next_in = config;
	strm.avail_in = nbytes;
	strm.avail_out = CHUNK;
	/* store deflated file beginning at byte 5 */
	strm.next_out = &out[4];
	i = deflate(&strm, Z_FINISH);
	deflated_size = CHUNK - strm.avail_out;
	deflateEnd(&strm);
	free(config);
	if (i != Z_STREAM_END) {
	    fprintf(stderr, "%s: bad status %d when compressing file %s\n", __func__, i, filename);
	    syslog(LOG_ERR, "%s: bad status %d when compressing file %s\n", __func__, i, filename);
	    free(out);
	    return -1;
	}

	/* now prepare the send buffer */
	inflated_size = htonl(nbytes);
	memcpy(out, &inflated_size, 4);
	/* prepare padding */
	padded_nbytes = deflated_size + 4;
	if (padded_nbytes % 8) {
	    padded_nbytes += 8 - (padded_nbytes % 8);
	}

	for (i = deflated_size + 4; i < padded_nbytes; i++) {
	    out[i] = 0;
	}

	crc = CRCCCITT(out, padded_nbytes, 0xffff);
	/* printf("%s: canid 0x%08x filesize %d deflated size: %d crc 0x%04x\n", __func__, canid, nbytes, deflated_size, crc); */
	memset(netframe, 0, MAXMTU);
	/* prepare first CAN frame   */
	/* delete response bit and set canid to config data stream */
	canid_be = htonl((canid & 0xFFFEFFFFUL) | 0x00020000UL);

	// repeat from here in case of broadcast
	for (int sn = 0; sn < socket_nmbr; sn++) {	/* check all clients for data */
	    if (socket_list[sn] < 0)
		continue;

	    memcpy(&netframe[0], &canid_be, 4);
	    /* CAN DLC is 6 */
	    netframe[4] = 0x06;
	    temp32 = htonl(deflated_size + 4);
	    memcpy(&netframe[5], &temp32, 4);
	    temp16 = htons(crc);
	    memcpy(&netframe[9], &temp16, 2);
	    netframe[11] = 0x00;
	    netframe[12] = 0x00;
	    if (flags & BCCHANGE) {
		netframe[4] = 0x07;
		netframe[11] = fill;
	    }
	    /* TCP frames are queued; UDP frames are sent individually. */
	    if (send(arg, socket_list[sn], netframe, CAN_ENCAP_SIZE)) {
		syslog(LOG_ERR, "%s: can't send config stream header for fd %d\n", __func__, socket_list[sn]);
		rc = -1;
		continue;
	    }

	    /* loop until all packets are queued */
	    src_i = 0;
	    do {
		n_packets = 0;
		i = 0;
		do {
		    memcpy(&netframe[i], &canid_be, 4);
		    i += 4;
		    /* CAN DLC is always 8 */
		    netframe[i] = 0x08;
		    i++;
		    memcpy(&netframe[i], &out[src_i], 8);
		    i += 8;
		    src_i += 8;
		    n_packets++;
		} while ((src_i < padded_nbytes) && (n_packets < packets_per_write));

		if (send(arg, socket_list[sn], netframe, i)) {
		    syslog(LOG_ERR, "%s: can't send config stream data for fd %d\n", __func__, socket_list[sn]);
		    rc = -1;
		    break;
		}
	    } while (src_i < padded_nbytes);
#if 0
	    /* print compressed data */
	    temp32 = i;
	    for (i = 0; i < temp32; i++) {
		if ((i % CAN_ENCAP_SIZE) == 0) {
		    printf("\n");
		}
		printf("%02x ", netframe[i]);
	    }
	    printf("\n");
#endif
	}
	free(out);
    }
    return rc;
}


/*
 * Initialize the core context, load local CS2 config data and store the
 * gateway I/O callbacks. The context must be zero-initialized by the
 * caller; options parsed before this call (slave mode, verbose, ...) are
 * preserved. The config clone state machine starts inactive.
 * Master mode: the 60113 start frame is sent to CAN, UDP and TCP first and
 * the periodic CAN member ping timer (PING_TIME seconds) is armed. Slave
 * mode: neither happens - the core only answers pings. Returns -1 if paths
 * are too long, start frames could not be sent, or the timer could not start.
 */
int cs2_core_init(struct cs2_core_t *core, const struct cs2_core_io *io, char *config_dir) {
    char track_file[MAXLINE];
    char loco_file[MAXLINE];
    size_t dir_len;
    int path_len;
    struct itimerspec timer = { { PING_TIME, 0 }, { PING_TIME, 0 } };

    core->io = *io;
    core->config_dir = config_dir;
    core->event_fd = -1;
    core->cfg.state = CS2_STATE_INACTIVE;
    core->cfg.track_index = MAX_TRACK_PAGE;
    if (!config_dir)
	return -1;
    if (!config_dir[0])
	strcpy(config_dir, ".");
    dir_len = strlen(config_dir);
    if (config_dir[dir_len - 1] != '/') {
	if (dir_len + 1 >= MAXLINE) {
	    fprint_syslog(stderr, LOG_ERR, "config directory path is too long");
	    return -1;
	}
	config_dir[dir_len++] = '/';
	config_dir[dir_len] = '\0';
    }
    path_len = snprintf(track_file, sizeof(track_file), "%sgleisbild.cs2", config_dir);
    if (path_len < 0 || (size_t)path_len >= sizeof(track_file)) {
	fprint_syslog(stderr, LOG_ERR, "track config file path is too long");
	return -1;
    }
    path_len = snprintf(loco_file, sizeof(loco_file), "%slokomotive.cs2", config_dir);
    if (path_len < 0 || (size_t)path_len >= sizeof(loco_file)) {
	fprint_syslog(stderr, LOG_ERR, "config file path is too long");
	return -1;
    }
    if (cs2_core_load_locos(core, loco_file) < 0) {
	cs2_core_close(core);
	return -1;
    }
    if (core->slave)
	return 0;
    if (!page_name) {
	page_name = calloc(MAX_TRACK_PAGE, sizeof(char *));
	if (!page_name) {
	    fprint_syslog_wc(stderr, LOG_ERR, "can't allocate track page names:", strerror(errno));
	    cs2_core_close(core);
	    return -1;
	}
    }
    core->cfg.page_name = calloc(MAX_TRACK_PAGE, sizeof(char *));
    if (!core->cfg.page_name) {
	fprint_syslog_wc(stderr, LOG_ERR, "can't allocate cloned track page names:", strerror(errno));
	cs2_core_close(core);
	return -1;
    }
    core->cfg.dir = config_dir;
    page_name = cs2_config_read_track_file(track_file, page_name);
    if (cs2_core_send_start_frames(core) < 0) {
	cs2_core_close(core);
	return -1;
    }
    core->event_fd = timerfd_create(CLOCK_MONOTONIC, TFD_CLOEXEC | TFD_NONBLOCK);
    if (core->event_fd < 0) {
	fprint_syslog_wc(stderr, LOG_ERR, "can't create core timer:", strerror(errno));
	cs2_core_close(core);
	return -1;
    }
    if (core->event_fd >= FD_SETSIZE) {
	fprint_syslog(stderr, LOG_ERR, "core event descriptor exceeds select limit");
	cs2_core_close(core);
	return -1;
    }
    if (timerfd_settime(core->event_fd, 0, &timer, NULL) < 0) {
	fprint_syslog_wc(stderr, LOG_ERR, "can't start core timer:", strerror(errno));
	cs2_core_close(core);
	return -1;
    }
    return 0;
}

int cs2_core_handle_event(struct cs2_core_t *core) {
    uint64_t expirations;
    ssize_t n = read(core->event_fd, &expirations, sizeof(expirations));

    if (n < 0 && (errno == EINTR || errno == EAGAIN))
	return 0;
    if (n != sizeof(expirations)) {
	if (n < 0)
	    fprint_syslog_wc(stderr, LOG_ERR, "can't read core timer:", strerror(errno));
	else
	    fprint_syslog(stderr, LOG_ERR, "short read from core timer");
	return -1;
    }
    if (expirations > 1)
	syslog(LOG_WARNING, "%s: missed %llu ping timer intervals\n",
	       __func__, (unsigned long long)(expirations - 1));
    cs2_core_send_ping(core);
    return 0;
}

void cs2_core_close(struct cs2_core_t *core) {
    size_t i;
    while (core->loknamen_requests) {
	struct cs2_loknamen_request *request = core->loknamen_requests;
	core->loknamen_requests = request->next;
	free(request);
    }
    while (core->loknamen_streams) {
	struct cs2_loknamen_stream *stream = core->loknamen_streams;
	core->loknamen_streams = stream->next;
	free(stream->data);
	free(stream);
    }
    for (i = 0; i < core->loco_count; i++)
	free(core->locos[i].name);
    free(core->locos);
    core->locos = NULL;
    core->loco_count = 0;
    if (core->event_fd >= 0) {
	if (close(core->event_fd) < 0)
	    fprint_syslog_wc(stderr, LOG_ERR, "can't close core timer:", strerror(errno));
	core->event_fd = -1;
    }
}

/*
 * Queue the Gleisbox (60113) start frame for CAN and send it to UDP and
 * connected TCP clients. Called before the gateway main loop runs.
 * Returns -1 if the frame could not be sent.
 */
int cs2_core_send_start_frames(struct cs2_core_t *core) {
    int ret = 0;

    if (core->io.can_enqueue(core->io.arg, M_GLEISBOX_ALL_PROTO_ENABLE) < 0) {
	fprint_syslog(stderr, LOG_ERR, "can't enable all loco protos");
	return -1;
    } else {
	if (core->cfg.verbose) {
	    printf("                CAN enabled all loco protos\n");
	    print_can_frame(CAN_FORMAT_STRG, M_GLEISBOX_ALL_PROTO_ENABLE, core->cfg.verbose);
	}
    }
    if (core->io.udp_send(core->io.arg, M_GLEISBOX_ALL_PROTO_ENABLE, CAN_ENCAP_SIZE) < 0) {
	fprint_syslog(stderr, LOG_ERR, "can't send UDP start frame");
	ret = -1;
    } else {
	print_can_frame(NET_UDP_FORMAT_STRG, M_GLEISBOX_ALL_PROTO_ENABLE, core->cfg.verbose);
    }
    if (core->io.tcp_send_all(core->io.arg, M_GLEISBOX_ALL_PROTO_ENABLE, CAN_ENCAP_SIZE) < 0) {
	fprint_syslog(stderr, LOG_ERR, "can't send TCP start frame");
	ret = -1;
    } else {
	print_can_frame(NET_TCP_FORMAT_STRG, M_GLEISBOX_ALL_PROTO_ENABLE, core->cfg.verbose);
    }
    return ret;
}

/*
 * Send a CAN member ping: the CAN-bound bootloader service frame (0x1B)
 * and the ping itself (0x18) are queued for the CAN bus (paced,
 * non-blocking). Both frames also go to UDP and all connected TCP clients.
 * Returns -1 if a frame could not be sent.
 */
int cs2_core_send_ping(struct cs2_core_t *core) {
    int ret = 0;

    if (core->io.can_enqueue(core->io.arg, M_BOOTLOADER_CAN_BOUND) < 0) {
	fprint_syslog(stderr, LOG_ERR, "can't queue CAN bootloader service frame");
	ret = -1;
    } else {
	if (core->cfg.verbose) {
	    printf("                CAN bootloader service frame written\n");
	    print_can_frame(CAN_FORMAT_STRG, M_BOOTLOADER_CAN_BOUND, core->cfg.verbose);
	}
    }
    if (core->io.udp_send(core->io.arg, M_BOOTLOADER_CAN_BOUND, CAN_ENCAP_SIZE) < 0) {
	fprint_syslog(stderr, LOG_ERR, "can't send UDP bootloader service frame");
	ret = -1;
    } else {
	print_can_frame(NET_UDP_FORMAT_STRG, M_BOOTLOADER_CAN_BOUND, core->cfg.verbose);
    }
    if (core->io.tcp_send_all(core->io.arg, M_BOOTLOADER_CAN_BOUND, CAN_ENCAP_SIZE) < 0) {
	fprint_syslog(stderr, LOG_ERR, "can't send TCP bootloader service frame");
	ret = -1;
    } else {
	print_can_frame(NET_TCP_FORMAT_STRG, M_BOOTLOADER_CAN_BOUND, core->cfg.verbose);
    }
    if (core->io.can_enqueue(core->io.arg, M_SOFTWARE_VERSION_REQUEST_MEMBER_PING) < 0) {
	fprint_syslog(stderr, LOG_ERR, "can't queue CAN ping");
	ret = -1;
    } else {
	if (core->cfg.verbose)
	    print_can_frame(CAN_FORMAT_STRG, M_SOFTWARE_VERSION_REQUEST_MEMBER_PING, core->cfg.verbose);
    }
    if (core->io.udp_send(core->io.arg, M_SOFTWARE_VERSION_REQUEST_MEMBER_PING, CAN_ENCAP_SIZE) < 0) {
	fprint_syslog(stderr, LOG_ERR, "can't send UDP ping");
	ret = -1;
    } else {
	print_can_frame(NET_UDP_FORMAT_STRG, M_SOFTWARE_VERSION_REQUEST_MEMBER_PING, core->cfg.verbose);
    }
    if (core->io.tcp_send_all(core->io.arg, M_SOFTWARE_VERSION_REQUEST_MEMBER_PING, CAN_ENCAP_SIZE) < 0) {
	fprint_syslog(stderr, LOG_ERR, "can't send TCP ping");
	ret = -1;
    } else {
	print_can_frame(NET_TCP_FORMAT_STRG, M_SOFTWARE_VERSION_REQUEST_MEMBER_PING, core->cfg.verbose);
    }
    return ret;
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
 * received as config data stream by the core, which then
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
 * Logical processing of a frame received from the CAN bus: convert it to
 * the 13-byte network format and let cs2_core_handle_frame() answer
 * requests. Forwarding to UDP/TCP is done by the gateway.
 */
void cs2_core_handle_can_frame(struct cs2_core_t *core, struct can_frame *frame) {
    unsigned char netframe[CAN_ENCAP_SIZE];
    uint32_t canid;

    memset(netframe, 0, CAN_ENCAP_SIZE);
    canid = htonl(frame->can_id & CAN_EFF_MASK);
    memcpy(netframe, &canid, 4);
    netframe[4] = frame->can_dlc;
    memcpy(&netframe[5], frame->data, 8);
    cs2_core_handle_frame(core, CS2_SRC_CAN, -1, netframe);
}

static int cs2_core_tcp_config_frame(void *arg, int socket, unsigned char *data, int length) {
    struct cs2_core_t *core = arg;
    return core->io.tcp_send(core->io.arg, socket, data, length);
}

static int cs2_core_udp_config_frame(void *arg, int socket, unsigned char *data, int length) {
    struct cs2_core_t *core = arg;
    (void)socket;
    return core->io.udp_send(core->io.arg, data, length);
}

static void cs2_core_send_config(struct cs2_core_t *core, int tcp_socket,
				 char *name, uint32_t canid, int udp_ready, int tcp_ready) {
    int udp_destination = 0;
    if (udp_ready && cs2_config_send_stream(name, core->config_dir, canid, &udp_destination, 1,
					    CRC | COMPRESSED, 0, 1, cs2_core_udp_config_frame, core) < 0)
	syslog(LOG_ERR, "%s: failed to send UDP config stream for %s\n", __func__, name);
    if (tcp_ready && cs2_config_send_stream(name, core->config_dir, canid, &tcp_socket, 1,
					    CRC | COMPRESSED, 0, MAX_PACKETS, cs2_core_tcp_config_frame, core) < 0)
	syslog(LOG_ERR, "%s: failed to send TCP config stream for %s\n", __func__, name);
}

static int cs2_core_send_can_response(struct cs2_core_t *core, unsigned char *frame) {
    int can_result = core->io.can_enqueue(core->io.arg, frame);
    if (can_result < 0)
	syslog(LOG_ERR, "%s: can't queue CAN response\n", __func__);
    if (core->io.udp_send(core->io.arg, frame, CAN_ENCAP_SIZE) < 0)
	syslog(LOG_ERR, "%s: can't send UDP response\n", __func__);
    if (core->io.tcp_send_all(core->io.arg, frame, CAN_ENCAP_SIZE) < 0)
	syslog(LOG_ERR, "%s: can't send TCP response\n", __func__);
    return can_result;
}

static int cs2_core_parse_loknamen_range(const unsigned char *data, size_t *first, size_t *count) {
    char text[9], *end;
    unsigned long value;
    size_t i;

    memcpy(text, data, 8);
    text[8] = '\0';
    for (i = 0; i < 8 && text[i]; i++)
	;
    for (; i < 8; i++)
	if (text[i] != '\0' && text[i] != ' ')
	    return -1;
    if (!isdigit((unsigned char)text[0]))
	return -1;
    errno = 0;
    value = strtoul(text, &end, 10);
    if (errno || *end != ' ')
	return -1;
    *first = value;
    while (*end == ' ')
	end++;
    if (!isdigit((unsigned char)*end))
	return -1;
    errno = 0;
    value = strtoul(end, &end, 10);
    if (errno)
	return -1;
    *count = value;
    while (*end == ' ')
	end++;
    return *end == '\0' ? 0 : -1;
}

static struct cs2_loknamen_stream *cs2_core_make_loknamen_stream(
	struct cs2_core_t *core, uint32_t canid, size_t first, size_t count) {
    struct cs2_loknamen_stream *stream;
    unsigned char *padded;
    char *data = NULL;
    size_t length = 0, padded_length, i;
    int failed = 0;
    FILE *output = open_memstream(&data, &length);

    if (!output) {
	fprint_syslog_wc(stderr, LOG_ERR, "can't create locomotive name stream:", strerror(errno));
	return NULL;
    }
    if (fprintf(output, "[lokomotive]\n") < 0)
	failed = 1;
    for (i = 0; i < core->loco_count; i++) {
	if (i >= first && i - first < count &&
	    fprintf(output, "lok\n .nr=%zu\n .name=%s\n", i, core->locos[i].name) < 0)
	    failed = 1;
    }
    if (fprintf(output, "numloks\n .wert=%zu\n", core->loco_count) < 0)
	failed = 1;
    if (fclose(output) != 0)
	failed = 1;
    if (failed || length > UINT32_MAX - 7 || length > SIZE_MAX - 7) {
	syslog(LOG_ERR, "%s: can't build locomotive name stream\n", __func__);
	free(data);
	return NULL;
    }
    padded_length = (length + 7) & ~(size_t)7;
    padded = realloc(data, padded_length);
    if (!padded) {
	fprint_syslog_wc(stderr, LOG_ERR, "can't allocate locomotive name stream:", strerror(errno));
	free(data);
	return NULL;
    }
    memset(padded + length, 0, padded_length - length);
    stream = calloc(1, sizeof(*stream));
    if (!stream) {
	fprint_syslog_wc(stderr, LOG_ERR, "can't allocate locomotive stream state:", strerror(errno));
	free(padded);
	return NULL;
    }
    stream->data = padded;
    stream->length = length;
    stream->canid = (canid & 0xFFFEFFFFUL) | 0x00020000UL;
    stream->crc = CRCCCITT(padded, padded_length, 0xFFFF);
    return stream;
}

static void cs2_core_handle_loknamen(struct cs2_core_t *core, uint32_t canid, unsigned char *frame) {
    struct cs2_loknamen_request **slot = &core->loknamen_requests;
    struct cs2_loknamen_request *request;
    struct cs2_loknamen_stream *stream, **tail;
    unsigned char reply[CAN_ENCAP_SIZE];
    size_t first, count;
    uint16_t hash = canid & 0xFFFF;

    while (*slot && (*slot)->hash != hash)
	slot = &(*slot)->next;
    if (memcmp(&frame[5], "loknamen", 8) == 0) {
	if (!*slot) {
	    request = calloc(1, sizeof(*request));
	    if (!request) {
		fprint_syslog_wc(stderr, LOG_ERR, "can't allocate locomotive request:", strerror(errno));
		return;
	    }
	    request->hash = hash;
	    *slot = request;
	}
	memcpy(reply, frame, CAN_ENCAP_SIZE);
	reply[1] |= 1;
	if (cs2_core_send_can_response(core, reply) < 0) {
	    request = *slot;
	    *slot = request->next;
	    free(request);
	}
	return;
    }
    if (!*slot || !isdigit(frame[5]))
	return;
    request = *slot;
    *slot = request->next;
    free(request);
    if (cs2_core_parse_loknamen_range(&frame[5], &first, &count) < 0) {
	syslog(LOG_WARNING, "%s: invalid locomotive name range\n", __func__);
	return;
    }
    stream = cs2_core_make_loknamen_stream(core, canid, first, count);
    if (!stream)
	return;
    memcpy(reply, frame, CAN_ENCAP_SIZE);
    reply[1] |= 1;
    if (cs2_core_send_can_response(core, reply) < 0) {
	free(stream->data);
	free(stream);
	return;
    }
    tail = &core->loknamen_streams;
    while (*tail)
	tail = &(*tail)->next;
    *tail = stream;
}

void cs2_core_service(struct cs2_core_t *core) {
    while (core->loknamen_streams && core->io.can_free(core->io.arg) > 0) {
	struct cs2_loknamen_stream *stream = core->loknamen_streams;
	unsigned char frame[CAN_ENCAP_SIZE] = { 0 };
	uint32_t value = htonl(stream->canid);
	size_t padded_length = (stream->length + 7) & ~(size_t)7;

	memcpy(frame, &value, 4);
	if (!stream->header_sent) {
	    uint16_t crc = htons(stream->crc);
	    value = htonl((uint32_t)stream->length);
	    frame[4] = 6;
	    memcpy(&frame[5], &value, 4);
	    memcpy(&frame[9], &crc, 2);
	    stream->header_sent = 1;
	} else {
	    frame[4] = 8;
	    memcpy(&frame[5], stream->data + stream->offset, 8);
	    stream->offset += 8;
	}
	if (cs2_core_send_can_response(core, frame) < 0 || stream->offset >= padded_length) {
	    core->loknamen_streams = stream->next;
	    free(stream->data);
	    free(stream);
	}
    }
}

/*
 * Logical processing of a received 13-byte frame, regardless of whether it
 * arrived via UDP, TCP or the CAN bus: answer CAN member pings (in slave
 * mode, faked as CS2), serve config file requests (loks/mags/gbs/fs and the
 * *stat files) from the local config directory, feed config data streams to
 * the core's stream receiver, distribute config change broadcasts and apply
 * the MS1 workaround. Config answers go to UDP and, for TCP requests, also
 * to the sending TCP client. The frame may be modified in place (e.g. MS1 workaround).
 * Forwarding the frame is the gateway's job - every frame is
 * forwarded, regardless of what is answered here.
 */
void cs2_core_handle_frame(struct cs2_core_t *core, enum cs2_core_source src, int tcp_socket, unsigned char *netframe) {
    uint32_t canid;
    unsigned char reply[CAN_ENCAP_SIZE];
    char config_name[9];
    char gbs_name[MAXLINE];
    int udp_ready, tcp_ready;

    gbs_name[0] = '\0';

    memcpy(&canid, netframe, 4);
    canid = ntohl(canid);

    /* frames from the CAN bus: a config change broadcast from a CAN member
       triggers a config data stream to all TCP clients */
    if (src == CS2_SRC_CAN) {
	cs2_core_update_loco(core, canid, netframe);
	if ((canid & 0x01FF0000UL) == 0x00400000UL && netframe[4] == 8) {
	    cs2_core_handle_loknamen(core, canid, netframe);
	}
	if (((canid & 0x1FFFF00UL) == 0x0434700UL) && (netframe[4] == 8)) {
	    uint8_t fill = canid & 0xFF;
	    int *clients;
	    int count;
	    strncpy(config_name, (char *)&netframe[5], 8);
	    config_name[8] = '\0';
	    syslog(LOG_NOTICE, "%s: config request >%s<\n", __func__, config_name);
	    count = core->io.tcp_clients(core->io.arg, &clients);
	    if (cs2_config_send_stream(config_name, core->config_dir, canid, clients, count,
				       CRC | COMPRESSED | BCCHANGE, fill, MAX_PACKETS,
				       cs2_core_tcp_config_frame, core) < 0)
		syslog(LOG_ERR, "%s: failed to send config change stream for %s\n", __func__, config_name);
	    return;
	}
	/* slave mode: answer CAN member pings from the bus */
	if (core->slave && ((canid & 0xFFFF0000UL) == 0x00300000UL)) {
	    if (core->cfg.verbose)
		printf("                received CAN ping\n");
	    cs2_core_answer_ping(core);
	}
	return;
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
		if (core->slave) {
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
	if (src == CS2_SRC_TCP && core->slave)
	    break;
	if (netframe[4] != 8) {
	    syslog(LOG_WARNING, "%s: ignoring config request with DLC %u\n", __func__, netframe[4]);
	    break;
	}
	if (src == CS2_SRC_UDP) {
	    /* check for initiated config request */
	    if (canid == 0x0040af7e) {
		if (core->cfg.verbose)
		    printf("copy config request\n");
		syslog(LOG_NOTICE, "%s %d: copy config request\n", __func__, __LINE__);
		core->cfg.cs2_config_copy = 1;
		cs2_core_copy_config(core);
		break;
	    }
	    if (core->slave)
		break;
	}
	memcpy(reply, netframe, CAN_ENCAP_SIZE);
	reply[1] |= 1;
	/* check for special copy request */
	if (canid == 0x0040af7e) {
	    reply[4] = 4;
	    strcpy((char *)&reply[5], "copy");
	    if (core->io.tcp_send(core->io.arg, tcp_socket, reply, CAN_ENCAP_SIZE) < 0)
		syslog(LOG_ERR, "%s: failed to send TCP copy acknowledgement\n", __func__);
	    if (core->io.udp_send(core->io.arg, reply, CAN_ENCAP_SIZE) < 0)
		syslog(LOG_ERR, "%s: failed to send UDP copy acknowledgement\n", __func__);
	    if (core->cfg.verbose)
		printf("CAN member copy request\n");
	    syslog(LOG_NOTICE, "%s: CAN member copy request\n", __func__);
	    core->cfg.cs2_config_copy = 1;
	} else {
	    strncpy(config_name, (char *)&netframe[5], 8);
	    config_name[8] = '\0';
	    syslog(LOG_NOTICE, "%s: config request >%s<\n", __func__, config_name);
	    if (core->cfg.verbose)
		printf("%s ID 0x%08x %s\n", __func__, canid, config_name);
	    udp_ready = core->io.udp_send(core->io.arg, reply, CAN_ENCAP_SIZE) >= 0;
	    if (!udp_ready)
		syslog(LOG_ERR, "%s: failed to send UDP config acknowledgement\n", __func__);
	    tcp_ready = 0;
	    if (src == CS2_SRC_TCP) {
		tcp_ready = core->io.tcp_send(core->io.arg, tcp_socket, reply, CAN_ENCAP_SIZE) >= 0;
		if (!tcp_ready)
		    syslog(LOG_ERR, "%s: failed to send TCP config acknowledgement\n", __func__);
	    }
	    if (strcmp("loks", config_name) == 0) {
		syslog(LOG_NOTICE, "%s: sending lokomotive.cs2\n", __func__);
		cs2_core_send_config(core, tcp_socket, "lokomotive.cs2", canid, udp_ready, tcp_ready);
		break;
	    } else if (strcmp("mags", config_name) == 0) {
		syslog(LOG_NOTICE, "%s: sending magnetartikel.cs2\n", __func__);
		cs2_core_send_config(core, tcp_socket, "magnetartikel.cs2", canid, udp_ready, tcp_ready);
		break;
	    } else if (strncmp("gbs-", config_name, 4) == 0) {
		char *end;
		long page_number = strtol(&config_name[4], &end, 10);
		if (isdigit((unsigned char)config_name[4]) && *end == '\0' &&
		    page_number < MAX_TRACK_PAGE && page_name && page_name[page_number]) {
		    int path_len = snprintf(gbs_name, sizeof(gbs_name), "gleisbilder/%s", page_name[page_number]);
		    if (path_len < 0 || (size_t)path_len >= sizeof(gbs_name)) {
			syslog(LOG_ERR, "%s: track page path is too long\n", __func__);
			break;
		    }
		    syslog(LOG_NOTICE, "%s: sending %s\n", __func__, gbs_name);
		    cs2_core_send_config(core, tcp_socket, gbs_name, canid, udp_ready, tcp_ready);
		    break;
		}
		syslog(LOG_NOTICE, "%s: can't send config page %s\n", __func__, config_name);
		break;
	    } else if (strcmp("gbs", config_name) == 0) {
		syslog(LOG_NOTICE, "%s: sending gleisbild.cs2\n", __func__);
		cs2_core_send_config(core, tcp_socket, "gleisbild.cs2", canid, udp_ready, tcp_ready);
		break;
	    } else if (strcmp("fs", config_name) == 0) {
		syslog(LOG_NOTICE, "%s: sending fahrstrassen.cs2\n", __func__);
		cs2_core_send_config(core, tcp_socket, "fahrstrassen.cs2", canid, udp_ready, tcp_ready);
		break;
	    }
	    /* TODO : these files depends on different internal states */
	    else if (strcmp("lokstat", config_name) == 0) {
		/* fprintf(stderr, "%s: lokstat (lokomotive.sr2) not implemented yet\n", __func__); */
		syslog(LOG_NOTICE, "%s: sending lokomotive.sr2\n", __func__);
		cs2_core_send_config(core, tcp_socket, "lokomotive.sr2", canid, udp_ready, tcp_ready);
		break;
	    } else if (strcmp("magstat", config_name) == 0) {
		/* fprintf(stderr, "%s: magstat (magnetartikel.sr2) not implemented yet\n\n", __func__); */
		syslog(LOG_NOTICE, "%s: sending magnetartikel.sr2\n", __func__);
		cs2_core_send_config(core, tcp_socket, "magnetartikel.sr2", canid, udp_ready, tcp_ready);
		break;
	    } else if (strcmp("gbsstat", config_name) == 0) {
		/* fprintf(stderr, "%s: gbsstat (gleisbild.sr2) not implemented yet\n\n", __func__); */
		syslog(LOG_NOTICE, "%s: sending gleisbild.sr2\n", __func__);
		cs2_core_send_config(core, tcp_socket, "gleisbild.sr2", canid, udp_ready, tcp_ready);
		break;
	    } else if (strcmp("fsstat", config_name) == 0) {
		/* fprintf(stderr, "%s: fsstat (fahrstrassen.sr2) not implemented yet\n\n", __func__); */
		syslog(LOG_NOTICE, "%s: sending fahrstrassen.sr2\n", __func__);
		cs2_core_send_config(core, tcp_socket, "fahrstrassen.sr2", canid, udp_ready, tcp_ready);
		break;
	    }
	    break;
	}
	break;
    case (0x00420000UL):
	if (src == CS2_SRC_TCP) {
	    /* check for bordcast config change: DLC = 7 */
	    if (netframe[4] == 7 &&
		(!(core->cfg.start || core->cfg.stream) ||
		 core->cfg.stream_hash == (canid & 0xFFFF))) {
		/* TODO */
		syslog(LOG_NOTICE, "%s: broadcast config change", __func__);
		if (!core->cfg.dir) {
		    syslog(LOG_WARNING, "%s: config directory is not initialized\n", __func__);
		    break;
		}
		core->cfg.name = BROADCAST_C0NFIG_UPDATE;
		core->cfg.state = CS2_STATE_BROADCAST_UPDATE;
	    }
	    /* check for initiated copy request or brodcast update */
	    cs2_config_reassemble(&core->cfg, netframe, cs2_core_tcp_config_frame, core);
	    print_can_frame(NET_TCP_FORMAT_STRG, netframe, core->cfg.verbose);
	}
	break;
	/* fake cyclic MS1 slave monitoring response: the modified frame
	   is forwarded by the gateway */
    case (0x0C000000UL):
	if (src == CS2_SRC_TCP && core->ms1_workaround)
	    netframe[5] = 0x03;
	break;
    default:
	break;
    }
}

int cs2_core_handle_ascii_frame(struct cs2_core_t *core, int tcp_socket, unsigned char *netframe, int length) {
    (void)core;
    return decode_ascii_frame(tcp_socket, netframe, length);
}
