/* ----------------------------------------------------------------------------
 * "THE BEER-WARE LICENSE" (Revision 42):
 * <info@gerhard-bertelsmann.de> wrote this file. As long as you retain this
 * notice you can do whatever you want with this stuff. If we meet some day,
 * and you think this stuff is worth it, you can buy me a beer in return.
 * Gerhard Bertelsmann
 * ----------------------------------------------------------------------------
 */

/*
 * CS2 lokomotive.cs2 to Z21 App (SQLite) converter
 */

/*
 * Server sends initial packet / UDP
 *
 * Epoch Time: 1664630770.036
 * Src: 192.168.0.171, Dst: 255.255.255.255
 * User Datagram Protocol, Src Port: 51312, Dst Port: 5728
 *    Destination Port: 5728
 * Data (13 bytes)
 *
 * 0000  31 36 36 34 36 33 30 37 36 39 39 38 32            1664630769982
 *
 *
 *  Epoch Time [ms]: 1664630770036 - 1664630769982 => 54 ms
 *
 *  Summary:
 *  UDP Broadcast (255.255.255.255) packet with destination port 5728 with Unix epoch timestamp [ms] string
 */

/*
 * Z21 App answer / UDP
    int known_count = HASH_COUNT(known_uids);
    int new_count = 0;
    if (only_new) {
        struct loco_data_t *l;
        for (l = loco_data; l != NULL; l = l->hh.next) {
            if (l->uid && !known_uid_exists(l->uid)) new_count++;
        }
        if (new_count == 0)
            return EXIT_SUCCESS;
    }
 *
 * {"os":"android","appVersion":"1.4.6","deviceName":"Z21 Emulator","deviceType":"OpenWRT",
 * "request":"device_information_request","buildNumber":6076,"apiVersion":1}
 */

/*
 * Switch to TCP Connection on Port 5728 / Server is Z21 App
 * Data Source sends file
 *
 * {"owningDevice":{"os":"ios","appVersion":"1.4.6","deviceName":"iPad von Gerhard","deviceType":"iPad7,3",
 *  "request":"device_information_request","buildNumber":6076,"apiVersion":1},"fileName":"Data.z21",
 *  "request":"file_transfer_info","fileSize":744444}
 *
 * Z21 App sends:
 * install
 *
 * Data Source sends the file Data.z21 and closes TCP connection
 */

#define _GNU_SOURCE
#include <arpa/inet.h>
#include <assert.h>
#include <errno.h>
#include <fcntl.h>
#include <libgen.h>
#include <net/if.h>
#include <netinet/in.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/inotify.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <sys/types.h>
#include <unistd.h>

#include "uthash.h"
#include <sqlite3.h>
#include <uuid/uuid.h>

#include "cs2_net.h"
#include "fmapping.h"
#include "geturl.h"
#include "net.h"
#include "read-cs2-config.h"
#include "utils.h"
#include "z21.h"
#include "Empty_Z21_sqlite.h"

#define MAXLINE 256
#define Z21PORT 5728

/* polling intervals (ms) */
#ifndef NET_POLL_INTERVAL_MS
#define NET_POLL_INTERVAL_MS 2000
#endif

#ifndef FILE_POLL_INTERVAL_MS
#define FILE_POLL_INTERVAL_MS 1000
#endif

#define UUIDTEXTSIZE (sizeof(uuid_t) * 2) + 5
#define INTERFACE_LIST "wlan0,br-lan,br0"

char z21_fstring_none[] = "none";
char *timestamp;
struct z21_data_t z21_data;
struct z21_config_data_t config_data;
extern char rfc3986[256];

static char *z21_tcp_target_ip = NULL;

static int file_poll_interval_ms = FILE_POLL_INTERVAL_MS;

#define SQL_EXEC(SQL)                                    \
    do {                                                 \
        ret = sqlite3_exec(db, (SQL), 0, 0, &err_msg);   \
        if (ret != SQLITE_OK) {                          \
            fprintf(stderr, "SQL error: %s\n", err_msg); \
            sqlite3_free(err_msg);                       \
            sqlite3_close(db);                           \
            return EXIT_FAILURE;                         \
        }                                                \
    } while (0)

unsigned char udpframe[MAXDG];
extern struct loco_data_t *loco_data;

struct known_uid_t {
    unsigned int uid;
    UT_hash_handle hh;
};
static struct known_uid_t *known_uids = NULL;

static int ipc_sock = -1;
static struct sockaddr_in ipc_server_addr;
static int ipc_available = 0;

/*
 * Print command line usage information and available options.
 */
void print_usage(char *prg) {
    fprintf(stderr, "\nUsage: %s -v -c <config_dir> -i <interface list> -s <config link> -p <icons link>\n", prg);
    fprintf(stderr, "   Version 1.0.0\n\n");
    fprintf(stderr, "         -a <time_out>       try to find CS2/CS2 for <time_out> seconds using -i <interface list>\n");
    fprintf(stderr, "         -c <config_dir>     set the config directory - default %s\n", config_data.config_dir);
    fprintf(stderr, "         -i <interface list> interface list - default %s\n", INTERFACE_LIST);
    fprintf(stderr, "         -t <ip>            direct TCP target IP (send file via TCP)\n");
    fprintf(stderr, "         -s <link to config> link to the lokomotive.cs2\n");
    fprintf(stderr, "         -p <link to icons>  link to the icons server directory\n");
    fprintf(stderr, "         -v                  verbose\n\n");
}

/*
 * Open the given ZIP file and send it via TCP to the specified
 * Z21 App client. Waits for an "install" acknowledgement and
 * then streams the file contents.
 */
int send_tcp_data(struct sockaddr_in *client_sa, const char *zip_name) {
    int n, st;
    size_t b;
    FILE *fp;
    struct sockaddr_in server_sa;
    char *offer;
    char *buffer;
    int32_t filesize;
    char path[128];

    snprintf(path, sizeof path, "/tmp/%s", zip_name);
    fp = fopen(path, "rb");
    if (!fp) {
        fprintf(stderr, "can't open Z21 data %s: %s\n", path, strerror(errno));
        return EXIT_FAILURE;
    }

    fseek(fp, 0, SEEK_END);
    filesize = ftell(fp);
    fseek(fp, 0, SEEK_SET);
    v_printf(config_data.verbose, "Filesize %d \n", filesize);

    /* prepare TCP client socket */
    if ((st = socket(AF_INET, SOCK_STREAM, 0)) < 0) {
        fprintf(stderr, "can't create TCP socket: %s\n", strerror(errno));
        fclose(fp);
        exit(EXIT_FAILURE);
    }

    memset(&server_sa, 0, sizeof server_sa);
    server_sa.sin_family = AF_INET;
    /* copy IP adresse from UDP request */
    memcpy(&server_sa.sin_addr.s_addr, &client_sa->sin_addr.s_addr, 4);
    server_sa.sin_port = htons(Z21PORT);

    if (connect(st, (struct sockaddr *)&server_sa, sizeof server_sa)) {
        fprintf(stderr, "can't connect to TCP socket : %s\n", strerror(errno));
        fclose(fp);
        return (EXIT_FAILURE);
    }
        asprintf(&offer,
                 "{\"owningDevice\":{\"os\":\"android\",\"appVersion\":\"1.4.7\",\"deviceName\":\"Z21 Emulator\",\"deviceType\":\"OpenWRT\","
                 "\"request\":\"device_information_request\",\"buildNumber\":6076,\"apiVersion\":1},\"fileName\":\"%s\","
                 "\"request\":\"file_transfer_info\",\"fileSize\":%d}\n",
                 zip_name, filesize);
    v_printf(config_data.verbose, "send TCP\n%s", offer);
    send(st, offer, strlen(offer), 0);
    free(offer);

    buffer = calloc(1024, 1);
    v_printf(config_data.verbose, "Waiting for <install> from client\n");
    n = recv(st, buffer, sizeof(buffer), 0);

    if (n < 0) {
        fprintf(stderr, "error receiveing answer install: %s\n", strerror(errno));
        free(buffer);
        fclose(fp);
        return EXIT_FAILURE;
    }

    v_printf(config_data.verbose, "received from Z21 App %d chars: >%s<\n", n, buffer);

    if (strncmp(buffer, "install", n) == 0) {
        while (!feof(fp)) {
            b = fread(buffer, 1, sizeof buffer, fp);
            if (send(st, buffer, b, 0) < 0) {
                fprintf(stderr, "error sending Z21 data file: %s\n", strerror(errno));
                fclose(fp);
                free(buffer);
                return EXIT_FAILURE;
            }
        }
        if (shutdown(st, SHUT_RDWR)) {
            fprintf(stderr, "error closing TCP stream: %s\n", strerror(errno));
            fclose(fp);
            free(buffer);
            return EXIT_FAILURE;
        }
    }

    printf("data send complete\n");
    free(buffer);
    fclose(fp);
    return EXIT_SUCCESS;
}

/*
 * Helper: send a Z21 data file (full or incremental) to a specific IP via TCP.
 * which == 0 -> Data.z21, which == 1 -> Data.z21loco
 */
static int send_z21_file_to_ip(int which, const char *ip) {
    struct sockaddr_in client;
    const char *zip_name;

    switch (which) {
    case 0:
        zip_name = "Data.z21";
        break;
    case 1:
        zip_name = "Data.z21loco";
        break;
    default:
        fprintf(stderr, "invalid Z21 file selector %d (use 0 or 1)\n", which);
        return EXIT_FAILURE;
    }

    memset(&client, 0, sizeof client);
    client.sin_family = AF_INET;
    if (inet_pton(AF_INET, ip, &client.sin_addr) != 1) {
        fprintf(stderr, "invalid TCP target IP: %s\n", ip);
        return EXIT_FAILURE;
    }

    v_printf(config_data.verbose, "Direct TCP send to %s:%d (file %s)\n", ip, Z21PORT, zip_name);
    return send_tcp_data(&client, zip_name);
}

/* send Z21 file directly via TCP to the configured target IP (-t)
 * which == 0 -> Data.z21 (full)
 * which == 1 -> Data.z21loco (incremental)
 */
int send_z21_file(int which) {
    if (!z21_tcp_target_ip) {
        fprintf(stderr, "no TCP target IP specified (use -t <ip>)\n");
        return EXIT_FAILURE;
    }
    return send_z21_file_to_ip(which, z21_tcp_target_ip);
}

/*
 * Return non-zero if the given locomotive UID is already
 * present in the known_uids hash table.
 */
static int known_uid_exists(unsigned int uid) {
    struct known_uid_t *e = NULL;
    HASH_FIND(hh, known_uids, &uid, sizeof(unsigned int), e);
    return e != NULL;
}

/*
 * Add the given locomotive UID to the known_uids hash table
 * if it is not already present.
 */
static void known_uid_add(unsigned int uid) {
    if (known_uid_exists(uid))
        return;
    struct known_uid_t *e = calloc(1, sizeof *e);
    if (!e)
        return;
    e->uid = uid;
    HASH_ADD(hh, known_uids, uid, sizeof(unsigned int), e);
}

/*
 * Create the export directory hierarchy below basedir using the
 * given UUID string. Returns the full path of the leaf directory
 * or NULL on error.
 */
char *create_directory(char *basedir, char *uuidtext) {
    struct stat st;
    char *dir;

    memset(&st, 0, sizeof st);
    if (stat(basedir, &st)) {
        fprintf(stderr, "%s: basedir \'%s\' doesn't exist\n", __func__, basedir);
        return NULL;
    }

    memset(&st, 0, sizeof st);
    asprintf(&dir, "%s/export", basedir);
    if (stat(dir, &st) == -1) {
        if (mkdir(dir, 0775)) {
            fprintf(stderr, "%s: can't create %s\n", __func__, dir);
            return NULL;
        }
    }
    free(dir);

    asprintf(&dir, "%s/export/%s", basedir, uuidtext);
    if (mkdir(dir, 0775)) {
        fprintf(stderr, "%s: can't create %s\n", __func__, dir);
        return NULL;
    }
    return dir;
}

/*
 * Copy the contents of the file src to dst using a simple
 * buffered read/write loop. Returns EXIT_SUCCESS on success.
 */
int copy_file(char *src, char *dst) {
    char c[4096];
    FILE *fd_in, *fd_out;

    // printf("copy file %s -> %s\n", src, dst);

    fd_in = fopen(src, "r");
    if (!fd_in) {
        fprintf(stderr, "%s: can't fopen %s\n", __func__, src);
        return EXIT_FAILURE;
    }

    fd_out = fopen(dst, "w");
    if (!fd_out) {
        fprintf(stderr, "%s: can't fopen %s\n", __func__, dst);
        fclose(fd_in);
        return EXIT_FAILURE;
    }

    while (!feof(fd_in)) {
        size_t bytes = fread(c, 1, sizeof c, fd_in);
        if (bytes) {
            fwrite(c, 1, bytes, fd_out);
        }
    }

    fclose(fd_in);
    fclose(fd_out);
    return EXIT_SUCCESS;
}

/*
 * Update the update_history table in the Z21 SQLite database
 * with the current timestamp and fixed version information.
 */
int sql_update_history(sqlite3 *db) {
    int ret;
    char *err_msg;
    char *time_st;
    time_t t = time(NULL);
    struct tm tm = *localtime(&t);

    char *sql = "DELETE FROM update_history;";
    SQL_EXEC(sql);
    asprintf(&time_st, "INSERT INTO update_history VALUES(1, \'ios\', \'%02d.%02d.%02d, %02d:%02d:%02d Mitteleuropäische Normalzeit\', \'1.4.7\', 1000, 100);",
             tm.tm_mday, tm.tm_mon + 1, tm.tm_year + 1900, tm.tm_hour, tm.tm_min, tm.tm_sec);
    SQL_EXEC(time_st);
    free(time_st);
    sql = "PRAGMA user_version = 15";
    SQL_EXEC(sql);
    return EXIT_SUCCESS;
}

/* internal helper: insert one loco and its functions */
static int insert_one_loco(sqlite3 *db, struct z21_config_data_t *config_data, char *z21_dir, char *icon_dir, char *ip_s,
                           struct loco_data_t *l, int vehicle_index, int *func_index_ptr) {
    char *err_msg;
    int button, n, ret;
    char *sql;
    char *z21_fstring;
    uuid_t uuid;
    char uuidtext[UUIDTEXTSIZE];
    char *picture;
    char *loco_icon_s, *loco_icon_d;
    uint16_t loco_address;

    url_encoder_rfc_tables_init();

    uuid_generate(uuid);
    uuid_unparse_upper(uuid, uuidtext);
    asprintf(&picture, "%s.png", uuidtext);
    asprintf(&loco_icon_d, "%s/%s", z21_dir, picture);

    if (config_data->icon_server) {
        char *icon_s = calloc(strlen(l->icon ? l->icon : "leeres Gleis") * 3, 1);
        if (!icon_s)
            return EXIT_FAILURE;
        url_encode((unsigned char *)(l->icon ? l->icon : "leeres Gleis"), icon_s);
        asprintf(&loco_icon_s, "%s/%s.png", config_data->icon_server, icon_s);
        get_url(loco_icon_s, NULL, loco_icon_d);
        free(icon_s);
    } else {
        asprintf(&loco_icon_s, "%s/%s.png", icon_dir, l->icon ? l->icon : "leeres Gleis");
        if (copy_file(loco_icon_s, loco_icon_d) == EXIT_FAILURE) {
            free(loco_icon_s);
            asprintf(&loco_icon_s, "%s/leeres Gleis.png", icon_dir);
            copy_file(loco_icon_s, loco_icon_d);
        }
    }

    loco_address = loco_address_mapping(l->uid);
    asprintf(&sql, "INSERT INTO vehicles VALUES(%d, '%s', '%s', 0, %d, %d, 1, %d, '', '', 0, '', '', '', '', '', '', '', '', '', '', '', "
                   "0, '', 0, '%s', 0, 0, 0, 786, 0, 0, 1024, '', 0, 0);",
             vehicle_index, l->name, picture, l->tmax, loco_address, vehicle_index - 1, ip_s);
    SQL_EXEC(sql);
    free(sql);
    free(loco_icon_s);
    free(loco_icon_d);
    free(picture);
    for (n = 0; n < 32; n++) {
        if (l->function[n].type) {
            z21_fstring = (l->function[n].type <= sizeof fmapping / sizeof fmapping[0] - 1) ? fmapping[l->function[n].type] : z21_fstring_none;
            button = l->function[n].duration ? 2 : 0;
            asprintf(&sql, "INSERT INTO functions VALUES( %d, %d, %d, '', %d.0, %d, \"%s\", %d, %d, %d);",
                     *func_index_ptr, vehicle_index, button, l->function[n].duration, n, z21_fstring, n, 1, 0);
            SQL_EXEC(sql);
            free(sql);
            (*func_index_ptr)++;
        }
    }
    return EXIT_SUCCESS;
}

/* insert a single locomotive into the SQLite DB and copy its icon */
/* unified inserter: insert all locos or only new ones based on known_uids */
int sql_insert_locos(sqlite3 *db, struct z21_config_data_t *config_data, char *z21_dir, char *icon_dir, char *ip_s, int only_new) {
    int veh_idx = 1, func_idx = 1;
    struct loco_data_t *l;
    for (l = loco_data; l != NULL; l = l->hh.next) {
        if (l->uid == 0)
            continue;
        if (only_new && known_uid_exists(l->uid))
            continue;
        insert_one_loco(db, config_data, z21_dir, icon_dir, ip_s, l, veh_idx, &func_idx);
        known_uid_add(l->uid);
        veh_idx++;
    }
    return EXIT_SUCCESS;
}

/* build Data.z21 for either all locos or only newly added UIDs. */
int build_z21_package(int only_new) {
    int ret;
    sqlite3 *db;
    FILE *fp;
    char *z21_dir, *sql_file, *icon_dir, *systemcmd;
    uuid_t local_uuid;
    char local_uuidtext[UUIDTEXTSIZE];

    int known_count = HASH_COUNT(known_uids);
    int new_count = 0;
    if (only_new) {
        struct loco_data_t *l;
        for (l = loco_data; l != NULL; l = l->hh.next) {
            if (l->uid && !known_uid_exists(l->uid))
                new_count++;
        }
        if (new_count == 0)
            return EXIT_SUCCESS;
    }

    uuid_generate(local_uuid);
    uuid_unparse_upper(local_uuid, local_uuidtext);
    z21_dir = create_directory("/tmp", local_uuidtext);
    if (!z21_dir) {
        fprintf(stderr, "problems creating export directory\n");
        return EXIT_FAILURE;
    }

    asprintf(&sql_file, "%s/Loco.sqlite", z21_dir);
    fp = fopen(sql_file, "w");
    if (!fp) {
        fprintf(stderr, "Cannot open empty Z21 database file for writing: %s\n", sql_file);
        return EXIT_FAILURE;
    }
    if (fwrite(Empty_Z21_sqlite, 1, sizeof Empty_Z21_sqlite, fp) != sizeof Empty_Z21_sqlite) {
        fprintf(stderr, "Cannot write Z21 empty database file: %s\n", sql_file);
        return EXIT_FAILURE;
    }
    fclose(fp);

    ret = sqlite3_open(sql_file, &db);
    if (ret != SQLITE_OK) {
        fprintf(stderr, "Cannot open database: %s\n", sqlite3_errmsg(db));
        sqlite3_close(db);
        return EXIT_FAILURE;
    }
    sql_update_history(db);
    asprintf(&icon_dir, "%s/icons", config_data.config_dir);

    int insert_all = (!only_new) || (known_count == 0);
    sql_insert_locos(db, &config_data, z21_dir, icon_dir, config_data.ip_address, insert_all ? 0 : 1);

    sqlite3_close(db);
    free(sql_file);
    if (config_data.config_server || config_data.icon_server)
        curl_global_cleanup();
    free(icon_dir);

    /* choose zip name: full on initial/all import, incremental otherwise */
    const char *zip_name = insert_all ? "Data.z21" : "Data.z21loco";
    asprintf(&systemcmd, "cd /tmp; minizip -i -o %s export/%s/* 2>&1 > /dev/null", zip_name, local_uuidtext);
    v_printf(config_data.verbose, "Zipping %s\n", systemcmd);
    system(systemcmd);
    free(systemcmd);
    asprintf(&systemcmd, "rm -rf /tmp/export/%s", local_uuidtext);
    system(systemcmd);
    free(systemcmd);

    return EXIT_SUCCESS;
}

/*
 * Forward declarations for IPC helper functions used below.
 */
static void ipc_poll_new_clients(void);
static void ipc_send_file_to_all_clients(int which);

/*
 * Helper: re-read loco file (local) and send incremental package if new UIDs appeared.
 * Returns number of new locos (>=0), or -1 on error.
 */
static int reload_and_send_if_new_file(const char *loco_file) {
    delete_all_loco_data();
    if (read_loco_data((char *)loco_file, CONFIG_FILE) < 0) {
        fprintf(stderr, "can't re-read loco file: %s\n", strerror(errno));
        return EXIT_FAILURE;
    }
    int new_count = 0;
    struct loco_data_t *l;
    for (l = loco_data; l != NULL; l = l->hh.next) {
        if (l->uid && !known_uid_exists(l->uid))
            new_count++;
    }
    if (new_count > 0) {
        build_z21_package(1); //build incremental for existing Z21-App, so only new locos are added
        ipc_send_file_to_all_clients(1); // send incremental update to all currently connected clients
    }
    build_z21_package(0); //build all in case, new Z21-App gets connected and needs full configuration
    return EXIT_SUCCESS;
}

/*
 * Helper: re-fetch config via URL and send incremental package if new UIDs appeared.
 * Returns number of new locos (>=0), or -1 on error.
 */
static int reload_and_send_if_new_url(const char *config_url) {
    char *config_buf = get_url((char *)config_url, NULL, NULL);
    if (!config_buf) {
        fprintf(stderr, "can't fetch config from %s: %s\n", config_url, strerror(errno));
        return EXIT_FAILURE;
    }
    delete_all_loco_data();
    if (read_loco_data(config_buf, 0) < 0) {
        fprintf(stderr, "can't parse loco data from URL\n");
        free(config_buf);
        return EXIT_FAILURE;
    }
    free(config_buf);
    int new_count = 0;
    struct loco_data_t *l;
    for (l = loco_data; l != NULL; l = l->hh.next) {
        if (l->uid && !known_uid_exists(l->uid))
            new_count++;
    }
    if (new_count > 0) {
        build_z21_package(1); //build incremental for existing Z21-App, so only new locos are added
        ipc_send_file_to_all_clients(1); // send incremental update to all currently connected clients
    }
    build_z21_package(0); //build all in case, new Z21-App gets connected and needs full configuration
    return EXIT_SUCCESS;
}

/*
 * File-mode: inotify watcher for local file changes only.
 */
static void watch_file_inotify(const char *loco_file) {
    char *dup1 = strdup(loco_file);
    char *dup2 = strdup(loco_file);
    if (!dup1 || !dup2) {
        fprintf(stderr, "oom deriving path for inotify\n");
        free(dup1);
        free(dup2);
        exit(EXIT_FAILURE);
    }
    char *watch_dir = dirname(dup1);
    char *watch_name = basename(dup2);

    int fd = inotify_init1(IN_NONBLOCK);
    if (fd < 0) {
        fprintf(stderr, "inotify_init failed: %s\n", strerror(errno));
        free(dup1);
        free(dup2);
        exit(EXIT_FAILURE);
    }

    int wd = inotify_add_watch(fd, watch_dir,
                                IN_CLOSE_WRITE | IN_MOVED_TO | IN_CREATE |
                                IN_MODIFY | IN_ATTRIB | IN_DELETE);
    if (wd < 0) {
        fprintf(stderr, "inotify_add_watch failed for %s: %s\n", watch_dir, strerror(errno));
        close(fd);
        free(dup1);
        free(dup2);
        exit(EXIT_FAILURE);
    }

    char buf[4096] __attribute__((aligned(__alignof__(struct inotify_event))));
    for (;;) {
        fd_set rfds;
        int maxfd = fd;
        int ret;

        FD_ZERO(&rfds);
        FD_SET(fd, &rfds);
        if (ipc_sock >= 0) {
            FD_SET(ipc_sock, &rfds);
            if (ipc_sock > maxfd)
                maxfd = ipc_sock;
        }

        /* Block, bis entweder eine Dateiänderung oder eine IPC-Nachricht anliegt */
        ret = select(maxfd + 1, &rfds, NULL, NULL, NULL);
        if (ret < 0) {
            if (errno == EINTR)
                continue;
            fprintf(stderr, "select failed: %s\n", strerror(errno));
            close(fd);
            free(dup1);
            free(dup2);
            exit(EXIT_FAILURE);
        }

        /* IPC: neue Clients von z21emu */
        if (ipc_sock >= 0 && FD_ISSET(ipc_sock, &rfds)) {
            ipc_poll_new_clients();
        }

        /* inotify: Dateiänderungen lokomotive.cs2 */
        if (FD_ISSET(fd, &rfds)) {
            int len = read(fd, buf, sizeof buf);
            if (len > 0) {
                int i = 0;
                while (i < len) {
                    struct inotify_event *event = (struct inotify_event *)&buf[i];
                    if (event->len > 0 && strcmp(event->name, watch_name) == 0) {
                        if (event->mask & (IN_CLOSE_WRITE | IN_MOVED_TO | IN_CREATE | IN_MODIFY | IN_ATTRIB | IN_DELETE)) {
                            /* debounce wie bisher */
                            usleep(200000);
                            reload_and_send_if_new_file(loco_file);
                        }
                    }
                    i += sizeof(struct inotify_event) + event->len;
                }
            }
        }
    }
}

/*
 * Network-mode: timer-based watcher that periodically fetches config via URL.
 */
static void watch_network_timer(const char *config_url) {
    for (;;) {
        /* handle asynchronous IPC notifications about new clients */
        ipc_poll_new_clients();

        usleep(NET_POLL_INTERVAL_MS * 1000);
        reload_and_send_if_new_url(config_url);
    }
}


/*
 * Initialize IPC socket to z21emu and perform an initial HELLO/list exchange.
 * For every known client IP, send a full Data.z21 package.
 * Blocks and retries until z21emu answers.
 */
static void ipc_init_and_sync(void) {
    if (ipc_sock >= 0 && ipc_available)
        return;

    if (ipc_sock < 0) {
        ipc_sock = socket(AF_INET, SOCK_DGRAM, 0);
        if (ipc_sock < 0) {
            fprintf(stderr, "can't create IPC UDP socket: %s\n", strerror(errno));
            return;
        }
    }

    memset(&ipc_server_addr, 0, sizeof ipc_server_addr);
    ipc_server_addr.sin_family = AF_INET;
    ipc_server_addr.sin_port = htons(Z21_IPC_PORT);
    inet_aton("127.0.0.1", &ipc_server_addr.sin_addr);

    v_printf(config_data.verbose, "Waiting for z21emu IPC on 127.0.0.1:%d ...\n", Z21_IPC_PORT);

    while (!ipc_available) {
        const char hello[] = "HELLO\n";
        ssize_t s = sendto(ipc_sock, hello, sizeof hello - 1, 0,
                           (struct sockaddr *)&ipc_server_addr, sizeof ipc_server_addr);
        if (s < 0) {
            fprintf(stderr, "IPC send HELLO failed: %s\n", strerror(errno));
        }

        /* wait for CLIENT/END responses */
        for (;;) {
            fd_set rfds;
            struct timeval tv;
            int ret;

            FD_ZERO(&rfds);
            FD_SET(ipc_sock, &rfds);
            tv.tv_sec = 5;
            tv.tv_usec = 0;

            ret = select(ipc_sock + 1, &rfds, NULL, NULL, &tv);
            if (ret < 0) {
                if (errno == EINTR)
                    continue;
                fprintf(stderr, "IPC select error: %s\n", strerror(errno));
                break;
            } else if (ret == 0) {
                /* timeout, retry HELLO */
                break;
            }

            if (FD_ISSET(ipc_sock, &rfds)) {
                char buf[128];
                ssize_t n;
                struct sockaddr_in src;
                socklen_t slen = sizeof src;

                n = recvfrom(ipc_sock, buf, sizeof buf - 1, 0,
                             (struct sockaddr *)&src, &slen);
                if (n <= 0)
                    continue;
                buf[n] = '\0';

                if (!strncmp(buf, "CLIENT ", 7)) {
                    char *ip = buf + 7;
                    char *nl = strchr(ip, '\n');
                    if (nl)
                        *nl = '\0';
                    send_z21_file_to_ip(0, ip);
                } else if (!strncmp(buf, "END", 3)) {
                    ipc_available = 1;
                    v_printf(config_data.verbose, "IPC initial sync complete.\n");
                    return;
                } else if (!strncmp(buf, "NEW ", 4)) {
                    /* treat NEW like CLIENT during initial sync */
                    char *ip = buf + 4;
                    char *nl = strchr(ip, '\n');
                    if (nl)
                        *nl = '\0';
                    send_z21_file_to_ip(0, ip);
                }
            }
        }

        /* wait a bit before re-trying HELLO */
        sleep(1);
    }
}

/*
 * Non-blocking poll for IPC NEW notifications from z21emu.
 * For each "NEW <ip>" message, send a full Data.z21 package to that client.
 */
static void ipc_poll_new_clients(void) {
    if (ipc_sock < 0)
        return;

    for (;;) {
        char buf[128];
        ssize_t n;
        struct sockaddr_in src;
        socklen_t slen = sizeof src;

        n = recvfrom(ipc_sock, buf, sizeof buf - 1, MSG_DONTWAIT,
                     (struct sockaddr *)&src, &slen);
        if (n <= 0)
            break;
        buf[n] = '\0';

        if (!strncmp(buf, "NEW ", 4)) {
            char *ip = buf + 4;
            char *nl = strchr(ip, '\n');
            if (nl)
                *nl = '\0';
            send_z21_file_to_ip(0, ip);
        }
    }
}

/*
 * Request the current list of clients from z21emu and send a Z21 file
 * (full or incremental) to each of them.
 */
static void ipc_send_file_to_all_clients(int which) {
    if (ipc_sock < 0)
        return;

    const char list_cmd[] = "LIST\n";
    ssize_t s = sendto(ipc_sock, list_cmd, sizeof list_cmd - 1, 0,
                       (struct sockaddr *)&ipc_server_addr, sizeof ipc_server_addr);
    if (s < 0) {
        fprintf(stderr, "IPC send LIST failed: %s\n", strerror(errno));
        return;
    }

    for (;;) {
        fd_set rfds;
        struct timeval tv;
        int ret;

        FD_ZERO(&rfds);
        FD_SET(ipc_sock, &rfds);
        tv.tv_sec = 5;
        tv.tv_usec = 0;

        ret = select(ipc_sock + 1, &rfds, NULL, NULL, &tv);
        if (ret < 0) {
            if (errno == EINTR)
                continue;
            fprintf(stderr, "IPC select error during LIST: %s\n", strerror(errno));
            break;
        } else if (ret == 0) {
            /* timeout */
            break;
        }

        if (FD_ISSET(ipc_sock, &rfds)) {
            char buf[128];
            ssize_t n;
            struct sockaddr_in src;
            socklen_t slen = sizeof src;

            n = recvfrom(ipc_sock, buf, sizeof buf - 1, 0,
                         (struct sockaddr *)&src, &slen);
            if (n <= 0)
                continue;
            buf[n] = '\0';

            if (!strncmp(buf, "CLIENT ", 7)) {
                char *ip = buf + 7;
                char *nl = strchr(ip, '\n');
                if (nl)
                    *nl = '\0';
                send_z21_file_to_ip(which, ip);
            } else if (!strncmp(buf, "END", 3)) {
                break;
            } else if (!strncmp(buf, "NEW ", 4)) {
                /* handle asynchronous NEW while we are waiting */
                char *ip = buf + 4;
                char *nl = strchr(ip, '\n');
                if (nl)
                    *nl = '\0';
                send_z21_file_to_ip(0, ip);
            }
        }
    }
}

/*
 * Program entry point: parse command line options, load the CS2
 * loco configuration, build the initial Z21 package and then
 * watch for configuration changes (file or HTTP) while serving
 * updates to all connected Z21 App clients via z21emu IPC.
 */
int main(int argc, char **argv) {
    char *config_file, *loco_file, *interface_list;
    int opt;

    memset(&config_data, 0, sizeof config_data);
    config_data.config_dir = strdup("/www");
    interface_list = strdup(INTERFACE_LIST);

    while ((opt = getopt(argc, argv, "a:c:i:p:s:f:t:vh?")) != -1) {
        switch (opt) {
        case 'a':
            config_data.auto_timeout = atoi(optarg);
            break;
        case 'c':
            if (strnlen(optarg, MAXLINE) < MAXLINE) {
                free(config_data.config_dir);
                config_data.config_dir = strndup(optarg, MAXLINE - 1);
            } else {
                fprintf(stderr, "config file dir to long\n");
                exit(EXIT_FAILURE);
            }
            break;
        case 'i':
            if (strnlen(optarg, MAXLINE) < MAXLINE) {
                free(interface_list);
                interface_list = strndup(optarg, MAXLINE - 1);
            } else {
                fprintf(stderr, "interface list to long\n");
                exit(EXIT_FAILURE);
            }
            break;
        case 'p':
            if (strnlen(optarg, MAXLINE) < MAXLINE) {
                config_data.icon_server = strndup(optarg, MAXLINE - 1);
            } else {
                fprintf(stderr, "server address to long\n");
                exit(EXIT_FAILURE);
            }
            break;
        case 's':
            if (strnlen(optarg, MAXLINE) < MAXLINE) {
                config_data.config_server = strndup(optarg, MAXLINE - 1);
            } else {
                fprintf(stderr, "server address to long\n");
                exit(EXIT_FAILURE);
            }
            break;
        case 'f':
            file_poll_interval_ms = atoi(optarg);
            if (file_poll_interval_ms < 100)
                file_poll_interval_ms = 100;
            break;
        case 't':
            if (strnlen(optarg, MAXLINE) < MAXLINE) {
                z21_tcp_target_ip = strndup(optarg, MAXLINE - 1);
            } else {
                fprintf(stderr, "TCP target IP to long\n");
                exit(EXIT_FAILURE);
            }
            break;
        case 'v':
            config_data.verbose = 1;
            break;
        case 'h':
        case '?':
            print_usage(basename(argv[0]));
            exit(EXIT_SUCCESS);
            break;
        }
    }

    /* we try to find the CS2 IP */
    if (config_data.auto_timeout) {
        /* find the broadcast address */
        char *broadcast_ip;
        if (!(broadcast_ip = find_first_ip(interface_list, BROADCAST_IP))) {
            fprintf(stderr, "can't find a valid broadcast IP on list: %s\n", interface_list);
            exit(EXIT_FAILURE);
        }
        /* we have found the CS2 IP so let's use network config */
        config_data.cs2_ip = find_cs2(broadcast_ip, config_data.auto_timeout);
        if (config_data.cs2_ip.s_addr) {
            config_data.ip_address = inet_ntoa(config_data.cs2_ip);
            asprintf(&config_data.config_server, "http://%s/config/lokomotive.cs2", config_data.ip_address);
            asprintf(&config_data.icon_server, "http://%s/icons", config_data.ip_address);
            v_printf(config_data.verbose, "guessed CS2 IP address %s\n", config_data.ip_address);
        } else {
            fprintf(stderr, "can't find CS2 on interfaces: %s\n", interface_list);
            exit(EXIT_FAILURE);
        }
    }

    /* find the IP address for the database */
    if (!(config_data.ip_address = find_first_ip(interface_list, 0)))
        config_data.ip_address = strdup("127.0.0.1");

    if (config_data.config_server || config_data.icon_server)
        curl_global_init(0);

    /* try to read the lokomotive.cs via http ... */
    if (config_data.config_server) {
        v_printf(config_data.verbose, "using network for config file\n");
        config_file = get_url(config_data.config_server, NULL, NULL);
        if (config_file) {
            read_loco_data(config_file, 0);
        } else {
            fprintf(stderr, "can't read loco file: %s\n", strerror(errno));
            exit(EXIT_FAILURE);
        }
        free(config_file);
        /* ... otherwise use file & watch for changes */
    } else {
        if (asprintf(&loco_file, "%s/config/%s", config_data.config_dir, loco_name) < 0) {
            fprintf(stderr, "can't alloc buffer for loco_name: %s\n", strerror(errno));
            exit(EXIT_FAILURE);
        }
        v_printf(config_data.verbose, "loco_file: >%s<\n", loco_file);
        read_loco_data(loco_file, CONFIG_FILE);
    }

    if (!HASH_COUNT(loco_data)) {
        fprintf(stderr, "no locos found !\n");
        exit(EXIT_FAILURE);
    }
    v_printf(config_data.verbose, "\nlocos in CS2 File: %u\n", HASH_COUNT(loco_data));

    /* initial build & send: create full package and push it to all
     * currently connected Z21 App clients via z21emu IPC */
    build_z21_package(0);
    ipc_init_and_sync();
    
    /* Start watcher modes: file (-c) uses inotify; network (-s or autodetected) uses timer. */
    if (!config_data.config_server) {
        watch_file_inotify(loco_file);
    } else {
        watch_network_timer(config_data.config_server);
    }
    return EXIT_SUCCESS;
}
