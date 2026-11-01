/*
 * Definitions gio.c expects from can2lan.c, so gio.c can be built as a
 * shared library and its real transmit queue code tested with ctypes.
 */
#include "can2lan.h"

unsigned char GETCONFIG[] = { 0x00, 0x40, 0xaf, 0x7e, 0x08 };
unsigned char GETCONFIG_DATA[] = { 0x00, 0x42, 0x03, 0x00, 0x08 };
char *cs2_configs[][2] = { { NULL, NULL } };
char **page_name;
struct filter_t filter[2];
unsigned char netframe[MAXDG];
