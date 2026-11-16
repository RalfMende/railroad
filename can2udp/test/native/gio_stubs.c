/*
 * Definitions gio.c expects from can2lan.c, so gio.c can be built as a
 * shared library and its real transmit queue code tested with ctypes.
 */
#include "can2lan.h"

char **page_name;
struct filter_t filter[2];
unsigned char netframe[MAXDG];
