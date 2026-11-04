#pragma once
#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>
typedef uint8_t (*mac_processor)(uint32_t *, const char *, const char *, uint8_t *, size_t *);
int mac_packet_loop(mac_processor processor);
bool mac_packet_emit(const void *data, size_t len);
int zapret_engine_main(int argc, char **argv);
