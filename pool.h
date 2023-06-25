#ifndef POOL_H__
#define POOL_H__

#include "dns.h"
#include <pthread.h>
#include "platform.h"

extern uint16_t pool_id_count;

void pool_id_init(uint16_t limit);
void pool_id_free();
uint8_t pool_id_is_full();
int32_t pool_id_get();
void pool_id_put(uint16_t id);

#endif