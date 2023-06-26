#define _GNU_SOURCE

#include "pool.h"

#include <pthread.h>
#include <sched.h>
#include <unistd.h>

pthread_mutex_t pool_id_mutex;
uint16_t pool_id_base_index = 0;
uint16_t pool_id_count = 0;
uint16_t pool_ids[65536] = {0};
uint16_t pool_limit = 2;
uint16_t pool_id_size = 0;

void pool_id_init(uint16_t limit) {
  pool_limit = limit;
  pthread_mutex_init(&pool_id_mutex, NULL);
  for (size_t i = 0; i < 65536; i++) {
    pool_ids[i] = i;
  }
  pool_id_size = 1 << pool_limit;
}

void pool_id_free() { pthread_mutex_destroy(&pool_id_mutex); }

inline uint8_t pool_id_is_full() { return pool_id_count == pool_id_size; }

int32_t pool_id_get() {
  pthread_mutex_lock(&pool_id_mutex);
  if (pool_id_is_full()) {
    pthread_mutex_unlock(&pool_id_mutex);
    return -1;
  }
  // LOG_INFO("pool_id_get");
  pool_id_count++;
  uint16_t pool_id =
      pool_ids[(pool_id_base_index + pool_id_count) & (pool_id_size - 1)];
  pthread_mutex_unlock(&pool_id_mutex);
  return pool_id;
}

void pool_id_put(uint16_t id) {
  pthread_mutex_lock(&pool_id_mutex);
  if (pool_id_count == 0) {
    pthread_mutex_unlock(&pool_id_mutex);
    return;
  }
  pool_id_count--;
  pool_ids[pool_id_base_index] = id;
  pool_id_base_index++;
  pool_id_base_index &= pool_id_size - 1;
  pthread_mutex_unlock(&pool_id_mutex);
}
