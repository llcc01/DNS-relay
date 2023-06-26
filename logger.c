#include "logger.h"

#include <pthread.h>

int log_level = LOG_LEVEL_DEBUG;

pthread_mutex_t log_mutex;

void logger_set_level(int level) {
  log_level = level;
  pthread_mutex_init(&log_mutex, NULL);
}