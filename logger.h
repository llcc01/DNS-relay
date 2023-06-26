#ifndef LOGGER_H__
#define LOGGER_H__

#include <stdio.h>
#include <time.h>
#include <pthread.h>

#define LOG_LEVEL_DEBUG 0
#define LOG_LEVEL_INFO 1
#define LOG_LEVEL_WARN 2
#define LOG_LEVEL_ERROR 3

extern int log_level;
extern pthread_mutex_t log_mutex;

#define LOG_LEVEL log_level

#define IF_LOG_LEVEL(level) if (LOG_LEVEL <= level)

#define LOG_DEBUG(...)                            \
  do {                                            \
    if (LOG_LEVEL <= LOG_LEVEL_DEBUG) {           \
      pthread_mutex_lock(&log_mutex);             \
      printf("[DEBUG] ");                         \
      printf("%lld ", (long long int)time(NULL)); \
      printf(__VA_ARGS__);                        \
      printf("\n");                               \
      pthread_mutex_unlock(&log_mutex);           \
    }                                             \
  } while (0)

#define LOG_INFO(...)                             \
  do {                                            \
    if (LOG_LEVEL <= LOG_LEVEL_INFO) {            \
      pthread_mutex_lock(&log_mutex);             \
      printf("[INFO] ");                          \
      printf("%lld ", (long long int)time(NULL)); \
      printf(__VA_ARGS__);                        \
      printf("\n");                               \
      pthread_mutex_unlock(&log_mutex);           \
    }                                             \
  } while (0)

#define LOG_WARN(...)                             \
  do {                                            \
    if (LOG_LEVEL <= LOG_LEVEL_WARN) {            \
      pthread_mutex_lock(&log_mutex);             \
      printf("[WARN] ");                          \
      printf("%lld ", (long long int)time(NULL)); \
      printf(__VA_ARGS__);                        \
      printf("\n");                               \
      pthread_mutex_unlock(&log_mutex);           \
    }                                             \
  } while (0)

#define LOG_ERROR(...)                            \
  do {                                            \
    if (LOG_LEVEL <= LOG_LEVEL_ERROR) {           \
      pthread_mutex_lock(&log_mutex);             \
      printf("[ERROR] ");                         \
      printf("%lld ", (long long int)time(NULL)); \
      printf(__VA_ARGS__);                        \
      printf("\n");                               \
      pthread_mutex_unlock(&log_mutex);           \
    }                                             \
  } while (0)

void logger_set_level(int level);

#endif