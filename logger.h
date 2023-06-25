#ifndef LOGGER_H__
#define LOGGER_H__

#include <stdio.h>
#include <time.h>

#define LOG_LEVEL_DEBUG 0
#define LOG_LEVEL_INFO 1
#define LOG_LEVEL_WARN 2
#define LOG_LEVEL_ERROR 3

extern int log_level;

#define LOG_LEVEL log_level

#define LOG_DEBUG(...) do { \
    if (LOG_LEVEL <= LOG_LEVEL_DEBUG) { \
        printf("[DEBUG] "); \
        printf("%lld ",(long long int)time(NULL)); \
        printf(__VA_ARGS__); \
        printf("\n"); \
    } \
} while (0)

#define LOG_INFO(...) do { \
    if (LOG_LEVEL <= LOG_LEVEL_INFO) { \
        printf("[INFO] "); \
        printf("%lld ",(long long int)time(NULL)); \
        printf(__VA_ARGS__); \
        printf("\n"); \
    } \
} while (0)

#define LOG_WARN(...) do { \
    if (LOG_LEVEL <= LOG_LEVEL_WARN) { \
        printf("[WARN] "); \
        printf("%lld ",(long long int)time(NULL)); \
        printf(__VA_ARGS__); \
        printf("\n"); \
    } \
} while (0)

#define LOG_ERROR(...) do { \
    if (LOG_LEVEL <= LOG_LEVEL_ERROR) { \
        printf("[ERROR] "); \
        printf("%lld ",(long long int)time(NULL)); \
        printf(__VA_ARGS__); \
        printf("\n"); \
    } \
} while (0)

void logger_set_level(int level);

#endif