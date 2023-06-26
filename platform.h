#ifndef PLATFORM_H__
#define PLATFORM_H__

#ifdef __linux__
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>
#define Sleep(x) usleep(x * 1000)
#endif

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include "logger.h"


#define BST_INVALID_ID -1
typedef int64_t db_id_t;

#define PANIC(msg, ...)                                                  \
  {                                                                      \
    fprintf(stderr, msg "\n%s:%d\n", ##__VA_ARGS__, __FILE__, __LINE__); \
    exit(1);                                                             \
  }

#endif