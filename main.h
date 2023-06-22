#ifndef MAIN_H__
#define MAIN_H__

#include <stdio.h>
#define PANIC(msg,...) { fprintf(stderr, msg "\n%s:%d\n", ##__VA_ARGS__,__FILE__, __LINE__); exit(1); }

#endif