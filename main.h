#ifndef MAIN_H__
#define MAIN_H__

#include <stdio.h>
#include <time.h>
// #include <windows.h>
#include "platform.h"
#include "protocol.h"

#define MULTI_THREAD

#ifdef MULTI_THREAD
#define THREAD_POOL
#endif

#ifdef THREAD_POOL
// 2^THREAD_LIMIT
#define THREAD_LIMIT 1
#define THREAD_NUM (1<<THREAD_LIMIT)
#endif


extern SOCKET s;
extern SOCKET s_upstream;
extern uint8_t* handle_thread_states;

#endif