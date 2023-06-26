#ifndef CACHE_H__
#define CACHE_H__

#include "protocol.h"

void cache_init();
void cache_lookup(const dns_question_t* question, dns_message_t* result);
void cache_add(const dns_message_t* msg);

#endif