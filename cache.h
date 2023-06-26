#ifndef CACHE_H__
#define CACHE_H__

#include "database.h"
#include "protocol.h"


typedef struct node_t {
  struct node_t* pre;
  db_id_t idx;
  struct node_t* next;
} node_t;

extern node_t* head;
extern node_t* tail;
extern short list_size;
// extern db_id_t temp_idx;
// extern db_id_t next_idx;
extern int cache_is_full;
extern database_t LRU_cache;

void linked_list_init();
void list_insert(db_id_t idx);

void list_delete_tail();
void list_delete_mid(short idx);
int list_isempty();

void cache_init();

void cache_put(const dns_message_t* msg);
void cache_refresh_id(db_id_t idx);

#endif