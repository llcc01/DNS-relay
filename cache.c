#include "cache.h"

#include "database.h"
#include "lookup.h"
#include "platform.h"

node_t* head;
node_t* tail;
node_t* temp;
short list_size;

database_t LRU_cache;
// db_id_t temp_idx = 0;
// db_id_t next_idx = 0;
int cache_is_full = 0;

void linked_list_init() {
  head = malloc(sizeof(node_t));
  tail = malloc(sizeof(node_t));
  temp = malloc(sizeof(node_t));
  head->next = tail;
  head->pre = NULL;
  head->idx = -1;
  tail->pre = head;
  tail->next = NULL;
  tail->idx = -1;
}

void cache_init() {
  LRU_cache.msgs = malloc(9000 * sizeof(dns_message_t));  // 8192
  LRU_cache.size = 8192;
}

void list_insert(db_id_t idx) {
  node_t* new_node = malloc(sizeof(node_t));
  new_node->idx = idx;
  new_node->next = head->next;
  new_node->pre = head;
  head->next->pre = new_node;
  head->next = new_node;
  list_size++;
  if (list_size >= 8192) cache_is_full = 1;
}

void list_delete_tail() {
  node_t* tmp = tail->pre;
  tail->pre->pre->next = tail;
  tail->pre = tail->pre->pre;
  free(tmp);
  list_size--;
}

void list_delete_mid(short idx) {
  node_t* tmp = NULL;
  for (node_t* i = head; i != tail; i = i->next) {
    if (idx == i->idx) {
      i->pre->next = i->next;
      i->next->pre = i->pre;
      tmp = i;
      list_size--;
    }
  }
  free(tmp);
}

int list_isempty() {
  if (head->next == tail && tail->pre == head)
    return 1;
  else
    return 0;
}

void cache_put(const dns_message_t* msg) {
  uint16_t new_idx = 0;
  if (cache_is_full) {
    new_idx = tail->pre->idx;
    bst_delete(cache_index, &(LRU_cache.msgs[new_idx].questions[0]));
    dns_message_free(&(LRU_cache.msgs[new_idx]));
    list_delete_tail();
  } else {
    new_idx = list_size;
  }
  dns_message_copy(&(LRU_cache.msgs[new_idx]), msg);

  list_insert(new_idx);
  head->next->idx = new_idx;
  cache_index = bst_insert(cache_index, &(msg->questions[0]), new_idx);

  IF_LOG_LEVEL(LOG_LEVEL_INFO) {
    char name[NAME_MAX_SIZE];
    qname_to_name(msg->questions[0].name, name);
    LOG_INFO("cache_put: %s,\tid: %d,\ttype: %d", name, new_idx,
             msg->questions[0].type);
  }
}