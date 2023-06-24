#ifndef DATABASE_H__
#define DATABASE_H__

#include "platform.h"
#include "protocol.h"

#define FILENAME "dnsrelay.txt"

#define LOCAL_NAME "1.0.0.127.in-addr.arpa."
#define LOCAL_DOMAIN "dns-relay."

typedef struct {
    dns_message_t* msgs;
    int size;
} database_t;

extern dns_record_t local_name_rec;

void database_init(void);
void database_load(const char* filename);
void database_add(const dns_message_t* msg);
void database_get_record(bst_id_t id, dns_record_t* record);
void database_get_msg(bst_id_t id, dns_message_t* msg);
bst_id_t database_lookup(const dns_question_t* question);
void database_free(void);

#endif