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
extern database_t database;

void database_init(database_t* db);
void database_load(database_t* db, const char* filename);
void database_add(database_t* db, const dns_message_t* msg);
void database_get_record(const database_t* db, db_id_t id,
                         dns_record_t* record);
void database_get_records(const database_t* db, db_id_t id, dns_message_t* msg);
void database_lookup_all(dns_message_t* msg);
void database_free(void);

#endif