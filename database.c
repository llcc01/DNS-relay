#include "database.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "cache.h"
#include "logger.h"
#include "lookup.h"
#include "main.h"
#include "protocol.h"

database_t database;

dns_record_t local_name_rec;

void database_init(database_t* db) {
  LOG_INFO("database_init");
  db->msgs = NULL;
  db->size = 0;

  char local_name[NAME_MAX_SIZE];
  name_to_qname(LOCAL_NAME, local_name);
  local_name_rec.name = malloc(strlen(local_name) + 1);
  strcpy(local_name_rec.name, local_name);

  local_name_rec.type = TYPE_PTR;
  local_name_rec.class = CLASS_IN;
  local_name_rec.ttl = 120;

  char local_domain[NAME_MAX_SIZE];
  name_to_qname(LOCAL_DOMAIN, local_domain);
  local_name_rec.rdlength = strlen(local_domain) + 1;
  local_name_rec.rdata = malloc(local_name_rec.rdlength);
  memcpy(local_name_rec.rdata, local_domain, local_name_rec.rdlength);
}

void database_add(database_t* db, const dns_message_t* msg) {
  // add the record to the database

  IF_LOG_LEVEL(LOG_LEVEL_DEBUG) {
    char name[NAME_MAX_SIZE];
    qname_to_name(msg->questions[0].name, name);
    LOG_DEBUG("database_add %s %d.%d.%d.%d", name, msg->answers[0].rdata[0],
              msg->answers[0].rdata[1], msg->answers[0].rdata[2],
              msg->answers[0].rdata[3]);
  }

  db->msgs = realloc(db->msgs, (db->size + 1) * sizeof(dns_message_t));
  dns_message_copy(&(db->msgs[db->size]), msg);
  db->msgs[db->size].header.id = db->size;
  db->size++;
}

void database_get_record(const database_t* db, db_id_t id,
                         dns_record_t* record) {
  // get the record from the database
  LOG_DEBUG("database_get_msg");
  if (id >= db->size) {
    PANIC("Error: database_get_msg: id >= db->size");
  }
  dns_record_copy(record, &(db->msgs[id].answers[0]));
}

void database_get_records(const database_t* db, db_id_t id,
                          dns_message_t* msg) {
  // get the message from the database
  LOG_DEBUG("database_get_msg");
  if (id >= db->size) {
    PANIC("Error: database_get_msg: id >= db->size");
  }
  dns_message_t* src = &(db->msgs[id]);
  // msg->header.id = src->header.id;

  // LOG_INFO("record qdcount: %d, ancount: %d, nscount: %d, arcount: %d",
  //          src->header.qdcount, src->header.ancount, src->header.nscount,
  //          src->header.arcount);
  msg->timestamp = src->timestamp;
  msg->expire = src->expire;

  if (msg->expire < time(NULL)) {
    LOG_INFO("cache expired, id: %" PRId64, id);
    msg->header.ancount = 0;
    msg->answers = NULL;
    msg->header.nscount = 0;
    msg->authorities = NULL;
    msg->header.arcount = 0;
    msg->additionals = NULL;
    return;
  }

  uint32_t ttl_offset = time(NULL) - src->timestamp;

  if (msg->header.ancount != 0) {
    for (size_t i = 0; i < msg->header.ancount; i++) {
      dns_record_free(&(msg->answers[i]));
    }
    free(msg->answers);
  }

  if (msg->header.nscount != 0) {
    for (size_t i = 0; i < msg->header.nscount; i++) {
      dns_record_free(&(msg->authorities[i]));
    }
    free(msg->authorities);
  }

  if (msg->header.arcount != 0) {
    for (size_t i = 0; i < msg->header.arcount; i++) {
      dns_record_free(&(msg->additionals[i]));
    }
    free(msg->additionals);
  }

  msg->header.ancount = src->header.ancount;
  if (msg->header.ancount > 0) {
    msg->answers = malloc(msg->header.ancount * sizeof(dns_record_t));
    for (size_t i = 0; i < msg->header.ancount; i++) {
      dns_record_copy(&(msg->answers[i]), &(src->answers[i]));
      if (msg->answers[i].ttl != 0) {
        msg->answers[i].ttl -= ttl_offset;
      }
    }
  } else {
    msg->answers = NULL;
  }

  msg->header.nscount = src->header.nscount;
  if (msg->header.nscount > 0) {
    msg->authorities = malloc(msg->header.nscount * sizeof(dns_record_t));
    for (size_t i = 0; i < msg->header.nscount; i++) {
      dns_record_copy(&(msg->authorities[i]), &(src->authorities[i]));
      if (msg->authorities[i].ttl != 0) {
        msg->authorities[i].ttl -= ttl_offset;
      }
    }
  } else {
    msg->authorities = NULL;
  }

  msg->header.arcount = src->header.arcount;
  if (msg->header.arcount > 0) {
    msg->additionals = malloc(msg->header.arcount * sizeof(dns_record_t));
    for (size_t i = 0; i < msg->header.arcount; i++) {
      dns_record_copy(&(msg->additionals[i]), &(src->additionals[i]));
      if (msg->additionals[i].ttl != 0) {
        msg->additionals[i].ttl -= ttl_offset;
      }
    }
  } else {
    msg->additionals = NULL;
  }
}

void database_load(database_t* db, const char* filename) {
  // load the database from the file
  LOG_DEBUG("database_load");
  FILE* fp = fopen(filename, "r");
  if (fp == NULL) {
    PANIC("Error: cannot open file %s", filename);
  }
  char name[256];
  int ip_addr[4];
  dns_question_t question;
  dns_record_t record;
  dns_message_t msg;
  msg.header.qdcount = 1;
  msg.header.ancount = 1;
  msg.header.nscount = 0;
  msg.header.arcount = 0;
  msg.questions = &question;
  msg.answers = &record;
  while (fscanf(fp, "%d.%d.%d.%d %s", &ip_addr[0], &ip_addr[1], &ip_addr[2],
                &ip_addr[3], name) != EOF) {
    char qname[NAME_MAX_SIZE];
    name_to_qname(name, qname);

    question.name = qname;
    question.type = TYPE_A;
    question.class = CLASS_IN;

    record.name = qname;
    record.type = TYPE_A;
    record.class = CLASS_IN;
    record.ttl = 120;
    record.rdlength = 4;
    record.rdata = malloc(4);
    for (size_t i = 0; i < 4; i++) {
      record.rdata[i] = ip_addr[i];
    }

    database_add(db, &msg);
    // dns_record_print(&record);
  }

  database_to_bst(db);
}

void database_lookup_all(dns_message_t* msg) {
  // lookup the record in the database
  LOG_DEBUG("database_lookup");
  db_id_t db_id = DB_INVALID_ID;

  db_id = database_bst_lookup(static_index, &(msg->questions[0]));
  if (db_id != DB_INVALID_ID) {
    LOG_DEBUG("database_lookup: found in database, id: %" PRId64, db_id);
    database_get_records(&database, db_id, msg);
    return;
  }

  db_id = database_bst_lookup(cache_index, &(msg->questions[0]));
  if (db_id != DB_INVALID_ID) {
    LOG_DEBUG("database_lookup: found in cache, id: %" PRId64, db_id);
    database_get_records(&LRU_cache, db_id, msg);
    cache_refresh_id(db_id);

    return;
  }
}
