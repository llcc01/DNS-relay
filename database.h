#ifndef DATABASE_H__
#define DATABASE_H__

#include <stdint.h>

#define FILENAME "dnsrelay.txt"

#define TYPE_A 1
#define TYPE_NS 2
#define TYPE_CNAME 5
#define TYPE_PTR 12
#define TYPE_MX 15
#define TYPE_AAAA 28

#define CLASS_IN 1

typedef struct {
    char* name;
    uint16_t type;
    uint16_t class;
    uint32_t ttl;
    uint16_t rdlength;
    uint8_t* rdata;
} dns_record_t;

typedef struct {
    dns_record_t* records;
    int size;
} database_t;


void database_init(void);
void database_load(const char* filename);
void database_add(const dns_record_t* record);
void database_lookup(const char* name, dns_record_t* record);
void database_free(void);

void dns_record_print(const dns_record_t* record);
void dns_record_to_buf(const dns_record_t* record, uint8_t* buf, size_t* len);
void dns_record_from_buf(const uint8_t* buf, size_t buf_len, size_t* len, size_t offset, dns_record_t* record);
void dns_record_free(dns_record_t* record);

#endif