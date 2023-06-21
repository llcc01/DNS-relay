#include "database.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "protocol.h"

database_t database;

void database_init()
{
    printf("database_init\n");
    database.records = NULL;
    database.size = 0;
}

void database_add(const dns_record_t* record)
{
    // add the record to the database
    // printf("database_add %s %d.%d.%d.%d\n", record->name, record->rdata[0], record->rdata[1], record->rdata[2], record->rdata[3]);
    database.records = realloc(database.records, (database.size + 1) * sizeof(dns_record_t));
    database.records[database.size].type = record->type;
    database.records[database.size].class = record->class;
    database.records[database.size].ttl = record->ttl;
    database.records[database.size].rdlength = record->rdlength;

    database.records[database.size].name = malloc(strlen(record->name) + 1);
    strcpy(database.records[database.size].name, record->name);

    database.records[database.size].rdata = malloc(record->rdlength);
    memcpy(database.records[database.size].rdata, record->rdata, record->rdlength);

    database.size++;
}

void database_load(const char* filename)
{
    // load the database from the file
    printf("database_load\n");
    FILE* fp = fopen(filename, "r");
    if (fp == NULL) {
        printf("Error: cannot open file %s\n", filename);
        exit(1);
    }
    char name[256];
    uint8_t ip_addr[4];
    dns_record_t record;
    while (fscanf(fp, "%d.%d.%d.%d %s", &ip_addr[0], &ip_addr[1], &ip_addr[2], &ip_addr[3], name) != EOF) {
        record.name = name;
        record.type = TYPE_A;
        record.class = CLASS_IN;
        record.ttl = 0;
        record.rdlength = 4;
        record.rdata = ip_addr;
        database_add(&record);
    }
}

void database_lookup(const char* name, dns_record_t* record)
{
    // lookup the record in the database
    printf("database_lookup\n");
    for (int i = 0; i < database.size; i++) {
        if (strcmp(database.records[i].name, name) == 0) {
            record->name = database.records[i].name;
            record->type = database.records[i].type;
            record->class = database.records[i].class;
            record->ttl = database.records[i].ttl;
            record->rdlength = database.records[i].rdlength;
            record->rdata = database.records[i].rdata;
            return;
        }
    }
    record->name = NULL;
    record->type = 0;
    record->class = 0;
    record->ttl = 0;
    record->rdlength = 0;
    record->rdata = NULL;
}

void dns_record_print(const dns_record_t* record)
{
    // print the record
    printf("dns_record_print\n");
    char name[NAME_MAX_SIZE];
    qname_to_name(record->name, name);
    printf("name: %s\n", name);
    printf("type: %d\n", record->type);
    printf("class: %d\n", record->class);
    printf("ttl: %d\n", record->ttl);
    printf("rdlength: %d\n", record->rdlength);
    printf("rdata: ");
    if (record->type == TYPE_A)
    {
        printf("A %d.%d.%d.%d\n", record->rdata[0], record->rdata[1], record->rdata[2], record->rdata[3]);
    }
    else if (record->type == TYPE_NS)
    {
        printf("NS %s\n", record->rdata);
    }
    else if (record->type == TYPE_CNAME)
    {
        char cname[NAME_MAX_SIZE];
        qname_to_name(record->rdata, cname);
        printf("CNAME %s\n", cname);
    }
    else if (record->type == TYPE_PTR)
    {
        printf("PTR %s\n", record->rdata);
    }
    else if (record->type == TYPE_MX)
    {
        printf("MX %d %s\n", record->rdata[0] << 8 | record->rdata[1], record->rdata + 2);
    }
    else if (record->type == TYPE_AAAA)
    {
        printf("AAAA ");
        printf("%02x%02x", record->rdata[0], record->rdata[1]);
        for (int i = 1; i < record->rdlength; i += 2)
        {
            printf(":%02x%02x", record->rdata[i], record->rdata[i + 1]);
        }
        printf("\n");
    }
    else
    {
        printf("rdata: ");
        for (int i = 0; i < record->rdlength; i++)
        {
            printf("%02x ", record->rdata[i]);
        }
        printf("\n");
    }
}

void dns_record_to_buf(const dns_record_t* record, uint8_t* buf, size_t* len)
{
    // convert the record to the buffer
    printf("dns_record_to_buf\n");
    int offset = 0;
    int name_len = strlen(record->name);
    memcpy(buf + offset, record->name, name_len);
    offset += name_len;
    buf[offset++] = 0;
    buf[offset++] = record->type >> 8;
    buf[offset++] = record->type & 0xFF;
    buf[offset++] = record->class >> 8;
    buf[offset++] = record->class & 0xFF;
    buf[offset++] = record->ttl >> 24;
    buf[offset++] = (record->ttl >> 16) & 0xFF;
    buf[offset++] = (record->ttl >> 8) & 0xFF;
    buf[offset++] = record->ttl & 0xFF;
    buf[offset++] = record->rdlength >> 8;
    buf[offset++] = record->rdlength & 0xFF;
    memcpy(buf + offset, record->rdata, record->rdlength);
    offset += record->rdlength;
    *len = offset;
}

void dns_record_from_buf(const uint8_t* buf, size_t buf_len, size_t* len, size_t offset, dns_record_t* record)
{
    // convert the buffer to the record
    printf("dns_record_from_buf\n");
    if (offset >= buf_len)
    {
        printf("Error: buffer is too short\n");
        exit(1);
    }
    size_t ori_offset = offset;
    size_t compress_name_len = 0;
    char name[NAME_MAX_SIZE];

    decompress_name(buf, buf_len, offset, &compress_name_len, name);
    record->name = malloc(strlen(name) + 1);
    strcpy(record->name, name);
    offset += compress_name_len;

    if (offset + 10 >= buf_len)
    {
        printf("Error: buffer is too short\n");
        exit(1);
    }
    record->type = (uint16_t)buf[offset++] << 8;
    record->type |= buf[offset++];
    record->class = (uint16_t)buf[offset++] << 8;
    record->class |= buf[offset++];
    record->ttl = (uint32_t)buf[offset++] << 24;
    record->ttl |= (uint32_t)buf[offset++] << 16;
    record->ttl |= (uint32_t)buf[offset++] << 8;
    record->ttl |= buf[offset++];
    record->rdlength = (uint16_t)buf[offset++] << 8;
    record->rdlength |= buf[offset++];
    if (offset + record->rdlength > buf_len)
    {
        printf("Error: buffer is too short\n");
        exit(1);
    }
    decompress_name(buf, buf_len, offset, &compress_name_len, name);
    size_t rd_real_len = strlen(name) + 1;
    record->rdata = malloc(rd_real_len);
    memcpy(record->rdata, name, rd_real_len);
    offset += record->rdlength;
    *len = offset - ori_offset;
}

void dns_record_free(dns_record_t* record)
{
    // free the record
    printf("dns_record_free\n");
    free(record->name);
    free(record->rdata);
}