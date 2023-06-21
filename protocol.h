#ifndef PROTOCOL_H__
#define PROTOCOL_H__

#include <winsock2.h>
#include <stdint.h>
#include "database.h"

typedef struct {
    uint16_t id;
    uint16_t flags;
    uint16_t qdcount;
    uint16_t ancount;
    uint16_t nscount;
    uint16_t arcount;
} dns_header_t;

typedef struct {
    char* name;
    uint16_t type;
    uint16_t class;
} dns_question_t;

typedef struct {
    dns_header_t header;
    dns_question_t* questions;
    dns_record_t* answers;
    dns_record_t* authorities;
    dns_record_t* additionals;
} dns_message_t;

#define FLAG_QR 0x8000
#define FLAG_AA 0x0400
#define FLAG_TC 0x0200
#define FLAG_RD 0x0100
#define FLAG_RA 0x0080

#define BUF_MAX_SIZE 1024
#define NAME_MAX_SIZE 65

void protocol_init(SOCKET* s);
void protocol_send(const SOCKET* s, SOCKADDR_IN* sock_in, const dns_message_t* msg);
void protocol_recv(const SOCKET* s, SOCKADDR_IN* sock_in, dns_message_t* msg);

void dns_header_set_flags(dns_header_t* header, uint16_t flags, uint8_t opcode, uint8_t rcode);
void dns_header_to_buf(const dns_header_t* header, uint8_t* buf, size_t* len);
void dns_header_from_buf(const uint8_t* buf, size_t buf_len, dns_header_t* header);
// void dns_header_free(dns_header_t* header);

void dns_message_to_buf(const dns_message_t* msg, uint8_t* buf, size_t* len);
void dns_message_from_buf(const uint8_t* buf, size_t buf_len, dns_message_t* msg);
void dns_message_free(dns_message_t* msg);

void dns_question_to_buf(const dns_question_t* question, uint8_t* buf, size_t* len);
void dns_question_from_buf(const uint8_t* buf, size_t buf_len, size_t* len, size_t offset, dns_question_t* question);
void dns_question_free(dns_question_t* question);

void name_to_qname(const char* name, char* qname);
void qname_to_name(const char* qname, char* name);

void decompress_name(const uint8_t* buf, size_t buf_len, size_t offset, size_t* len, char* name);

#endif