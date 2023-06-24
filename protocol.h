#ifndef PROTOCOL_H__
#define PROTOCOL_H__

#include <stdint.h>
#include "platform.h"

#ifdef _WIN32
#include <winsock2.h>
#elif __linux__
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <errno.h> 
typedef int SOCKET;
#define INVALID_SOCKET -1
typedef struct sockaddr_in SOCKADDR_IN;
typedef struct sockaddr SOCKADDR;
typedef struct in_addr IN_ADDR;
#define closesocket(s) close(s)
#define WSAGetLastError() errno
#define SOCKET_ERROR -1

#endif

typedef struct {
    char* name;
    uint16_t type;
    uint16_t class;
    uint32_t ttl;
    uint16_t rdlength;
    uint8_t* rdata;
} dns_record_t;

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

#define TYPE_A 1
#define TYPE_NS 2
#define TYPE_CNAME 5
#define TYPE_SOA 6
#define TYPE_PTR 12
#define TYPE_MX 15
#define TYPE_TXT 16
#define TYPE_AAAA 28
#define TYPE_SRV 33
#define TYPE_ANY 255

#define CLASS_IN 1

#define FLAG_QR 0x8000
#define FLAG_AA 0x0400
#define FLAG_TC 0x0200
#define FLAG_RD 0x0100
#define FLAG_RA 0x0080

#define BUF_MAX_SIZE 1024
#define NAME_MAX_SIZE 65

#define RCODE_NO_ERROR 0
#define RCODE_FORMAT_ERROR 1
#define RCODE_SERVER_FAILURE 2
#define RCODE_NAME_ERROR 3

#define SIO_UDP_CONNRESET _WSAIOW(IOC_VENDOR, 12)

void dns_record_print(const dns_record_t* record);
void dns_record_to_buf(const dns_record_t* record, uint8_t* buf, size_t* len, size_t offset, size_t name_offset, size_t* cname_offset);
void dns_record_from_buf(const uint8_t* buf, size_t buf_len, size_t* len, size_t offset, dns_record_t* record);
void dns_record_free(dns_record_t* record);
void dns_record_copy(dns_record_t* dst, const dns_record_t* src);

void protocol_init(SOCKET* s, uint16_t port);
void protocol_send(SOCKET s, const SOCKADDR_IN* sock_in, const dns_message_t* msg);
void protocol_recv(SOCKET s, SOCKADDR_IN* sock_in, dns_message_t* msg);

void dns_header_set_flags(dns_header_t* header, uint16_t flags, uint8_t opcode, uint8_t rcode);
void dns_header_to_buf(const dns_header_t* header, uint8_t* buf, size_t* len);
void dns_header_from_buf(const uint8_t* buf, size_t buf_len, dns_header_t* header);
// void dns_header_free(dns_header_t* header);

void dns_message_to_buf(const dns_message_t* msg, uint8_t* buf, size_t* len);
void dns_message_from_buf(const uint8_t* buf, size_t buf_len, dns_message_t* msg);
void dns_message_free(dns_message_t* msg);
void dns_message_copy(dns_message_t* dst, const dns_message_t* src);
uint8_t dns_message_is_empty(const dns_message_t* msg);

void dns_question_to_buf(const dns_question_t* question, uint8_t* buf, size_t* len);
void dns_question_from_buf(const uint8_t* buf, size_t buf_len, size_t* len, size_t offset, dns_question_t* question);
void dns_question_free(dns_question_t* question);
void dns_question_copy(dns_question_t* dst, const dns_question_t* src);

void name_to_qname(const char* name, char* qname);
void qname_to_name(const char* qname, char* name);

void decompress_name(const uint8_t* buf, size_t buf_len, size_t offset, size_t* len, char* name);

#endif