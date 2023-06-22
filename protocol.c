#include "protocol.h"

#include <stdio.h>

WSADATA wsaData;

void protocol_init(SOCKET* s, uint16_t port)
{
    // initialize the protocol
    printf("protocol_init\n");
    int iResult = WSAStartup(MAKEWORD(2, 2), &wsaData);
    if (iResult != NO_ERROR) {
        printf("Error at WSAStartup()\n");
        exit(1);
    }

    // UDP
    *s = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    if (*s == INVALID_SOCKET) {
        printf("Error at socket(): %ld\n", WSAGetLastError());
        WSACleanup();
        exit(1);
    }

    SOCKADDR_IN sock_in;
    sock_in.sin_family = AF_INET;
    sock_in.sin_port = htons(port);
    sock_in.sin_addr.s_addr = INADDR_ANY;

    if (bind(*s, (SOCKADDR*)&sock_in, sizeof(sock_in)) == SOCKET_ERROR) {
        printf("bind() failed.\n");
        closesocket(*s);
        WSACleanup();
        exit(1);
    }

    printf("bind() is OK!\n");
}

void protocol_send(const SOCKET* s, const SOCKADDR_IN* sock_in, const dns_message_t* msg)
{
    // send the message to the client
    printf("protocol_send\n");

    char* buffer = malloc(BUF_MAX_SIZE);
    size_t buffer_size;
    dns_message_to_buf(msg, buffer, &buffer_size);

    if (sendto(*s, (char*)buffer, buffer_size, 0, (SOCKADDR*)sock_in, sizeof(*sock_in)) == SOCKET_ERROR) {
        free(buffer);
        printf("sendto() failed. %d\n", WSAGetLastError());
        closesocket(*s);
        WSACleanup();
        exit(1);
    }

    free(buffer);
    printf("sendto() is OK!\n");
}

void protocol_recv(const SOCKET* s, SOCKADDR_IN* sock_in, dns_message_t* msg)
{
    // receive the message from the client
    printf("protocol_recv\n");

    int sock_in_size = sizeof(*sock_in);

    char* buffer = malloc(BUF_MAX_SIZE);
    int res = recvfrom(*s, (char*)buffer, BUF_MAX_SIZE, 0, (SOCKADDR*)sock_in, &sock_in_size);
    if (res == SOCKET_ERROR) {
        free(buffer);
        printf("recvfrom() failed. %d\n", WSAGetLastError());
        closesocket(*s);
        WSACleanup();
        exit(1);
    }

    printf("recvfrom() recv %d bytes \n", res);

    for (size_t i = 0; i < res; i++) {
        printf("%02x ", (uint8_t)buffer[i]);
    }
    printf("\n");

    dns_message_from_buf(buffer, res, msg);
}

void dns_header_set_flags(dns_header_t* header, uint16_t flags, uint8_t opcode, uint8_t rcode)
{
    // set the flags of the header
    printf("dns_header_set_flags\n");
    header->flags = flags;
    header->flags &= ~(0xF << 11);
    header->flags &= ~(0xF << 0);

    header->flags |= (opcode << 11);
    header->flags |= (rcode << 0);
}

void dns_header_to_buf(const dns_header_t* header, uint8_t* buf, size_t* len)
{
    // convert the header to a buffer
    printf("dns_header_to_buf\n");
    buf[0] = header->id >> 8;
    buf[1] = header->id & 0xFF;
    buf[2] = header->flags >> 8;
    buf[3] = header->flags & 0xFF;
    buf[4] = header->qdcount >> 8;
    buf[5] = header->qdcount & 0xFF;
    buf[6] = header->ancount >> 8;
    buf[7] = header->ancount & 0xFF;
    buf[8] = header->nscount >> 8;
    buf[9] = header->nscount & 0xFF;
    buf[10] = header->arcount >> 8;
    buf[11] = header->arcount & 0xFF;
    *len = 12;
}

void dns_header_from_buf(const uint8_t* buf, size_t buf_len, dns_header_t* header)
{
    // convert the buffer to the header
    printf("dns_header_from_buf\n");
    if (buf_len < 12) {
        printf("Error: buffer is too short\n");
        exit(1);
    }
    header->id = buf[0] << 8;
    header->id |= buf[1];
    header->flags = buf[2] << 8;
    header->flags |= buf[3];
    header->qdcount = buf[4] << 8;
    header->qdcount |= buf[5];
    header->ancount = buf[6] << 8;
    header->ancount |= buf[7];
    header->nscount = buf[8] << 8;
    header->nscount |= buf[9];
    header->arcount = buf[10] << 8;
    header->arcount |= buf[11];
}

// void dns_header_free(dns_header_t* header)
// {
//     // free the header
//     printf("dns_header_free\n");
//     free(header);
// }

void dns_message_to_buf(const dns_message_t* msg, uint8_t* buf, size_t* len)
{
    // convert the message to a buffer
    printf("dns_message_to_buf\n");
    size_t l = 0;
    dns_header_to_buf(&msg->header, buf, &l);
    for (size_t i = 0; i < msg->header.qdcount; i++) {
        size_t question_len;
        dns_question_to_buf(&msg->questions[i], buf + l, &question_len);
        l += question_len;
    }

    for (size_t i = 0; i < msg->header.ancount; i++) {
        size_t record_len;
        dns_record_to_buf(&msg->answers[i], buf + l, &record_len);
        l += record_len;
    }

    for (size_t i = 0; i < msg->header.nscount; i++) {
        size_t record_len;
        dns_record_print(&msg->authorities[i]);
        dns_record_to_buf(&msg->authorities[i], buf + l, &record_len);
        l += record_len;
    }

    for (size_t i = 0; i < msg->header.arcount; i++) {
        size_t record_len;
        dns_record_to_buf(&msg->additionals[i], buf + l, &record_len);
        l += record_len;
    }

    *len = l;
}

void dns_message_from_buf(const uint8_t* buf, size_t buf_len, dns_message_t* msg)
{
    // convert the buffer to the message
    printf("dns_message_from_buf\n");
    dns_header_from_buf(buf, buf_len, &msg->header);

    if (msg->header.qdcount > 0)
    {
        msg->questions = malloc(msg->header.qdcount * sizeof(dns_question_t));
    }
    else
    {
        msg->questions = NULL;
    }

    if (msg->header.ancount > 0)
    {
        msg->answers = malloc(msg->header.ancount * sizeof(dns_record_t));
    }
    else
    {
        msg->answers = NULL;
    }

    if (msg->header.nscount > 0)
    {
        msg->authorities = malloc(msg->header.nscount * sizeof(dns_record_t));
    }
    else
    {
        msg->authorities = NULL;
    }

    if (msg->header.arcount > 0)
    {
        msg->additionals = malloc(msg->header.arcount * sizeof(dns_record_t));
    }
    else
    {
        msg->additionals = NULL;
    }


    size_t offset = sizeof(dns_header_t);
    for (size_t i = 0; i < msg->header.qdcount; i++) {
        if (offset >= buf_len) {
            break;
        }
        size_t question_len;
        dns_question_from_buf(buf, buf_len, &question_len, offset, &msg->questions[i]);
        offset += question_len;
    }

    for (size_t i = 0; i < msg->header.ancount; i++) {
        if (offset >= buf_len) {
            break;
        }
        size_t record_len;
        dns_record_from_buf(buf, buf_len, &record_len, offset, &msg->answers[i]);
        offset += record_len;
    }

    for (size_t i = 0; i < msg->header.nscount; i++) {
        if (offset >= buf_len) {
            break;
        }
        size_t record_len;
        dns_record_from_buf(buf, buf_len, &record_len, offset, &msg->authorities[i]);
        offset += record_len;
    }

    for (size_t i = 0; i < msg->header.arcount; i++) {
        if (offset >= buf_len) {
            break;
        }
        size_t record_len;
        dns_record_from_buf(buf, buf_len, &record_len, offset, &msg->additionals[i]);
        offset += record_len;
    }

    if (offset > buf_len) {
        printf("Error: buffer is too short\n");
        exit(1);
    }
}

void dns_message_free(dns_message_t* msg)
{
    // free the message
    printf("dns_message_free\n");
    for (size_t i = 0; i < msg->header.qdcount; i++) {
        dns_question_free(&msg->questions[i]);
    }
    free(msg->questions);

    for (size_t i = 0; i < msg->header.ancount; i++) {
        dns_record_free(&msg->answers[i]);
    }
    free(msg->answers);

    for (size_t i = 0; i < msg->header.nscount; i++) {
        dns_record_free(&msg->authorities[i]);
    }
    free(msg->authorities);

    for (size_t i = 0; i < msg->header.arcount; i++) {
        dns_record_free(&msg->additionals[i]);
    }
    free(msg->additionals);
}

void dns_question_to_buf(const dns_question_t* question, uint8_t* buf, size_t* len)
{
    // convert the question to a buffer
    printf("dns_question_to_buf\n");
    size_t l = strlen(question->name) + 1;
    memcpy(buf, question->name, l);
    buf[l++] = question->type >> 8;
    buf[l++] = question->type & 0xFF;
    buf[l++] = question->class >> 8;
    buf[l++] = question->class & 0xFF;
    *len = l;
}

void dns_question_from_buf(const uint8_t* buf, size_t buf_len, size_t* len, size_t offset, dns_question_t* question)
{
    // convert the buffer to the question
    printf("dns_question_from_buf\n");
    size_t ori_offset = offset;
    if (offset >= buf_len) {
        printf("Error: buffer is too short\n");
        exit(1);
    }

    size_t compress_name_len = 0;
    char name[NAME_MAX_SIZE];
    decompress_name(buf, buf_len, offset, &compress_name_len, name);
    question->name = malloc(compress_name_len);
    strcpy(question->name, name);
    offset += compress_name_len;

    question->type = (uint16_t)buf[offset++] << 8;
    question->type |= buf[offset++];
    question->class = (uint16_t)buf[offset++] << 8;
    question->class |= buf[offset++];

    *len = offset - ori_offset;
}

void dns_question_free(dns_question_t* question)
{
    // free the question
    printf("dns_question_free\n");
    free(question->name);
}

void name_to_qname(const char* name, char* qname)
{
    // convert the name to a qname
    // printf("name_to_qname\n");
    memcpy(qname + 1, name, strlen(name) + 1);
    qname[0] = '.';
    for (int8_t i = strlen(qname) - 1, j = 0; i >= 0; i--)
    {
        if (qname[i] == '.')
        {
            qname[i] = j;
            j = 0;
            continue;
        }
        j++;
    }
}

void qname_to_name(const char* qname, char* name)
{
    // convert the qname to a name
    // printf("qname_to_name\n");
    for (size_t i = 0; i < NAME_MAX_SIZE;)
    {
        size_t len = qname[i];
        if (len == 0)
        {
            name[i] = '\0';
            break;
        }
        memcpy(name + i, qname + i + 1, len);
        name[i + len] = '.';
        i += len + 1;
    }
}

void decompress_name(const uint8_t* buf, size_t buf_len, size_t offset, size_t* len, char* name)
{
    // decompress the name
    printf("decompress_name\n");
    size_t ori_offset = offset;
    if (offset >= buf_len) {
        printf("Error: buffer is too short\n");
        exit(1);
    }
    int name_len = 0;
    while (offset < buf_len)
    {
        if ((buf[offset] & 0xC0) == 0xC0)
        {
            // pointer
            uint16_t pointer = (uint16_t)buf[offset] << 8 | buf[offset + 1];
            pointer &= 0x3FFF;
            char buf2[NAME_MAX_SIZE];
            decompress_name(buf, buf_len, pointer, NULL, buf2);
            size_t name_base = name_len;
            size_t new_name_len = strlen(buf2) + 1;
            memcpy(name + name_base, buf2, new_name_len);
            name_len += new_name_len;
            offset += 2;
            break;
        }
        else
        {
            // name
            name[name_len] = buf[offset++];
            if (name[name_len] == 0)
            {
                break;
            }
            name_len++;
        }
    }

    if (len != NULL)
    {
        *len = offset - ori_offset;
    }
}