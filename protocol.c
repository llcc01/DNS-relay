#include "protocol.h"

#include <stdio.h>

#include "main.h"

#ifdef _WIN32
WSADATA wsaData;
#elif __linux__


#endif

void dns_record_print(const dns_record_t* record)
{
    // print the record
    printf("----------------\n");
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
        qname_to_name((char*)(record->rdata), cname);
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
    printf("----------------\n");
}

void dns_record_to_buf(const dns_record_t* record, uint8_t* buf, size_t* len, size_t offset, size_t name_offset, size_t* cname_offset)
{
    // convert the record to the buffer
    // printf("dns_record_to_buf\n");

    size_t ori_offset = offset;

    // compress
    if (strcmp((char*)&(buf[name_offset]), record->name) == 0)
    {
        // printf("compress\n");
        uint16_t pointer = name_offset;
        pointer |= 0xc000;
        buf[offset++] = pointer >> 8;
        buf[offset++] = pointer & 0xFF;
    }
    else if (*cname_offset != 0 && strcmp((char*)&(buf[*cname_offset]), record->name) == 0)
    {
        // printf("compress cname\n");
        uint16_t pointer = *cname_offset;
        pointer |= 0xc000;
        buf[offset++] = pointer >> 8;
        buf[offset++] = pointer & 0xFF;
    }
    else
    {
        // printf("not compress\n");
        size_t name_len = strlen(record->name);
        memcpy(buf + offset, record->name, name_len);
        offset += name_len;
        buf[offset++] = 0;
    }


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
    if (record->type == TYPE_CNAME)
    {
        *cname_offset = offset;
    }
    memcpy(buf + offset, record->rdata, record->rdlength);
    offset += record->rdlength;
    *len = offset - ori_offset;
}

void dns_record_from_buf(const uint8_t* buf, size_t buf_len, size_t* len, size_t offset, dns_record_t* record)
{
    // convert the buffer to the record
    // printf("dns_record_from_buf\n");
    if (offset >= buf_len)
    {
        PANIC("Error: buffer is too short");
    }
    size_t ori_offset = offset;
    size_t compress_name_len = 0;
    char name[NAME_MAX_SIZE];

    decompress_name(buf, buf_len, offset, &compress_name_len, name);
    size_t name_len = strlen(name);
    record->name = malloc(name_len + 1);
    memcpy(record->name, name, name_len + 1);
    offset += compress_name_len;

    if (offset + 10 >= buf_len)
    {
        PANIC("Error: buffer is too short");
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
        PANIC("Error: buffer is too short");
    }
    if (record->type == TYPE_CNAME)
    {
        decompress_name(buf, buf_len, offset, &compress_name_len, name);
        size_t rd_real_len = strlen(name) + 1;
        record->rdata = malloc(rd_real_len);
        memcpy(record->rdata, name, rd_real_len);

        offset += compress_name_len;
        record->rdlength = rd_real_len;
    }
    else
    {
        record->rdata = malloc(record->rdlength);
        memcpy(record->rdata, buf + offset, record->rdlength);
        offset += record->rdlength;
    }
    *len = offset - ori_offset;
}

void dns_record_free(dns_record_t* record)
{
    // free the record
    // printf("dns_record_free\n");
    free(record->name);
    free(record->rdata);
}

// 深拷贝记录
void dns_record_copy(dns_record_t* dst, const dns_record_t* src)
{
    // copy the record
    // printf("dns_record_copy\n");
    dst->name = malloc(strlen(src->name) + 1);
    strcpy(dst->name, src->name);
    dst->type = src->type;
    dst->class = src->class;
    dst->ttl = src->ttl;
    dst->rdlength = src->rdlength;
    dst->rdata = malloc(src->rdlength);
    memcpy(dst->rdata, src->rdata, src->rdlength);
}

// 协议初始化
void protocol_init(SOCKET* s, uint16_t port)
{

    // initialize the protocol
    printf("protocol_init\n");
#ifdef _WIN32
    int iResult = WSAStartup(MAKEWORD(2, 2), &wsaData);
    if (iResult != NO_ERROR) {
        PANIC("Error at WSAStartup()");
    }

    // UDP
    *s = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    if (*s == INVALID_SOCKET) {
        printf("Error at socket(): %d\n", WSAGetLastError());
        WSACleanup();
        PANIC("Error at socket()");
    }

    // 忽略reset
    BOOL bNewBehavior = FALSE;
    DWORD dwBytesReturned = 0;
    WSAIoctl(*s, SIO_UDP_CONNRESET, &bNewBehavior, sizeof(bNewBehavior), NULL, 0, &dwBytesReturned, NULL, NULL);
#elif __linux__
    // UDP
    * s = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    if (*s == -1) {
        PANIC("Error at socket()");
    }

#endif

    SOCKADDR_IN sock_in;
    sock_in.sin_family = AF_INET;
    sock_in.sin_port = htons(port);
    sock_in.sin_addr.s_addr = INADDR_ANY;

    if (bind(*s, (SOCKADDR*)&sock_in, sizeof(sock_in)) < 0) {
        printf("bind() failed. %d\n", WSAGetLastError());
        closesocket(*s);
#ifdef _WIN32
        WSACleanup();
#endif
        PANIC("Error at bind()");
    }

    printf("bind() is OK!\n");
}

// 协议发送消息
void protocol_send(SOCKET s, const SOCKADDR_IN* sock_in, const dns_message_t* msg)
{
    // send the message to the client
    // printf("protocol_send\n");

    // uint8_t buffer[BUF_MAX_SIZE];
    uint8_t* buffer = malloc(BUF_MAX_SIZE);
    size_t buffer_size;

    // LARGE_INTEGER start, end, freq;

    dns_message_to_buf(msg, buffer, &buffer_size);

    if (buffer_size > 512)
    {
        printf("warning: send buffer_size: %lld\n", buffer_size);
    }

    // QueryPerformanceCounter(&start);

    int res = sendto(s, (char*)buffer, buffer_size, 0, (SOCKADDR*)sock_in, sizeof(*sock_in));
    free(buffer);
    if (res <= 0)
    {
        printf("sendto() failed. %d\n", WSAGetLastError());
        closesocket(s);
#ifdef _WIN32
        WSACleanup();
#endif
        PANIC("Error at sendto()");
    }


    // QueryPerformanceCounter(&end);
    // QueryPerformanceFrequency(&freq);
    // printf("(%d)", end.QuadPart - start.QuadPart);

    // printf("sendto() is OK!\n");
}

// 协议接受消息
void protocol_recv(SOCKET s, SOCKADDR_IN* sock_in, dns_message_t* msg)
{
    // receive the message from the client
    // printf("protocol_recv\n");

    int sock_in_size = sizeof(*sock_in);

    // uint8_t buffer[BUF_MAX_SIZE];
    uint8_t* buffer = malloc(BUF_MAX_SIZE);

    int res = recvfrom(s, (char*)buffer, BUF_MAX_SIZE, 0, (SOCKADDR*)sock_in, &sock_in_size);
    if (res <= 0)
    {
        free(buffer);
        printf("recvfrom() failed. %d\n", WSAGetLastError());
        closesocket(s);
#ifdef _WIN32
        WSACleanup();
#endif
        PANIC("Error at recvfrom()");
    }
    else
    {
        if (res > 512)
        {
            printf("warning: recv size: %d\n", res);
        }
        // printf("recvfrom() recv %d bytes \n", res);

        // for (size_t i = 0; i < res; i++) {
        //     printf("%02x ", (uint8_t)buffer[i]);
        // }
        // printf("\n");

        dns_message_from_buf(buffer, res, msg);
        free(buffer);
    }
}

void dns_header_set_flags(dns_header_t* header, uint16_t flags, uint8_t opcode, uint8_t rcode)
{
    // set the flags of the header
    // printf("dns_header_set_flags\n");
    header->flags = flags;
    header->flags &= ~(0xF << 11);
    header->flags &= ~(0xF << 0);

    header->flags |= (opcode << 11);
    header->flags |= (rcode << 0);
}

void dns_header_to_buf(const dns_header_t* header, uint8_t* buf, size_t* len)
{
    // convert the header to a buffer
    // printf("dns_header_to_buf\n");
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
    // printf("dns_header_from_buf\n");
    if (buf_len < 12) {
        PANIC("Error: buffer is too short");
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
    // printf("dns_message_to_buf\n");
    size_t offset = 0;
    dns_header_to_buf(&msg->header, buf, &offset);
    size_t name_offset = offset;
    size_t cname_offset = 0;
    for (size_t i = 0; i < msg->header.qdcount; i++) {
        size_t question_len;
        dns_question_to_buf(&msg->questions[i], buf + offset, &question_len);
        offset += question_len;
    }

    for (size_t i = 0; i < msg->header.ancount; i++) {
        size_t record_len;
        // dns_record_print(&msg->answers[i]);
        dns_record_to_buf(&msg->answers[i], buf, &record_len, offset, name_offset, &cname_offset);
        offset += record_len;
    }

    for (size_t i = 0; i < msg->header.nscount; i++) {
        size_t record_len;
        // dns_record_print(&msg->authorities[i]);
        dns_record_to_buf(&msg->authorities[i], buf, &record_len, offset, name_offset, &cname_offset);
        offset += record_len;
    }

    for (size_t i = 0; i < msg->header.arcount; i++) {
        size_t record_len;
        dns_record_to_buf(&msg->additionals[i], buf, &record_len, offset, name_offset, &cname_offset);
        offset += record_len;
    }

    *len = offset;
}

void dns_message_from_buf(const uint8_t* buf, size_t buf_len, dns_message_t* msg)
{
    // convert the buffer to the message
    // printf("dns_message_from_buf\n");
    dns_header_from_buf(buf, buf_len, &msg->header);

    // if (msg->header.qdcount ==1 && msg->header.ancount == 0 && msg->header.nscount == 1 && msg->header.arcount == 1)
    // {
    //     for (size_t i = 0; i < 10; i++)
    //     {
    //         printf("-- ");
    //     }
    //     for (size_t i = 0; i < buf_len; i++)
    //     {
    //         printf("%02x ", buf[i]);
    //         if (i % 16 == 5)
    //         {
    //             printf("\n");
    //         }
    //     }
    //     printf("\n");
    // }

    // 异常情况
    // if (msg->header.qdcount > 2)
    // {
    //     printf("Error: qdcount > 2, %d\n", msg->header.qdcount);
    //     msg->header.qdcount = 0;
    //     msg->header.ancount = 0;
    //     msg->header.nscount = 0;
    //     msg->header.arcount = 0;
    //     return;
    // }

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
    for (size_t i = 0; i < msg->header.qdcount; i++)
    {
        // printf("offset: %d, buf_len: %d\n", offset, buf_len);
        if (offset >= buf_len)
        {
            PANIC("Error: buffer is too short");
        }
        size_t question_len;
        dns_question_from_buf(buf, buf_len, &question_len, offset, &msg->questions[i]);
        offset += question_len;
    }

    // char name[NAME_MAX_SIZE];
    // qname_to_name(msg->questions[0].name, name);
    // printf("name: %s\n", name);

    for (size_t i = 0; i < msg->header.ancount; i++)
    {
        // printf("offset: %d, buf_len: %d\n", offset, buf_len);
        if (offset >= buf_len)
        {
            PANIC("Error: buffer is too short");
        }
        size_t record_len;
        dns_record_from_buf(buf, buf_len, &record_len, offset, &msg->answers[i]);
        offset += record_len;
    }

    for (size_t i = 0; i < msg->header.nscount; i++)
    {
        // printf("offset: %d, buf_len: %d\n", offset, buf_len);
        if (offset >= buf_len)
        {
            PANIC("Error: buffer is too short");
        }
        size_t record_len;
        dns_record_from_buf(buf, buf_len, &record_len, offset, &msg->authorities[i]);
        offset += record_len;
    }

    for (size_t i = 0; i < msg->header.arcount; i++)
    {
        // printf("offset: %d, buf_len: %d\n", offset, buf_len);
        if (offset >= buf_len)
        {
            PANIC("Error: buffer is too short");
        }
        size_t record_len;
        dns_record_from_buf(buf, buf_len, &record_len, offset, &msg->additionals[i]);
        offset += record_len;
    }

    if (offset > buf_len) {
        PANIC("Error: buffer is too short");
    }
}

// 释放消息内容
void dns_message_free(dns_message_t* msg)
{
    // free the message
    // printf("dns_message_free\n");
    if (msg->header.qdcount > 0)
    {
        for (size_t i = 0; i < msg->header.qdcount; i++) {
            dns_question_free(&msg->questions[i]);
        }
        free(msg->questions);
    }

    if (msg->header.ancount > 0)
    {
        for (size_t i = 0; i < msg->header.ancount; i++) {
            dns_record_free(&msg->answers[i]);
        }
        free(msg->answers);
    }

    if (msg->header.nscount > 0)
    {
        for (size_t i = 0; i < msg->header.nscount; i++) {
            dns_record_free(&msg->authorities[i]);
        }
        free(msg->authorities);
    }

    if (msg->header.arcount > 0)
    {
        for (size_t i = 0; i < msg->header.arcount; i++) {
            dns_record_free(&msg->additionals[i]);
        }
        free(msg->additionals);
    }

    msg->header.qdcount = 0;
    msg->header.ancount = 0;
    msg->header.nscount = 0;
    msg->header.arcount = 0;
}

// 深拷贝消息
void dns_message_copy(dns_message_t* dst, const dns_message_t* src)
{
    dst->header = src->header;

    if (dst->header.qdcount > 0)
    {
        dst->questions = malloc(dst->header.qdcount * sizeof(dns_question_t));
        for (size_t i = 0; i < dst->header.qdcount; i++)
        {
            dns_question_copy(&dst->questions[i], &src->questions[i]);
        }
    }
    else
    {
        dst->questions = NULL;
    }

    if (dst->header.ancount > 0)
    {
        dst->answers = malloc(dst->header.ancount * sizeof(dns_record_t));
        for (size_t i = 0; i < dst->header.ancount; i++)
        {
            dns_record_copy(&dst->answers[i], &src->answers[i]);
        }
    }
    else
    {
        dst->answers = NULL;
    }

    if (dst->header.nscount > 0)
    {
        dst->authorities = malloc(dst->header.nscount * sizeof(dns_record_t));
        for (size_t i = 0; i < dst->header.nscount; i++)
        {
            dns_record_copy(&dst->authorities[i], &src->authorities[i]);
        }
    }
    else
    {
        dst->authorities = NULL;
    }

    if (dst->header.arcount > 0)
    {
        dst->additionals = malloc(dst->header.arcount * sizeof(dns_record_t));
        for (size_t i = 0; i < dst->header.arcount; i++)
        {
            dns_record_copy(&dst->additionals[i], &src->additionals[i]);
        }
    }
    else
    {
        dst->additionals = NULL;
    }

}

uint8_t dns_message_is_empty(const dns_message_t* msg)
{
    return msg->header.qdcount == 0 && msg->header.ancount == 0 && msg->header.nscount == 0 && msg->header.arcount == 0;
}


void dns_question_to_buf(const dns_question_t* question, uint8_t* buf, size_t* len)
{
    // convert the question to a buffer
    // printf("dns_question_to_buf\n");
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
    // printf("dns_question_from_buf\n");
    size_t ori_offset = offset;
    if (offset >= buf_len) {
        PANIC("Error: buffer is too short");
    }

    size_t compress_name_len = 0;
    char name[NAME_MAX_SIZE];
    decompress_name(buf, buf_len, offset, &compress_name_len, name);
    question->name = malloc(strlen(name) + 1);
    strcpy(question->name, name);
    offset += compress_name_len;

    question->type = (uint16_t)buf[offset++] << 8;
    question->type |= buf[offset++];
    question->class = (uint16_t)buf[offset++] << 8;
    question->class |= buf[offset++];

    *len = offset - ori_offset;
}

// 释放请求内容
void dns_question_free(dns_question_t* question)
{
    // free the question
    // printf("dns_question_free\n");
    free(question->name);
}

// 深拷贝请求
void dns_question_copy(dns_question_t* dst, const dns_question_t* src)
{
    dst->name = malloc(strlen(src->name) + 1);
    strcpy(dst->name, src->name);
    dst->type = src->type;
    dst->class = src->class;
}

// name转DNS格式
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

// DNS格式转name
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

// 解压缩name
void decompress_name(const uint8_t* buf, size_t buf_len, size_t offset, size_t* len, char* name)
{
    // decompress the name
    // printf("decompress_name\n");
    size_t ori_offset = offset;
    if (offset >= buf_len) {
        PANIC("Error: buffer is too short");
    }
    int name_len = 0;
    while (offset < buf_len)
    {
        if ((buf[offset] & 0xC0) == 0xC0)
        {
            // pointer
            uint16_t pointer = (uint16_t)buf[offset] << 8 | buf[offset + 1];
            pointer &= 0x3FFF;

            // printf("pointer: %d\n", pointer);

            // size_t new_name_len = 0;

            // 递归解压缩
            decompress_name(buf, buf_len, pointer, NULL, name + name_len);

            name_len += strlen(name + name_len);
            offset += 2;
            break;
        }
        else
        {
            // name
            name[name_len] = buf[offset++];
            // printf("name[%d]: %02x\n", name_len, name[name_len]);
            if (name[name_len] == 0)
            {
                break;
            }
            name_len++;
        }
    }

    // printf("res_name: \n");
    // for (size_t i = 0; i < name_len; i++)
    // {
    //     printf("%02x ", name[i]);
    // }
    // printf("\n");


    if (len != NULL)
    {
        *len = offset - ori_offset;
    }
}
