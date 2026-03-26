#include "common.h"
#include <stdarg.h>
#include <stdint.h>
#include <string.h>
#include <unistd.h>

#define LOG_FILE "wsmini.log"
#define MAX_LOG_MSG_SIZE (718)

static char service_name[30] = {0};

static const char *log_level_str[] = {
    "DEBUG",
    "INFO",
    "WARN",
    "ERROR"};

void log_init(const char *service)
{
    strncpy(service_name, service, sizeof(service_name) - 1);
}

void log_write(log_level_t level,
               const char *file,
               int line,
               const char *fmt,
               ...)
{
    char msg[MAX_LOG_MSG_SIZE];
    char log_line[MAX_LOG_MSG_SIZE + 128];
    char time_buff[32];

    va_list args;
    va_start(args, fmt);
    vsnprintf(msg, sizeof(msg), fmt, args);
    va_end(args);

    time_t now = time(NULL);
    struct tm *t = localtime(&now);
    strftime(time_buff, sizeof(time_buff), "%y-%m-%d %H:%M:%S", t);

    snprintf(log_line, sizeof(log_line),
             "[%s] [%s] [%s] [%s:%d] %s\n",
             time_buff,
             log_level_str[level],
             (strlen(service_name) == 0) ? "unknown" : service_name,
             file,
             line,
             msg);

    FILE *f = fopen(LOG_FILE, "a");
    if (f)
    {
        // Check if putting worked
        if (fputs(log_line, f) == EOF)
        {
            fprintf(stderr, "[logger] failed to write to %s\n", LOG_FILE);
        }

        if (fclose(f) == EOF)
        {
            fprintf(stderr, "[logger] failed to close %s\n", LOG_FILE);
        }
    }
    else
    {
        // can't open log file
        fprintf(stderr, "[logger] failed to open %s\n", LOG_FILE);
    }
}

int create_udp_server(uint16_t udp_port)
{
    int socket_desc = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    if (socket_desc < 0)
    {
        LOG(LOG_ERROR, "Could not initialize socket");
        return -1;
    }

    struct sockaddr_in server_addr;
    memset(&server_addr, 0, sizeof(server_addr));
    server_addr.sin_family = AF_INET;
    server_addr.sin_port = htons(udp_port);
    server_addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);

    if (bind(socket_desc, (struct sockaddr *)&server_addr, sizeof(server_addr)) < 0)
    {
        LOG(LOG_ERROR, "Could not bind to socket");
        close(socket_desc);
        return -1;
    }

    return socket_desc;
}

int create_udp_client()
{
    int socket_desc = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    if (socket_desc < 0)
    {
        LOG(LOG_ERROR, "Could not initialize socket");
        return socket_desc;
    }
    return socket_desc;
}

void send_udp_message_one_way(int sock, udp_message_t *msg,
                              uint16_t dest_port)
{
    struct sockaddr_in dest = {0};
    dest.sin_family = AF_INET;
    dest.sin_port = htons(dest_port);
    dest.sin_addr.s_addr = htonl(INADDR_LOOPBACK);

    if (sendto(sock, msg, sizeof(udp_message_t), 0,
               (struct sockaddr *)&dest, sizeof(dest)) < 0)
    {
        LOG(LOG_ERROR, "sendto on port %u failed",
            dest_port);
    }
}

bool send_udp_message_and_receive(int sock, udp_message_t *req,
                                  udp_message_t *resp, uint16_t dest_port)
{
    // Build destination address (always localhost)
    struct sockaddr_in dest = {0};
    dest.sin_family = AF_INET;
    dest.sin_port = htons(dest_port);
    dest.sin_addr.s_addr = htonl(INADDR_LOOPBACK);

    // Send the request
    if (sendto(sock, req, sizeof(udp_message_t), 0,
               (struct sockaddr *)&dest, sizeof(dest)) < 0)
    {
        LOG(LOG_ERROR, "sendto on port %u failed", dest_port);
        return false;
    }

    // Wait for reply (will respect SO_RCVTIMEO if set on the socket)
    if (recvfrom(sock, resp, sizeof(udp_message_t), 0, NULL, NULL) < 0)
    {
        LOG(LOG_ERROR, "recvfrom on port %u failed", dest_port);
        return false;
    }

    return true;
}

void set_error_msg(udp_message_t *resp, const char *msg)
{
    resp->status = STATUS_FAILURE;
    udp_cmd_reply_t *reply = (udp_cmd_reply_t *)resp->payload;
    strncpy(reply->error_msg, msg, sizeof(reply->error_msg) - 1);
}