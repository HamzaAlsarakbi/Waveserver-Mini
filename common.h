#pragma once
#include <arpa/inet.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <sys/select.h>
#include <sys/socket.h>
#include <time.h>

#define PORT_MANAGER_UDP (5001)
#define CONN_MANAGER_UDP (5002)
#define TRAFFIC_MGR_UDP (5003)
#define PROTECTION_MGR_UDP (5004)

#define MAX_UDP_MSG_SIZE (512)
#define MAX_CONN_NAME_CHARACTER (32)
#define MAX_OTN_PAYLOAD_SIZE (128)

#define MAX_CONNS (4)

#define LOG_FILE_PATH "wsmini.log"

////// LOGGING ////
typedef enum
{
    LOG_DEBUG = 0,
    LOG_INFO,
    LOG_WARN,
    LOG_ERROR
} log_level_t;

void log_init(const char *service);
void log_write(log_level_t level, const char *file, int line, const char *fmt,
               ...);

#define LOG(level, fmt, ...) \
    log_write((level), __FILE__, __LINE__, (fmt), ##__VA_ARGS__);

/////// Port Info ////
#define MAX_PORT_NUM (6)
#define MAX_LINE_PORTS (2)
#define MAX_CLIENT_PORTS (4)

typedef enum
{
    PORT_DOWN = 0,
    PORT_UP
} port_state_t;
typedef enum
{
    LINE_PORT = 0,
    CLIENT_PORT
} port_type_t;

typedef struct
{
    uint8_t id;
    port_type_t type;
    port_state_t operational_state;
    bool admin_enabled;
    bool fault_active;
    uint32_t rx_frames;
    uint32_t dropped_frames;
} port_t;

/////// CONN INFO /////
typedef enum
{
    CONN_DOWN = 0,
    CONN_UP
} conn_state_t;

typedef struct
{
    char conn_name[MAX_CONN_NAME_CHARACTER];
    uint8_t client_port;
    uint8_t line_port;
    conn_state_t operational_state;
} conn_t;

/////// OTN ///////
typedef struct {
    uint8_t  client_port;
    uint8_t  line_port;
    uint32_t frame_id;
} otn_header_t;

typedef struct {
    otn_header_t header;
    char         data[MAX_OTN_PAYLOAD_SIZE];
} otn_frame_t;

typedef struct {
    uint32_t next_frame_id;
    uint32_t total_dropped;
    uint32_t total_forwarded;
    bool running;
    uint8_t client_port;
    uint8_t line_port;
} traffic_stats_t;

/////// Message types /////
typedef enum
{
    // Port Manager messages
    MSG_GET_PORT_INFO = 0, // Conn Mgr / CLI → Port Mgr : port_info_request_t → port_t
    MSG_UPDATE_COUNTERS,   // Traffic → Port Mgr : counter_update_t → (no reply)
    MSG_PORT_STATE_CHANGE, // Port Mgr → Conn Mgr : port_state_change_t → (no reply)

    // CLI → Port Manager
    MSG_SET_PORT,          // CLI → Port Mgr : enable a port (request → reply)
    MSG_DELETE_PORT,       // CLI → Port Mgr : disable a port (request → reply)
    MSG_INJECT_FAULT,      // CLI → Port Mgr : simulate signal loss (request → reply)
    MSG_CLEAR_FAULT,       // CLI → Port Mgr : clear a fault (request → reply)

    // Connection Manager messages
    MSG_LOOKUP_CONNECTION, // Traffic → Conn Mgr : route_lookup_request_t → route_lookup_reply_t
    MSG_CREATE_CONN,       // CLI → Conn Mgr : create a connection (request → reply)
    MSG_DELETE_CONN,       // CLI → Conn Mgr : delete a connection (request → reply)
    MSG_GET_CONNECTIONS,   // CLI → Conn Mgr : get all connections (request → reply)

    // Traffic Manager messages
    MSG_GET_TRAFFIC_STATS, // CLI → Traffic Mgr : get traffic counters and if traffic up/down (request → reply)
    MSG_START_TRAFFIC,     // CLI → Traffic Mgr : start frame generation (request → reply)
    MSG_STOP_TRAFFIC,      // CLI → Traffic Mgr : stop frame generation (request → reply)

    // Protection Manager messages
    MSG_CREATE_PROTECTION_GROUP
} msg_type_t;

typedef enum
{
    STATUS_REQUEST = 0,
    STATUS_SUCCESS,
    STATUS_FAILURE
} msg_status_t;

typedef struct
{
    uint8_t msg_type; // msg_type_t
    uint8_t status;
    char payload[MAX_UDP_MSG_SIZE];
} udp_message_t;

// MSG_SET_PORT, MSG_DELETE_PORT, MSG_INJECT_FAULT, MSG_CLEAR_FAULT
typedef struct
{
    uint8_t port_id;
} udp_port_cmd_request_t;

//MSG_SET_PORT, MSG_DELETE_PORT, MSG_INJECT_FAULT, MSG_CLEAR_FAULT reply
// MSG_CREATE_CONN and MSG_DELETE_CONN
typedef struct
{
    char error_msg[64]; // populated on STATUS_FAILURE, empty on success
} udp_cmd_reply_t;

// MSG_UPDATE_COUNTERS (fire-and-forget)
typedef struct
{
    uint8_t  port_id;
    uint32_t pkts_rx;
    uint32_t pkts_dropped;
} udp_counter_update_t;

// MSG_PORT_STATE_CHANGE (fire_and_forget)
typedef struct
{
    uint8_t port_id;
    uint8_t operational_state; // port_state_t
} udp_port_state_change_t;

// MSG_LOOKUP_CONNECTION request
typedef struct
{
    uint8_t client_port;
    uint8_t line_port;
} udp_route_lookup_request_t;

// MSG_LOOKUP_CONNECTION reply
typedef struct
{
    char conn_name[MAX_CONN_NAME_CHARACTER];
    uint8_t operational_state; // conn_state_t
} udp_route_lookup_reply_t;

// MSG_CREATE_CONN request
typedef struct
{
    char name[MAX_CONN_NAME_CHARACTER];
    uint8_t client_port;
    uint8_t line_port;
} udp_create_conn_request_t;

// MSG_DELETE_CONN request
typedef struct
{
    char name[MAX_CONN_NAME_CHARACTER];
} udp_delete_conn_request_t;

// MSG_GET_CONNECTIONS request
typedef struct
{
    conn_t all_connections[MAX_CONNS];
    uint8_t conn_count;
} udp_get_connections_reply_t;

// MSG_START_TRAFFIC request
typedef struct
{
    uint8_t client_port; // 0 = random (3-6)
    uint8_t line_port;   // 0 = random (1-2)
} udp_start_traffic_request_t;

////// Shared functions /////
int create_udp_server(uint16_t);
int create_udp_client();
void set_error_msg(udp_message_t *resp, const char *msg);

// Fire-and-forget: send a message, don't wait for a reply
void send_udp_message_one_way(int sock, udp_message_t *msg, uint16_t dest_port);

// Request-reply: send a message and wait for a response. Returns true on success.
bool send_udp_message_and_receive(int sock, udp_message_t *req, udp_message_t *resp, uint16_t dest_port);