#include "common.h"
#include <stdlib.h>
#include <time.h>
#include <unistd.h>
#include <errno.h>

#define SERVICE_NAME "traffic_mgr"

static traffic_stats_t stats;
static int client_socket = 0;

static void update_port_counters(uint8_t port_id, uint32_t rx, uint32_t dropped)
{
    udp_message_t req = {0};
    req.msg_type = MSG_UPDATE_COUNTERS;
    req.status = STATUS_REQUEST;

    udp_counter_update_t *payload = (udp_counter_update_t *)req.payload;
    payload->port_id = port_id;
    payload->pkts_rx = rx;
    payload->pkts_dropped = dropped;

    send_udp_message_one_way(client_socket, &req, PORT_MANAGER_UDP);
}

void initialize_stats()
{
    memset(&stats, 0, sizeof(stats));
    stats.next_frame_id = 1; // Start from 1
    LOG(LOG_INFO, "Traffic stats initialized");
}

void generate_traffic()
{
    const char *sample_payloads[] = {
        "Data payload alpha",
        "Waveserver mini frame",
        "OTN test payload"
    };

    uint8_t client_port = stats.client_port ? stats.client_port : (uint8_t)(3 + (rand() % 4));
    uint8_t line_port = stats.line_port ? stats.line_port : (uint8_t)(1 + (rand() % 2));

    otn_frame_t frame = {0};
    frame.header.client_port = client_port;
    frame.header.line_port = line_port;
    frame.header.frame_id = stats.next_frame_id++;
    strncpy(frame.data,
            sample_payloads[rand() % (sizeof(sample_payloads) / sizeof(sample_payloads[0]))],
            sizeof(frame.data) - 1);

    LOG(LOG_DEBUG, "Frame #%u generated: client-%u -> line-%u msg=\"%s\"",
        frame.header.frame_id,
        frame.header.client_port,
        frame.header.line_port,
        frame.data);

    udp_message_t lookup_req = {0};
    lookup_req.msg_type = MSG_LOOKUP_CONNECTION;
    lookup_req.status = STATUS_REQUEST;

    udp_route_lookup_request_t *lookup_payload = (udp_route_lookup_request_t *)lookup_req.payload;
    lookup_payload->client_port = frame.header.client_port;
    lookup_payload->line_port = frame.header.line_port;

    udp_message_t lookup_resp = {0};
    if (!send_udp_message_and_receive(client_socket, &lookup_req, &lookup_resp, CONN_MANAGER_UDP) ||
        lookup_resp.status != STATUS_SUCCESS)
    {
        stats.total_dropped++;
        update_port_counters(frame.header.client_port, 0, 1);
        LOG(LOG_WARN, "Frame #%u DROPPED: no connection for client-%u line-%u",
            frame.header.frame_id,
            frame.header.client_port,
            frame.header.line_port);
        return;
    }

    const udp_route_lookup_reply_t *route = (const udp_route_lookup_reply_t *)lookup_resp.payload;
    if (route->operational_state != CONN_UP)
    {
        stats.total_dropped++;
        update_port_counters(frame.header.client_port, 0, 1);
        LOG(LOG_WARN, "Frame #%u DROPPED: connection %s is DOWN",
            frame.header.frame_id,
            route->conn_name);
        return;
    }

    stats.total_forwarded++;
    update_port_counters(frame.header.client_port, 1, 0);
    update_port_counters(frame.header.line_port, 1, 0);
    LOG(LOG_DEBUG, "Frame #%u FORWARDED: client-%u -> line-%u via %s",
        frame.header.frame_id,
        frame.header.client_port,
        frame.header.line_port,
        route->conn_name);
}

void handle_get_traffic_stats(udp_message_t *resp)
{
    resp->msg_type = MSG_GET_TRAFFIC_STATS;
    resp->status = STATUS_SUCCESS;
    memcpy(resp->payload, &stats, sizeof(stats));
    LOG(LOG_DEBUG, "Returning traffic stats");
}

void handle_start_traffic(const udp_message_t *req, udp_message_t *resp)
{
    const udp_start_traffic_request_t *udp_request = (const udp_start_traffic_request_t *)req->payload;
    stats.client_port = udp_request->client_port;
    stats.line_port = udp_request->line_port;

    resp->status = STATUS_FAILURE;

    if (stats.line_port != 0 && (stats.line_port < 1 || stats.line_port > 2)) 
    {
        LOG(LOG_ERROR, "[ERROR] Line port must be 1 or 2, got %d\n", stats.line_port);
        return;
    }

    if (stats.client_port != 0 && (stats.client_port < 3 || stats.client_port > 6))
    {
        LOG(LOG_ERROR, "[ERROR] Client port must be 3–6, got %d\n", stats.client_port);
        return;
    }

    stats.running = true;
    resp->status = STATUS_SUCCESS;
    LOG(LOG_INFO, "Traffic started (client=%u, line=%u, 0=random)",
        stats.client_port, stats.line_port);
}

void handle_stop_traffic(udp_message_t *resp)
{
    // TODO: F4 — Stop Traffic Handler (/2 pts)
}

bool dispatch(const udp_message_t *req, udp_message_t *resp)
{
    bool send_reply = true;

    resp->msg_type = req->msg_type;
    resp->status = STATUS_FAILURE;

    switch ((msg_type_t)req->msg_type)
    {
    case MSG_GET_TRAFFIC_STATS:
        handle_get_traffic_stats(resp);
        break;
    case MSG_START_TRAFFIC:
    {
        handle_start_traffic(req, resp);
        break;
    }
    case MSG_STOP_TRAFFIC:
        handle_stop_traffic(resp);
        break;
    default:
        LOG(LOG_WARN, "Unknown msg_type: %d", req->msg_type);
        send_reply = false;
        break;
    }

    return send_reply;
}

int main()
{
    log_init(SERVICE_NAME);
    initialize_stats();
    srand(time(NULL)); // Seed random

    int server_socket = create_udp_server(TRAFFIC_MGR_UDP);
    if (server_socket < 0)
    {
        LOG(LOG_ERROR, "Failed to create server socket - exiting");
        return 1;
    }

    client_socket = create_udp_client();
    if (client_socket < 0)
    {
        LOG(LOG_ERROR, "Failed to create client socket - exiting");
        return 1;
    }

    struct timeval rx_timeout = {.tv_sec = 1, .tv_usec = 0};
    setsockopt(server_socket, SOL_SOCKET, SO_RCVTIMEO, &rx_timeout, sizeof(rx_timeout));

    time_t last_traffic = time(NULL);

    while (true)
    {
        udp_message_t req = {0};
        struct sockaddr_in sender;
        socklen_t sender_len = sizeof(sender);

        ssize_t n = recvfrom(server_socket, &req, sizeof(req), 0, (struct sockaddr *)&sender, &sender_len);
        if (n < 0 && errno != EAGAIN && errno != EWOULDBLOCK)
        {
            LOG(LOG_ERROR, "recvfrom failed");
        }
        else if (n > 0)
        {
            udp_message_t resp = {0};
            if (dispatch(&req, &resp) &&
                (sendto(server_socket, &resp, sizeof(resp), 0, (struct sockaddr *)&sender, sender_len) < 0))
            {
                LOG(LOG_ERROR, "sendto reply failed");
            }
        }

        time_t now = time(NULL);
        if (stats.running && now - last_traffic >= 3)
        {
            generate_traffic();
            last_traffic = now;
        }
    }
    return 0;
}