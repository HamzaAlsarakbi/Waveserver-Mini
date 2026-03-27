#include "common.h"
#include <errno.h>
#include <stdint.h>

#define SERVICE_NAME "port_mgr"

// TODO: F2 — Inject & Clear Fault (/8 pts)
//
// Implement inject-fault and clear-fault handlers + dispatch wiring.
// Only support fault injection for ports that are admin-enabled.
// We do not support this feature for ports that are admin-disabled.

static port_t ports[MAX_PORT_NUM];
static int notify_socket; // used to send to connection mgr

void initialize_ports()
{
    for (int i = 0; i < MAX_PORT_NUM; i++)
    {
        ports[i].id = i + 1;
        ports[i].type = (i < MAX_LINE_PORTS) ? LINE_PORT : CLIENT_PORT;
        ports[i].operational_state = PORT_DOWN;
        ports[i].admin_enabled = false;
        ports[i].fault_active = false;
        ports[i].dropped_frames = 0;
        ports[i].rx_frames = 0;
    }

    LOG(LOG_INFO, "Initialized ports");
}

/*
 * Convert 1-based port system to 0-based system
 */
int convert_port_idx(uint8_t port_id)
{
    if (port_id <= 0 || port_id > MAX_PORT_NUM)
    {
        LOG(LOG_ERROR, "Invalid port number %d", port_id);
        return -1;
    }

    return port_id - 1;
}

void notify_port_state(uint8_t port_id)
{
    int port_idx = convert_port_idx(port_id);
    if (port_idx < 0)
        return;

    udp_message_t udp_request = {0};
    udp_request.msg_type      = MSG_PORT_STATE_CHANGE;
    udp_request.status        = STATUS_REQUEST;

    udp_port_state_change_t *payload = (udp_port_state_change_t *)udp_request.payload;
    payload->port_id = port_id;
    payload->operational_state = ports[port_idx].operational_state;

    send_udp_message_one_way(notify_socket, &udp_request, CONN_MANAGER_UDP);
    LOG(LOG_DEBUG, "Notified conn-mgr: port_idx=%d, operational_state=%s",
        port_idx,
        ports[port_idx].operational_state == PORT_UP ? "UP" : "DOWN");
}

void recalculate_oper_state(port_t *port) {
    port_state_t prev_state = port->operational_state;

    if (port->admin_enabled && !port->fault_active) {
        port->operational_state = PORT_UP;
    } else {
        port->operational_state = PORT_DOWN;
    }

    if (port->operational_state != prev_state) {
        LOG(LOG_INFO, "port_idx=%d oper_state changed: %s -> %s (admin=%s fault=%s)",
            port->id - 1,
            prev_state == PORT_UP ? "UP" : "DOWN",
            port->operational_state == PORT_UP ? "UP" : "DOWN",
            port->admin_enabled ? "enabled" : "disabled",
            port->fault_active ? "active" : "none");
        notify_port_state(port->id);
    }
}

/**
 * Extract the port from a request that uses udp_port_cmd_request_t.
 * Returns a pointer to the port, or NULL if the port ID is invalid
 * (sets STATUS_FAILURE and an error message on the response).
 */
port_t *get_port_from_request(const udp_message_t *request, udp_message_t *response)
{
    const udp_port_cmd_request_t *request_payload = (udp_port_cmd_request_t *)request->payload;
    int port_idx = convert_port_idx(request_payload->port_id);
    if (port_idx < 0)
    {
        // set_error_msg sets response->status = STATUS_FAILURE
        set_error_msg(response, "Invalid port id, out-of-range [1, 6]");
        return NULL;
    }
    return &ports[port_idx];
}

void handle_get_port_info(const udp_message_t *request, udp_message_t *response)
{
    port_t *port = get_port_from_request(request, response);
    if (!port) return;

    memcpy(response->payload, port, sizeof(port_t));
    response->status = STATUS_SUCCESS;
    LOG(LOG_DEBUG, "MSG_GET_PORT_INFO: Returning info for port_idx-%d", port->id - 1);
}

void handle_update_counters(const udp_message_t *request)
{
    const udp_counter_update_t *payload = (udp_counter_update_t *)request->payload;
    int port_idx = convert_port_idx(payload->port_id);
    if (port_idx < 0)
    {
        LOG(LOG_ERROR, "Invalid port_id in counter update: %d", payload->port_id);
        return;
    }

    ports[port_idx].rx_frames += payload->pkts_rx;
    ports[port_idx].dropped_frames += payload->pkts_dropped;
    LOG(LOG_INFO, "Updated counters for port_idx=%d: rx=%u dropped=%u",
        port_idx, payload->pkts_rx, payload->pkts_dropped);
}

void handle_set_port(const udp_message_t *request, udp_message_t *response)
{
    port_t *port = get_port_from_request(request, response);
    if (!port) return;

    port->admin_enabled = true;
    recalculate_oper_state(port);
    LOG(LOG_INFO, "Port admin-enabled: port_idx=%d", port->id - 1);
    response->status = STATUS_SUCCESS;
}

void handle_delete_port(const udp_message_t *request, udp_message_t *response)
{
    port_t *port = get_port_from_request(request, response);
    if (!port) return;

    port->admin_enabled = false;
    recalculate_oper_state(port);
    LOG(LOG_INFO, "Port admin-disabled: port_idx=%d", port->id - 1);
    response->status = STATUS_SUCCESS;
}
void handle_inject_fault(const udp_message_t *request, udp_message_t *response)
{
    port_t *port = get_port_from_request(request, response);
    if (!port) return;

    port->fault_active = true;
    recalculate_oper_state(port);
    LOG(LOG_ERROR, "[Error] port_idx=%d SIGNAL LOSS", port->id - 1);
    response->status = STATUS_SUCCESS;
}
void handle_clear_fault(const udp_message_t *request, udp_message_t *response)
{
    port_t *port = get_port_from_request(request, response);
    if (!port) return;

    port->fault_active = false;
    recalculate_oper_state(port);
    LOG(LOG_INFO, "Injection Fault Cleared: port_idx=%d", port->id - 1);
    response->status = STATUS_SUCCESS;
}
void perform_health_check(void)
{
    LOG(LOG_INFO, "----------------------------- HEALTH CHECK -----------------------------");
    
    for (int i = 0; i < MAX_PORT_NUM; i++)
    {
        port_t *port = &ports[i];
        const char *type_str = (port->type == LINE_PORT) ? "LINE" : "CLIENT";
        const char *admin_str = port->admin_enabled ? "Enabled" : "Disabled";
        const char *fault_str = port->fault_active ? "Active" : "None";
        const char *oper_str = (port->operational_state == PORT_UP) ? "UP" : "DOWN";
        
        LOG(LOG_INFO, "port_idx=%d (%s) admin=%s fault=%s oper=%s received=%u dropped=%u",
            i,
            type_str,
            admin_str,
            fault_str,
            oper_str,
            port->rx_frames,
            port->dropped_frames);
    }
}

bool dispatch(const udp_message_t *req, udp_message_t *resp)
{
    bool send_reply = true;

    resp->msg_type = req->msg_type;
    resp->status = STATUS_FAILURE; // default

    switch ((msg_type_t)req->msg_type)
    {
    case MSG_GET_PORT_INFO:
        handle_get_port_info(req, resp);
        break;
    case MSG_UPDATE_COUNTERS:
        handle_update_counters(req);
        send_reply = false; // fire-and-forget, no reply expected
        break;
    case MSG_SET_PORT:
        handle_set_port(req, resp);
        break;
    case MSG_DELETE_PORT:
        handle_delete_port(req, resp);
        break;
    case MSG_INJECT_FAULT:
        handle_inject_fault(req, resp);
        break;
    case MSG_CLEAR_FAULT:
        handle_clear_fault(req, resp);
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
    initialize_ports();
    int server_socket = create_udp_server(PORT_MANAGER_UDP);
    if (server_socket < 0)
    {
        LOG(LOG_ERROR, "Failed to create server socket - exiting");
        return 1;
    }

    notify_socket = create_udp_client();
    if (notify_socket < 0)
    {
        LOG(LOG_ERROR, "Failed to create notify socket - exiting");
        return 1;
    }

    time_t last_health_check = time(NULL);

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
        // Check if it has been 5 seconds since the last health check or more.
        if (now - last_health_check >= 5)
        {
            perform_health_check();
            last_health_check = now;
        }
    }
    return 0;
}
