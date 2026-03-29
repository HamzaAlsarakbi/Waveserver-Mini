#include "common.h"
#include <stdint.h>

#define SERVICE_NAME "protection_mgr"

static bool     protection_group_active;
static uint32_t switchover_count;
static int      client_socket;

// Per-connection tracking entry
typedef struct
{
    char    conn_name[MAX_CONN_NAME_CHARACTER];
    uint8_t original_line;
    uint8_t current_line;
    bool    switched;
    bool    valid; // slot is in use
} prot_conn_entry_t;

static prot_conn_entry_t prot_conns[MAX_CONNS];

// ── helpers ─────────────────────────────────────────────────────────────────

bool get_port_info(uint8_t port_id, port_t *out)
{
    udp_message_t req = {0};
    req.msg_type = MSG_GET_PORT_INFO;
    req.status   = STATUS_REQUEST;

    udp_port_cmd_request_t *payload = (udp_port_cmd_request_t *)req.payload;
    payload->port_id = port_id;

    udp_message_t resp = {0};
    if (!send_udp_message_and_receive(client_socket, &req, &resp, PORT_MANAGER_UDP))
    {
        LOG(LOG_ERROR, "send/receive failed for port-%d", port_id);
        return false;
    }

    if (resp.status != STATUS_SUCCESS)
    {
        LOG(LOG_ERROR, "port-%d not found", port_id);
        return false;
    }

    memcpy(out, resp.payload, sizeof(*out));
    return true;
}

bool get_all_connections(conn_t *out, int *count)
{
    udp_message_t req = {0};
    req.msg_type = MSG_GET_CONNECTIONS;
    req.status   = STATUS_REQUEST;

    udp_message_t resp = {0};
    if (!send_udp_message_and_receive(client_socket, &req, &resp, CONN_MANAGER_UDP))
    {
        LOG(LOG_ERROR, "failed to query connections from conn_mgr");
        return false;
    }

    const udp_get_connections_reply_t *reply = (const udp_get_connections_reply_t *)resp.payload;
    *count = reply->conn_count;
    for (int i = 0; i < reply->conn_count; i++)
        out[i] = reply->all_connections[i];
    return true;
}

bool switch_conn_line(const char *conn_name, uint8_t new_line_port)
{
    udp_message_t req = {0};
    req.msg_type = MSG_SWITCH_CONN_LINE;
    req.status   = STATUS_REQUEST;

    udp_switch_conn_line_t *payload = (udp_switch_conn_line_t *)req.payload;
    strncpy(payload->conn_name, conn_name, MAX_CONN_NAME_CHARACTER - 1);
    payload->new_line_port = new_line_port;

    udp_message_t resp = {0};
    if (!send_udp_message_and_receive(client_socket, &req, &resp, CONN_MANAGER_UDP))
    {
        LOG(LOG_ERROR, "failed to switch connection '%s' to line-%d", conn_name, new_line_port);
        return false;
    }

    return resp.status == STATUS_SUCCESS;
}

void snapshot_connections(void)
{
    memset(prot_conns, 0, sizeof(prot_conns));

    conn_t conns[MAX_CONNS];
    int count = 0;
    if (!get_all_connections(conns, &count))
        return;

    for (int i = 0; i < count && i < MAX_CONNS; i++)
    {
        strncpy(prot_conns[i].conn_name, conns[i].conn_name, MAX_CONN_NAME_CHARACTER - 1);
        prot_conns[i].original_line = conns[i].line_port;
        prot_conns[i].current_line  = conns[i].line_port;
        prot_conns[i].switched      = false;
        prot_conns[i].valid         = true;
    }
}

// ── command handlers ─────────────────────────────────────────────────────────

void handle_create_protection_group(udp_message_t *resp)
{
    if (protection_group_active)
    {
        set_error_msg(resp, "protection group is already active");
        return;
    }

    port_t port1 = {0};
    port_t port2 = {0};

    if (!get_port_info(1, &port1) || !get_port_info(2, &port2))
    {
        set_error_msg(resp, "failed to get line port info");
        return;
    }

    if (port1.type != LINE_PORT || port2.type != LINE_PORT)
    {
        set_error_msg(resp, "protection members must be line ports");
        return;
    }

    if (!port1.admin_enabled || !port2.admin_enabled)
    {
        set_error_msg(resp, "both line ports must be admin-enabled");
        return;
    }

    protection_group_active = true;
    switchover_count = 0;
    snapshot_connections();

    resp->status = STATUS_SUCCESS;
    LOG(LOG_INFO, "protection group activated for port-1 <-> port-2");
}

void handle_delete_protection_group(udp_message_t *resp)
{
    if (!protection_group_active)
    {
        set_error_msg(resp, "no protection group is active");
        return;
    }

    // Revert all switched connections to their original line port
    for (int i = 0; i < MAX_CONNS; i++)
    {
        if (!prot_conns[i].valid || !prot_conns[i].switched)
            continue;

        if (switch_conn_line(prot_conns[i].conn_name, prot_conns[i].original_line))
        {
            LOG(LOG_INFO, "Revert on delete: '%s' moved back to port-%d",
                prot_conns[i].conn_name, prot_conns[i].original_line);
        }
    }

    protection_group_active = false;
    switchover_count = 0;
    memset(prot_conns, 0, sizeof(prot_conns));

    resp->status = STATUS_SUCCESS;
    LOG(LOG_INFO, "protection group deleted");
}

void handle_fault_notify(const udp_message_t *req)
{
    if (!protection_group_active)
        return;

    const udp_fault_notify_t *payload = (const udp_fault_notify_t *)req->payload;
    uint8_t faulted_port = payload->port_id;

    // Only react to line ports (1 and 2)
    if (faulted_port != 1 && faulted_port != 2)
        return;

    uint8_t protect_port = (faulted_port == 1) ? 2 : 1;

    if (payload->fault_active)
    {
        // Fault injected: switch connections on the faulted port to the protect port
        for (int i = 0; i < MAX_CONNS; i++)
        {
            if (!prot_conns[i].valid)
                continue;
            if (prot_conns[i].current_line != faulted_port)
                continue;

            if (switch_conn_line(prot_conns[i].conn_name, protect_port))
            {
                prot_conns[i].current_line = protect_port;
                prot_conns[i].switched     = true;
                switchover_count++;
                printf("[INFO] Protection switchover: %s moved from port-%d -> port-%d\n",
                       prot_conns[i].conn_name, faulted_port, protect_port);
                LOG(LOG_INFO, "Protection switchover: '%s' port-%d -> port-%d",
                    prot_conns[i].conn_name, faulted_port, protect_port);
            }
        }
    }
    else
    {
        // Fault cleared: revertive switch — move connections back to their original port
        for (int i = 0; i < MAX_CONNS; i++)
        {
            if (!prot_conns[i].valid)
                continue;
            // Only revert connections whose original line was the now-recovered port
            if (prot_conns[i].original_line != faulted_port || !prot_conns[i].switched)
                continue;

            if (switch_conn_line(prot_conns[i].conn_name, faulted_port))
            {
                prot_conns[i].current_line = faulted_port;
                prot_conns[i].switched     = false;
                printf("[INFO] Revertive switch: %s moved from port-%d -> port-%d\n",
                       prot_conns[i].conn_name, protect_port, faulted_port);
                LOG(LOG_INFO, "Revertive switch: '%s' port-%d -> port-%d",
                    prot_conns[i].conn_name, protect_port, faulted_port);
            }
        }
    }
}

void handle_show_prot_group(udp_message_t *resp)
{
    udp_prot_group_reply_t *reply = (udp_prot_group_reply_t *)resp->payload;

    reply->active          = protection_group_active ? 1 : 0;
    reply->switchover_count = switchover_count;

    int count = 0;
    for (int i = 0; i < MAX_CONNS; i++)
    {
        if (!prot_conns[i].valid)
            continue;
        strncpy(reply->conns[count].name, prot_conns[i].conn_name, MAX_CONN_NAME_CHARACTER - 1);
        reply->conns[count].original_line = prot_conns[i].original_line;
        reply->conns[count].current_line  = prot_conns[i].current_line;
        reply->conns[count].switched      = prot_conns[i].switched ? 1 : 0;
        count++;
    }
    reply->conn_count = (uint8_t)count;

    resp->status = STATUS_SUCCESS;
}

// ── dispatch ─────────────────────────────────────────────────────────────────

bool dispatch(const udp_message_t *req, udp_message_t *resp)
{
    resp->msg_type = req->msg_type;

    switch ((msg_type_t)req->msg_type)
    {
    case MSG_CREATE_PROTECTION_GROUP:
        handle_create_protection_group(resp);
        return true;
    case MSG_DELETE_PROTECTION_GROUP:
        handle_delete_protection_group(resp);
        return true;
    case MSG_FAULT_NOTIFY:
        handle_fault_notify(req);
        return false; // fire-and-forget, no reply
    case MSG_SHOW_PROT_GROUP:
        handle_show_prot_group(resp);
        return true;
    default:
        LOG(LOG_WARN, "Unknown msg_type: %d", req->msg_type);
        return false;
    }
}

int main(void)
{
    log_init(SERVICE_NAME);
    protection_group_active = false;
    switchover_count = 0;
    memset(prot_conns, 0, sizeof(prot_conns));

    int server_socket = create_udp_server(PROTECTION_MGR_UDP);
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

    while (true)
    {
        udp_message_t req = {0};
        struct sockaddr_in sender = {0};
        socklen_t sender_len = sizeof(sender);

        ssize_t n = recvfrom(server_socket, &req, sizeof(req), 0, (struct sockaddr *)&sender, &sender_len);
        if (n < 0)
        {
            LOG(LOG_ERROR, "recvfrom failed");
            continue;
        }

        udp_message_t resp = {0};
        if (dispatch(&req, &resp) &&
            (sendto(server_socket, &resp, sizeof(resp), 0, (struct sockaddr *)&sender, sender_len) < 0))
        {
            LOG(LOG_ERROR, "sendto reply failed");
        }
    }

    return 0;
}
