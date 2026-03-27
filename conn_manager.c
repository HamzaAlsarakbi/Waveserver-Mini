#include "common.h"
#include <netinet/in.h>
#include <stdint.h>

#define SERVICE_NAME "conn_mgr"

static conn_t conns[MAX_CONNS];
static int client_socket;

void initialize_connections()
{
    memset(conns, 0, sizeof(conns));
    LOG(LOG_INFO, "Initialize connection table");
}

bool get_port_info(uint8_t port_id, port_t *out)
{
    udp_message_t req = {0};
    req.msg_type = MSG_GET_PORT_INFO;
    req.status = STATUS_REQUEST;

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

conn_t *find_connection_by_name(const char *name)
{
    for (int i = 0; i < MAX_CONNS; i++)
    {
        if (conns[i].client_port != 0 &&
            strncmp(conns[i].conn_name, name, MAX_CONN_NAME_CHARACTER) == 0)
            return &conns[i];
    }
    return NULL;
}

void handle_port_state_change(const udp_message_t *req)
{
    const udp_port_state_change_t *payload = (udp_port_state_change_t *)req->payload;
    uint8_t port_id = payload->port_id;

    if (port_id < 1 || port_id > MAX_PORT_NUM) {
        LOG(LOG_ERROR, "Port-%d out of range");
        return;
    }

    LOG(LOG_INFO, "Port-%d operational_state changed to %s",
        port_id,
        payload->operational_state == PORT_UP ? "UP" : "DOWN");

    for (int i = 0; i < MAX_CONNS; i++)
    {
        if (conns[i].client_port == 0)
            continue; // empty slot

        if (conns[i].client_port == port_id || conns[i].line_port == port_id)
        {
            if (payload->operational_state == PORT_DOWN)
            {
                conns[i].operational_state = CONN_DOWN;
                LOG(LOG_WARN, "Connection %s DOWN (port-%d went down)", conns[i].conn_name, port_id);
            }
            else
            {
                // check if the other port is also up
                uint8_t other_port = (conns[i].client_port == port_id) ? conns[i].line_port : conns[i].client_port;
                port_t other_port_info = {0};
                if (get_port_info(other_port, &other_port_info) == false)
                {
                    LOG(LOG_ERROR, "handle port up: Could not get info for port-%d, leaving connection %s DOWN",
                        other_port,
                        conns[i].conn_name);
                }
                else if (other_port_info.operational_state == PORT_UP)
                {
                    conns[i].operational_state = CONN_UP;
                    LOG(LOG_INFO, "Connection %s UP (port-%d recovered, port-%d also UP)",
                        conns[i].conn_name,
                        port_id,
                        other_port);
                }
                else
                {
                    LOG(LOG_WARN, "Connection %s DOWN (port-%d recovered, but port-%d still DOWN)",
                        conns[i].conn_name,
                        port_id,
                        other_port);
                }
            }
        }
    }
}

void handle_lookup_connection(const udp_message_t *req, udp_message_t *resp)
{
    const udp_route_lookup_request_t *payload = (const udp_route_lookup_request_t *)req->payload;

    conn_t *conn = NULL;
    for (int i = 0; i < MAX_CONNS; i++)
    {
        if (conns[i].client_port == payload->client_port &&
            conns[i].line_port == payload->line_port)
        {
            conn = &conns[i];
            break;
        }
    }

    if (conn == NULL)
    {
        LOG(LOG_WARN, "MSG_LOOKUP_CONNECTION: no connection for client port-%d and line port-%d",
            payload->client_port,
            payload->line_port);
        resp->status = STATUS_FAILURE;
        return;
    }

    udp_route_lookup_reply_t *reply = (udp_route_lookup_reply_t *)resp->payload;

    strncpy(reply->conn_name, conn->conn_name, sizeof(reply->conn_name) - 1);
    reply->operational_state = (uint8_t)conn->operational_state;
    resp->status = STATUS_SUCCESS;

    LOG(LOG_DEBUG,
        "MSG_LOOKUP_CONNECTION: client-%d → line-%d via %s operational_state=%s",
        payload->client_port, conn->line_port, conn->conn_name,
        conn->operational_state == CONN_UP ? "UP" : "DOWN");
}

void handle_create_connection(const udp_message_t *req, udp_message_t *resp)
{
    const udp_create_conn_request_t *payload = (const udp_create_conn_request_t *)req->payload;

    resp->status = STATUS_FAILURE;

    size_t name_len = 0;
    while (name_len < MAX_CONN_NAME_CHARACTER && payload->name[name_len] != '\0')
        name_len++;
    if (name_len == 0 || name_len >= MAX_CONN_NAME_CHARACTER)
    {
        set_error_msg(resp, "connection name must be 1-31 characters");
        return;
    }

    if (payload->line_port < 1 || payload->line_port > 2)
    {
        set_error_msg(resp, "line port must be in range 1-2");
        return;
    }

    if (payload->client_port < 3 || payload->client_port > 6)
    {
        set_error_msg(resp, "client port must be in range 3-6");
        return;
    }

    if (find_connection_by_name(payload->name) != NULL)
    {
        set_error_msg(resp, "connection name already exists");
        return;
    }

    for (int i = 0; i < MAX_CONNS; i++)
    {
        if (conns[i].client_port == payload->client_port)
        {
            set_error_msg(resp, "client port already has a connection");
            return;
        }
    }

    port_t line_info = {0};
    port_t client_info = {0};
    if (!get_port_info(payload->line_port, &line_info) ||
        !get_port_info(payload->client_port, &client_info))
    {
        set_error_msg(resp, "failed to get port info");
        return;
    }

    if (line_info.admin_enabled == false || line_info.operational_state != PORT_UP)
    {
        set_error_msg(resp, "line port is not operationally UP");
        return;
    }

    if (client_info.admin_enabled == false || client_info.operational_state != PORT_UP)
    {
        set_error_msg(resp, "client port is not operationally UP");
        return;
    }

    conn_t *slot = NULL;
    for (int i = 0; i < MAX_CONNS; i++)
    {
        if (conns[i].client_port == 0)
        {
            slot = &conns[i];
            break;
        }
    }

    if (slot == NULL)
    {
        set_error_msg(resp, "connection table is full");
        return;
    }

    memset(slot, 0, sizeof(*slot));
    strncpy(slot->conn_name, payload->name, MAX_CONN_NAME_CHARACTER - 1);
    slot->line_port = payload->line_port;
    slot->client_port = payload->client_port;
    slot->operational_state = CONN_UP;

    resp->status = STATUS_SUCCESS;
    LOG(LOG_INFO, "created connection '%s': client-%d -> line-%d",
        slot->conn_name,
        slot->client_port,
        slot->line_port);
}

void handle_get_connections(udp_message_t *resp)
{
    resp->status = STATUS_SUCCESS;

    udp_get_connections_reply_t *resp_payload = (udp_get_connections_reply_t *)resp->payload;
    int count = 0;

    for (int i = 0; i < MAX_CONNS; i++)
    {
        if (conns[i].line_port > 0 && conns[i].client_port > 0) {
            resp_payload->all_connections[count].client_port = conns[i].client_port;
            resp_payload->all_connections[count].line_port = conns[i].line_port;
            resp_payload->all_connections[count].operational_state = conns[i].operational_state;
            strncpy(resp_payload->all_connections[count].conn_name, conns[i].conn_name, MAX_CONN_NAME_CHARACTER - 1);
            count++;
        }
    }

    resp_payload->conn_count = count;
}

void handle_delete_conn(const udp_message_t *req, udp_message_t *resp)
{
    const udp_delete_conn_request_t *udp_payload = (const udp_delete_conn_request_t *)req->payload;
    conn_t *found_conn = find_connection_by_name(udp_payload->name);

    if (found_conn == NULL) {
        const char *err = "could not find connection with that name";
        LOG(LOG_ERROR, "%s (name=%s)", err, udp_payload->name);
        resp->status = STATUS_FAILURE;
        set_error_msg(resp, err);
        return;
    }

    resp->status = STATUS_SUCCESS;

    found_conn->client_port = 0;
    found_conn->line_port = 0;
    found_conn->operational_state = CONN_DOWN;
    found_conn->conn_name[0] = '\0';
    LOG(LOG_INFO, "deleted connection '%s'", udp_payload->name);
}

bool dispatch(const udp_message_t *req, udp_message_t *resp)
{
    bool send_reply = false;
    resp->msg_type = req->msg_type;

    switch ((msg_type_t)req->msg_type)
    {
    case MSG_PORT_STATE_CHANGE:
        handle_port_state_change(req);
        break;
    case MSG_LOOKUP_CONNECTION:
        handle_lookup_connection(req, resp);
        send_reply = true;
        break;
    case MSG_CREATE_CONN:
        handle_create_connection(req, resp);
        send_reply = true;
        break;
    case MSG_GET_CONNECTIONS:
        handle_get_connections(resp);
        send_reply = true;
        break;
    case MSG_DELETE_CONN:
        handle_delete_conn(req, resp);
        send_reply = true;
        break;
    default:
        LOG(LOG_WARN, "Unknown msg_type: %d", req->msg_type);
        break;
    }

    return send_reply;
}

int main()
{
    log_init(SERVICE_NAME);
    initialize_connections();

    int server_socket = create_udp_server(CONN_MANAGER_UDP);
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
