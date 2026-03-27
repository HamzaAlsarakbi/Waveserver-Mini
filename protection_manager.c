#include "common.h"
#include <stdint.h>

#define SERVICE_NAME "protection_mgr"

static bool protection_group_active;
static int client_socket;

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

void handle_create_protection_group(udp_message_t *resp)
{
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

    if (protection_group_active)
    {
        set_error_msg(resp, "protection group is already active");
        return;
    }

    protection_group_active = true;
    resp->status = STATUS_SUCCESS;
    LOG(LOG_INFO, "protection group activated for port-1 <-> port-2");
}

bool dispatch(const udp_message_t *req, udp_message_t *resp)
{
    resp->msg_type = req->msg_type;

    switch ((msg_type_t)req->msg_type)
    {
    case MSG_CREATE_PROTECTION_GROUP:
        handle_create_protection_group(resp);
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
