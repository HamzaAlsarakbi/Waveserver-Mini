/**
 * cli.c — Waveserver Mini Management Console
 *
 * This is the user-facing CLI for the router simulator.
 * It sends UDP requests to the other three services and displays results.
 *
 * The CLI does NOT run as a server — it's a client that sends requests
 * and waits for replies. It's the only process with direct user interaction.
 */

#include "common.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <errno.h>
#include <unistd.h>

#define SERVICE_NAME "cli" /* used for logging */
#define MAX_INPUT_LEN (256) /* maximum length of user input - arbitrary.. */

// Socket used to send requests to other services and receive replies
static int cli_socket;

// ============================================================================
//  CLI Command Handlers (defined below)
// ============================================================================
//  cmd_show_ports          — show ports
//  cmd_show_connections    — show connections
//  cmd_show_traffic_stats  — show traffic-stats
//  cmd_show_logs           — show logs [--level X] [--service S]
//  cmd_set_port            — set port <id>
//  cmd_delete_port         — delete port <id>
//  cmd_create_connection   — create connection ...
//  cmd_delete_connection   — delete connection ...
//  cmd_inject_fault        — inject-fault <id>
//  cmd_clear_fault         — clear-fault <id>
//  cmd_start_traffic       — start traffic
//  cmd_stop_traffic        — stop traffic
//  cmd_help                — help

// ============================================================================
//  Helper: Send a request to a service and wait for a reply
// ============================================================================

/**
 * Sends a udp_message_t to the given destination port (e.g., PORT_MANAGER_UDP)
 * and waits for a reply. Returns true if we got a reply, false on error/timeout.
 *
 * This is the core request-reply pattern used by most CLI commands:
 *   1. Build a udp_message_t with the right msg_type and payload
 *   2. Call this function to send it and get the response
 *   3. Read the response payload to display results
 */
bool send_and_receive(udp_message_t *req, udp_message_t *resp, uint16_t dest_port)
{
    if (!send_udp_message_and_receive(cli_socket, req, resp, dest_port))
    {
        if (errno == EAGAIN || errno == EWOULDBLOCK)
        {
            LOG(LOG_ERROR, "Request timed out — is the service running?");
        }
        else
        {
            LOG(LOG_ERROR, "Failed to communicate with service: %s", strerror(errno));
        }
        return false;
    }
    return true;
}

/**
 * Print an error from a command reply. If the response contains an error
 * message, print it; otherwise print a generic fallback.
 */
void print_cmd_error(udp_message_t *resp, const char *cmd_name, const char *target)
{
    udp_cmd_reply_t *reply = (udp_cmd_reply_t *)resp->payload;
    if (reply->error_msg[0] != '\0')
        fprintf(stderr, "[ERROR] %s failed: %s\n", cmd_name, reply->error_msg);
    else
        fprintf(stderr, "[ERROR] %s failed for %s\n", cmd_name, target);
}

/**
 * Common handler for port commands (set, delete).
 * Validates the port ID, sends the message, and returns true on success.
 */
bool exec_port_cmd(uint8_t port_id, msg_type_t cmd, const char *cmd_name)
{
    if (port_id < 1 || port_id > MAX_PORT_NUM)
    {
        fprintf(stderr, "[ERROR] Invalid port ID %d (must be 1–6)\n", port_id);
        return false;
    }

    udp_message_t udp_request = {0};
    udp_message_t udp_response = {0};

    udp_request.msg_type = cmd;
    udp_request.status   = STATUS_REQUEST;

    udp_port_cmd_request_t *payload = (udp_port_cmd_request_t *)udp_request.payload;
    payload->port_id = port_id;

    if (!send_and_receive(&udp_request, &udp_response, PORT_MANAGER_UDP))
    {
        LOG(LOG_ERROR, "send_and_receive failed to send message to PORT_MANAGER");
        return false;
    }

    if (udp_response.status == STATUS_SUCCESS)
        return true;

    char target[32];
    snprintf(target, sizeof(target), "port-%d", port_id);
    print_cmd_error(&udp_response, cmd_name, target);
    return false;
}

// ============================================================================
//  CLI Command Handlers
// ============================================================================

/**
 * show ports — Query Port Manager for all 6 ports and display a table.
 *
 * Since MSG_GET_PORT_INFO returns one port at a time, we query 6 times
 * (once for each port) and build the table from the responses.
 */
void cmd_show_ports(void)
{
    printf("\n");
    printf(" Port  Type    Admin State  Fault   Oper State  Frames In  Frames Dropped\n");
    printf(" ────  ──────  ───────────  ──────  ──────────  ─────────  ──────────────\n");

    for (uint8_t port_id = 1; port_id <= MAX_PORT_NUM; port_id++)
    {
        udp_message_t udp_request = {0};
        udp_request.msg_type = MSG_GET_PORT_INFO;
        udp_request.status = STATUS_REQUEST;

        // Fill in which port we're asking about
        udp_port_cmd_request_t *port_req = (udp_port_cmd_request_t *) udp_request.payload;
        port_req->port_id = port_id;

        udp_message_t udp_response = {0};
        if (!send_and_receive(&udp_request, &udp_response, PORT_MANAGER_UDP) || udp_response.status != STATUS_SUCCESS)
        {
            printf("  %d    ??      ??        ??        ??      ??         ??\n", port_id);
            continue;
        }

        // The response payload contains the full port_t struct
        port_t *port = (port_t *) udp_response.payload;
        printf("  %d    %-6s  %-11s  %-6s  %-10s  %9u  %9u\n",
               port->id,
               (port->type == LINE_PORT) ? "line" : "client",
               (port->admin_enabled) ? "enabled" : "disabled",
               (port->fault_active) ? "yes" : "no",
               (port->operational_state == PORT_UP) ? "UP" : "DOWN",
               port->rx_frames,
               port->dropped_frames);
    }
    printf("\n");
}

/**
 * show connections — Query Connection Manager for the connection table.
 *
 */
void cmd_show_connections(void)
{
    udp_message_t udp_request = {0};
    udp_request.msg_type = MSG_GET_CONNECTIONS;
    udp_request.status = STATUS_REQUEST;

    udp_message_t udp_response = {0};
    if (!send_and_receive(&udp_request, &udp_response, CONN_MANAGER_UDP))
    {
        printf("[ERROR] Failed to get connections from Connection Manager\n");
        return;
    }

    if (udp_response.status != STATUS_SUCCESS)
    {
        printf("[ERROR] Connection Manager returned failure status\n");
        return;
    }

    udp_get_connections_reply_t *rsp_payload = (udp_get_connections_reply_t *)udp_response.payload;

    if (rsp_payload->conn_count == 0)
    {
        printf("No connections available to display\n");
        return;
    }

    printf("\n");
    printf(" Name     Client  Line  Operational state\n");
    printf(" ───────  ──────  ────  ──────────────────\n");

    uint8_t count = rsp_payload->conn_count;
    for (int i = 0; i < count; i++)
    {
        conn_t *conn = &rsp_payload->all_connections[i];
        printf(" %-7s  %6d  %4d  %-5s\n",
               conn->conn_name,
               conn->client_port,
               conn->line_port,
               (conn->operational_state == CONN_UP) ? "UP" : "DOWN");
    }
    printf("\n");
}

/**
 * show traffic-stats — Query Traffic Manager for traffic counters.
 *
 */
void cmd_show_traffic_stats(void)
{
    udp_message_t req = {0};
    req.msg_type = MSG_GET_TRAFFIC_STATS;
    req.status = STATUS_REQUEST;

    udp_message_t resp = {0};
    if (!send_and_receive(&req, &resp, TRAFFIC_MGR_UDP) || resp.status != STATUS_SUCCESS)
    {
        printf("[ERROR] Failed to get traffic stats\n");
        return;
    }

    const traffic_stats_t *s = (const traffic_stats_t *)resp.payload;
    printf("  Total frames forwarded: %u\n", s->total_forwarded);
    printf("  Total frames dropped:   %u\n", s->total_dropped);
    printf("  Traffic is %s\n", s->running ? "UP" : "DOWN");
}

/**
 * show logs [--level LEVEL] [--service SERVICE] — Read and display the shared log file.
 * If --level is given, only show lines matching that level (ERROR, WARN, INFO, DEBUG)
 * If --service is given, only show lines from that service (conn_mgr, port_mgr, traffic_mgr, cli)
 * Both filters can be combined.
 *
 * This command doesn't use sockets — it reads the log file directly.
 */
void cmd_show_logs(const char *level_filter, const char *service_filter)
{
    FILE *file = fopen(LOG_FILE_PATH, "r");
    if (!file)
    {
        fprintf(stderr, "[ERROR] Could not open log file\n");
        return;
    }

    char line[512];
    while (fgets(line, sizeof(line), file))
    {
        // Parse log line format: [timestamp] [LEVEL] [service] [file:line] message
        // Find bracket pairs for level (2nd) and service (3rd)
        
        char *bracket_pos = line;
        char *level_start = NULL;
        char *level_end = NULL;
        char *service_start = NULL;
        char *service_end = NULL;
        
        // Skip to 1st bracket pair (timestamp)
        bracket_pos = strchr(bracket_pos, '[');
        if (!bracket_pos) continue;
        bracket_pos = strchr(bracket_pos + 1, ']');
        if (!bracket_pos) continue;
        
        // 2nd bracket pair (LEVEL)
        bracket_pos = strchr(bracket_pos + 1, '[');
        if (!bracket_pos) continue;
        level_start = bracket_pos + 1;
        level_end = strchr(level_start, ']');
        if (!level_end) continue;
        
        // 3rd bracket pair (service)
        bracket_pos = strchr(level_end + 1, '[');
        if (!bracket_pos) continue;
        service_start = bracket_pos + 1;
        service_end = strchr(service_start, ']');
        if (!service_end) continue;
        
        // Extract level and service into temporary buffers
        char level[32] = {0};
        char service[64] = {0};
        
        if (level_end > level_start && level_end - level_start < (int)sizeof(level))
            strncpy(level, level_start, level_end - level_start);
        
        if (service_end > service_start && service_end - service_start < (int)sizeof(service))
            strncpy(service, service_start, service_end - service_start);
        
        // Apply filters (case-insensitive comparison)!
        bool matches = true;
        
        if (level_filter && strcasecmp(level, level_filter) != 0)
            matches = false;
        
        if (service_filter && strcasecmp(service, service_filter) != 0)
            matches = false;
        
        if (matches)
            printf("%s", line);
    }
    
    // Close file when done (avoiding the B2 bug lol)
    fclose(file);
}

/**
 * create connection <name> <port-a> <port-b>
 *
 * Accepts ports in either order — one must be a line port (1–2) and the
 * other a client port (3–6). The function figures out which is which.
 */
void cmd_create_connection(const char *name, uint8_t port_a, uint8_t port_b)
{
    if (strlen(name) == 0 || strlen(name) >= MAX_CONN_NAME_CHARACTER)
    {
        fprintf(stderr, "[ERROR] Connection name must be 1–%d characters\n",
                MAX_CONN_NAME_CHARACTER - 1);
        return;
    }

    // Determine which argument is the line port and which is the client port
    uint8_t line_port, client_port;
    bool a_is_line   = (port_a >= 1 && port_a <= 2);
    bool a_is_client = (port_a >= 3 && port_a <= 6);
    bool b_is_line   = (port_b >= 1 && port_b <= 2);
    bool b_is_client = (port_b >= 3 && port_b <= 6);

    if (a_is_line && b_is_client)
    {
        line_port   = port_a;
        client_port = port_b;
    }
    else if (a_is_client && b_is_line)
    {
        line_port   = port_b;
        client_port = port_a;
    }
    else
    {
        fprintf(stderr, "[ERROR] One port must be a line port (1–2) and the other a client port (3–6), got %d and %d\n",
                port_a, port_b);
        return;
    }

    udp_message_t udp_request = {0};
    udp_request.msg_type = MSG_CREATE_CONN;
    udp_request.status = STATUS_REQUEST;

    // Set up the udp payload to send to connection manager
    udp_create_conn_request_t *udp_payload = (udp_create_conn_request_t *)udp_request.payload;
    strncpy(udp_payload->name, name, sizeof(udp_payload->name) - 1);
    udp_payload->line_port   = line_port;
    udp_payload->client_port = client_port;

    udp_message_t udp_response = {0};
    if (!send_and_receive(&udp_request, &udp_response, CONN_MANAGER_UDP))
    {
        LOG(LOG_ERROR, "send_and_receive failed to send message to CONN_MANAGER");
        return;
    }

    if (udp_response.status == STATUS_SUCCESS)
        printf("[OK] Connection %s created: Client-%d \u2192 Line-%d\n", name, client_port, line_port);
    else
        print_cmd_error(&udp_response, "create connection", name);
}

/**
 * delete connection <name>
 *
 */
void cmd_delete_connection(const char *name)
{
    if (strlen(name) == 0 || strlen(name) >= MAX_CONN_NAME_CHARACTER)
    {
        fprintf(stderr, "[ERROR] Connection name must be 1–%d characters\n",
                MAX_CONN_NAME_CHARACTER - 1);
        return;
    }

    udp_message_t udp_request = {0};
    udp_request.msg_type = MSG_DELETE_CONN;
    udp_request.status = STATUS_REQUEST;

    udp_delete_conn_request_t *udp_payload = (udp_delete_conn_request_t *)udp_request.payload;
    strncpy(udp_payload->name, name, sizeof(udp_payload->name) - 1);

    udp_message_t udp_response = {0};
    if (!send_and_receive(&udp_request, &udp_response, CONN_MANAGER_UDP))
    {
        LOG(LOG_ERROR, "send_and_receive failed to send message to CONN_MANAGER");
        return;
    }

    if (udp_response.status == STATUS_SUCCESS)
        printf("[OK] Connection %s deleted\n", name);
    else
        print_cmd_error(&udp_response, "delete connection", name);
}

void cmd_set_port(uint8_t port_id)
{
    if (exec_port_cmd(port_id, MSG_SET_PORT, "set-port"))
        printf("[OK] Port-%d enabled\n", port_id);
    else
        printf("[ERROR] Failed to set port\n");
}

void cmd_delete_port(uint8_t port_id)
{
    if (exec_port_cmd(port_id, MSG_DELETE_PORT, "delete-port"))
        printf("[OK] Port-%d disabled\n", port_id);
    else
        printf("[ERROR] Failed to delete port\n");
}

void cmd_inject_fault(uint8_t port_id)
{
    // TODO: F2 — Inject Fault — CLI Side (/8 pts)
    // On success: print the OK message below.
    // printf("[OK] Fault injected on Port-%d (%s)\n", port_id, port_id <= 2 ? "line" : "client");
    // On failure: print the ERROR message below.
    // printf("[ERROR] Failed to inject fault\n");
    if (exec_port_cmd(port_id, MSG_INJECT_FAULT, "inject-fault"))
        printf("[OK] Port-%d disabled\n", port_id);
    else
        printf("[ERROR] Failed to delete port\n");
}

void cmd_clear_fault(uint8_t port_id)
{
    // TODO: F2 — Clear Fault — CLI Side (/8 pts)
    // On success: print the OK message below.
    // printf("[OK] Fault cleared on Port-%d (%s)\n", port_id, port_id <= 2 ? "line" : "client");
    // On failure: print the ERROR message below.
    // printf("[ERROR] Failed to clear fault\n");
    if (exec_port_cmd(port_id, MSG_CLEAR_FAULT, "clear-fault"))
        printf("[OK] Port-%d disabled\n", port_id);
    else
        printf("[ERROR] Failed to delete port\n");
}

/**
 * start traffic — Tell the Traffic Manager to begin generating frames.
 */
void cmd_start_traffic(uint8_t client_port, uint8_t line_port)
{
    udp_message_t req = {0};
    req.msg_type = MSG_START_TRAFFIC;
    req.status = STATUS_REQUEST;
    udp_start_traffic_request_t *udp_request = (udp_start_traffic_request_t *)req.payload;
    udp_request->client_port = client_port;
    udp_request->line_port = line_port;

    udp_message_t resp = {0};
    if (!send_and_receive(&req, &resp, TRAFFIC_MGR_UDP) || resp.status != STATUS_SUCCESS)
    {
        printf("[ERROR] Failed to start traffic\n");
        return;
    }
    printf("[OK] Traffic started (client=%u, line=%u)\n", client_port, line_port);
}

/**
 * stop traffic — Tell the Traffic Manager to stop generating frames.
 */
void cmd_stop_traffic(void)
{
    // TODO: F4 — Stop Traffic CLI (/2 pts)
    //
    // Send a stop-traffic request to the traffic manager.
    // Print the appropriate message based on the outcome:
    // printf("[ERROR] Failed to stop traffic\n");
    // printf("[OK] Traffic generation stopped\n");
    udp_message_t req = {0};
    req.msg_type = MSG_STOP_TRAFFIC;
    req.status = STATUS_REQUEST;

    udp_message_t resp = {0};
    if (!send_and_receive(&req, &resp, TRAFFIC_MGR_UDP) || resp.status != STATUS_SUCCESS)
    {
        printf("[ERROR] Failed to stop traffic\n");
        return;
    }
    printf("[OK] Traffic generation stopped\n");
}

void cmd_set_protection_group(void)
{
    udp_message_t req = {0};
    req.msg_type = MSG_CREATE_PROTECTION_GROUP;
    req.status = STATUS_REQUEST;

    udp_message_t resp = {0};
    if (!send_and_receive(&req, &resp, PROTECTION_MGR_UDP))
    {
        printf("[ERROR] Failed to set protection group\n");
        return;
    }

    if (resp.status == STATUS_SUCCESS)
    {
        printf("[OK] Protection group created: port-1 <-> port-2\n");
    }
    else
    {
        print_cmd_error(&resp, "set protection group", "port-1/port-2");
    }
}

/**
 * help — Print all available commands.
 */
void cmd_help(void)
{
    printf("\n");
    printf("Waveserver Mini CLI — Command Reference\n");
    printf("═══════════════════════════════════════════════════════════════\n");
    printf("\n");
    printf("  show ports                                  Show all port states and counters\n");
    printf("  show connections                            Show the connection table\n");
    printf("  show traffic-stats                          Show traffic statistics\n");
    printf("  show logs [--level LEVEL] [--service SVC]   Display the log file (optional filters)\n");
    printf("\n");
    printf("  set port <id>                               Enable a port (1–6)\n");
    printf("  delete port <id>                            Disable a port (1–6)\n");
    printf("\n");
    printf("  create connection <name> <line> <client>    Create a named connection\n");
    printf("  delete connection <name>                    Delete a connection by name\n");
    printf("\n");
    printf("  inject-fault <port-id>                      Simulate a signal loss\n");
    printf("  clear-fault <port-id>                       Clear a simulated fault\n");
    printf("\n");
    printf("  start traffic [--client <id>] [--line <id>] Start traffic for specified ports (ports that are not specified will be randomized)\n");
    printf("  stop traffic                                Stop frame generation\n");
    printf("  set protection group                        Create protection group port-1 <-> port-2\n");
    printf("\n");
    printf("  help                                        Show this help message\n");
    printf("  exit                                        Quit the CLI\n");
    printf("\n");
}

// ============================================================================
//  Command Parser
// ============================================================================

/**
 * Parse the user's input string and call the appropriate command handler.
 * Returns false if the user typed "exit" (to break the main loop).
 *
 * We use strtok() to split the input into tokens (words) and match
 * against known commands.
 */
bool parse_and_execute(char *input)
{
    // Strip trailing newline from fgets
    input[strcspn(input, "\n")] = '\0';

    // Skip empty input
    if (strlen(input) == 0)
        return true;

    // Skip leading spaces/tabs
    while (*input == ' ' || *input == '\t')
        input++;

    // Remove trailing spaces/tabs
    for (int i = strlen(input) - 1; i >= 0 && (input[i] == ' ' || input[i] == '\t'); i--)
        input[i] = '\0';

    // Tokenize: split the input into words separated by spaces
    char *tokens[8] = {0};
    int token_count = 0;
    char *tok = strtok(input, " ");
    while (tok && token_count < 8)
    {
        tokens[token_count++] = tok;
        tok = strtok(NULL, " ");
    }

    // ---- exit ----
    if (strcmp(tokens[0], "exit") == 0 || strcmp(tokens[0], "quit") == 0)
    {
        printf("Goodbye!\n");
        return false;
    }

    // ---- help ----
    if (strcmp(tokens[0], "help") == 0)
    {
        cmd_help();
        return true;
    }

    // ---- show <subcommand> ----
    if (strcmp(tokens[0], "show") == 0 && token_count >= 2)
    {
        if (strcmp(tokens[1], "ports") == 0)
        {
            cmd_show_ports();
        }
        else if (strcmp(tokens[1], "connections") == 0)
        {
            cmd_show_connections();
        }
        else if (strcmp(tokens[1], "traffic-stats") == 0)
        {
            cmd_show_traffic_stats();
        }
        else if (strcmp(tokens[1], "logs") == 0)
        {
            // Parse optional --level and --service flags (order-independent)
            const char *level = NULL;
            const char *service = NULL;
            for (int i = 2; i < token_count - 1; i++)
            {
                if (strcmp(tokens[i], "--level") == 0)
                    level = tokens[++i];
                else if (strcmp(tokens[i], "--service") == 0)
                    service = tokens[++i];
            }
            cmd_show_logs(level, service);
        }
        else
        {
            fprintf(stderr, "[ERROR] Unknown show command: %s\n", tokens[1]);
        }
        return true;
    }

    // ---- set port <id> ----
    if (strcmp(tokens[0], "set") == 0 && token_count >= 3)
    {
        if (strcmp(tokens[1], "port") == 0)
        {
            uint8_t port_id = (uint8_t)atoi(tokens[2]);
            cmd_set_port(port_id);
        }
        else if (strcmp(tokens[1], "protection") == 0 && strcmp(tokens[2], "group") == 0)
        {
            cmd_set_protection_group();
        }
        else
        {
            fprintf(stderr, "[ERROR] Unknown set command\n");
        }
        return true;
    }

    // ---- delete port <id> ----
    // ---- delete connection <name> ----
    if (strcmp(tokens[0], "delete") == 0 && token_count >= 3)
    {
        if (strcmp(tokens[1], "port") == 0)
        {
            uint8_t port_id = (uint8_t)atoi(tokens[2]);
            cmd_delete_port(port_id);
        }
        else if (strcmp(tokens[1], "connection") == 0)
        {
            cmd_delete_connection(tokens[2]);
        }
        else
        {
            fprintf(stderr, "[ERROR] Unknown delete command: %s\n", tokens[1]);
        }
        return true;
    }

    // ---- create connection <name> <line> <client> ----
    if (strcmp(tokens[0], "create") == 0 && token_count >= 5 &&
        strcmp(tokens[1], "connection") == 0)
    {
        const char *name = tokens[2];
        uint8_t port_a = (uint8_t)atoi(tokens[3]);
        uint8_t port_b = (uint8_t)atoi(tokens[4]);
        cmd_create_connection(name, port_a, port_b);
        return true;
    }

    // ---- inject-fault <port-id> ----
    if (strcmp(tokens[0], "inject-fault") == 0 && token_count >= 2)
    {
        uint8_t port_id = (uint8_t)atoi(tokens[1]);
        cmd_inject_fault(port_id);
        return true;
    }

    // ---- clear-fault <port-id> ----
    if (strcmp(tokens[0], "clear-fault") == 0 && token_count >= 2)
    {
        uint8_t port_id = (uint8_t)atoi(tokens[1]);
        cmd_clear_fault(port_id);
        return true;
    }

    // ---- start traffic [--client <id>] [--line <id>] ----
    if (strcmp(tokens[0], "start") == 0 && token_count >= 2 &&
        strcmp(tokens[1], "traffic") == 0)
    {
        uint8_t client_port = 0, line_port = 0;
        for (int i = 2; i + 1 < token_count; i += 2)
        {
            if (strcmp(tokens[i], "--client") == 0)
            {
                client_port = (uint8_t)atoi(tokens[i + 1]);
                if (client_port < 3 || client_port > 6)
                {
                    fprintf(stderr, "[ERROR] Client port must be 3–6, got %d\n", client_port);
                    return true;
                }
            }
            else if (strcmp(tokens[i], "--line") == 0)
            {
                line_port = (uint8_t)atoi(tokens[i + 1]);
                if (line_port < 1 || line_port > 2)
                {
                    fprintf(stderr, "[ERROR] Line port must be 1 or 2, got %d\n", line_port);
                    return true;
                }
            }
        }
        cmd_start_traffic(client_port, line_port);
        return true;
    }

    // ---- stop traffic ----
    if (strcmp(tokens[0], "stop") == 0 && token_count >= 2 &&
        strcmp(tokens[1], "traffic") == 0)
    {
        cmd_stop_traffic();
        return true;
    }

    fprintf(stderr, "[ERROR] Unknown command. Type 'help' for usage.\n");
    return true;
}

int main(void)
{
    log_init(SERVICE_NAME);

    // Create a UDP client socket for sending requests to other services.
    // Unlike the other services, the CLI doesn't need to bind/listen —
    // it only sends requests and waits for replies.
    cli_socket = create_udp_client();
    if (cli_socket < 0)
    {
        fprintf(stderr, "[FATAL] Failed to create socket — exiting\n");
        return 1;
    }

    // Set a 3-second receive timeout so the CLI doesn't hang forever
    // if a service isn't running. recvfrom() will return EAGAIN after 3s.
    struct timeval rx_timeout = {.tv_sec = 3, .tv_usec = 0};
    setsockopt(cli_socket, SOL_SOCKET, SO_RCVTIMEO, &rx_timeout, sizeof(rx_timeout));

    LOG(LOG_INFO, "CLI started");
    printf("\n");
    printf("╔═══════════════════════════════════════════╗\n");
    printf("║     Waveserver Mini — Management CLI      ║\n");
    printf("║     Type 'help' for available commands    ║\n");
    printf("╚═══════════════════════════════════════════╝\n");
    printf("\n");

    // ========== MAIN INPUT LOOP ==========
    // Unlike the other services which loop on recvfrom() waiting for messages,
    // the CLI loops on fgets() waiting for user keyboard input.
    char input[MAX_INPUT_LEN];
    while (true)
    {
        printf("wsmini> ");
        fflush(stdout);

        // fgets() blocks until the user types a line and presses Enter
        if (fgets(input, sizeof(input), stdin) == NULL)
        {
            printf("\n");
            break;
        }

        if (!parse_and_execute(input))
            break;
    }

    close(cli_socket);
    LOG(LOG_INFO, "CLI exited");
    return 0;
}
