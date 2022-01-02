#pragma once
#include "util/types.h"
#include "network/socket.h"

/*
Roles of the Network Manager:
- Accept new connections
    - Do all the necessary work so the server can then do it's thing
- Receive data from clients
- Send data to clients
- Handle disconnections
- Process basic packets
*/

struct packet
{
    i32 client_id;
    i32 packet_id;

    i32 size;
    u8 *data;
};

void *network_manager_thread(void *args);

void packet_write(u32 client_id, u8 *data, u32 size);