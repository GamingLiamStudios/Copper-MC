#pragma once

#include "util/types.h"
#include "network/socket.h"
#include "util/containers/buffer.h"
#include "packets/packets.h"

/*
Roles of the Network Manager:
- Accept new connections
    - Do all the necessary work so the server can then do it's thing
- Receive data from clients
- Send data to clients
- Handle disconnections
- Process basic packets
*/

void *network_manager_thread(void *args);