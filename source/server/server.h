#pragma once

#include <pthread.h>

#include "util/containers/queue.h"

/*
Roles of the Server:
- Starts the Network Thread
- Handles all player infomation
- Handles the chat
- Tells the world/s when and what to update
- Dynamically changes what threads are used
- Updates the 'Update Graph'
- Handles all plugins
- Handles all the server commands
*/

struct packet_queue
{
    struct queue serverbound;
    struct queue clientbound;
};

void server_run();