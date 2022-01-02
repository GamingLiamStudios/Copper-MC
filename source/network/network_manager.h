#pragma once
#include "util/types.h"
#include "network/socket.h"

void network_manager_thread();

void packet_write(u32 client_id, u8 *data, u32 size);