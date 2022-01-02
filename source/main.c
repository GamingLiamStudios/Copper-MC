#include <stdio.h>
#include "util/types.h"

#include "network/network_manager.h"
#include "util/containers/queue.h"

int main(int argv, char **argc)
{
    printf("Starting Server!\n");
    network_manager_thread();

    return 0;
}