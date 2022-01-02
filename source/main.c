#include <stdio.h>
#include "util/types.h"

#include "server/server.h"

int main(int argv, char **argc)
{
    printf("Starting Server!\n");
    server_run();

    return 0;
}