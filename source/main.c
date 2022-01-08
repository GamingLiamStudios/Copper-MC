#include <stdio.h>
#include <stdlib.h>
#include "util/types.h"

#include "server/server.h"
#include <curl/curl.h>
#include <openssl/crypto.h>

int main(int argv, char **argc)
{
    printf("Starting Server!\n");

    // One-time Initialization
    srand(time(NULL));
    curl_global_init(CURL_GLOBAL_ALL);
    OPENSSL_init();

    server_run();

    // Cleanup
    curl_global_cleanup();

    return 0;
}