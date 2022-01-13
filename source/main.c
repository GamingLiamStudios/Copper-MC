#include <stdio.h>
#include <stdlib.h>
#include "util/types.h"

#include <curl/curl.h>
#include <openssl/crypto.h>

#include "server/server.h"
#include "logger/logger.h"

int main(int argv, char **argc)
{
    // One-time Initialization
    srand(time(NULL));
    curl_global_init(CURL_GLOBAL_ALL);
    OPENSSL_init();
    logger_init();

    logger_log("Starting Server!\n");
    server_run();

    // Cleanup
    logger_cleanup();
    curl_global_cleanup();
    OPENSSL_cleanup();

    return 0;
}