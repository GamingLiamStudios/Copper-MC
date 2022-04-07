#include <stdio.h>
#include <stdlib.h>
#include "util/types.h"

#include <locale.h>
#include <curl/curl.h>
#include <openssl/crypto.h>

#include "server/server.h"
#include "logger/logger.h"

int main(int argv, char **argc)
{
    // One-time Initialization
    setlocale(LC_ALL, "");
    srand(time(NULL));

    OPENSSL_init();
    curl_global_init(CURL_GLOBAL_ALL);
    logger_init();

    server_run();

    // Cleanup
    logger_cleanup();
    curl_global_cleanup();
    OPENSSL_cleanup();

    return 0;
}