#pragma once

#include <stdarg.h>
#include "util/types.h"

enum
{
    LOG_LEVEL_DEBUG,
    LOG_LEVEL_INFO,
    LOG_LEVEL_WARN,
    LOG_LEVEL_ERROR
};

void logger_init();
void logger_cleanup();

void logger_log_level(int level, const char *message, ...);
#define logger_log(message, ...) logger_log_level(LOG_LEVEL_INFO, message, ##__VA_ARGS__)
