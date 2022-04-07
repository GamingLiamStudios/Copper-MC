#include "logger.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdarg.h>

#include <unistd.h>
#include <unistdio.h>
#include <uniconv.h>

#include <pthread.h>
#include "util/containers/queue.h"

#define LOG_LEVEL LOG_LEVEL_DEBUG

struct queue message_queue;

pthread_t       thread;
pthread_cond_t  cv;
pthread_mutex_t mutex;
bool            logger_running;

void *logger_thread(void *args)
{
    pthread_mutex_lock(&mutex);
    while (logger_running)
    {
        pthread_cond_wait(&cv, &mutex);
        char *msg = NULL;
        do {
            msg = queue_pop(&message_queue);
            if (msg)
            {
                printf("%s\x1b[0m\n", msg);
                free(msg);
            }
        } while (msg);
    }
    pthread_mutex_unlock(&mutex);

    return NULL;
}

void logger_init()
{
    queue_init(&message_queue);
    pthread_cond_init(&cv, NULL);
    pthread_mutex_init(&mutex, NULL);
    logger_running = true;

    pthread_create(&thread, NULL, logger_thread, NULL);
}
void logger_cleanup()
{
    pthread_mutex_lock(&mutex);
    logger_running = false;
    pthread_cond_signal(&cv);
    pthread_mutex_unlock(&mutex);
    pthread_join(thread, NULL);
    queue_destroy(&message_queue);
}

void logger_log_level(int level, const char *message, ...)
{
    if (LOG_LEVEL > level) return;

    // TODO: Make sure this is cross-platform
    u8 *msg = NULL, *msg_fmt = NULL;

    va_list args;
    va_start(args, message);
    int msg_len = u8_vasprintf(&msg, message, args);
    va_end(args);

    char *fmt;
    switch (level)
    {
    case LOG_LEVEL_DEBUG: fmt = "\x1b[0;35m[DEBUG] %U"; break;    // Purple
    case LOG_LEVEL_INFO: fmt = "\x1b[0;37m[INFO] %U"; break;      // White / Light-Gray
    case LOG_LEVEL_WARN: fmt = "\x1b[0;33m[WARN] %U"; break;      // Yellow
    case LOG_LEVEL_ERROR: fmt = "\x1b[0;31m[ERROR] %U"; break;    // Red
    default: fmt = "[UNKNOWN] %U"; break;
    }

    // if (msg[msg_len - 1] == L'\n') msg[msg_len - 1] = L'\0'; // TODO: Reimplement this

    u8_asprintf(&msg_fmt, fmt, msg);
    char *msg_locale = u8_strconv_to_locale(msg_fmt);
    free(msg);
    free(msg_fmt);

    pthread_mutex_lock(&mutex);
    queue_push(&message_queue, msg_locale);
    pthread_cond_signal(&cv);
    pthread_mutex_unlock(&mutex);
}
