#include "logger.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdarg.h>

#include <unistd.h>

#include <pthread.h>
#include "util/containers/queue.h"

#define LOG_LEVEL LOG_LEVEL_DEBUG

struct queue message_queue;

pthread_t       thread;
pthread_cond_t  cv;
pthread_mutex_t mutex;
int             logger_running;

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
    logger_running = 1;

    pthread_create(&thread, NULL, logger_thread, NULL);
}
void logger_cleanup()
{
    pthread_mutex_lock(&mutex);
    logger_running = 0;
    pthread_cond_signal(&cv);
    pthread_mutex_unlock(&mutex);
    pthread_join(thread, NULL);
    queue_destroy(&message_queue);
}

void logger_log_level(int level, const char *message, ...)
{
    if (LOG_LEVEL > level) return;

    // TODO: Make sure this is cross-platform
    va_list args;
    va_start(args, message);
    int msg_len = vsnprintf(NULL, 0, message, args);
    va_end(args);

    va_start(args, message);
    char *msg = malloc(msg_len + 1);
    int   i   = vsnprintf(msg, msg_len + 1, message, args);
    va_end(args);

    char *fmt;
    switch (level)
    {
    case LOG_LEVEL_DEBUG: fmt = "\x1b[0;35m[DEBUG] %s"; break;        // Purple
    case LOG_LEVEL_INFO: fmt = "\x1b[0;37m[INFO] %s"; break;          // White / Light-Gray
    case LOG_LEVEL_WARNING: fmt = "\x1b[0;33m[WARNING] %s"; break;    // Yellow
    case LOG_LEVEL_ERROR: fmt = "\x1b[0;31m[ERROR] %s"; break;        // Red
    default: fmt = "[UNKNOWN] %s"; break;
    }

    if (msg[msg_len - 1] == '\n') msg[msg_len - 1] = '\0';

    int   msg_fmt_len = snprintf(NULL, 0, fmt, msg);
    char *msg_fmt     = malloc(msg_fmt_len + 1);
    snprintf(msg_fmt, msg_fmt_len + 1, fmt, msg);
    free(msg);

    pthread_mutex_lock(&mutex);
    queue_push(&message_queue, msg_fmt);
    pthread_cond_signal(&cv);
    pthread_mutex_unlock(&mutex);
}
