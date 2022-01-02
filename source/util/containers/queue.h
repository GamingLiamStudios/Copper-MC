#pragma once

#include <pthread.h>

#include "util/types.h"

struct queue_node
{
    struct queue_node *next;
    void              *data;
};

// TODO: Look into performance
struct queue
{
    struct queue_node *head;
    struct queue_node *tail;
    pthread_spinlock_t lock;
};

void queue_init(struct queue *queue);
void queue_destroy(struct queue *queue);

void  queue_push(struct queue *queue, void *data);
void *queue_pop(struct queue *queue);
