#pragma once

#include <stdlib.h>
#include <pthread.h>

#include "util/types.h"

struct queue_node
{
    struct queue_node *next;
    void              *data;
};

struct queue
{
    struct queue_node *head;
    pthread_spinlock_t head_lock;

    struct queue_node *tail;
    pthread_spinlock_t tail_lock;
};

void queue_init(struct queue *queue)
{
    queue->head       = malloc(sizeof(struct queue_node));
    queue->head->next = NULL;
    queue->tail       = queue->head;

    pthread_spin_init(&queue->head_lock, PTHREAD_PROCESS_PRIVATE);
    pthread_spin_init(&queue->tail_lock, PTHREAD_PROCESS_PRIVATE);
}
void queue_destroy(struct queue *queue)
{
    struct queue_node *node = queue->head;
    while (node)
    {
        struct queue_node *next = node->next;
        free(node);
        node = next;
    }
    queue->head = NULL;
    queue->tail = NULL;

    pthread_spin_destroy(&queue->head_lock);
    pthread_spin_destroy(&queue->tail_lock);
}

inline void queue_push(struct queue *queue, void *data)
{
    struct queue_node *node = malloc(sizeof(struct queue_node));
    node->data              = data;
    node->next              = NULL;
    pthread_spin_lock(&queue->tail_lock);
    queue->tail->next = node;
    queue->tail       = node;
    pthread_spin_unlock(&queue->tail_lock);
}
inline void *queue_pop(struct queue *queue)
{
    struct queue_node *node;
    void              *data = NULL;
    pthread_spin_lock(&queue->head_lock);
    if (queue->head->next)
    {
        node              = queue->head->next;
        queue->head->next = node->next;
        pthread_spin_unlock(&queue->head_lock);
        data = node->data;
        free(node);
    }
    else
        pthread_spin_unlock(&queue->head_lock);
    return data;
}
