#include "queue.h"

#include <stdlib.h>

void queue_init(struct queue *queue)
{
    queue->head       = malloc(sizeof(struct queue_node));
    queue->head->next = NULL;
    queue->tail       = queue->head;

    pthread_spin_init(&queue->lock, PTHREAD_PROCESS_PRIVATE);
}
void queue_destroy(struct queue *queue)
{
    struct queue_node *node = queue->head;
    struct queue_node *next;

    while (node)
    {
        next = node->next;
        free(node);
        node = next;
    }

    pthread_spin_destroy(&queue->lock);
}

inline void queue_push(struct queue *queue, void *data)
{
    struct queue_node *node = malloc(sizeof(struct queue_node));
    node->data              = data;
    node->next              = NULL;
    pthread_spin_lock(&queue->lock);
    queue->tail->next = node;
    queue->tail       = node;
    pthread_spin_unlock(&queue->lock);
}
inline void *queue_pop(struct queue *queue)
{
    struct queue_node *node;
    void              *data = NULL;
    pthread_spin_lock(&queue->lock);
    if (queue->head->next)
    {
        node              = queue->head->next;
        queue->head->next = node->next;
        if (queue->tail == node) queue->tail = queue->head;
        pthread_spin_unlock(&queue->lock);

        data = node->data;
        free(node);
    }
    else
        pthread_spin_unlock(&queue->lock);
    return data;
}
