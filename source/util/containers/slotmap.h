#pragma once

#include "util/types.h"

// Slotmap implementation

struct slotmap_entry
{
    u32   key;
    void *value;
};

struct slotmap
{
    struct slotmap_entry *data;
    u32                  *slots;

    u32 size;
    u32 capacity;

    u32 free_head;
    u32 free_tail;
};

void slotmap_init(struct slotmap *map, u32 size);
void slotmap_destroy(struct slotmap *map);

u32 slotmap_insert(struct slotmap *map, void *value);
int slotmap_remove(struct slotmap *map, u32 key);

void *slotmap_get(struct slotmap *map, u32 key);

u32 slotmap_size(struct slotmap *map);
u32 slotmap_capacity(struct slotmap *map);    // TODO: Allow changing capacity

struct slotmap_entry *const slotmap_begin(struct slotmap *map);
struct slotmap_entry *const slotmap_end(struct slotmap *map);

u32 slotmap_get_array_index_from_key(u32 key);