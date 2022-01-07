#include "slotmap.h"
#include <stdlib.h>

const u32 _SLOTMAP_INDEX_BITS      = (sizeof(u32) * 8) / 2;
const u32 _SLOTMAP_INDEX_MASK      = ~(u32) 0 << _SLOTMAP_INDEX_BITS;
const u32 _SLOTMAP_GENERATION_MASK = ~_SLOTMAP_INDEX_MASK;

#define _slotmap_increment_generation(key) ((key) + 1)
#define _slotmap_get_generation(key)       ((key) &_SLOTMAP_GENERATION_MASK)
#define _slotmap_set_key_index(key, index) \
    (((key) &_SLOTMAP_GENERATION_MASK) | ((index) << _SLOTMAP_INDEX_BITS))
#define _slotmap_key_to_index(key)   ((key) >> _SLOTMAP_INDEX_BITS)
#define _slotmap_index_to_key(index) ((index) << _SLOTMAP_INDEX_BITS)
#define _slotmap_generations_match(lhs, rhs) \
    (_slotmap_get_generation(lhs) == _slotmap_get_generation(rhs))

inline u32 slotmap_get_array_index_from_key(u32 key)
{
    return _slotmap_key_to_index(key);
}

void slotmap_init(struct slotmap *map, u32 size)
{
    map->data      = malloc(sizeof(struct slotmap_entry) * size);
    map->slots     = malloc(sizeof(u32) * size);
    map->size      = 0;
    map->capacity  = size;
    map->free_head = 0;
    map->free_tail = (size > 0) ? size - 1 : 0;

    if (size > 0)
    {
        for (u32 i = 0; i < size; i++) map->slots[i] = _slotmap_index_to_key(i + 1);
        map->slots[size - 1] = _slotmap_index_to_key(size - 1);
    }
}
void slotmap_destroy(struct slotmap *map)
{
    free(map->data);
    free(map->slots);

    map->size      = 0;
    map->capacity  = 0;
    map->free_head = 0;
    map->free_tail = 0;
}

u32 slotmap_insert(struct slotmap *map, void *value)
{
    u32 free_slot_index = map->free_head;
    u32 free_slot       = map->slots[free_slot_index];
    map->free_head      = _slotmap_key_to_index(free_slot);

    u32 user_key = _slotmap_set_key_index(free_slot, free_slot_index);

    map->slots[free_slot_index] = _slotmap_set_key_index(free_slot, map->size);
    map->data[map->size].key    = user_key;
    map->data[map->size].value  = value;

    map->size++;

    return user_key;
}
int slotmap_remove(struct slotmap *map, u32 key)
{
    u32 key_index      = _slotmap_key_to_index(key);
    u32 key_generation = _slotmap_get_generation(key);

    if (map->size == map->capacity)
    {
        map->free_tail = key_index;
        map->free_head = key_index;
    }

    u32 slot            = map->slots[key_index];
    u32 slot_index      = _slotmap_key_to_index(slot);
    u32 slot_generation = _slotmap_get_generation(slot);

    if (key_generation != slot_generation) return 0;

    map->slots[key_index] = _slotmap_increment_generation(_slotmap_set_key_index(slot, key_index));

    struct slotmap_entry entry = map->data[map->size - 1];
    map->data[map->size - 1]   = (struct slotmap_entry) { 0, NULL };

    map->slots[_slotmap_key_to_index(entry.key)] =
      _slotmap_set_key_index(map->slots[_slotmap_key_to_index(entry.key)], slot_index);

    map->slots[map->free_tail] = _slotmap_set_key_index(map->slots[map->free_tail], key_index);
    map->free_tail             = key_index;

    map->size--;
    return 1;
}

inline void *slotmap_get(struct slotmap *map, u32 key)
{
    u32 key_index = _slotmap_key_to_index(key);

    if (_slotmap_get_generation(key) != _slotmap_get_generation(map->slots[key_index])) return NULL;

    u32 data_index = _slotmap_key_to_index(map->slots[key_index]);
    return map->data[data_index].value;
}

inline u32 slotmap_size(struct slotmap *map)
{
    return map->size;
}
inline u32 slotmap_capacity(struct slotmap *map)
{
    return map->capacity;
}

inline struct slotmap_entry *const slotmap_begin(struct slotmap *map)
{
    return map->data;
}
inline struct slotmap_entry *const slotmap_end(struct slotmap *map)
{
    return map->data + map->size;
}