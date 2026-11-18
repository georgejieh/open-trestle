#ifndef KVSTORE_H
#define KVSTORE_H

#include <stddef.h>
#include <stdio.h>
#include "kv_config.h"

#ifdef __cplusplus
extern "C" {
#endif

#define KV_API_VERSION 3
#define KV_UNUSED(x) ((void)(x))

typedef enum kv_status {
    KV_OK = 0,
    KV_NOT_FOUND,
    KV_TOO_LARGE
} kv_status;

typedef struct kv_store kv_store;
typedef void (*kv_listener)(int kind, const char *key, void *user);
typedef unsigned long kv_size_t;

struct kv_options {
    size_t capacity;
    unsigned verbose : 1;
    unsigned shared : 1;
    kv_listener on_event;
};

extern int kv_verbose;
extern const char *const kv_version;
const int KV_LIMIT = 4096;

kv_store *kv_open(size_t capacity);
void kv_close(kv_store *store);
kv_status kv_get(kv_store *store, const char *key, const char **value);
kv_status kv_put(kv_store *store, const char *key, const char *value);
static inline int kv_is_ok(kv_status st)
{
    return st == KV_OK;
}

#if defined(KV_ENABLE_STATS)
size_t kv_entry_count(const kv_store *store);
extern unsigned long kv_hits;
#else
#define kv_entry_count(s) 0
#endif

#ifdef __cplusplus
}
#endif

#endif /* KVSTORE_H */
