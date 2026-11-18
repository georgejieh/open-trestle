/* kvstore.c: a small in-memory key-value store with an LRU list,
 * a hash index and a line-oriented command interpreter. */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <stdbool.h>
#include <errno.h>
#include "kvstore.h"
#include "util/hash.h"

#define KV_MAX_KEY 64
#define KV_MAX_VALUE 1024
#define KV_DEFAULT_BUCKETS 128
#define KV_VERSION "1.4.2"
#define KV_MIN(a, b) ((a) < (b) ? (a) : (b))
#define KV_CHECK(expr)                                  \
    do {                                                \
        if (!(expr)) {                                  \
            fprintf(stderr, "check failed: %s\n", #expr); \
            return -1;                                  \
        }                                               \
    } while (0)

#ifdef KV_DEBUG
#define KV_TRACE(fmt, ...) fprintf(stderr, "[kv] " fmt "\n", __VA_ARGS__)
#else
#define KV_TRACE(fmt, ...) ((void)0)
#endif

typedef enum kv_status {
    KV_OK = 0,
    KV_NOT_FOUND,
    KV_TOO_LARGE,
    KV_NO_MEMORY,
    KV_BAD_COMMAND
} kv_status;

enum kv_event_kind {
    KV_EVENT_SET,
    KV_EVENT_DELETE,
    KV_EVENT_EVICT
};

typedef uint32_t (*kv_hash_fn)(const char *key, size_t length);
typedef void (*kv_listener)(enum kv_event_kind kind, const char *key, void *user);

typedef struct kv_entry {
    char key[KV_MAX_KEY];
    char *value;
    size_t value_length;
    struct kv_entry *next;
    struct kv_entry *lru_prev;
    struct kv_entry *lru_next;
} kv_entry;

struct kv_store {
    kv_entry **buckets;
    size_t bucket_count;
    size_t size;
    size_t capacity;
    kv_entry *lru_head;
    kv_entry *lru_tail;
    kv_hash_fn hash;
    kv_listener listener;
    void *listener_user;
};

typedef union kv_number {
    long as_long;
    double as_double;
} kv_number;

struct kv_command {
    const char *name;
    int min_args;
    kv_status (*run)(struct kv_store *store, int argc, char **argv, FILE *out);
};

static const size_t kv_growth_factor = 2;
static const char *const kv_status_names[] = {
    "ok", "not found", "too large", "out of memory", "bad command"
};
static unsigned long kv_operation_count;
int kv_verbose = 0;

static kv_status kv_cmd_get(struct kv_store *store, int argc, char **argv, FILE *out);
static kv_status kv_cmd_set(struct kv_store *store, int argc, char **argv, FILE *out);
static kv_status kv_cmd_del(struct kv_store *store, int argc, char **argv, FILE *out);
static kv_status kv_cmd_stats(struct kv_store *store, int argc, char **argv, FILE *out);

static const struct kv_command kv_commands[] = {
    { "get", 1, kv_cmd_get },
    { "set", 2, kv_cmd_set },
    { "del", 1, kv_cmd_del },
    { "stats", 0, kv_cmd_stats },
};

static uint32_t default_hash(const char *key, size_t length)
{
    uint32_t h = 2166136261u;
    for (size_t i = 0; i < length; i++) {
        h ^= (uint8_t)key[i];
        h *= 16777619u;
    }
    return h;
}

const char *kv_status_name(kv_status status)
{
    if ((size_t)status >= sizeof kv_status_names / sizeof kv_status_names[0]) {
        return "unknown";
    }
    return kv_status_names[status];
}

static void lru_unlink(struct kv_store *store, kv_entry *entry)
{
    if (entry->lru_prev != NULL) {
        entry->lru_prev->lru_next = entry->lru_next;
    } else {
        store->lru_head = entry->lru_next;
    }
    if (entry->lru_next != NULL) {
        entry->lru_next->lru_prev = entry->lru_prev;
    } else {
        store->lru_tail = entry->lru_prev;
    }
    entry->lru_prev = entry->lru_next = NULL;
}

static void lru_push_front(struct kv_store *store, kv_entry *entry)
{
    entry->lru_prev = NULL;
    entry->lru_next = store->lru_head;
    if (store->lru_head != NULL) {
        store->lru_head->lru_prev = entry;
    }
    store->lru_head = entry;
    if (store->lru_tail == NULL) {
        store->lru_tail = entry;
    }
}

static void lru_touch(struct kv_store *store, kv_entry *entry)
{
    lru_unlink(store, entry);
    lru_push_front(store, entry);
}

static void notify(struct kv_store *store, enum kv_event_kind kind, const char *key)
{
    if (store->listener) {
        store->listener(kind, key, store->listener_user);
    }
}

struct kv_store *kv_open(size_t capacity, kv_hash_fn hash)
{
    struct kv_store *store = calloc(1, sizeof *store);
    if (store == NULL) {
        return NULL;
    }
    store->bucket_count = KV_DEFAULT_BUCKETS;
    store->buckets = calloc(store->bucket_count, sizeof *store->buckets);
    if (store->buckets == NULL) {
        free(store);
        return NULL;
    }
    store->capacity = capacity;
    store->hash = hash != NULL ? hash : default_hash;
    KV_TRACE("opened store with %zu buckets", store->bucket_count);
    return store;
}

void kv_set_listener(struct kv_store *store, kv_listener listener, void *user)
{
    store->listener = listener;
    store->listener_user = user;
}

static size_t bucket_index(const struct kv_store *store, const char *key)
{
    return store->hash(key, strlen(key)) % store->bucket_count;
}

static kv_entry *find_entry(struct kv_store *store, const char *key)
{
    kv_entry *e = store->buckets[bucket_index(store, key)];
    while (e != NULL && strcmp(e->key, key) != 0) {
        e = e->next;
    }
    return e;
}

static kv_status grow(struct kv_store *store)
{
    size_t new_count = store->bucket_count * kv_growth_factor;
    kv_entry **fresh = calloc(new_count, sizeof *fresh);
    if (!fresh) {
        return KV_NO_MEMORY;
    }
    for (size_t i = 0; i < store->bucket_count; i++) {
        kv_entry *e = store->buckets[i];
        while (e) {
            kv_entry *next = e->next;
            size_t slot = store->hash(e->key, strlen(e->key)) % new_count;
            e->next = fresh[slot];
            fresh[slot] = e;
            e = next;
        }
    }
    free(store->buckets);
    store->buckets = fresh;
    store->bucket_count = new_count;
    return KV_OK;
}

static void entry_free(kv_entry *entry)
{
    free(entry->value);
    free(entry);
}

static void evict_oldest(struct kv_store *store)
{
    kv_entry *victim = store->lru_tail;
    if (victim == NULL) {
        return;
    }
    notify(store, KV_EVENT_EVICT, victim->key);
    kv_delete(store, victim->key);
}

kv_status kv_get(struct kv_store *store, const char *key, const char **value)
{
    kv_entry *e = find_entry(store, key);
    kv_operation_count++;
    if (e == NULL) {
        return KV_NOT_FOUND;
    }
    lru_touch(store, e);
    *value = e->value;
    return KV_OK;
}

kv_status kv_put(struct kv_store *store, const char *key, const char *value)
{
    size_t length = strlen(value);
    kv_entry *e;
    if (strlen(key) >= KV_MAX_KEY || length >= KV_MAX_VALUE) {
        return KV_TOO_LARGE;
    }
    kv_operation_count++;
    e = find_entry(store, key);
    if (e != NULL) {
        char *copy = malloc(length + 1);
        if (copy == NULL) {
            return KV_NO_MEMORY;
        }
        memcpy(copy, value, length + 1);
        free(e->value);
        e->value = copy;
        e->value_length = length;
        lru_touch(store, e);
        notify(store, KV_EVENT_SET, key);
        return KV_OK;
    }
    if (store->size >= store->bucket_count * 2 && grow(store) != KV_OK) {
        return KV_NO_MEMORY;
    }
    if (store->capacity != 0 && store->size >= store->capacity) {
        evict_oldest(store);
    }
    e = calloc(1, sizeof *e);
    if (e == NULL) {
        return KV_NO_MEMORY;
    }
    e->value = malloc(length + 1);
    if (e->value == NULL) {
        free(e);
        return KV_NO_MEMORY;
    }
    memcpy(e->value, value, length + 1);
    e->value_length = length;
    strncpy(e->key, key, KV_MAX_KEY - 1);
    size_t slot = bucket_index(store, key);
    e->next = store->buckets[slot];
    store->buckets[slot] = e;
    lru_push_front(store, e);
    store->size++;
    notify(store, KV_EVENT_SET, key);
    return KV_OK;
}

kv_status kv_delete(struct kv_store *store, const char *key)
{
    size_t slot = bucket_index(store, key);
    kv_entry **link = &store->buckets[slot];
    while (*link != NULL) {
        kv_entry *e = *link;
        if (strcmp(e->key, key) == 0) {
            *link = e->next;
            lru_unlink(store, e);
            entry_free(e);
            store->size--;
            notify(store, KV_EVENT_DELETE, key);
            return KV_OK;
        }
        link = &e->next;
    }
    return KV_NOT_FOUND;
}

size_t kv_size(const struct kv_store *store)
{
    return store->size;
}

void kv_close(struct kv_store *store)
{
    for (size_t i = 0; i < store->bucket_count; i++) {
        kv_entry *e = store->buckets[i];
        while (e != NULL) {
            kv_entry *next = e->next;
            entry_free(e);
            e = next;
        }
    }
    free(store->buckets);
    free(store);
}

static kv_status kv_cmd_get(struct kv_store *store, int argc, char **argv, FILE *out)
{
    const char *value = NULL;
    (void)argc;
    kv_status st = kv_get(store, argv[1], &value);
    if (st == KV_OK) {
        fprintf(out, "%s\n", value);
    }
    return st;
}

static kv_status kv_cmd_set(struct kv_store *store, int argc, char **argv, FILE *out)
{
    (void)argc;
    (void)out;
    return kv_put(store, argv[1], argv[2]);
}

static kv_status kv_cmd_del(struct kv_store *store, int argc, char **argv, FILE *out)
{
    (void)argc;
    (void)out;
    return kv_delete(store, argv[1]);
}

static kv_status kv_cmd_stats(struct kv_store *store, int argc, char **argv, FILE *out)
{
    (void)argc;
    (void)argv;
    fprintf(out, "entries=%zu buckets=%zu ops=%lu\n",
            kv_size(store), store->bucket_count, kv_operation_count);
    return KV_OK;
}

static int split_line(char *line, char **argv, int max_args)
{
    int argc = 0;
    char *token = strtok(line, " \t\r\n");
    while (token != NULL && argc < max_args) {
        argv[argc++] = token;
        token = strtok(NULL, " \t\r\n");
    }
    return argc;
}

kv_status kv_execute(struct kv_store *store, char *line, FILE *out)
{
    char *argv[8];
    int argc = split_line(line, argv, 8);
    if (argc == 0) {
        return KV_BAD_COMMAND;
    }
    for (size_t i = 0; i < sizeof kv_commands / sizeof kv_commands[0]; i++) {
        const struct kv_command *c = &kv_commands[i];
        if (strcmp(c->name, argv[0]) == 0) {
            if (argc - 1 < c->min_args) {
                return KV_BAD_COMMAND;
            }
            return c->run(store, argc, argv, out);
        }
    }
    return KV_BAD_COMMAND;
}

static void log_event(enum kv_event_kind kind, const char *key, void *user)
{
    FILE *log = user;
    static const char *const names[] = { "set", "delete", "evict" };
    fprintf(log, "%s %s\n", names[kind], key);
}

int main(int argc, char **argv)
{
    struct kv_store *store = kv_open(KV_MIN(1000, 4096), NULL);
    char line[KV_MAX_KEY + KV_MAX_VALUE + 16];
    KV_CHECK(store != NULL);
    if (argc > 1 && strcmp(argv[1], "-v") == 0) {
        kv_verbose = 1;
        kv_set_listener(store, log_event, stderr);
    }
    printf("kvstore %s\n", KV_VERSION);
    while (fgets(line, sizeof line, stdin) != NULL) {
        kv_status st = kv_execute(store, line, stdout);
        if (st != KV_OK) {
            fprintf(stderr, "error: %s\n", kv_status_name(st));
        }
    }
    kv_close(store);
    return EXIT_SUCCESS;
}
