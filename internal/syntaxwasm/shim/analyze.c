// Analysis shim linked with the tree-sitter runtime and the grammars of one
// language family into a WASI reactor module. The host never sees
// tree-sitter pointers: it writes source and query text into memory obtained
// from ot_alloc and reads flat little-endian result buffers that it
// bounds-checks before use.
//
// Every result buffer starts with the magic word and its total length in
// bytes. A buffer stays valid until the next call into the module.
//
// Parsing, query matching and the error-region walk ask the host at regular
// intervals whether to stop, through the one import ot_host.should_stop.
// That keeps the per-file deadline cheap; the host still bounds a guest that
// stops asking.

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include <tree_sitter/api.h>

#define OT_EXPORT(name) __attribute__((export_name(name)))

#define OT_ABI_VERSION 1u
#define OT_MAGIC 0x3153544fu /* "OTS1" */

#define OT_STATUS_OK 0u
#define OT_STATUS_BAD_LANGUAGE 1u
#define OT_STATUS_NO_QUERY 2u
#define OT_STATUS_QUERY_ERROR 3u
#define OT_STATUS_QUERY_PREDICATE 4u
#define OT_STATUS_PARSE_FAILED 5u
#define OT_STATUS_QUERY_LOADED 6u
#define OT_STATUS_STOPPED 7u

#define OT_FLAG_MATCH_LIMIT 1u
#define OT_FLAG_RESULT_LIMIT 2u
#define OT_FLAG_ERROR_LIMIT 4u
#define OT_FLAG_TREE_HAS_ERROR 8u

#define OT_REGION_ERROR 0u
#define OT_REGION_MISSING 1u

// The in-progress match limit of the query cursor. Exceeding it can drop
// matches, so the host reports it as a coverage gap.
#define OT_QUERY_MATCH_LIMIT 1024u

// Nodes visited by the error-region walk between two stop checks.
#define OT_WALK_CHECK_INTERVAL 4096u

__attribute__((import_module("ot_host"), import_name("should_stop")))
uint32_t ot_host_should_stop(void);

#define OT_LANGUAGE(name, symbol) extern const TSLanguage *symbol(void);
#include "ot_languages.h"
#undef OT_LANGUAGE

static const struct {
  const char *name;
  const TSLanguage *(*load)(void);
} languages[] = {
#define OT_LANGUAGE(name, symbol) {name, symbol},
#include "ot_languages.h"
#undef OT_LANGUAGE
};

#define OT_LANGUAGE_COUNT (sizeof(languages) / sizeof(languages[0]))

static TSQuery *queries[OT_LANGUAGE_COUNT];
static TSParser *parser;
static TSQueryCursor *cursor;

// Set before the module traps on an allocation failure, so that the host can
// report a memory limit without calling into the trapped instance.
static volatile uint32_t failure_flag;

static bool stopped;

static bool should_stop(void) {
  if (!stopped && ot_host_should_stop() != 0) {
    stopped = true;
  }
  return stopped;
}

static bool parse_progress(TSParseState *state) {
  (void)state;
  return should_stop();
}

static bool query_progress(TSQueryCursorState *state) {
  (void)state;
  return should_stop();
}

typedef struct {
  const char *source;
  uint32_t length;
} Input;

static const char *read_input(void *payload, uint32_t byte_index, TSPoint position, uint32_t *bytes_read) {
  (void)position;
  const Input *input = payload;
  if (byte_index >= input->length) {
    *bytes_read = 0;
    return "";
  }
  *bytes_read = input->length - byte_index;
  return input->source + byte_index;
}

static uint8_t *out;
static size_t out_length;
static size_t out_capacity;

static void fail_out_of_memory(void) {
  failure_flag = 1;
  __builtin_trap();
}

static void *checked_malloc(size_t size) {
  void *result = malloc(size);
  if (result == NULL && size != 0) {
    fail_out_of_memory();
  }
  return result;
}

static void *checked_calloc(size_t count, size_t size) {
  void *result = calloc(count, size);
  if (result == NULL && count != 0 && size != 0) {
    fail_out_of_memory();
  }
  return result;
}

static void *checked_realloc(void *pointer, size_t size) {
  void *result = realloc(pointer, size);
  if (result == NULL && size != 0) {
    fail_out_of_memory();
  }
  return result;
}

static void reserve(size_t extra) {
  if (out_capacity - out_length >= extra) {
    return;
  }
  size_t capacity = out_capacity == 0 ? 4096 : out_capacity;
  while (capacity - out_length < extra) {
    if (capacity > SIZE_MAX / 2) {
      fail_out_of_memory();
    }
    capacity *= 2;
  }
  out = checked_realloc(out, capacity);
  out_capacity = capacity;
}

static void store_u32(size_t at, uint32_t value) {
  out[at] = (uint8_t)value;
  out[at + 1] = (uint8_t)(value >> 8);
  out[at + 2] = (uint8_t)(value >> 16);
  out[at + 3] = (uint8_t)(value >> 24);
}

static void put_u32(uint32_t value) {
  reserve(4);
  store_u32(out_length, value);
  out_length += 4;
}

static void put_bytes(const char *bytes, uint32_t length) {
  put_u32(length);
  reserve(length);
  memcpy(out + out_length, bytes, length);
  out_length += length;
}

static void begin(void) {
  out_length = 0;
  put_u32(OT_MAGIC);
  put_u32(0);
}

static uint32_t finish(void) {
  store_u32(4, (uint32_t)out_length);
  return (uint32_t)(uintptr_t)out;
}

static void ensure_runtime(void) {
  if (parser == NULL) {
    ts_set_allocator(checked_malloc, checked_calloc, checked_realloc, free);
    parser = ts_parser_new();
    cursor = ts_query_cursor_new();
    ts_query_cursor_set_match_limit(cursor, OT_QUERY_MATCH_LIMIT);
  }
}

OT_EXPORT("ot_abi_version")
uint32_t ot_abi_version(void) { return OT_ABI_VERSION; }

OT_EXPORT("ot_failure_flag_address")
uint32_t ot_failure_flag_address(void) { return (uint32_t)(uintptr_t)&failure_flag; }

OT_EXPORT("ot_alloc")
uint32_t ot_alloc(uint32_t size) {
  void *pointer = malloc(size == 0 ? 1 : size);
  return (uint32_t)(uintptr_t)pointer;
}

OT_EXPORT("ot_free")
void ot_free(uint32_t pointer) { free((void *)(uintptr_t)pointer); }

// Layout: magic, length, language count, then per language its ABI version
// and its length-prefixed name.
OT_EXPORT("ot_describe")
uint32_t ot_describe(void) {
  ensure_runtime();
  begin();
  put_u32((uint32_t)OT_LANGUAGE_COUNT);
  for (size_t i = 0; i < OT_LANGUAGE_COUNT; i++) {
    put_u32(ts_language_abi_version(languages[i].load()));
    put_bytes(languages[i].name, (uint32_t)strlen(languages[i].name));
  }
  return finish();
}

// Compiles and keeps the query for a language. Layout: magic, length,
// status, error offset, error type, pattern count, capture count, then the
// length-prefixed capture names in capture-index order.
OT_EXPORT("ot_load_query")
uint32_t ot_load_query(uint32_t language, uint32_t source, uint32_t length) {
  ensure_runtime();
  begin();
  if (language >= OT_LANGUAGE_COUNT) {
    put_u32(OT_STATUS_BAD_LANGUAGE);
    return finish();
  }
  if (queries[language] != NULL) {
    put_u32(OT_STATUS_QUERY_LOADED);
    return finish();
  }
  uint32_t error_offset = 0;
  TSQueryError error_type = TSQueryErrorNone;
  TSQuery *query = ts_query_new(languages[language].load(), (const char *)(uintptr_t)source, length, &error_offset, &error_type);
  if (query == NULL) {
    put_u32(OT_STATUS_QUERY_ERROR);
    put_u32(error_offset);
    put_u32((uint32_t)error_type);
    return finish();
  }
  uint32_t pattern_count = ts_query_pattern_count(query);
  for (uint32_t i = 0; i < pattern_count; i++) {
    uint32_t steps = 0;
    ts_query_predicates_for_pattern(query, i, &steps);
    if (steps != 0) {
      uint32_t pattern_start = ts_query_start_byte_for_pattern(query, i);
      ts_query_delete(query);
      put_u32(OT_STATUS_QUERY_PREDICATE);
      put_u32(pattern_start);
      put_u32(0);
      return finish();
    }
  }
  queries[language] = query;
  uint32_t capture_count = ts_query_capture_count(query);
  put_u32(OT_STATUS_OK);
  put_u32(0);
  put_u32(0);
  put_u32(pattern_count);
  put_u32(capture_count);
  for (uint32_t i = 0; i < capture_count; i++) {
    uint32_t name_length = 0;
    const char *name = ts_query_capture_name_for_id(query, i, &name_length);
    put_bytes(name, name_length);
  }
  return finish();
}

// Reports the outermost ERROR and MISSING nodes, descending only into
// subtrees that contain an error.
static uint32_t collect_error_regions(TSNode root, uint32_t max_regions, bool *limited) {
  uint32_t count = 0;
  uint32_t visited = 0;
  if (!ts_node_has_error(root)) {
    return 0;
  }
  TSTreeCursor walk = ts_tree_cursor_new(root);
  for (;;) {
    if (++visited % OT_WALK_CHECK_INTERVAL == 0 && should_stop()) {
      break;
    }
    TSNode node = ts_tree_cursor_current_node(&walk);
    bool error = ts_node_is_error(node);
    bool missing = ts_node_is_missing(node);
    bool descend = false;
    if (error || missing) {
      if (count == max_regions) {
        *limited = true;
        break;
      }
      put_u32(ts_node_start_byte(node));
      put_u32(ts_node_end_byte(node));
      put_u32(error ? OT_REGION_ERROR : OT_REGION_MISSING);
      count++;
    } else if (ts_node_has_error(node)) {
      descend = true;
    }
    if (descend && ts_tree_cursor_goto_first_child(&walk)) {
      continue;
    }
    bool moved = false;
    while (!moved) {
      if (ts_tree_cursor_goto_next_sibling(&walk)) {
        moved = true;
      } else if (!ts_tree_cursor_goto_parent(&walk)) {
        break;
      }
    }
    if (!moved) {
      break;
    }
  }
  ts_tree_cursor_delete(&walk);
  return count;
}

// Parses the source and runs the language's query. Layout: magic, length,
// status, flags, match count, region count, then each match as pattern
// index, capture count and (capture index, start byte, end byte) per
// capture, then each error region as start byte, end byte and kind.
OT_EXPORT("ot_analyze")
uint32_t ot_analyze(uint32_t language, uint32_t source, uint32_t length, uint32_t max_matches, uint32_t max_regions) {
  ensure_runtime();
  begin();
  if (language >= OT_LANGUAGE_COUNT) {
    put_u32(OT_STATUS_BAD_LANGUAGE);
    return finish();
  }
  TSQuery *query = queries[language];
  if (query == NULL) {
    put_u32(OT_STATUS_NO_QUERY);
    return finish();
  }
  if (!ts_parser_set_language(parser, languages[language].load())) {
    put_u32(OT_STATUS_BAD_LANGUAGE);
    return finish();
  }
  stopped = false;
  Input input = {(const char *)(uintptr_t)source, length};
  TSInput reader = {&input, read_input, TSInputEncodingUTF8, NULL};
  TSParseOptions parse_options = {NULL, parse_progress};
  TSTree *tree = ts_parser_parse_with_options(parser, NULL, reader, parse_options);
  if (tree == NULL) {
    ts_parser_reset(parser);
    put_u32(stopped ? OT_STATUS_STOPPED : OT_STATUS_PARSE_FAILED);
    return finish();
  }
  TSNode root = ts_tree_root_node(tree);
  put_u32(OT_STATUS_OK);
  size_t flags_at = out_length;
  put_u32(0);
  put_u32(0);
  put_u32(0);
  uint32_t flags = ts_node_has_error(root) ? OT_FLAG_TREE_HAS_ERROR : 0;
  uint32_t matches = 0;
  TSQueryCursorOptions query_options = {NULL, query_progress};
  ts_query_cursor_exec_with_options(cursor, query, root, &query_options);
  TSQueryMatch match;
  while (ts_query_cursor_next_match(cursor, &match)) {
    if (matches == max_matches) {
      flags |= OT_FLAG_RESULT_LIMIT;
      break;
    }
    put_u32(match.pattern_index);
    put_u32(match.capture_count);
    for (uint16_t i = 0; i < match.capture_count; i++) {
      put_u32(match.captures[i].index);
      put_u32(ts_node_start_byte(match.captures[i].node));
      put_u32(ts_node_end_byte(match.captures[i].node));
    }
    matches++;
  }
  if (ts_query_cursor_did_exceed_match_limit(cursor)) {
    flags |= OT_FLAG_MATCH_LIMIT;
  }
  bool regions_limited = false;
  uint32_t regions = collect_error_regions(root, max_regions, &regions_limited);
  if (regions_limited) {
    flags |= OT_FLAG_ERROR_LIMIT;
  }
  ts_tree_delete(tree);
  if (stopped) {
    out_length = flags_at - 4;
    put_u32(OT_STATUS_STOPPED);
    return finish();
  }
  store_u32(flags_at, flags);
  store_u32(flags_at + 4, matches);
  store_u32(flags_at + 8, regions);
  return finish();
}
