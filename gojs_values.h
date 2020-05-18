#ifndef gojs_values_h
#define gojs_values_h

#include <stdint.h>

typedef int64_t gojs_v;

static const int nanHead = 0x7FF80000;

typedef struct {
    unsigned char *d;
    int64_t len;
} gojs_s;

#define gojs_str(s) (gojs_s){ .d = (unsigned char*)(s), .len = sizeof(s)-1 }

typedef enum gojs_type {
    gojs_type_none,
    gojs_type_object,
    gojs_type_string,
    gojs_type_symbol,
    gojs_type_function,
} gojs_type;

typedef enum js_type {
    js_type_empty,
    js_type_null,
    js_type_bool,
    js_type_float,
    js_type_int,
    js_type_map,
    js_type_function,
} js_type;

typedef struct js_map js_map;

typedef struct js_val {
    js_type tag;
    union {
        double f;
        uint64_t i;
        js_map *map;
        void (*func)();
    } as;
} js_val;

typedef struct js_kv {
    gojs_s key;
    js_val val;
} js_kv;

#define null_node  { .key={.d=NULL, .len=0}, .val={ js_type_null, { .i = 0 }}}

js_map *gojs_new_map(const js_kv data[]);
js_val *gojs_map_get(const js_map *map, const gojs_s key);
void gojs_map_set(js_map *map, const gojs_s key, const js_val val);
void gojs_map_remove(js_map *map, const gojs_s key);

#endif
