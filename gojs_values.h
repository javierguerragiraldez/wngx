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
    js_type_str,
    js_type_error,
    js_type_map,
    js_type_class,
    js_type_obj,
    js_type_function,
} js_type;

typedef enum js_subtype {
    js_stype_null,
    js_stype_uint8array,
} js_subtype;

struct js_uint8array {
    uint8_t *d;
    uint64_t offset;
    uint64_t length;
};

typedef struct js_map js_map;

typedef struct js_val_slice js_val_slice;

typedef struct js_val {
    js_type tag;
    js_subtype sub_tag;
    union {
        double f;
        uint64_t i;
        gojs_s str;
        js_map *map;
        void (*func)();
        struct js_val (*constructor)(const js_val_slice *args);
        struct js_uint8array *obj_uint8array;
    } as;
} js_val;

typedef struct js_kv {
    gojs_s key;
    js_val val;
} js_kv;

struct js_val_slice {
    int n;
    js_val d[10];
};

#define null_jskv  { .key={.d=NULL, .len=0}, .val={ js_type_null }}

js_map *gojs_new_map(const js_kv data[]);
js_val *gojs_map_get(const js_map *map, const gojs_s key);
void gojs_map_set(js_map *map, const gojs_s key, const js_val val);
void gojs_map_remove(js_map *map, const gojs_s key);

gojs_s loadString(const uint8_t *mem, uint32_t offset);
js_val loadValue(const ngx_array_t *js_values, uint8_t *addr);
const struct js_val_slice *loadSliceOfValues( const ngx_array_t *js_values,
    uint8_t *mem, ptrdiff_t offset);

void store_value(ngx_array_t *js_values, js_val val, uint8_t *addr);
js_val make_err(const char *msg);

struct js_uint8array loadSlice (uint8_t *mem);

#endif
