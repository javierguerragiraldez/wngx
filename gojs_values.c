#include <math.h>

// #include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>

#define WASMER_WASI_ENABLED
#include "wasmer.h"

#include "utils.h"
// #include "wngx_structs.h"
// #include "wngx_host.h"
// #include "wngx_go_host.h"
#include "gojs_values.h"
// #include "ngx_http_wasm_module.h"

struct js_map {
    ngx_array_t a;
};

#define js_map_tombstone    (js_kv){ .key = {.d=NULL,.len=0}, .val={.tag=js_type_empty} }


static bool jsstr_eq(const gojs_s *a, const gojs_s *b) {
    if (a->len != b->len) return false;
    return ngx_memcmp(a->d, b->d, a->len) == 0;
}


js_map * gojs_new_map (const js_kv data[]) {
    ngx_pool_t *pool = ngx_cycle->pool;
    js_map *map = ngx_pcalloc(pool, sizeof(js_map));
    if (!map) goto fail;

    if (ngx_array_init(&map->a, pool, 10, sizeof(js_kv)) != NGX_OK)
        goto fail;

    if (!data) return map;

    for (const js_kv *p = data; p->key.d; p++) {
        js_kv *entry = ngx_array_push(&map->a);
        if (!entry) goto fail;

        *entry = *p;
    }

    return map;

fail:
    return NULL;
}


js_val * gojs_map_get ( const js_map* map, const gojs_s key ) {
    for (int i = map->a.nelts-1; i >= 0; i--) {
        js_kv *p = (js_kv *)map->a.elts + i;
        if (jsstr_eq(&p->key, &key))
            return &p->val;
    }
    return NULL;
}

void gojs_map_set ( js_map* map, const gojs_s key, const js_val val ) {
    for (int i = map->a.nelts-1; i >= 0; i--) {
        js_kv *p = (js_kv *)map->a.elts + i;
        if (jsstr_eq(&p->key, &key)) {
            p->val = val;
            return;
        }
    }

    js_kv *entry = ngx_array_push(&map->a);
    if (!entry) return;

    *entry = (js_kv){ .key = key, .val = val };
}

void gojs_map_remove ( js_map* map, const gojs_s key ) {
    for (int i = map->a.nelts-1; i >= 0; i--) {
        js_kv *p = (js_kv *)map->a.elts + i;
        if (jsstr_eq(&p->key, &key)) {
            *p = js_map_tombstone;
        }
    }
}






static uint64_t id2ref(uint32_t id, gojs_type type) {
    return ((uint64_t)(nanHead | type) << 32) | id;
}


gojs_s loadString(const uint8_t *mem, uint32_t offset) {
    int64_t addr = *(int64_t*)(mem + offset);
    gojs_s str = {
        .d = (uint8_t *)(mem + addr),
        .len = *(int64_t *)(mem + offset + 8),
    };
    return str;
}

js_val loadValue(const ngx_array_t *js_values, uint8_t *addr) {
    d("loadValue");
    double f = *(double *)addr;
    d("f: %f", f);
    if (f == 0.0) return (js_val){ .tag = js_type_empty };
    if (!isnan(f)) return (js_val){ .tag = js_type_float, {.f = f}};
    unsigned int id = *(uint32_t*)addr;
    d("id: %ud", id);
    if (id < js_values->nelts)
        return ((js_val*)js_values->elts)[id];
    d("out of bounds [0,%d)", js_values->nelts);
    return (js_val){.tag = js_type_empty};
}

static js_val_slice _slice;

const struct js_val_slice *loadSliceOfValues(
    const ngx_array_t *js_values,
    uint8_t *mem, ptrdiff_t offset
) {
    (void)js_values;
    unsigned array = *(uint64_t*)(mem+offset);
    unsigned len = *(uint64_t*)(mem+offset + 8);
    if (len > sizeof_array(_slice.d)) {
        d("slice too big!");
        return NULL;
    }
    d("loadSliceOfValues: %d, len: %d", array, len);
    _slice.n = len;
    for (unsigned i = 0; i < len; i++) {
        d("[%d]: %p", i, array + i + mem);
        _slice.d[i] = loadValue(js_values, mem + array + i);
    }
    return &_slice;
}

void store_value(ngx_array_t *js_values, js_val val, uint8_t *addr) {

    // all numbers are passed as f64
    if (val.tag == js_type_int) {
        *(double *)addr = (double) val.as.i;
        return;
    }

    if (val.tag == js_type_float) {
        if (isnan(val.as.f)) {
            *(uint64_t *)addr = ((uint64_t)nanHead << 32);
        } else if (val.as.f == 0) {
            *(uint64_t *)addr = ((uint64_t)nanHead << 32) | 0x01;
        } else {
            *(double *)addr = val.as.f;
        }
        return;
    }

    // everything else is a reference
    // TODO: deduplicate
    // TODO: reuse slots
    js_val *p = ngx_array_push(js_values);
    if (!p) return;

    int index = p - (js_val *)js_values->elts;
    d("store_value at index %d (%p)", index, p);
    if (index < 0 || (unsigned)index >= js_values->nelts) {
        d("must grow values");
        return;
    }

    gojs_type type;

    switch(val.tag) {
        case js_type_empty:
        case js_type_null:
            type = gojs_type_none;
            d("it's a _none");
            break;

        case js_type_function:
            type = gojs_type_function;
            d("it's a _function");
            break;

        default:
            type = gojs_type_object;
            d("it's an object");
            break;
    }

    *p = val;
    *(uint64_t *)addr = id2ref(index, type);
}

js_val make_err(const char *msg) {
    return (js_val){
        .tag = js_type_str,
        .as.str = { .d = (unsigned char*)msg, .len = strlen(msg) },
    };
}
