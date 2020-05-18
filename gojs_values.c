
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

