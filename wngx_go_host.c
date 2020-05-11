
#include <math.h>
#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>

#include "wasmer.h"

#include "utils.h"
#include "wngx_structs.h"
#include "wngx_host.h"
#include "wngx_go_host.h"
#include "ngx_http_wasm_module.h"

#define wctx_mem(wctx) ({ \
    const wasmer_memory_t *mem_ctx = wasmer_instance_context_memory(wctx, 0);\
    (mem_ctx ? wasmer_memory_data(mem_ctx) : NULL); \
})


typedef int64_t gojs_v;

static const int nanHead = 0x7FF80000;

typedef struct {
    unsigned char *d;
    int64_t len;
} gojs_s;

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

typedef struct js_val {
    js_type tag;
    union {
        double f;
        uint64_t i;
        ngx_hash_t hash;
        void (*func)();
    } as;
} js_val;


typedef struct js_map_kv {
    ngx_str_t key;
    js_val val;
} js_map_kv;

#define null_kv  { ngx_null_string, { js_type_null, { .i = 0 }}}

static ngx_hash_t empty_hash() {
    ngx_hash_t e = { NULL, 0 };
    return e;
}


void stub_func() {}

static ngx_hash_t init_js_map(ngx_pool_t *pool, js_map_kv *data) {
    d("init_js_map");
    ngx_pool_t *temp_pool = ngx_create_pool(NGX_DEFAULT_POOL_SIZE, ngx_cycle->log);
    d("temp_pool: %p", temp_pool);
    if (!temp_pool) goto fail;

    ngx_hash_t js_map;
    ngx_hash_init_t js_map_init = {
        .hash = &js_map,
        .key = ngx_hash_key,
        .max_size = 512,
        .bucket_size = ngx_align(64, ngx_cacheline_size),
        .name = "js_map",
        .pool = pool,
        .temp_pool = temp_pool,
    };

    ngx_hash_keys_arrays_t js_map_keys = {
        .pool = pool,
        .temp_pool = temp_pool,
    };
    if (ngx_hash_keys_array_init(&js_map_keys, NGX_HASH_SMALL))
        goto fail;


    js_map_kv *kv = data;
    while (kv->key.len > 0) {
        d("inserting key %V", &kv->key);
        if (ngx_hash_add_key(&js_map_keys, &kv->key, &kv->val, NGX_HASH_READONLY_KEY) != NGX_OK)
            goto fail;
        kv++;
    }

    if (ngx_hash_init(&js_map_init, js_map_keys.keys.elts, js_map_keys.keys.nelts) != NGX_OK)
        goto fail;

    ngx_destroy_pool(temp_pool);
    d("js_map: %p/%ui", js_map.buckets, js_map.size);
    return js_map;

fail:
    d("init_js_global failed");
    ngx_destroy_pool(temp_pool);
    return empty_hash();
}

static ngx_array_t *init_js_values(ngx_pool_t *pool) {
    d("init_js_values");
    ngx_array_t *js_values = ngx_array_create(pool, 10, sizeof(js_val));
    if (!js_values)
        return NULL;

    js_val *vals = ngx_array_push_n(js_values, 8);
    d("vals: %p", vals);
    vals[0] = (js_val){ js_type_float, { .f = NAN }};
    vals[1] = (js_val){ js_type_int, { .i = 0 }};
    vals[2] = (js_val){ js_type_null, { .i = 0 }};
    vals[3] = (js_val){ js_type_bool, { .i = 1 }};
    vals[4] = (js_val){ js_type_bool, { .i = 0 }};
    vals[5] = (js_val){ .tag = js_type_map, { .hash = init_js_map(pool, (js_map_kv[]){
            { ngx_string("Object"), { js_type_int, { .i = 1 }}},
            { ngx_string("Array"), { js_type_int, { .i = 1 }}},
            { ngx_string("process"), { .tag = js_type_map, { .hash = init_js_map(pool, (js_map_kv[]){
                { ngx_string("getuid"), { js_type_function, { .func = stub_func }}},
                { ngx_string("getgid"), { js_type_function, { .func = stub_func }}},
                { ngx_string("geteuid"), { js_type_function, { .func = stub_func }}},
                { ngx_string("getegid"), { js_type_function, { .func = stub_func }}},
                { ngx_string("getgroups"), { js_type_function, { .func = stub_func }}},
                { ngx_string("pid"), { js_type_int, { .i = -1 }}},
                { ngx_string("ppid"), { js_type_int, { .i = -1 }}},
                { ngx_string("umask"), { js_type_function, { .func = stub_func }}},
                { ngx_string("cmd"), { js_type_function, { .func = stub_func }}},
                { ngx_string("chdir"), { js_type_function, { .func = stub_func }}},
                null_kv,
            }) }}},
            { ngx_string("fs"), { .tag = js_type_map, { .hash = init_js_map(pool, (js_map_kv[]){
                { ngx_string("constants"), { .tag = js_type_map, { .hash = init_js_map(pool, (js_map_kv[]){
                    { ngx_string("O_WRONLY"), { js_type_int, { .i = -1 }}},
                    { ngx_string("O_RDWR"), { js_type_int, { .i = -1 }}},
                    { ngx_string("O_CREAT"), { js_type_int, { .i = -1 }}},
                    { ngx_string("O_TRUNC"), { js_type_int, { .i = -1 }}},
                    { ngx_string("O_APPEND"), { js_type_int, { .i = -1 }}},
                    { ngx_string("O_EXCL"), { js_type_int, { .i = -1 }}},
                    null_kv,
                })}}},
                { ngx_string("writeSync"), { js_type_function, { .func = stub_func }}},
                { ngx_string("write"), { js_type_function, { .func = stub_func }}},
                null_kv,
            }) }}},
            null_kv,
        }) }};
    vals[6] = (js_val){ .tag = js_type_map, { .hash = empty_hash() }};
    vals[7] = (js_val){ js_type_empty, { .i = -1 }};

    return js_values;
}


static uint64_t id2ref(uint32_t id, gojs_type type) {
    return ((uint64_t)(nanHead | type) << 32) | id;
}


// static gojs_v loadValue(const uint8_t *mem, uint32_t offset) {
//     return *(int64_t *)(mem + offset);
// }

static gojs_s loadString(const uint8_t *mem, uint32_t offset) {
    int64_t addr = *(int64_t*)(mem + offset);
    gojs_s str = {
        .d = (uint8_t *)(mem + addr),
        .len = *(int64_t *)(mem + offset + 8),
    };
    return str;
}


static void store_value(ngx_array_t *js_values, const js_val *val, uint8_t *addr) {
    js_val *p = ngx_array_push(js_values);
    if (!p) return;

    int index = p - (js_val *)js_values->elts;
    d("store_value at index %d (%p)", index, p);
    if (index < 0 || (unsigned)index >= js_values->nelts)
        return;

    gojs_type type;

    switch(val->tag) {
        case js_type_empty:
        case js_type_null:
            type = gojs_type_none;
            break;

        case js_type_function:
            type = gojs_type_function;
            break;

        default:
            type = gojs_type_object;
            break;
    }

    *p = *val;
    *(uint64_t *)addr = id2ref(index, type);
}


void wngx_go_debug(const wasmer_instance_context_t *wctx, uint32_t value) {
    (void)wctx;
    d("go_debug: %d", value);
}

void wngx_go_resetMemoryDataView(const wasmer_instance_context_t *wctx, uint32_t sp) {
    (void)wctx; (void)sp;
    d("wngx_go_resetMemoryDataView");
}

void wngx_go_wasmExit(const wasmer_instance_context_t *wctx, uint32_t sp) {
    (void)wctx; (void)sp;
    d("wngx_go_wasmExit");
}

void wngx_go_wasmWrite(const wasmer_instance_context_t *wctx, uint32_t sp) {
    uint8_t *mem = wctx_mem(wctx);
    if (!mem) return;

    int64_t fd = *(int64_t *)(mem+sp+8);
    int64_t p = *(int64_t *)(mem+sp+16);
    int32_t n = *(int32_t *)(mem+sp+24);

    if (fd == 2) {
        /* stderr => log */
        d("go stderr: %*s", n, mem+p);
        return;
    }

    // write n bytes to file fd from buffer mem+p
    d("write %d bytes to file %d from buffer %p (%p+%d):\"%*s\"",
      n, fd, mem+p, mem, p, n, mem+p);
}

void wngx_go_nanotime1(const wasmer_instance_context_t *wctx, uint32_t sp) {
    uint8_t *mem = wctx_mem(wctx);
    if (!mem) return;

    struct timespec tp;
    if (clock_gettime(CLOCK_REALTIME, &tp) != 0) {
        d("clock_gettime: %s", strerror(errno));
    }

    uint64_t nanosecs = tp.tv_sec * 1e9 + tp.tv_nsec;
    *(uint64_t *)(mem+sp+8) = nanosecs;
    d("nanotime1: %ud (=> %T)", nanosecs, (time_t)(nanosecs/1e9));
}

void wngx_go_walltime1(const wasmer_instance_context_t *wctx, uint32_t sp) {
    uint8_t *mem = wctx_mem(wctx);
    if (!mem) return;

    struct timespec tp;
    if (clock_gettime(CLOCK_REALTIME, &tp) != 0) {
        d("clock_gettime: %s", strerror(errno));
    }

    *(uint64_t *)(mem+sp+8) = tp.tv_sec;
    *(int32_t *)(mem+sp+16) = tp.tv_nsec;
    d("walltime1: %ud(%T)/%d", tp.tv_sec, tp.tv_sec, tp.tv_nsec);
}

void wngx_go_scheduleTimeoutEvent(const wasmer_instance_context_t *wctx, uint32_t sp) {
    uint8_t *mem = wctx_mem(wctx);
    if (!mem) return;

    int64_t delay_milis = *(int64_t *)(mem+sp+8);
    (void)delay_milis;
    // create an ID, return it, after the delay, resume until it's not there,
    // presumably because clearTimeoutEvent has been called

    *(int32_t *)(mem+sp+16) = 4;  // some timer id
}

void wngx_go_clearTimeoutEvent(const wasmer_instance_context_t *wctx, uint32_t sp) {
    uint8_t *mem = wctx_mem(wctx);
    if (!mem) return;

    int id = *(int32_t *)(mem+sp+8);
    (void)id;
    // remove timer #id
}

void wngx_go_getRandomData(const wasmer_instance_context_t *wctx, uint32_t sp) {
    (void)wctx; (void)sp;
    d("wngx_go_getRandomData");
}

void wngx_go_finalizeRef(const wasmer_instance_context_t *wctx, uint32_t sp) {
    (void)wctx; (void)sp;
    d("wngx_go_finalizeRef");
}

void wngx_go_stringVal(const wasmer_instance_context_t *wctx, uint32_t sp) {
    (void)wctx; (void)sp;
    d("wngx_go_stringVal");
}

void wngx_go_valueGet(const wasmer_instance_context_t *wctx, uint32_t sp) {
    d("wngx_go_valueGet");
    wngx_instance *inst = wasmer_instance_context_data_get(wctx);
    if (!inst) return;

    uint8_t *mem = wctx_mem(wctx);
    if (!mem) return;

    ngx_array_t *js_values = inst->ctx;
    if (!js_values) {
        inst->ctx = init_js_values(ngx_cycle->pool);
        js_values = inst->ctx;
    }
    if (!js_values)
        return;

    double f = *(double *)(mem + sp + 8);
    if (!isnan(f)) {
        d("got number %g", f);
    }

    ngx_uid_t valId = *(uint32_t *)(mem + sp + 8);
    if (valId >= js_values->nelts) {
        d("invalid index: %ui (nelts: %ui)", valId, js_values->nelts);
        return;
    }

    js_val *valA = &((js_val*)js_values->elts)[valId];
    gojs_s str = loadString(mem, sp+16);

    d("wngx_go_valueGet, (%d:%p).%*s", valId, valA, str.len, str.d);

    if (valA->tag != js_type_map) {
        d("ref value isn't a map : %d", valA->tag);
        return;
    }

    ngx_uint_t key = ngx_hash_key(str.d, str.len);
    js_val *valB = ngx_hash_find(&valA->as.hash, key, str.d, str.len);

    // TODO: get sp again

    if (!valB) {
        d("not found");
        *(uint64_t *)(mem + sp + 32) = id2ref(2, gojs_type_none);
        return;
    }

    d("found %p:%d", valB, valB->tag);

    store_value(js_values, valB, mem + sp + 32);
}

void wngx_go_valueSet(const wasmer_instance_context_t *wctx, uint32_t sp) {
    (void)wctx; (void)sp;
    d("wngx_go_valueSet");
}

void wngx_go_valueDelete(const wasmer_instance_context_t *wctx, uint32_t sp) {
    (void)wctx; (void)sp;
    d("wngx_go_valueDelete");
}

void wngx_go_valueIndex(const wasmer_instance_context_t *wctx, uint32_t sp) {
    (void)wctx; (void)sp;
    d("wngx_go_valueIndex");
}

void wngx_go_valueSetIndex(const wasmer_instance_context_t *wctx, uint32_t sp) {
    (void)wctx; (void)sp;
    d("wngx_go_valueSetIndex");
}

void wngx_go_valueCall(const wasmer_instance_context_t *wctx, uint32_t sp) {
    (void)wctx; (void)sp;
    d("wngx_go_valueCall");
}

void wngx_go_valueInvoke(const wasmer_instance_context_t *wctx, uint32_t sp) {
    (void)wctx; (void)sp;
    d("wngx_go_valueInvoke");
}

void wngx_go_valueNew(const wasmer_instance_context_t *wctx, uint32_t sp) {
    (void)wctx; (void)sp;
    d("wngx_go_valueNew");
}

void wngx_go_valueLength(const wasmer_instance_context_t *wctx, uint32_t sp) {
    (void)wctx; (void)sp;
    d("wngx_go_valueLength");
}

void wngx_go_valuePrepareString(const wasmer_instance_context_t *wctx, uint32_t sp) {
    (void)wctx; (void)sp;
    d("wngx_go_valuePrepareString");
}

void wngx_go_valueLoadString(const wasmer_instance_context_t *wctx, uint32_t sp) {
    (void)wctx; (void)sp;
    d("wngx_go_valueLoadString");
}

void wngx_go_valueInstanceOf(const wasmer_instance_context_t *wctx, uint32_t sp) {
    (void)wctx; (void)sp;
    d("wngx_go_valueInstanceOf");
}

void wngx_go_copyBytesToGo(const wasmer_instance_context_t *wctx, uint32_t sp) {
    (void)wctx; (void)sp;
    d("wngx_go_copyBytesToGo");
}

void wngx_go_copyBytesToJS(const wasmer_instance_context_t *wctx, uint32_t sp) {
    (void)wctx; (void)sp;
    d("wngx_go_copyBytesToJS");
}


static const func_defs_t _go_func_defs[] = {
    {
        .func_name = LIT_BYTEARRAY("debug"),
        .func = (func_t) wngx_go_debug,
        .n_returns = 0,
        .returns = {},
        .n_params = 1,
        .params = { WASM_I32 },
    },
    {
        .func_name = LIT_BYTEARRAY("runtime.resetMemoryDataView"),
        .func = (func_t) wngx_go_resetMemoryDataView,
        .n_returns = 0,
        .returns = {},
        .n_params = 1,
        .params = { WASM_I32 },
    },
    {
        .func_name = LIT_BYTEARRAY("runtime.wasmExit"),
        .func = (func_t) wngx_go_wasmExit,
        .n_returns = 0,
        .returns = {},
        .n_params = 1,
        .params = { WASM_I32 },
    },
    {
        .func_name = LIT_BYTEARRAY("runtime.wasmWrite"),
        .func = (func_t) wngx_go_wasmWrite,
        .n_returns = 0,
        .returns = {},
        .n_params = 1,
        .params = { WASM_I32 },
    },
    {
        .func_name = LIT_BYTEARRAY("runtime.nanotime1"),
        .func = (func_t) wngx_go_nanotime1,
        .n_returns = 0,
        .returns = {},
        .n_params = 1,
        .params = { WASM_I32 },
    },
    {
        .func_name = LIT_BYTEARRAY("runtime.walltime1"),
        .func = (func_t) wngx_go_walltime1,
        .n_returns = 0,
        .returns = {},
        .n_params = 1,
        .params = { WASM_I32 },
    },
    {
        .func_name = LIT_BYTEARRAY("runtime.scheduleTimeoutEvent"),
        .func = (func_t) wngx_go_scheduleTimeoutEvent,
        .n_returns = 0,
        .returns = {},
        .n_params = 1,
        .params = { WASM_I32 },
    },
    {
        .func_name = LIT_BYTEARRAY("runtime.clearTimeoutEvent"),
        .func = (func_t) wngx_go_clearTimeoutEvent,
        .n_returns = 0,
        .returns = {},
        .n_params = 1,
        .params = { WASM_I32 },
    },
    {
        .func_name = LIT_BYTEARRAY("runtime.getRandomData"),
        .func = (func_t) wngx_go_getRandomData,
        .n_returns = 0,
        .returns = {},
        .n_params = 1,
        .params = { WASM_I32 },
    },
    {
        .func_name = LIT_BYTEARRAY("syscall/js.finalizeRef"),
        .func = (func_t) wngx_go_finalizeRef,
        .n_returns = 0,
        .returns = {},
        .n_params = 1,
        .params = { WASM_I32 },
    },
    {
        .func_name = LIT_BYTEARRAY("syscall/js.stringVal"),
        .func = (func_t) wngx_go_stringVal,
        .n_returns = 0,
        .returns = {},
        .n_params = 1,
        .params = { WASM_I32 },
    },
    {
        .func_name = LIT_BYTEARRAY("syscall/js.valueGet"),
        .func = (func_t) wngx_go_valueGet,
        .n_returns = 0,
        .returns = {},
        .n_params = 1,
        .params = { WASM_I32 },
    },
    {
        .func_name = LIT_BYTEARRAY("syscall/js.valueSet"),
        .func = (func_t) wngx_go_valueSet,
        .n_returns = 0,
        .returns = {},
        .n_params = 1,
        .params = { WASM_I32 },
    },
    {
        .func_name = LIT_BYTEARRAY("syscall/js.valueDelete"),
        .func = (func_t) wngx_go_valueDelete,
        .n_returns = 0,
        .returns = {},
        .n_params = 1,
        .params = { WASM_I32 },
    },
    {
        .func_name = LIT_BYTEARRAY("syscall/js.valueIndex"),
        .func = (func_t) wngx_go_valueIndex,
        .n_returns = 0,
        .returns = {},
        .n_params = 1,
        .params = { WASM_I32 },
    },
    {
        .func_name = LIT_BYTEARRAY("syscall/js.valueSetIndex"),
        .func = (func_t) wngx_go_valueSetIndex,
        .n_returns = 0,
        .returns = {},
        .n_params = 1,
        .params = { WASM_I32 },
    },
    {
        .func_name = LIT_BYTEARRAY("syscall/js.valueCall"),
        .func = (func_t) wngx_go_valueCall,
        .n_returns = 0,
        .returns = {},
        .n_params = 1,
        .params = { WASM_I32 },
    },
    {
        .func_name = LIT_BYTEARRAY("syscall/js.valueInvoke"),
        .func = (func_t) wngx_go_valueInvoke,
        .n_returns = 0,
        .returns = {},
        .n_params = 1,
        .params = { WASM_I32 },
    },
    {
        .func_name = LIT_BYTEARRAY("syscall/js.valueNew"),
        .func = (func_t) wngx_go_valueNew,
        .n_returns = 0,
        .returns = {},
        .n_params = 1,
        .params = { WASM_I32 },
    },
    {
        .func_name = LIT_BYTEARRAY("syscall/js.valueLength"),
        .func = (func_t) wngx_go_valueLength,
        .n_returns = 0,
        .returns = {},
        .n_params = 1,
        .params = { WASM_I32 },
    },
    {
        .func_name = LIT_BYTEARRAY("syscall/js.valuePrepareString"),
        .func = (func_t) wngx_go_valuePrepareString,
        .n_returns = 0,
        .returns = {},
        .n_params = 1,
        .params = { WASM_I32 },
    },
    {
        .func_name = LIT_BYTEARRAY("syscall/js.valueLoadString"),
        .func = (func_t) wngx_go_valueLoadString,
        .n_returns = 0,
        .returns = {},
        .n_params = 1,
        .params = { WASM_I32 },
    },
    {
        .func_name = LIT_BYTEARRAY("syscall/js.valueInstanceOf"),
        .func = (func_t) wngx_go_valueInstanceOf,
        .n_returns = 0,
        .returns = {},
        .n_params = 1,
        .params = { WASM_I32 },
    },
    {
        .func_name = LIT_BYTEARRAY("syscall/js.copyBytesToGo"),
        .func = (func_t) wngx_go_copyBytesToGo,
        .n_returns = 0,
        .returns = {},
        .n_params = 1,
        .params = { WASM_I32 },
    },
    {
        .func_name = LIT_BYTEARRAY("syscall/js.copyBytesToJS"),
        .func = (func_t) wngx_go_copyBytesToJS,
        .n_returns = 0,
        .returns = {},
        .n_params = 1,
        .params = { WASM_I32 },
    },
    { .func = NULL },
};

const func_defs_t *go_func_defs = _go_func_defs;

wasmer_result_t wngx_go_host_try_run(const wngx_instance *inst, const ngx_str_t *name) {
    (void)name;
    wasmer_value_t params[] = {
        { WASM_I32, { .I32 = 0 } },
        { WASM_I32, { .I32 = 0 } },
    };
    wasmer_value_t results[] = {};

    wasmer_result_t call_result = wasmer_instance_call(inst->w_instance, "run",
                                                       params, sizeof_array(params),
                                                       results, sizeof_array(results));
    log_wasmer_error("after run");
    return call_result;
}
