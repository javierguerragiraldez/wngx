#include <math.h>

#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>

#define WASMER_WASI_ENABLED
#include "wasmer.h"

#include "utils.h"
#include "wngx_structs.h"
#include "wngx_host.h"
#include "wngx_go_host.h"
#include "gojs_values.h"
#include "ngx_http_wasm_module.h"

#define wctx_mem(wctx) ({ \
    const wasmer_memory_t *mem_ctx = wasmer_instance_context_memory(wctx, 0);\
    (mem_ctx ? wasmer_memory_data(mem_ctx) : NULL); \
})


void stub_func() {}

js_val new_Uint8Array(const js_val_slice *args) {
    if (args->n == 1) {
        unsigned int n;
        switch (args->d[0].tag) {
            case js_type_int:
                n = args->d[0].as.i;
                break;

            case js_type_float:
                n = args->d[0].as.f;
                break;

            default:
                return (js_val){ .tag = js_type_null };
        }
        struct js_uint8array *array_obj = ngx_pcalloc(ngx_cycle->pool,
                                                      sizeof(struct js_uint8array));
        if (!array_obj) return (js_val){ .tag = js_type_null };

        uint8_t *d = ngx_pcalloc(ngx_cycle->pool, n);
        if (!d) return (js_val){ .tag = js_type_null };

        *array_obj = (struct js_uint8array){ .d = d, .offset = 0, .length = n };

        return (js_val){
            .tag = js_type_obj,
            .sub_tag = js_stype_uint8array,
            .as.obj_uint8array = array_obj,
        };
    }

    return (js_val){ .tag = js_type_null };
}

static ngx_array_t *init_js_values(ngx_pool_t *pool) {
    d("init_js_values");
    ngx_array_t *js_values = ngx_array_create(pool, 10, sizeof(js_val));
    if (!js_values)
        return NULL;

    js_val *vals = ngx_array_push_n(js_values, 8);
    d("vals: %p", vals);
    vals[0] = (js_val){ .tag=js_type_float, .as.f = NAN };
    vals[1] = (js_val){ .tag=js_type_int, .as.i = 0 };
    vals[2] = (js_val){ .tag=js_type_null };
    vals[3] = (js_val){ .tag=js_type_bool, .as.i = 1 };
    vals[4] = (js_val){ .tag=js_type_bool, .as.i = 0 };
    vals[5] = (js_val){ .tag = js_type_map, .as.map = gojs_new_map( (js_kv[]){
            { gojs_str("Object"), { .tag = js_type_class, .as.constructor = NULL }},
            { gojs_str("Array"), { .tag = js_type_class, .as.constructor = NULL }},
            { gojs_str("Uint8Array"), { .tag = js_type_class, .as.constructor = new_Uint8Array }},
            { gojs_str("fs"), { .tag = js_type_map, .as.map = gojs_new_map( (js_kv[]){
                { gojs_str("constants"), { .tag = js_type_map, .as.map = gojs_new_map( (js_kv[]){
                    { gojs_str("O_WRONLY"), { .tag = js_type_int, .as.i = -1 }},
                    { gojs_str("O_RDWR"), { .tag = js_type_int, .as.i = -1 }},
                    { gojs_str("O_CREAT"), { .tag = js_type_int, .as.i = -1 }},
                    { gojs_str("O_TRUNC"), { .tag = js_type_int, .as.i = -1 }},
                    { gojs_str("O_APPEND"), { .tag = js_type_int, .as.i = -1 }},
                    { gojs_str("O_EXCL"), { .tag = js_type_int, .as.i = -1 }},
                                    null_jskv,
                })}},
                { gojs_str("writeSync"), { .tag = js_type_function, .as.func = stub_func }},
                { gojs_str("write"), { .tag = js_type_function, .as.func = stub_func }},
                        null_jskv,
            }) }},
            { gojs_str("process"), { .tag = js_type_map, .as.map = gojs_new_map( (js_kv[]){
                { gojs_str("getuid"), { .tag = js_type_function, .as.func = stub_func }},
                { gojs_str("getgid"), { .tag = js_type_function, .as.func = stub_func }},
                { gojs_str("geteuid"), { .tag = js_type_function, .as.func = stub_func }},
                { gojs_str("getegid"), { .tag = js_type_function, .as.func = stub_func }},
                { gojs_str("getgroups"), { .tag = js_type_function, .as.func = stub_func }},
                { gojs_str("pid"), { .tag = js_type_int, .as.i = -1 }},
                { gojs_str("ppid"), { .tag = js_type_int, .as.i = -1 }},
                { gojs_str("umask"), { .tag = js_type_function, .as.func = stub_func }},
                { gojs_str("cmd"), { .tag = js_type_function, .as.func = stub_func }},
                { gojs_str("chdir"), { .tag = js_type_function, .as.func = stub_func }},
                        null_jskv,
            }) }},
            null_jskv,
        }) };
    vals[6] = (js_val){ .tag = js_type_map, .as.map = gojs_new_map( (js_kv[]){
        { gojs_str("_makeFuncWrapper"), { .tag = js_type_function, .as.func = stub_func }},
    }) };
    vals[7] = (js_val){ .tag = js_type_empty, .as.i = -1 };

    d("js_values: %p", js_values);
    return js_values;
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

    ngx_uint_t valId = *(uint32_t *)(mem + sp + 8);
    if (valId >= js_values->nelts) {
        d("invalid index: %ui (nelts: %ui)", valId, js_values->nelts);
        return;
    }

    js_val *valA = &((js_val*)js_values->elts)[valId];
    gojs_s str = loadString(mem, sp+16);

    d("wngx_go_valueGet, (%d:%p).'%*s'", valId, valA, str.len, str.d);

    if (valA->tag != js_type_map) {
        d("ref value isn't a map : %d", valA->tag);
        return;
    }

    js_val *valB = gojs_map_get(valA->as.map, str);

    // TODO: get sp again

    if (!valB) {
        d("not found");
        *(uint64_t *)(mem + sp + 32) = 0; //id2ref(2, gojs_type_none);
        return;
    }

    store_value(js_values, *valB, mem + sp + 32);
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
    d("wngx_go_valueCall");
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

    js_val v = loadValue(js_values, mem + sp + 8);
    (void) v;
    gojs_s str = loadString(mem, sp+16);
    d("call .%*s", str.len, str.d);
    const js_val_slice *args = loadSliceOfValues(js_values, mem, sp + 32);
    (void) args;
}

void wngx_go_valueInvoke(const wasmer_instance_context_t *wctx, uint32_t sp) {
    (void)wctx; (void)sp;
    d("wngx_go_valueInvoke");
}

void wngx_go_valueNew(const wasmer_instance_context_t *wctx, uint32_t sp) {
    d("wngx_go_valueNew");
    wngx_instance *inst = wasmer_instance_context_data_get(wctx);
    if (!inst) return;

    uint8_t *mem = wctx_mem(wctx);
    if (!mem) return;

    ngx_array_t *js_values = inst->ctx;
//     d("inst->ctx (js_values): %p", js_values);
    if (!js_values) {
        inst->ctx = init_js_values(ngx_cycle->pool);
        js_values = inst->ctx;
    }
    if (!js_values)
        return;

    js_val v = loadValue(js_values, mem + sp + 8);
    if (v.tag != js_type_class) {
        d("not a class (.tag:%d)", v.tag);
        store_value(js_values, make_err("not class"), mem + sp + 40);
        *(uint64_t*)(mem + sp + 48) = 0;
        return;
    }
    if (!v.as.constructor) {
        d("no constructor");
        *(uint64_t*)(mem + sp + 40) = 0;
        *(uint64_t*)(mem + sp + 48) = 0;
        return;
    }

    const js_val_slice *args = loadSliceOfValues(js_values, mem, sp + 16);

    js_val result = v.as.constructor(args);

    // TODO: reload sp
    store_value(js_values, result, mem + sp + 40);
    *(uint64_t*)(mem + sp + 48) = 1;
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
    d("wngx_go_copyBytesToJS");
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

    js_val dst = loadValue(js_values, mem + sp + 8);
    if (dst.tag != js_type_obj || dst.sub_tag != js_stype_uint8array) {
        d("src is not uint8array");
        *(uint8_t*)(mem + sp + 48) = 0;
        return;
    }
    d("dst: (%p:%z:%z)", dst.as.obj_uint8array->d, dst.as.obj_uint8array->length, dst.as.obj_uint8array->offset);
    struct js_uint8array src = loadSlice(mem + sp + 16);
    d("src: (%p:%z:%z)", src.d, src.length, src.offset);
    size_t len = dst.as.obj_uint8array->length < src.length ?
                    dst.as.obj_uint8array->length : src.length;
    ngx_memcpy(dst.as.obj_uint8array->d, src.d, len);

    *(uint8_t*)(mem + sp + 48) = 1;
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
