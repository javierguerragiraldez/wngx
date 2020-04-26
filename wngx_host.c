
#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>

#include "wasmer.h"

#include "utils.h"
#include "wngx_host.h"
#include "ngx_http_wasm_module.h"

static wasmer_byte_array export_func_names[] = {
    LIT_BYTEARRAY("alloc"),
    LIT_BYTEARRAY("free"),
    LIT_BYTEARRAY("config"),
    LIT_BYTEARRAY("init_proc"),
    LIT_BYTEARRAY("req_init"),
    LIT_BYTEARRAY("req_rewrite"),
    LIT_BYTEARRAY("req_access"),
    LIT_BYTEARRAY("req_content"),
    LIT_BYTEARRAY("req_header_filter"),
    LIT_BYTEARRAY("req_body_filter"),
    LIT_BYTEARRAY("req_log"),
};


/* misc functions */

// #define d(...) ngx_log_debug(NGX_LOG_DEBUG_HTTP, ngx_cycle->log, 0, __VA_ARGS__)
#define d(...) ngx_log_stderr(NGX_LOG_STDERR, __VA_ARGS__)

// static void show_module_info(const wasmer_module_t *module) {
//     wasmer_export_descriptors_t *descs;
//
//     wasmer_export_descriptors(module, &descs);
//     int ndescs = wasmer_export_descriptors_len(descs);
//
//     int i;
//     for (i = 0; i < ndescs; i++) {
//         wasmer_export_descriptor_t *desc = wasmer_export_descriptors_get(descs, i);
//         wasmer_byte_array expname = wasmer_export_descriptor_name(desc);
//         wasmer_import_export_kind kind = wasmer_export_descriptor_kind(desc);
//         d("module export: %*s, kind: %s (%d)", expname.bytes_len, expname.bytes,
//             kind == WASM_FUNCTION ? "Function" :
//             kind == WASM_GLOBAL ? "Global" :
//             kind == WASM_MEMORY ? "Memory" :
//             kind == WASM_TABLE ? "Table" :
//                 "unknown", kind );
//     }
// }

// static void show_instance_info(wasmer_instance_t *instance) {
//     wasmer_exports_t *exports;
//
//     wasmer_instance_exports(instance, &exports);
//     int nexps = wasmer_exports_len(exports);
//
//     int i;
//     for (i = 0; i < nexps; i++) {
//         wasmer_export_t *exp = wasmer_exports_get(exports, i);
//         wasmer_byte_array expname = wasmer_export_name(exp);
//         wasmer_import_export_kind kind = wasmer_export_kind(exp);
//         d("instance export %*s, kind %s (%d)", expname.bytes_len, expname.bytes,
//             kind == WASM_FUNCTION ? "Function" :
//             kind == WASM_GLOBAL ? "Global" :
//             kind == WASM_MEMORY ? "Memory" :
//             kind == WASM_TABLE ? "Table" :
//                 "unknown", kind );
//     }
// }

/* symbols imported by WASM module */

static void wngx_log(
    const wasmer_instance_context_t* wctx,
    uint32_t level,
    uint32_t msg, uint32_t msg_len
) {
    const ngx_http_request_t *r = wasmer_instance_context_data_get(wctx);
    if (!r) return;

//     ngx_http_wasm_conf_t *wlcf = ngx_http_get_module_loc_conf(r, ngx_http_wasm_module);

    const wasmer_memory_t *mem_ctx = wasmer_instance_context_memory(wctx, 0);
    if (!mem_ctx) return;

    uint8_t *mem = wasmer_memory_data(mem_ctx);
    if (!mem) return;

    ngx_str_t msg_str = { .len = msg_len, .data = mem + msg };
//     ngx_log_debug(level, r->connection->log, 0, "module %V: '%V'", &wlcf->wasm_path, &msg_str);
    ngx_log_debug(level, r->connection->log, 0, "module -: '%V'", &msg_str);
}

static uint32_t wngx_request_size ( const wasmer_instance_context_t* wctx ) {
    const ngx_http_request_t *r = wasmer_instance_context_data_get(wctx);
    if (!r) return 0;

    return request_size(r);
}

static void wngx_get_request (
    const wasmer_instance_context_t* wctx,
    uint32_t buff_off, uint32_t buff_size
) {
    const ngx_http_request_t *r = wasmer_instance_context_data_get(wctx);
    if (!r) return;

    const wasmer_memory_t *mem_ctx = wasmer_instance_context_memory(wctx, 0);
    if (!mem_ctx) return;

    uint8_t *mem = wasmer_memory_data(mem_ctx);
    if (!mem) return;

    uint32_t memsize = wasmer_memory_data_length(mem_ctx);
    if (buff_off + buff_size >= memsize) return;

    pack_request(r, mem, buff_off, buff_size);
}




static const char *dup_wasmer_error() {
    int error_len = wasmer_last_error_length();
    char *error_str = ngx_pcalloc(ngx_cycle->pool, error_len);
    wasmer_last_error_message(error_str, error_len);
    return error_str;
}

void log_wasmer_error(const char *msg) {
    const char *w_err = dup_wasmer_error();
    ngx_log_error(NGX_LOG_ERR, ngx_cycle->log, 0, "%s: %s", msg, w_err);
    free((void*)w_err);
}

static uint32_t wngx_get_uri(
    const wasmer_instance_context_t *wctx,
    uint32_t buf_off, uint32_t buff_sz
) {
    ngx_http_request_t *r = wasmer_instance_context_data_get(wctx);
    if (!r) return 0;

    const wasmer_memory_t *mem = wasmer_instance_context_memory(wctx, 0);
    if (!mem) return 0;

    uint8_t *mem_buf = wasmer_memory_data(mem);
    if (!mem_buf) return 0;

    size_t len = r->uri.len < buff_sz ? r->uri.len : buff_sz;
    ngx_memcpy(mem_buf + buf_off, r->uri.data, len);

    return r->uri.len;
}

static void wngx_add_header (
    const wasmer_instance_context_t *wctx,
    uint32_t key_off, uint32_t key_len,
    uint32_t val_off, uint32_t val_len
) {
    ngx_http_request_t *r = wasmer_instance_context_data_get(wctx);
    if (!r) return;

    const wasmer_memory_t *mem = wasmer_instance_context_memory(wctx, 0);
    if (!mem) return;

    uint8_t *mem_buf = wasmer_memory_data(mem);
    if (!mem_buf) return;

    ngx_table_elt_t *h = ngx_list_push(&r->headers_out.headers);
    if (!h) return;

    h->hash = 1;
    h->key.data = mem_buf + key_off;
    h->key.len = key_len;
    h->value.data = mem_buf + val_off;
    h->value.len = val_len;
    d("wngx_add_header %V / %V", &h->key, &h->value);
}

typedef void (*func_t)(void *);
typedef struct {
    wasmer_byte_array func_name;
    func_t func;
    int n_returns;
    wasmer_value_tag returns[1];
    int n_params;
    wasmer_value_tag params[10];
} func_defs_t;

func_defs_t func_defs[] = {
    {
        .func_name = LIT_BYTEARRAY("wngx_log"),
        .func = (func_t) wngx_log,
        .n_returns = 0,
        .returns = {},
        .n_params = 3,
        .params = { WASM_I32, WASM_I32, WASM_I32 },
    },
    {
        .func_name = LIT_BYTEARRAY("wngx_request_size"),
        .func = (func_t) wngx_request_size,
        .n_returns = 1,
        .returns = { WASM_I32 },
        .n_params = 0,
        .params =  {},
    },
    {
        .func_name = LIT_BYTEARRAY("wngx_get_request"),
        .func = (func_t)wngx_get_request,
        .n_returns = 0,
        .returns = {},
        .n_params = 2,
        .params = { WASM_I32, WASM_I32 },
    },
    {
        .func_name = LIT_BYTEARRAY("wngx_get_uri"),
        .func = (func_t) wngx_get_uri,
        .n_returns = 1,
        .returns = { WASM_I32 },
        .n_params = 2,
        .params = { WASM_I32, WASM_I32 },
    },
    {
        .func_name = LIT_BYTEARRAY("wngx_add_header"),
        .func = (func_t) wngx_add_header,
        .n_returns = 0,
        .returns = {},
        .n_params = 4,
        .params = { WASM_I32, WASM_I32, WASM_I32, WASM_I32 },
    }
};


static wasmer_import_t imports[sizeof_array(func_defs)];

static void init_imports() {
    size_t i;
    for (i = 0; i < sizeof_array(func_defs); i++) {
        func_defs_t *fd = &func_defs[i];

        wasmer_import_t imp = {
            .module_name = LIT_BYTEARRAY("env"),
            .import_name = fd->func_name,
            .tag = WASM_FUNCTION,
            .value.func = wasmer_import_func_new(fd->func,
                                                 fd->params, fd->n_params,
                                                 fd->returns, fd->n_returns),
        };

        imports[i] = imp;
    }
}

/* functions used by other C files */

wngx_module * wngx_host_load_module(const ngx_str_t* path) {
    ngx_log_stderr(NGX_LOG_STDERR, "wngx_host_load_module %V", path);
    ngx_log_stderr(NGX_LOG_STDERR, "as C string: '%s'", path->data);
    wngx_module *mod = ngx_pcalloc(ngx_cycle->pool, sizeof(wngx_module));
    if (mod == NULL) {
        ngx_log_abort(0, "can't alloc module");
        return NULL;
    }

    uint32_t bytes_len;
    uint8_t *bytes = read_file(ngx_cycle->pool, (const char *)path->data, &bytes_len);
    if (bytes == NULL) {
        ngx_log_abort(0, "can't read WASM file '%V'", path);
        return NULL;
    }

    wasmer_result_t compile_result = wasmer_compile(
        &mod->w_module, bytes, bytes_len);
    if (compile_result != WASMER_OK) {
        log_wasmer_error("compiling module");
        ngx_free(bytes);
        ngx_free(mod);
        return NULL;
    }
//     show_module_info(mod->w_module);
    {
        /* record export index of the funcs we need */

        wasmer_export_descriptors_t *descs;

        wasmer_export_descriptors(mod->w_module, &descs);
        int ndescs = wasmer_export_descriptors_len(descs);
        int i;
        for (i = 0; i < ndescs; i++) {
            wasmer_export_descriptor_t *desc = wasmer_export_descriptors_get(descs, i);
            if (wasmer_export_descriptor_kind(desc) != WASM_FUNCTION) continue;

            wasmer_byte_array expname = wasmer_export_descriptor_name(desc);
            wngx_export_id id;
            for (id = 0; id < __wngx_num_export_ids__; id++) {
                if (bytearray_eq(&expname, &export_func_names[id])) {
                    mod->export_index[id] = i;
                    break;
                }
            }
        }
        wasmer_export_descriptors_destroy(descs);

//         unsigned ui;
//         for (ui = 0; ui < sizeof_array(mod->export_index); ui++)
//             d("export_index %d -> %d", ui, mod->export_index[ui]);
    }


    return mod;
}

wngx_instance * wngx_host_load_instance(const wngx_module* mod) {
    init_imports();

    wngx_instance *inst = ngx_pcalloc(ngx_cycle->pool, sizeof(wngx_instance));
    if (inst == NULL) {
        ngx_log_abort(0, "can't alloc instance");
        return NULL;
    }

    wasmer_result_t instantiate_result = wasmer_module_instantiate(
        mod->w_module, &inst->w_instance, imports, sizeof_array(imports));
    if (instantiate_result != WASMER_OK) {
        ngx_log_abort(0, "can't create instance");
        log_wasmer_error("instantiating WASM module");
        return NULL;
    }
//     show_instance_info(inst->w_instance);
    {
        /* record instance functions we need */
        wasmer_exports_t *exports;
        wasmer_instance_exports(inst->w_instance, &exports);
        wngx_export_id id;
        for (id = 0; id < __wngx_num_export_ids__; id++) {
            if (mod->export_index[id] != 0) {
                /* TODO: get a better non-index than zero */
                wasmer_export_t *exp = wasmer_exports_get(exports, mod->export_index[id]);
                if (wasmer_export_kind(exp) == WASM_FUNCTION)
                    inst->w_funcs[id] = wasmer_export_to_func(exp);
            }
        }
        wasmer_exports_destroy(exports);

//         for (id = 0; id < sizeof_array(inst->w_funcs); id++) {
//             d("func: %d -> %p", id, inst->w_funcs[id]);
//         }
    }

    return inst;
}

wasmer_result_t maybe_call(wngx_instance* inst, wngx_export_id method) {
    wasmer_value_t params[] = {};
    wasmer_value_t results[] = {};

    const wasmer_export_func_t *func = inst->w_funcs[method];
    if (inst->w_funcs[method] == NULL)
        return WASMER_ERROR;

    return wasmer_export_func_call(func,
                                   params, sizeof_array(params),
                                   results, sizeof_array(results));
}



#if 0

static wasmer_instance_t *get_or_create_wasm_instance(ngx_http_request_t *r) {
    ngx_http_wasm_conf_t *wlcf = ngx_http_get_module_loc_conf(r, ngx_http_wasm_module);
    if (wlcf->wasm_path.data == NULL) return NULL;

    if (wlcf->wasm_module == NULL) {
        wasmer_module_t *module;

        wlcf->module_bytes = read_file(r->pool, (char*)wlcf->wasm_path.data, &wlcf->module_bytes_len);

        wasmer_result_t compile_result = wasmer_compile(&module, wlcf->module_bytes, wlcf->module_bytes_len);
        if (compile_result != WASMER_OK) {
            const char *errstr = dup_wasmer_error();
            free((void *)errstr);
            return NULL;
        }
        wlcf->wasm_module = module;

        show_module_info(r, module);
    }

    ngx_http_wasm_ctx *ctx = ngx_http_get_module_ctx(r, ngx_http_wasm_module);
    if (ctx == NULL) {
        ctx = ngx_pcalloc(r->pool, sizeof(ngx_http_wasm_ctx));
        if (ctx == NULL) {
            return NULL;
        }

        wasmer_instance_t *instance;

        init_imports();

        wasmer_result_t instantiate_result = wasmer_module_instantiate(
            wlcf->wasm_module, &instance, imports, sizeof_array(imports));
        r_log_debug("instantiate_result: %d: %p", instantiate_result, instance);
        if (instantiate_result != WASMER_OK) {
            r_log_debug("Error instantiating WASM module");
            log_wasmer_error(r);
            return NULL;
        }

        ctx->instance = instance;
        wasmer_instance_context_data_set(instance, r);
        ngx_http_set_ctx(r, ctx, ngx_http_wasm_module);
    }

    return ctx->instance;
}


wasmer_result_t maybe_call(ngx_http_request_t *r, const char *method) {
    wasmer_instance_t *instance = get_or_create_wasm_instance(r);
    if (instance == NULL) return WASMER_OK;

    wasmer_value_t params[] = {};
    wasmer_value_t results[] = {};

    wasmer_result_t rc = wasmer_instance_call(instance, method,
                                params, sizeof_array(params),
                                results, sizeof_array(results));

    return rc;
}
#endif
