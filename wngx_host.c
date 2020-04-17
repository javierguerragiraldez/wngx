
#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>

#include "wasmer.h"

#include "ngx_http_wasm_module.h"
#include "wngx_host.h"
#include "utils.h"


static void wngx_log(
    const wasmer_instance_context_t* wctx,
    uint32_t level,
    uint32_t msg, uint32_t msg_len
) {
    const ngx_http_request_t *r = wasmer_instance_context_data_get(wctx);
    if (!r) return;

    ngx_http_wasm_loc_conf_t *wlcf = ngx_http_get_module_loc_conf(r, ngx_http_wasm_module);

    const wasmer_memory_t *mem_ctx = wasmer_instance_context_memory(wctx, 0);
    if (!mem_ctx) return;

    uint8_t *mem = wasmer_memory_data(mem_ctx);
    if (!mem) return;

    ngx_str_t msg_str = { .len = msg_len, .data = mem + msg };

    ngx_log_debug(level, r->connection->log, 0, "module %V: '%V'", &wlcf->wasm_path, &msg_str);
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
    char *error_str = calloc(error_len, 1);
    wasmer_last_error_message(error_str, error_len);
    return error_str;
}

void log_wasmer_error(ngx_http_request_t *r) {
    const char *w_err = dup_wasmer_error();
    r_log_debug("wasmer error: '%s'", w_err);
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
    r_log_debug("wngx_add_header %V / %V", &h->key, &h->value);
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



static wasmer_instance_t *get_or_create_wasm_instance(ngx_http_request_t *r) {
    ngx_http_wasm_loc_conf_t *wlcf = ngx_http_get_module_loc_conf(r, ngx_http_wasm_module);
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
