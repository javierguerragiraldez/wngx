
#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>

#define WASMER_WASI_ENABLED
#include "wasmer.h"

#include "utils.h"
#include "wngx_structs.h"
#include "wngx_host.h"
#include "wngx_go_host.h"
#include "ngx_http_wasm_module.h"

static wasmer_byte_array export_func_names[] = {
    LIT_BYTEARRAY("alloc"),
    LIT_BYTEARRAY("free"),
    LIT_BYTEARRAY("on_config"),
    LIT_BYTEARRAY("on_init_proc"),
    LIT_BYTEARRAY("on_request"),
    LIT_BYTEARRAY("on_req_rewrite"),
    LIT_BYTEARRAY("on_req_access"),
    LIT_BYTEARRAY("on_content"),
    LIT_BYTEARRAY("on_res_header"),
    LIT_BYTEARRAY("on_res_body"),
    LIT_BYTEARRAY("on_log"),
    LIT_BYTEARRAY("on_callback"),
};


/* misc functions */

#define current_req(wctx) ({ \
    const wngx_instance *inst = wasmer_instance_context_data_get(wctx); \
    inst ? inst->current_req : NULL; \
})

#define wstr2ngx(ws,mem)  { .data = ((ws).d + (mem)), .len = (ws).len }

inline ngx_str_t wstr2ngx_dup(wngx_str ws, uint8_t *mem, ngx_pool_t *pool) {
    void *buf = ngx_pcalloc(pool, ws.len);
    ngx_memcpy(buf, mem + ws.d, ws.len);

    return (ngx_str_t){ .data = buf, .len = ws.len };
}


/* symbols imported by WASM module */

static void wngx_log(
    const wasmer_instance_context_t* wctx,
    uint32_t level,
    uint32_t msg, uint32_t msg_len
) {
    const ngx_http_request_t *r = current_req(wctx);
    if (!r) return;

    const wasmer_memory_t *mem_ctx = wasmer_instance_context_memory(wctx, 0);
    if (!mem_ctx) return;

    uint8_t *mem = wasmer_memory_data(mem_ctx);
    if (!mem) return;

    ngx_str_t msg_str = { .len = msg_len, .data = mem + msg };
    ngx_log_debug(level, r->connection->log, 0, "module -: '%V'", &msg_str);
}

static uint32_t wngx_request_size ( const wasmer_instance_context_t* wctx ) {
    const ngx_http_request_t *r = current_req(wctx);
    if (!r) return 0;

    return request_size(r);
}

static void wngx_get_request (
    const wasmer_instance_context_t* wctx,
    uint32_t buff_off, uint32_t buff_size
) {
    const ngx_http_request_t *r = current_req(wctx);
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
//     ngx_free((void*)w_err);
}

static uint32_t wngx_get_uri(
    const wasmer_instance_context_t *wctx,
    uint32_t buf_off, uint32_t buff_sz
) {
    ngx_http_request_t *r = current_req(wctx);
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
    ngx_http_request_t *r = current_req(wctx);
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


struct subrequest_handle_data {
    ngx_http_post_subrequest_t ps;
    ngx_http_request_t *subreq;
    wngx_instance *wngx_instance;
    uint32_t ref;
    uint32_t req_off;
    uint32_t cb_off;
};

static ngx_int_t wngx_handle_post_subrequest(ngx_http_request_t *r, void *data, ngx_int_t rc) {
    d("wngx_handle_post_subrequest (%p / %d)", data, rc);
    struct subrequest_handle_data *handle_data = data;

    handle_data->wngx_instance->current_req = r;
    wasmer_result_t wrc = wngx_host_call_back(handle_data->wngx_instance, handle_data->req_off);
    if (wrc != WASMER_OK) {
        log_wasmer_error("error calling subrequest post callback");
        return NGX_ERROR;
    }

    d("wngx_handle_post_subrequest done");
    return rc;
}

static uint32_t wngx_subrequest(const wasmer_instance_context_t *wctx, uint32_t req_off) {
    struct subrequest_handle_data *handle_data = NULL;

    const wasmer_memory_t *mem = wasmer_instance_context_memory(wctx, 0);
    if (!mem) goto fail;

    uint8_t *mem_buf = wasmer_memory_data(mem);
    if (!mem_buf) goto fail;

    wngx_instance *inst = wasmer_instance_context_data_get(wctx);
    if (!inst) goto fail;

    ngx_http_request_t *r = inst->current_req;
    if (!r) goto fail;

    wngx_subrequest_params *wsr = (wngx_subrequest_params *)(mem_buf + req_off);
    ngx_str_t uri = wstr2ngx_dup(wsr->uri, mem_buf, r->pool);
    ngx_str_t args = wstr2ngx_dup(wsr->args, mem_buf, r->pool);

    handle_data = ngx_pcalloc(r->pool, sizeof(struct subrequest_handle_data));
    if (!handle_data) goto fail;

    handle_data->ps.data = handle_data;
    handle_data->ps.handler = wngx_handle_post_subrequest;
    handle_data->wngx_instance = inst;
    handle_data->req_off = req_off;
//     handle_data->cb_off = cb_off;

    ngx_int_t rc = ngx_http_subrequest(r, &uri, &args,
                                       &handle_data->subreq, &handle_data->ps,
                                       NGX_HTTP_SUBREQUEST_IN_MEMORY);
    if (rc != NGX_OK) goto fail;

    handle_data->ref = registry_add(&inst->registry, handle_data->subreq);
    if (!handle_data->ref) goto fail;

    wsr->ref = handle_data->ref;
    return handle_data->ref;

fail:
    if (handle_data && handle_data->ref)
        registry_delete(&inst->registry, handle_data->ref);
    if (handle_data)
        ngx_free(handle_data);
    return 0;
}

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
    },
    {
        /* promise *wngx_subrequest(request *r); */
        .func_name = LIT_BYTEARRAY("wngx_subrequest"),
        .func = (func_t) wngx_subrequest,
        .n_returns = 1,
        .returns = { WASM_I32 },
        .n_params = 1,
        .params = { WASM_I32 },
    },
    { .func = NULL },
};


static size_t count_defs(const func_defs_t *defs) {
    const func_defs_t *p = defs;
    while (p->func) {
        p++;
    }
    return p - defs;
}

static size_t add_imports(wasmer_import_t *imps, size_t n, wasmer_byte_array modname, const func_defs_t *defs) {
    d("add_imports: (imps: %p, n: %d, modname: '%*s', defs: %p)",
        imps, n, modname.bytes_len, modname.bytes, defs);
    wasmer_import_t *p = imps + n;
    const func_defs_t *fd = defs;

    while(fd->func) {
        wasmer_import_t imp = {
            .module_name = modname,
            .import_name = fd->func_name,
            .tag = WASM_FUNCTION,
            .value.func = wasmer_import_func_new(fd->func,
                                                 fd->params, fd->n_params,
                                                 fd->returns, fd->n_returns),
        };
        *p = imp;
        p++; fd++;
    }
    return p - imps;
}

static wasmer_import_object_t *init_imports() {
    d("init_imports");
    size_t num_imports = count_defs(func_defs) + count_defs(go_func_defs);
    d("num_imports: %d", num_imports);
//     if (n_imps) *n_imps = num_imports;

    wasmer_import_t *p = ngx_calloc(sizeof(wasmer_import_t) * num_imports, ngx_cycle->log);
    if (!p) {
        ngx_log_error(NGX_LOG_ERR, ngx_cycle->log, 0, "can't allocate imports table");
        return NULL;
    }

    wasmer_byte_array env_modname = LIT_BYTEARRAY("env");
    size_t n = add_imports(p, 0, env_modname, func_defs);
    d("n: %d", n);

    wasmer_byte_array go_modname = LIT_BYTEARRAY("go");
    n = add_imports(p, n, go_modname, go_func_defs);
    d("n: %d", n);

    wasmer_import_object_t *imp_obj = wasmer_wasi_generate_import_object_for_version(
        Snapshot0, NULL, 0, NULL, 0, NULL, 0, NULL, 0);
    if (!imp_obj) {
        ngx_log_error(NGX_LOG_ERR, ngx_cycle->log, 0, "can't allocate import object");
        return NULL;
    }

    if (wasmer_import_object_extend( imp_obj, p, n) != WASMER_OK) {
        ngx_log_error(NGX_LOG_ERR, ngx_cycle->log, 0, "can't extend import object");
        return NULL;
    }

    return imp_obj;
}

/* functions used by other C files */

static const char *kindname(wasmer_import_export_kind kind) {
    return (kind == WASM_FUNCTION) ? "function" :
            (kind == WASM_GLOBAL) ? "global" :
            (kind == WASM_MEMORY) ? "memory" :
            (kind == WASM_TABLE) ? "table" : "-?-";
}

static void show_imp_exp(wasmer_module_t *mod) {
    {
        wasmer_export_descriptors_t *mod_exports;
        wasmer_export_descriptors(mod, &mod_exports);
        int i;
        for (i=0; i < wasmer_export_descriptors_len(mod_exports); i++) {
            wasmer_export_descriptor_t *exp_desc = wasmer_export_descriptors_get(mod_exports, i);
            wasmer_byte_array impname = wasmer_export_descriptor_name(exp_desc);
            d("export #%i: %*s (%s)",
              i, impname.bytes_len, impname.bytes,
              kindname(wasmer_export_descriptor_kind(exp_desc)));
        }

        wasmer_export_descriptors_destroy(mod_exports);
    }
    {
        wasmer_import_descriptors_t *mod_imports;
        wasmer_import_descriptors(mod, &mod_imports);
        unsigned int i;
        for (i=0; i < wasmer_import_descriptors_len(mod_imports); i++) {
            wasmer_import_descriptor_t *imp_desc = wasmer_import_descriptors_get(mod_imports, i);
            wasmer_byte_array impname = wasmer_import_descriptor_name(imp_desc);
            d("import #%i: %*s (%s)",
              i, impname.bytes_len, impname.bytes,
              kindname(wasmer_import_descriptor_kind(imp_desc)));
        }

        wasmer_import_descriptors_destroy(mod_imports);
    }
}

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

    show_imp_exp(mod->w_module);

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
    }

    return mod;
}

wngx_instance * wngx_host_load_instance(const wngx_module* mod) {
    static wasmer_import_object_t *imports = NULL;
//     static size_t num_imports;
    if (!imports)
        imports = init_imports();

    wngx_instance *inst = ngx_pcalloc(ngx_cycle->pool, sizeof(wngx_instance));
    if (inst == NULL) {
        ngx_log_abort(0, "can't alloc instance");
        return NULL;
    }

    if (initialize_registry(&inst->registry, ngx_cycle->pool) != NGX_OK) {
        ngx_log_abort(0, "can't inialize registry");
        return NULL;
    }

    wasmer_result_t instantiate_result = wasmer_module_import_instantiate(
        &inst->w_instance, mod->w_module, imports);
    if (instantiate_result != WASMER_OK) {
        ngx_log_abort(0, "can't create instance");
        log_wasmer_error("instantiating WASM module");
        return NULL;
    }
    wasmer_instance_context_data_set(inst->w_instance, inst);

    {
        /* record instance functions we need */
        wasmer_instance_exports(inst->w_instance, &inst->w_exports);
        wngx_export_id id;
        for (id = 0; id < __wngx_num_export_ids__; id++) {
            if (mod->export_index[id] != 0) {
                /* TODO: get a better non-index than zero */
                wasmer_export_t *exp = wasmer_exports_get(inst->w_exports, mod->export_index[id]);
                if (wasmer_export_kind(exp) == WASM_FUNCTION)
                    inst->w_funcs[id] = wasmer_export_to_func(exp);
            }
        }
    }


    return inst;
}

wasmer_result_t maybe_call(wngx_instance* inst, wngx_export_id method) {
    wasmer_value_t params[] = {};
    wasmer_value_t results[] = {};

    if (inst->current_req != NULL) {
        ngx_http_set_ctx(inst->current_req, inst, ngx_http_wasm_module);
    }

    const wasmer_export_func_t *func = inst->w_funcs[method];
    if (func == NULL)
        return WASMER_OK;       /* not having a method is not an error */
    d("func '%*s': %p",
      export_func_names[method].bytes_len, export_func_names[method].bytes, func);

    return wasmer_export_func_call(func,
                                   params, sizeof_array(params),
                                   results, sizeof_array(results));
}


wasmer_result_t wngx_host_call_back ( wngx_instance* inst, uint32_t data ) {
    d("wngx_host_call_back: %Xd", data);
    wasmer_value_t params[] = {
        { WASM_I32, { .I32 = data } },
    };
    wasmer_value_t results[1];

    if (inst->current_req != NULL) {
        ngx_http_set_ctx(inst->current_req, inst, ngx_http_wasm_module);
    }

    const wasmer_export_func_t *func = inst->w_funcs[wngx_on_callback];
    if (!func) {
        ngx_log_error(NGX_LOG_ERR, ngx_cycle->log, 0, "no 'on_callback' method");
        return WASMER_ERROR;
    }

    return wasmer_export_func_call(inst->w_funcs[wngx_on_callback],
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
