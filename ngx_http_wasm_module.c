
/*
 * Copyright (C) Igor Sysoev
 * Copyright (C) Nginx, Inc.
 */


#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>
#include <ngx_string.h>

#include "wasmer.h"

static void *ngx_http_wasm_create_loc_conf(ngx_conf_t *cf);
static char *ngx_http_wasm_merge_loc_conf(ngx_conf_t *cf, void *parent, void *child);
static ngx_int_t ngx_http_wasm_postconf(ngx_conf_t *cf);
static ngx_int_t ngx_http_wasm_init_proc(ngx_cycle_t *cycle);


typedef struct {
    ngx_str_t  wasm_path;
    uint8_t *module_bytes;
    uint32_t module_bytes_len;
    const wasmer_module_t *wasm_module;
} ngx_http_wasm_loc_conf_t;


typedef struct {
    wasmer_instance_t *instance;
} ngx_http_wasm_ctx;



#define sizeof_array(x) (sizeof(x) / sizeof((x)[0]))
// #define sizeof_litstr(s) (sizeof_array(s) - 1)
#define LIT_BYTEARRAY(s) { .bytes = (const uint8_t*)(s), .bytes_len=sizeof(s)-1 }
// #define STR_BYTEARRAY(s) { .bytes = (const uint8_t*)(s), .bytes_len=strlen(s) }


#define r_log_debug(...) ngx_log_debug(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, __VA_ARGS__)



const char *dup_wasmer_error() {
    int error_len = wasmer_last_error_length();
    char *error_str = calloc(error_len, 1);
    wasmer_last_error_message(error_str, error_len);
    return error_str;
}

uint8_t *read_file(ngx_pool_t *pool, const char *fname, uint32_t *out_len) {
	// read .wasm file
    uint8_t *bytes = NULL;
    long len = 0;
    long readlen = 0;

	FILE *file = fopen(fname, "r");
    if (!file) goto end;

	fseek(file, 0, SEEK_END);
	len = ftell(file);
	bytes = ngx_pcalloc(pool, len);
    if (!bytes) goto end;

	fseek(file, 0, SEEK_SET);
	readlen = fread(bytes, 1, len, file);

end:
	fclose(file);
    if (out_len)
        *out_len = readlen;
    return bytes;
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

    r_log_debug("wngx_add_header: %d,%d %d,%d", key_off, key_len, val_off, val_len);

    const wasmer_memory_t *mem = wasmer_instance_context_memory(wctx, 0);
    if (!mem) return;

    uint8_t *mem_buf = wasmer_memory_data(mem);
    if (!mem_buf) return;

    r_log_debug("key: %10s", mem_buf+key_off);
    r_log_debug("val: %10s", mem_buf+val_off);

    ngx_table_elt_t *h = ngx_list_push(&r->headers_out.headers);
    if (!h) return;

    h->hash = 1;
    h->key.data = mem_buf + key_off;
    h->key.len = key_len;
    h->value.data = mem_buf + val_off;
    h->value.len = val_len;
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


wasmer_import_t imports[sizeof_array(func_defs)];

void init_imports() {
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

static ngx_command_t  ngx_http_wasm_commands[] = {
    {
        ngx_string("wasm_file"),
        NGX_HTTP_LOC_CONF | NGX_CONF_TAKE1,
        ngx_conf_set_str_slot,
        NGX_HTTP_LOC_CONF_OFFSET,
        offsetof(ngx_http_wasm_loc_conf_t, wasm_path),
        NULL,
    },
    ngx_null_command
};


static ngx_http_module_t  ngx_http_wasm_module_ctx = {
    NULL,                           /* preconfiguration */
    ngx_http_wasm_postconf,         /* postconfiguration */

    NULL,                           /* create main configuration */
    NULL,                           /* init main configuration */

    NULL,                           /* create server configuration */
    NULL,                           /* merge server configuration */

    ngx_http_wasm_create_loc_conf,  /* create location configuration */
    ngx_http_wasm_merge_loc_conf,   /* merge location configuration */
};


ngx_module_t  ngx_http_wasm_module = {
    NGX_MODULE_V1,
    &ngx_http_wasm_module_ctx,  /* module context */
    ngx_http_wasm_commands,     /* module directives */
    NGX_HTTP_MODULE,            /* module type */
    NULL,                       /* init master */
    NULL,                       /* init module */
    ngx_http_wasm_init_proc,    /* init process */
    NULL,                       /* init thread */
    NULL,                       /* exit thread */
    NULL,                       /* exit process */
    NULL,                       /* exit master */
    NGX_MODULE_V1_PADDING
};


static void *ngx_http_wasm_create_loc_conf(ngx_conf_t *cf) {
    ngx_http_wasm_loc_conf_t *conf = ngx_pcalloc(cf->pool, sizeof(ngx_http_wasm_loc_conf_t));
    if (conf == NULL) {
        return NGX_CONF_ERROR;
    }

    return conf;
}

static char *ngx_http_wasm_merge_loc_conf(ngx_conf_t *cf, void *parent, void *child) {
    (void)cf;

    ngx_http_wasm_loc_conf_t *prev = parent;
    ngx_http_wasm_loc_conf_t *conf = child;

    ngx_log_stderr(0, "prev wasm file: '%*s'", prev->wasm_path.len, prev->wasm_path.data);
    ngx_log_stderr(0, "conf wasm file: '%*s'", conf->wasm_path.len, conf->wasm_path.data);

    ngx_conf_merge_str_value(conf->wasm_path, prev->wasm_path, "");
    ngx_log_stderr(0, "mrgd wasm file: '%*s'", conf->wasm_path.len, conf->wasm_path.data);

    return NGX_CONF_OK;
}



static wasmer_instance_t *get_or_create_wasm_instance(ngx_http_request_t *r) {
    r_log_debug("get_or_create_wasm_instance");
    ngx_http_wasm_loc_conf_t *wlcf = ngx_http_get_module_loc_conf(r, ngx_http_wasm_module);
    if (wlcf->wasm_path.data == NULL) return NULL;

//     r_log_debug("no instance");

    if (wlcf->wasm_module == NULL) {
        r_log_debug("no module");
        wasmer_module_t *module;

//         {
//             struct stat fstat;
//             int rc = ngx_file_info(wlcf->wasm_path.data, &fstat);
//             if (rc != 0) {
//                 r_log_debug("can't stat wasm file: %s", strerror(errno));
//                 return NULL;
//             }
//
//             wlcf->module_bytes_len = fstat.st_size;
//             wlcf->module_bytes = ngx_pcalloc(r->pool, wlcf->module_bytes_len);
//             if (wlcf->module_bytes == NULL) return NULL;
//
//             int fd = ngx_open_file(wlcf->wasm_path.data, NGX_FILE_RDONLY, 0, 4);
//             if (fd < 0) {
//                 r_log_debug("can't open wasm file: %s", strerror(errno));
//                 return NULL;
//             }
//
//             rc = pread(fd, wlcf->module_bytes, wlcf->module_bytes_len, 0);
//             if (rc != 0) {
//                 r_log_debug("can't read wasm file: %s", strerror(errno));
//                 return NULL;
//             }
//
//             close(fd);
//             r_log_debug("bytes: %p:%d", wlcf->module_bytes, wlcf->module_bytes_len);
//         }

        wlcf->module_bytes = read_file(r->pool, (char*)wlcf->wasm_path.data, &wlcf->module_bytes_len);
        r_log_debug("read file: %p(%d)", wlcf->module_bytes, wlcf->module_bytes_len);

        wasmer_result_t compile_result = wasmer_compile(&module, wlcf->module_bytes, wlcf->module_bytes_len);
        if (compile_result != WASMER_OK) {
            const char *errstr = dup_wasmer_error();
            r_log_debug("Error loading WASM '%*s': \"%s\"",
                        wlcf->wasm_path.len, wlcf->wasm_path.data, errstr);
            free((void *)errstr);
            return NULL;
        }
        r_log_debug("compile_result: %d", compile_result);
        wlcf->wasm_module = module;
    }

    ngx_http_wasm_ctx *ctx = ngx_http_get_module_ctx(r, ngx_http_wasm_module);
    r_log_debug("got ctx: %p", ctx);
    if (ctx == NULL) {
        r_log_debug("no context");
        ctx = ngx_pcalloc(r->pool, sizeof(ngx_http_wasm_ctx));
        if (ctx == NULL) {
            r_log_debug("can't allocate ngx_http_wasm_ctx");
            return NULL;
        }

        r_log_debug("new ctx: %p", ctx);
        wasmer_instance_t *instance;

        init_imports();
        r_log_debug("init_imports done");

        wasmer_result_t instantiate_result = wasmer_module_instantiate(
            wlcf->wasm_module, &instance, imports, sizeof_array(imports));
        r_log_debug("instantiate_result: %d: %p", instantiate_result, instance);
        if (instantiate_result != WASMER_OK) {
            r_log_debug("Error instantiating WASM module");
            return NULL;
        }

        ctx->instance = instance;
        wasmer_instance_context_data_set(instance, r);
        ngx_http_set_ctx(r, ctx, ngx_http_wasm_module);
        r_log_debug("set ctx");
    }

    r_log_debug("got ctx: %p, instance: %p", ctx, ctx->instance);
    return ctx->instance;
}


static wasmer_result_t maybe_call(ngx_http_request_t *r, const char *method) {
    r_log_debug("maybe call r:%p  method:'%s'", r, method);
    wasmer_instance_t *instance = get_or_create_wasm_instance(r);
    r_log_debug("got instance %p", instance);
    if (instance == NULL) return WASMER_OK;

    wasmer_value_t params[] = {};
    wasmer_value_t results[] = {};

    wasmer_result_t rc = wasmer_instance_call(instance, method,
                                params, sizeof_array(params),
                                results, sizeof_array(results));
    r_log_debug("rc: %d", rc);

    return rc;
}



ngx_int_t ngx_http_wasm_rewrite_handler ( ngx_http_request_t* r ) {
    r_log_debug("rewrite handler");
    ngx_http_wasm_loc_conf_t  *wlcf = ngx_http_get_module_loc_conf(r, ngx_http_wasm_module);
    r_log_debug("wasm file: '%*s'", wlcf->wasm_path.len, wlcf->wasm_path.data);

    wasmer_result_t call_result = maybe_call(r, "rewrite");
    if (call_result != WASMER_OK) {
        r_log_debug("error calling 'rewrite' method");
        return NGX_ERROR;
    }

    return NGX_DECLINED;
}

ngx_int_t ngx_http_wasm_access_handler ( ngx_http_request_t* r ) {
    r_log_debug("access handler");
    ngx_http_wasm_loc_conf_t  *wlcf = ngx_http_get_module_loc_conf(r, ngx_http_wasm_module);
    r_log_debug("wasm file: '%*s'", wlcf->wasm_path.len, wlcf->wasm_path.data);

    wasmer_result_t call_result = maybe_call(r, "access");
    if (call_result != WASMER_OK) {
        r_log_debug("error calling 'access' method");
        return NGX_ERROR;
    }

    return NGX_DECLINED;
}

ngx_int_t ngx_http_wasm_content_hanlder ( ngx_http_request_t* r ) {
    r_log_debug("content handler");
    ngx_http_wasm_loc_conf_t  *wlcf = ngx_http_get_module_loc_conf(r, ngx_http_wasm_module);
    r_log_debug("wasm file: '%*s'", wlcf->wasm_path.len, wlcf->wasm_path.data);

    wasmer_result_t call_result = maybe_call(r, "content");
    if (call_result != WASMER_OK) {
        r_log_debug("error calling 'content' method");
        return NGX_ERROR;
    }

    return NGX_DECLINED;
}

ngx_int_t ngx_http_wasm_log_handler ( ngx_http_request_t* r ) {
    r_log_debug("log handler");
    ngx_http_wasm_loc_conf_t  *wlcf = ngx_http_get_module_loc_conf(r, ngx_http_wasm_module);
    r_log_debug("wasm file: '%*s'", wlcf->wasm_path.len, wlcf->wasm_path.data);

    wasmer_result_t call_result = maybe_call(r, "do_log");
    if (call_result != WASMER_OK) {
        r_log_debug("error calling 'log' method");
        return NGX_ERROR;
    }

    return NGX_DECLINED;
}


static ngx_int_t add_handler(
    ngx_http_core_main_conf_t *cmcf,
    ngx_http_phases phase,
    ngx_http_handler_pt h
) {
    ngx_http_handler_pt *new_h;
    new_h = ngx_array_push(&cmcf->phases[phase].handlers);
    if (new_h == NULL) {
        return NGX_ERROR;
    }

    *new_h = h;

    return NGX_OK;
}



static ngx_http_output_header_filter_pt ngx_http_next_header_filter;

static ngx_int_t ngx_http_wasm_header_filter(ngx_http_request_t *r) {
    r_log_debug("header filter");
    ngx_http_wasm_loc_conf_t  *wlcf = ngx_http_get_module_loc_conf(r, ngx_http_wasm_module);
    r_log_debug("wasm file: '%*s'", wlcf->wasm_path.len, wlcf->wasm_path.data);

    wasmer_result_t call_result = maybe_call(r, "header_filter");
    if (call_result != WASMER_OK) {
        r_log_debug("error calling 'header_filter' method");
        return NGX_ERROR;
    }

    return ngx_http_next_header_filter (r);
}


static ngx_http_output_body_filter_pt ngx_http_next_body_filter;

static ngx_int_t ngx_http_wasm_body_filter(ngx_http_request_t *r, ngx_chain_t *in) {
    r_log_debug("body filter");
    ngx_http_wasm_loc_conf_t *wlcf = ngx_http_get_module_loc_conf(r, ngx_http_wasm_module);
    r_log_debug("wasm file: '%*s'", wlcf->wasm_path.len, wlcf->wasm_path.data);

    wasmer_result_t call_result = maybe_call(r, "body_filter");
    if (call_result != WASMER_OK) {
        r_log_debug("error calling 'body_filter' method");
        return NGX_ERROR;
    }

    return ngx_http_next_body_filter(r, in);
}



static ngx_int_t ngx_http_wasm_postconf ( ngx_conf_t* cf ) {
    ngx_http_wasm_loc_conf_t *wlcf = ngx_http_conf_get_module_loc_conf(cf, ngx_http_wasm_module);
    if (wlcf == NULL) {
        ngx_conf_log_error(NGX_LOG_DEBUG_ALL, cf, NGX_EBADF, "no wasm conf");
        return NGX_ERROR;
    }

    ngx_log_stderr(0, "postconf (stderr)");
    ngx_log_stderr(0, "(%d) wasm file: '%*s'", getpid(), wlcf->wasm_path.len, wlcf->wasm_path.data);

    ngx_http_core_main_conf_t *cmcf = ngx_http_conf_get_module_main_conf(cf, ngx_http_core_module);

    ngx_int_t rc = add_handler(cmcf, NGX_HTTP_REWRITE_PHASE, ngx_http_wasm_rewrite_handler)
                || add_handler(cmcf, NGX_HTTP_ACCESS_PHASE, ngx_http_wasm_access_handler)
                || add_handler(cmcf, NGX_HTTP_CONTENT_PHASE, ngx_http_wasm_content_hanlder)
                || add_handler(cmcf, NGX_HTTP_LOG_PHASE, ngx_http_wasm_log_handler);

    if (rc != NGX_OK) {
        ngx_log_stderr(0, "rc %d != NGX_OK", rc);
        return rc;
    }

    ngx_http_next_header_filter = ngx_http_top_header_filter;
    ngx_http_top_header_filter = ngx_http_wasm_header_filter;

    ngx_http_next_body_filter = ngx_http_top_body_filter;
    ngx_http_top_body_filter = ngx_http_wasm_body_filter;

    ngx_log_stderr(0, "postconf'ed");

    return rc;
}

ngx_int_t ngx_http_wasm_init_proc ( ngx_cycle_t* cycle ) {
    ngx_log_debug(NGX_LOG_DEBUG, cycle->log, 0, "init proc");
    ngx_log_stderr(0, "init proc (%d > %d)", getppid(), getpid());

//     ngx_http_wasm_main_conf_t *wmcf = ngx_http_cycle_get_module_main_conf(cycle, ngx_http_wasm_module);
//     if (wmcf == NULL) {
//         return NGX_ERROR;
//     }

    return NGX_OK;
}
