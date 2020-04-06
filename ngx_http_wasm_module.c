
/*
 * Copyright (C) Igor Sysoev
 * Copyright (C) Nginx, Inc.
 */


#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>

static void *ngx_http_wasm_create_loc_conf(ngx_conf_t *cf);
static char *ngx_http_wasm_merge_loc_conf(ngx_conf_t *cf, void *parent, void *child);
static ngx_int_t ngx_http_wasm_postconf(ngx_conf_t *cf);
static ngx_int_t ngx_http_wasm_init_proc(ngx_cycle_t *cycle);


typedef struct {
    ngx_str_t  wasm_path;
} ngx_http_wasm_loc_conf_t;

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
    &ngx_http_wasm_module_ctx,      /* module context */
    ngx_http_wasm_commands,              /* module directives */
    NGX_HTTP_MODULE,                       /* module type */
    NULL,                                  /* init master */
    NULL,                                  /* init module */
    ngx_http_wasm_init_proc,               /* init process */
    NULL,                                  /* init thread */
    NULL,                                  /* exit thread */
    NULL,                                  /* exit process */
    NULL,                                  /* exit master */
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



#define r_log_debug(...) ngx_log_debug(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, __VA_ARGS__)

ngx_int_t ngx_http_wasm_rewrite_handler ( ngx_http_request_t* r ) {
    r_log_debug("rewrite handler");
    ngx_http_wasm_loc_conf_t  *wlcf = ngx_http_get_module_loc_conf(r, ngx_http_wasm_module);
    r_log_debug("wasm file: '%*s'", wlcf->wasm_path.len, wlcf->wasm_path.data);
    return NGX_DECLINED;
}

ngx_int_t ngx_http_wasm_access_handler ( ngx_http_request_t* r ) {
    r_log_debug("access handler");
    ngx_http_wasm_loc_conf_t  *wlcf = ngx_http_get_module_loc_conf(r, ngx_http_wasm_module);
    r_log_debug("wasm file: '%*s'", wlcf->wasm_path.len, wlcf->wasm_path.data);
    return NGX_DECLINED;
}

ngx_int_t ngx_http_wasm_content_hanlder ( ngx_http_request_t* r ) {
    r_log_debug("content handler");
    ngx_http_wasm_loc_conf_t  *wlcf = ngx_http_get_module_loc_conf(r, ngx_http_wasm_module);
    r_log_debug("wasm file: '%*s'", wlcf->wasm_path.len, wlcf->wasm_path.data);
    return NGX_DECLINED;
}

ngx_int_t ngx_http_wasm_log_handler ( ngx_http_request_t* r ) {
    r_log_debug("log handler");
    ngx_http_wasm_loc_conf_t  *wlcf = ngx_http_get_module_loc_conf(r, ngx_http_wasm_module);
    r_log_debug("wasm file: '%*s'", wlcf->wasm_path.len, wlcf->wasm_path.data);
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

    return ngx_http_next_header_filter (r);
}


static ngx_http_output_body_filter_pt ngx_http_next_body_filter;

static ngx_int_t ngx_http_wasm_body_filter(ngx_http_request_t *r, ngx_chain_t *in) {
    r_log_debug("body filter");
    ngx_http_wasm_loc_conf_t *wlcf = ngx_http_get_module_loc_conf(r, ngx_http_wasm_module);
    r_log_debug("wasm file: '%*s'", wlcf->wasm_path.len, wlcf->wasm_path.data);

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
