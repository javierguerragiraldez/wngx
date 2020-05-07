
/*
 * Copyright (C) Igor Sysoev
 * Copyright (C) Nginx, Inc.
 */


#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>
#include <ngx_string.h>

#include "wasmer.h"

#include "utils.h"
#include "wngx_host.h"
#include "ngx_http_wasm_module.h"

typedef struct loaded_module {
    ngx_str_t module_path;
    wngx_module *module;
} loaded_module;

typedef struct named_instance {
    ngx_str_t module_path;
    ngx_str_t instance_name;
    wngx_instance *instance;
    ngx_uint_t index;
} named_instance;

typedef struct ngx_http_wasm_main_conf_t {
    ngx_array_t modules;
    ngx_array_t instances;
} ngx_http_wasm_main_conf_t;

typedef struct ngx_http_wasm_conf_t {
    ngx_array_t instances;
} ngx_http_wasm_conf_t;

/* misc funcs */

#define r_log_debug(...) ngx_log_debug(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, __VA_ARGS__)

#define ngxarray_for(iv,pv,a, t)   \
    ngx_uint_t iv; \
    t * pv; \
    for(iv=0,pv=(a)->elts; iv<(a)->nelts; iv++, pv++)



static void log_cf(const ngx_conf_t *cf, const char *msg, const void *p) {
    ngx_log_stderr(NGX_LOG_STDERR, "%s(%p) :: cf: %p, #args: %d, module_type: %Xd, cmd_type: %Xd",
        msg, p, cf, cf->args->nelts,  cf->module_type, cf->cmd_type );

    ngxarray_for(i, arg, cf->args, const ngx_str_t){
        ngx_log_stderr(NGX_LOG_STDERR, "   arg #%d: %V", i, arg);
    }
}

void maybe_call_each(const ngx_array_t *instances, wngx_export_id method, ngx_http_request_t *r) {
    ngxarray_for(i, inst, instances, const named_instance) {
        if (inst->instance != NULL) {
            inst->instance->current_req = r;
            wasmer_result_t call_result = maybe_call(inst->instance, method);
            if (call_result != WASMER_OK) {
                log_wasmer_error("error calling XX method");
            }
            inst->instance->current_req = NULL;
        }
    }
}

/* handlers */

static ngx_int_t ngx_http_wasm_rewrite_handler ( ngx_http_request_t* r ) {
    ngx_http_wasm_conf_t *wlcf = ngx_http_get_module_loc_conf(r, ngx_http_wasm_module);
    if (wlcf == NULL) {
        r_log_debug("no local conf ??");
        return NGX_ERROR;
    }
    maybe_call_each(&wlcf->instances, wngx_on_req_rewrite, r);

    return NGX_DECLINED;
}

static ngx_int_t ngx_http_wasm_access_handler ( ngx_http_request_t* r ) {
    ngx_http_wasm_conf_t *wlcf = ngx_http_get_module_loc_conf(r, ngx_http_wasm_module);
    if (wlcf == NULL) {
        r_log_debug("no local conf ??");
        return NGX_ERROR;
    }
    maybe_call_each(&wlcf->instances, wngx_on_req_access, r);

    return NGX_DECLINED;
}

static ngx_int_t ngx_http_wasm_content_hanlder ( ngx_http_request_t* r ) {
    ngx_http_wasm_conf_t *wlcf = ngx_http_get_module_loc_conf(r, ngx_http_wasm_module);
    if (wlcf == NULL) {
        r_log_debug("no local conf ??");
        return NGX_ERROR;
    }
    maybe_call_each(&wlcf->instances, wngx_on_content, r);

    return NGX_DECLINED;
}

static ngx_http_output_header_filter_pt ngx_http_next_header_filter;

static ngx_int_t ngx_http_wasm_header_filter(ngx_http_request_t *r) {
    ngx_http_wasm_conf_t *wlcf = ngx_http_get_module_loc_conf(r, ngx_http_wasm_module);
    if (wlcf == NULL) {
        r_log_debug("no local conf ??");
        return NGX_ERROR;
    }
    maybe_call_each(&wlcf->instances, wngx_on_res_header, r);

    return ngx_http_next_header_filter (r);
}


static ngx_http_output_body_filter_pt ngx_http_next_body_filter;

static ngx_int_t ngx_http_wasm_body_filter(ngx_http_request_t *r, ngx_chain_t *in) {
    ngx_http_wasm_conf_t *wlcf = ngx_http_get_module_loc_conf(r, ngx_http_wasm_module);
    if (wlcf == NULL) {
        r_log_debug("no local conf ??");
        return NGX_ERROR;
    }
    maybe_call_each(&wlcf->instances, wngx_on_res_body, r);

    return ngx_http_next_body_filter(r, in);
}


static ngx_int_t ngx_http_wasm_log_handler ( ngx_http_request_t* r ) {
    ngx_http_wasm_conf_t *wlcf = ngx_http_get_module_loc_conf(r, ngx_http_wasm_module);
    if (wlcf == NULL) {
        r_log_debug("no local conf ??");
        return NGX_ERROR;
    }
    maybe_call_each(&wlcf->instances, wngx_on_log, r);

    return NGX_DECLINED;
}





/* conf callbacks */

static void *ngx_http_wasm_create_main_conf(ngx_conf_t *cf) {
    ngx_http_wasm_main_conf_t *conf = ngx_pcalloc(cf->pool, sizeof(ngx_http_wasm_main_conf_t));
    if (conf == NULL) {
        return NULL;
    }
    log_cf(cf, "create_main_conf", conf);

    ngx_array_init(&conf->modules, cf->pool, 10, sizeof(loaded_module));
    ngx_array_init(&conf->instances, cf->pool, 10, sizeof(named_instance));

    return conf;
}

static void *ngx_http_wasm_create_conf(ngx_conf_t *cf) {
    ngx_http_wasm_conf_t *conf = ngx_pcalloc(cf->pool, sizeof(ngx_http_wasm_conf_t));
    if (conf == NULL) {
        return NULL;
    }
    log_cf(cf, "create_conf", conf);

    if (ngx_array_init(&conf->instances, cf->pool, 10, sizeof(named_instance)) != NGX_OK) {
        ngx_free(conf);
        return NULL;
    }

    return conf;
}


static inline int streq(const ngx_str_t *s1, const ngx_str_t *s2) {
    return (s1->len == s2->len)
        && (ngx_memcmp(s1->data, s2->data, s1->len) == 0);
}


static char *ngx_http_wasm_set_loc_conf_module_file(
    ngx_conf_t *cf,
    ngx_command_t *cmd,
    void *conf
) {
    (void)cmd;

    log_cf(cf, "set_loc_conf", conf);

    if (cf->args->nelts < 2 || cf->args->nelts > 3) {
        return "syntax: wasm_file path [name];";
    }

    ngx_http_wasm_conf_t *wlcf = conf;
    if (wlcf == NULL)   return "cant't find local config";

    ngx_http_wasm_main_conf_t *wmcf = ngx_http_conf_get_module_main_conf(cf, ngx_http_wasm_module);
    d("wmcf: %p", wmcf);

    ngx_str_t *args = cf->args->elts;

    named_instance *inst = ngx_array_push(&wlcf->instances);
    if (inst == NULL) {
        return "can't push new instance";
    }
    ngx_memzero(inst, sizeof(*inst));

    inst->module_path = args[1];
    if (cf->args->nelts > 2) {
        inst->instance_name = args[2];
    } else {
        ngx_str_null(&inst->instance_name);
    }

    return NGX_CONF_OK;
}


static void get_named_instance(named_instance *inst, ngx_array_t *instances, ngx_array_t *modules) {
    if (inst == NULL || inst->module_path.data == NULL) return;
    d("inst: %p: %V", inst, &inst->module_path);

    if (inst->instance_name.data != NULL) {
        /* has a name, search in old named instances */
        ngxarray_for(i, old_inst, instances, const named_instance) {
            d("old_inst: %p (%V:%V)", old_inst, &old_inst->module_path, &old_inst->instance_name);
            if (streq(&old_inst->instance_name, &inst->instance_name)
                && streq(&old_inst->module_path, &inst->module_path)
            ){
                d("found!");
                inst->instance = old_inst->instance;
                return;
            }
        }
    }

    /* no old instance, get a module */
    wngx_module *mod = NULL;

    /* search in loaded modules */
    ngxarray_for(i, old_mod, modules, const loaded_module) {
        d("loaded_module: %p (%V)", old_mod, &old_mod->module_path);
        if (streq(&old_mod->module_path, &inst->module_path)) {
            d("found!");
            mod = old_mod->module;
            break;
        }
    }

    if (mod == NULL) {
        /* no loaded module, load it */
        d("loading...");
        mod = wngx_host_load_module(&inst->module_path);
    }
    if (mod == NULL) {
        ngx_log_error(NGX_LOG_ERR, ngx_cycle->log, 0,
                        "can't load module %V", &inst->module_path);
        return;
    }

    /* register loaded module */
    loaded_module *new_mod = ngx_array_push(modules);
    if (new_mod == NULL) {
        ngx_log_error(NGX_LOG_ERR, ngx_cycle->log, 0, "can't register loaded module");
        return;
    }
    new_mod->module_path = inst->module_path;
    new_mod->module = mod;

    /* instantiate it */
    inst->instance = wngx_host_load_instance(mod);
    if (inst->instance == NULL) {
        ngx_log_error(NGX_LOG_ERR, ngx_cycle->log, 0,
                      "can't instantiate module %V", &inst->module_path);
        return;
    }

    /* register it */
    named_instance *new_inst = ngx_array_push(instances);
    if (new_inst == NULL) {
        ngx_log_error(NGX_LOG_ERR, ngx_cycle->log, 0, "can't push named module %V:%V",
                        &inst->module_path, &inst->instance_name);
        return;
    }
    new_inst->module_path = inst->module_path;
    new_inst->instance_name = inst->instance_name;
    new_inst->instance = inst->instance;
}

static char *ngx_http_wasm_merge_loc_conf(ngx_conf_t *cf, void *parent, void *child) {
    (void)cf;

    ngx_http_wasm_conf_t *prev = parent;
    ngx_http_wasm_main_conf_t *root = ngx_http_conf_get_module_main_conf(cf, ngx_http_wasm_module); //prev->root;
    ngx_http_wasm_conf_t *conf = child;

    if (root == NULL) {
        ngx_log_debug(NGX_LOG_DEBUG_HTTP, cf->log, 0, "parent %p doesn't have main pointer");
        return NGX_CONF_OK;
    }

    ngx_log_stderr(NGX_LOG_STDERR, "merge - root: %p (%d/%d)  prev: %p => conf: %p (%d)",
                   root, root->instances.nelts, root->modules.nelts, prev,
                   conf, conf->instances.nelts);

    ngxarray_for(i, inst, &conf->instances, named_instance) {
        d("get: %V:%V", &inst->module_path, &inst->instance_name);
        get_named_instance(inst, &root->instances, &root->modules);
    }

    ngxarray_for(_, inst_, &conf->instances, const named_instance) {
        d("instance %V:%V -> %p", &inst_->module_path, &inst_->instance_name, inst_->instance);
    }
    d("---");

    return NGX_CONF_OK;
}


/* postconf setup */

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


static ngx_int_t ngx_http_wasm_postconf ( ngx_conf_t* cf ) {
    ngx_http_wasm_conf_t *wlcf = ngx_http_conf_get_module_loc_conf(cf, ngx_http_wasm_module);
    if (wlcf == NULL) {
        ngx_conf_log_error(NGX_LOG_DEBUG_ALL, cf, NGX_EBADF, "no wasm conf");
        return NGX_ERROR;
    }

    ngx_http_core_main_conf_t *cmcf = ngx_http_conf_get_module_main_conf(cf, ngx_http_core_module);

    ngx_int_t rc = add_handler(cmcf, NGX_HTTP_REWRITE_PHASE, ngx_http_wasm_rewrite_handler)
                || add_handler(cmcf, NGX_HTTP_ACCESS_PHASE, ngx_http_wasm_access_handler)
                || add_handler(cmcf, NGX_HTTP_CONTENT_PHASE, ngx_http_wasm_content_hanlder)
                || add_handler(cmcf, NGX_HTTP_LOG_PHASE, ngx_http_wasm_log_handler);

    if (rc != NGX_OK) {
//         ngx_log_stderr(0, "rc %d != NGX_OK", rc);
        return rc;
    }

    ngx_http_next_header_filter = ngx_http_top_header_filter;
    ngx_http_top_header_filter = ngx_http_wasm_header_filter;

    ngx_http_next_body_filter = ngx_http_top_body_filter;
    ngx_http_top_body_filter = ngx_http_wasm_body_filter;

    return rc;
}


/* process initialization */

ngx_int_t ngx_http_wasm_init_proc ( ngx_cycle_t* cycle ) {
    (void)cycle;
//     ngx_log_debug(NGX_LOG_DEBUG, cycle->log, 0, "init proc");
//     ngx_log_stderr(0, "init proc (%d > %d)", getppid(), getpid());

//     ngx_http_wasm_main_conf_t *wmcf = ngx_http_cycle_get_module_main_conf(cycle, ngx_http_wasm_module);
//     if (wmcf == NULL) {
//         return NGX_ERROR;
//     }

    return NGX_OK;
}


/* register structs */

static ngx_command_t  ngx_http_wasm_commands[] = {
    {
        ngx_string("wasm_file"),
        NGX_HTTP_MAIN_CONF | NGX_HTTP_SRV_CONF | NGX_HTTP_LOC_CONF
        | NGX_CONF_TAKE12,
        ngx_http_wasm_set_loc_conf_module_file,
        NGX_HTTP_LOC_CONF_OFFSET,
        0, NULL,
    },
    ngx_null_command
};


static ngx_http_module_t  ngx_http_wasm_module_ctx = {
    NULL,                           /* preconfiguration */
    ngx_http_wasm_postconf,         /* postconfiguration */

    ngx_http_wasm_create_main_conf, /* create main configuration */
    NULL,                           /* init main configuration */

    NULL,                           /* create server configuration */
    NULL,                           /* merge server configuration */

    ngx_http_wasm_create_conf,      /* create location configuration */
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


