#ifndef wngx_host_h
#define wngx_host_h

typedef enum wngx_export_id {
    wngx_alloc,
    wngx_free,
    wngx_config,
    wngx_init_proc,
    wngx_req_init,
    wngx_req_rewrite,
    wngx_req_access,
    wngx_req_content,
    wngx_res_header_filter,
    wngx_res_body_filter,
    wngx_on_log,

    __wngx_num_export_ids__,
} wngx_export_id;

typedef struct wngx_module {
    wasmer_module_t *w_module;
    int export_index[__wngx_num_export_ids__];
} wngx_module;

typedef struct wngx_instance {
    wasmer_instance_t *w_instance;
    const wasmer_export_func_t *w_funcs[__wngx_num_export_ids__];
} wngx_instance;

void log_wasmer_error(const char *msg);

wngx_module *wngx_host_load_module(const ngx_str_t *path);
wngx_instance *wngx_host_load_instance(const wngx_module *mod);

wasmer_result_t maybe_call(wngx_instance *inst, wngx_export_id method);

#endif
