#ifndef wngx_host_h
#define wngx_host_h

typedef enum wngx_export_id {
    wngx_alloc,
    wngx_free,
    wngx_on_config,
    wngx_on_init_proc,
    wngx_on_request,
    wngx_on_req_rewrite,
    wngx_on_req_access,
    wngx_on_content,
    wngx_on_res_header,
    wngx_on_res_body,
    wngx_on_log,
    wngx_on_callback,

    __wngx_num_export_ids__,
} wngx_export_id;


typedef enum ApiExpected {
    ExpectApiNone = 0x00,
    ExpectApiWasi = 0x01,
    ExpectApiGo = 0x02,
} ApiExpected;

typedef struct wngx_module {
    wasmer_module_t *w_module;
    ApiExpected apis_expected;
    int export_index[__wngx_num_export_ids__];
} wngx_module;

typedef struct wngx_instance {
    wasmer_instance_t *w_instance;
    wasmer_exports_t *w_exports;
    const wasmer_export_func_t *w_funcs[__wngx_num_export_ids__];
    const wngx_module *module;
    ngx_http_request_t *current_req;
    wngx_registry registry;
    void *ctx;
} wngx_instance;


typedef void (*func_t)(void *);
typedef struct {
    wasmer_byte_array func_name;
    func_t func;
    int n_returns;
    wasmer_value_tag returns[1];
    int n_params;
    wasmer_value_tag params[10];
} func_defs_t;



void log_wasmer_error(const char *msg);

wngx_module *wngx_host_load_module(const ngx_str_t *path);
wngx_instance *wngx_host_load_instance(const wngx_module *mod);

wasmer_result_t maybe_call(wngx_instance *inst, wngx_export_id method);

wasmer_result_t wngx_host_call_back(wngx_instance *inst, uint32_t data);

#endif
