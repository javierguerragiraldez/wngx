#ifndef wngx_host_h
#define wngx_host_h

typedef struct wngx_module {
//     ngx_str_t *path;
    wasmer_module_t *w_module;
} wngx_module;

typedef struct wngx_instance {
    wasmer_instance_t *w_instance;
} wngx_instance;

void log_wasmer_error(const char *msg);

wngx_module *wngx_host_load_module(const ngx_str_t *path);
wngx_instance *wngx_host_load_instance(const wngx_module *mod);

wasmer_result_t maybe_call(wngx_instance *inst, const char *method);

#endif
