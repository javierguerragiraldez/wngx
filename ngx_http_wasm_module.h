#ifndef WASM_MODULE_H
#define WASM_MODULE_H


typedef struct ngx_http_wasm_conf_s {
//     struct ngx_http_wasm_conf_s *root;
//     ngx_array_t *modules;       /* only on main. */
    ngx_array_t *instances;
} ngx_http_wasm_conf_t;


typedef struct {
    wngx_instance *instance;
} ngx_http_wasm_ctx;

extern ngx_module_t  ngx_http_wasm_module;

#endif
