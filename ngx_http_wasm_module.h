#ifndef WASM_MODULE_H
#define WASM_MODULE_H


typedef struct {
    ngx_str_t  wasm_path;
    uint8_t *module_bytes;
    uint32_t module_bytes_len;
    const wasmer_module_t *wasm_module;
} ngx_http_wasm_loc_conf_t;


typedef struct {
    wasmer_instance_t *instance;
} ngx_http_wasm_ctx;

extern ngx_module_t  ngx_http_wasm_module;

#endif
