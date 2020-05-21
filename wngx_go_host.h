#ifndef wngx_go_host_h
#define wngx_go_host_h

const func_defs_t *go_func_defs;

wasmer_result_t wngx_go_host_try_run(const wngx_instance *inst, const ngx_str_t *name);

#endif
