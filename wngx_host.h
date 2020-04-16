#ifndef wngx_host_h
#define wngx_host_h

void log_wasmer_error(ngx_http_request_t *r);
wasmer_result_t maybe_call(ngx_http_request_t *r, const char *method);

#endif
