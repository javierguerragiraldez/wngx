#ifndef wngx_host_h
#define wngx_host_h

uint32_t wngx_request_size(const wasmer_instance_context_t *wctx);
void wngx_get_request(const wasmer_instance_context_t *wctx,
                      uint32_t buff_off, uint32_t buff_size);

#endif
