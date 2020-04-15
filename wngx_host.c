
#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>

#include "wasmer.h"
#include "wngx_host.h"
#include "utils.h"

uint32_t wngx_request_size ( const wasmer_instance_context_t* wctx ) {
    const ngx_http_request_t *r = wasmer_instance_context_data_get(wctx);
    if (!r) return 0;

    return request_size(r);
}

void wngx_get_request (
    const wasmer_instance_context_t* wctx,
    uint32_t buff_off, uint32_t buff_size
) {
    const ngx_http_request_t *r = wasmer_instance_context_data_get(wctx);
    if (!r) return;

    const wasmer_memory_t *mem_ctx = wasmer_instance_context_memory(wctx, 0);
    if (!mem_ctx) return;

    uint8_t *mem = wasmer_memory_data(mem_ctx);
    if (!mem) return;

    pack_request(r, mem, buff_off, buff_size);
}

