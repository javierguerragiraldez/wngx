
#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>

#include "wasmer.h"

#include "utils.h"
#include "wngx_structs.h"



uint8_t *read_file(ngx_pool_t *pool, const char *fname, uint32_t *out_len) {
    uint8_t *bytes = NULL;
    long len = 0;
    long readlen = 0;

    FILE *file = fopen(fname, "r");
    if (!file) goto end;

    fseek(file, 0, SEEK_END);
    len = ftell(file);
    bytes = ngx_pcalloc(pool, len);
    if (!bytes) goto end;

    fseek(file, 0, SEEK_SET);
    readlen = fread(bytes, 1, len, file);

end:
    if (file) fclose(file);
    if (out_len) *out_len = readlen;
    return bytes;
}



ngx_uint_t count_ngx_list(const ngx_list_t *list) {
    ngx_uint_t n = 0;
    const ngx_list_part_t *part = &list->part;

    while (part != NULL) {
        n += part->nelts;
        part = part->next;
    }

    return n;
}

size_t request_size ( const ngx_http_request_t* r ) {

    ngx_uint_t n_headers = count_ngx_list(&r->headers_in.headers);

    return sizeof(wngx_request)
        + sizeof(wngx_header) * n_headers
        + (r->header_in->end - r->header_in->start);
}


inline wngx_str pack_str(ngx_str_t s, u_char *ref_p) {
    wngx_str ws = { .d = s.data - ref_p, .len = s.len };
    return ws;
}


void pack_request (
    const ngx_http_request_t* r,
    uint8_t *mem,
    uint32_t dst_offst,
    uint32_t dst_size
) {
    u_char *header_start = r->header_in->start;
    u_char *header_end = r->header_in->end;

    wngx_request *dst_r = (wngx_request *)(mem + dst_offst);
    ngx_uint_t n_headers = count_ngx_list(&r->headers_in.headers);
    u_char *dst_buf = mem + dst_offst
                        + sizeof(wngx_request)
                        + sizeof(wngx_header) * n_headers;
    dst_r->n_headers = n_headers;
    dst_r->buf_start = dst_buf - mem;
    dst_r->total_size = sizeof(wngx_request)
                        + sizeof(wngx_header) * n_headers
                        + header_end - header_start;
    if (dst_size < dst_r->total_size)
        return;
    ngx_memcpy(dst_buf, header_start, header_end - header_start);

    u_char *ref_p = header_start - dst_r->buf_start;

    dst_r->request_line = pack_str(r->request_line, ref_p);
    dst_r->method = pack_str(r->method_name, ref_p);
    dst_r->uri = pack_str(r->unparsed_uri, ref_p);
    dst_r->http_version = pack_str(r->http_protocol, ref_p);
    dst_r->uri_path = pack_str(r->uri, ref_p);
    dst_r->uri_args = pack_str(r->args, ref_p);
    dst_r->uri_exten = pack_str(r->exten, ref_p);

    {
        const ngx_list_t *l = &r->headers_in.headers;
        const ngx_list_part_t *part = &l->part;
        ngx_table_elt_t *h = part->elts;

        u_int i, j;
        for (i = 0, j = 0; ; i++, j++) {
            if (i >= part->nelts) {
                if (part->next == NULL) break;

                part = part->next;
                h = part->elts;
                i = 0;
            }
            dst_r->headers[j].name = pack_str(h[i].key, ref_p);
            dst_r->headers[j].value = pack_str(h[i].value, ref_p);
        }
    }
}



typedef union registry_entry {
    void *ptr;
    unsigned int next_free;
} registry_entry;


ngx_int_t initialize_registry ( wngx_registry* registry, ngx_pool_t* pool ) {
    if (ngx_array_init(registry, pool, 10, sizeof(registry_entry)) != NGX_OK) {
        return NGX_ERROR;
    }

    registry_entry *e0 = ngx_array_push(registry);
    if (!e0 || e0 != registry->elts) {
        ngx_log_debug(NGX_LOG_ERR, pool->log, 0, "invalid zero-entry: %p", e0);
        return NGX_ERROR;
    }

    e0->next_free = 1;
    return NGX_OK;
}

uint32_t registry_add ( wngx_registry* registry, void* p ) {
    if (registry->nelts < 1) {
        ngx_log_error(NGX_LOG_ERR, ngx_cycle->log, 0, "uninitialized registry.");
    }
    registry_entry *e0 = registry->elts;
    unsigned int index = e0->next_free;

    if (e0->next_free == registry->nelts) {
        /* push at the end */
        registry_entry *entry = ngx_array_push(registry);
        e0->next_free = registry->nelts;
        entry->ptr = p;
        return index;

    } else if (e0->next_free < registry->nelts) {
        /* reuse old slot */
        registry_entry *entry = &((registry_entry*)registry->elts)[index];
        e0->next_free = entry->next_free;
        entry->ptr = p;
        return index;
    }

    /* wrong! fail! */
    return 0;
}

void *registry_get ( const wngx_registry* registry, uint32_t index ) {
    if (registry->nelts < 1 || index > registry->nelts) {
        ngx_log_debug(NGX_LOG_ERR, ngx_cycle->log, 0,
                      "invalid index %d, registry size %d.", index, registry->nelts);
        return NULL;
    }

    registry_entry *entry = &((registry_entry*)registry->elts)[index];
    return entry->ptr;
}

void registry_delete (wngx_registry* registry, uint32_t index) {
    if (registry->nelts < 1 || index > registry->nelts) {
        ngx_log_debug(NGX_LOG_ERR, ngx_cycle->log, 0,
                      "invalid index %d, registry size %d.", index, registry->nelts);
    }

    registry_entry *e0 = registry->elts;
    registry_entry *entry = &((registry_entry*)registry->elts)[index];

    entry->next_free = e0->next_free;
    e0->next_free = index;
}
