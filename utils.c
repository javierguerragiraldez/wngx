
#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>

#include "wngx_data.h"
#include "utils.h"

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
    //wngx_str c =  header_start - mem + dst_buf;

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

        u_int i = 0, j = 0;
        for (i = 0; ; i++) {
            if (i >= part->nelts) {
                if (part->next == NULL) break;

                part = part->next;
                h = part->elts;
                i = 0;
            }
            dst_r->headers[j].name = pack_str(h->key, ref_p);
            dst_r->headers[j].value = pack_str(h->value, ref_p);
        }
    }
}


