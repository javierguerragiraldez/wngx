#ifndef wasmdemo_utils_h
#define wasmdemo_utils_h

#define sizeof_array(x) (sizeof(x) / sizeof((x)[0]))
#define LIT_BYTEARRAY(s) { .bytes = (const uint8_t*)(s), .bytes_len=sizeof(s)-1 }


inline int bytearray_eq(const wasmer_byte_array *wba_a, const wasmer_byte_array *wba_b) {
    return wba_a->bytes_len == wba_b->bytes_len
        && (memcmp(wba_a->bytes, wba_b->bytes, wba_a->bytes_len) == 0);
}


uint8_t *read_file(ngx_pool_t *pool, const char *fname, uint32_t *out_len);

size_t request_size(const ngx_http_request_t *r);
void pack_request(const ngx_http_request_t *r, uint8_t *mem, uint32_t offst, uint32_t size);

#endif
