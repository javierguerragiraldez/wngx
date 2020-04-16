#ifndef wasmdemo_utils_h
#define wasmdemo_utils_h

#define sizeof_array(x) (sizeof(x) / sizeof((x)[0]))
// #define sizeof_litstr(s) (sizeof_array(s) - 1)
#define LIT_BYTEARRAY(s) { .bytes = (const uint8_t*)(s), .bytes_len=sizeof(s)-1 }
// #define STR_BYTEARRAY(s) { .bytes = (const uint8_t*)(s), .bytes_len=strlen(s) }


#define r_log_debug(...) ngx_log_debug(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, __VA_ARGS__)



uint8_t *read_file(ngx_pool_t *pool, const char *fname, uint32_t *out_len);

size_t request_size(const ngx_http_request_t *r);
void pack_request(const ngx_http_request_t *r, uint8_t *mem, uint32_t offst, uint32_t size);

#endif