#ifndef wasmdemo_utils_h
#define wasmdemo_utils_h

size_t request_size(const ngx_http_request_t *r);
void pack_request(const ngx_http_request_t *r, uint8_t *mem, uint32_t offst, uint32_t size);

#endif
