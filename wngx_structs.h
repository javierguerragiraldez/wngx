#ifndef wngx_structs_h
#define wngx_structs_h

#include <stdint.h>
#include "wasmer.h"

const size_t ptrsize = sizeof(void*);

#if ptrsize==4

typedef uchar *char_ptr;

#else

typedef uint32_t char_ptr;

#endif

typedef struct wngx_str {
    char_ptr d;
    uint32_t len;
} wngx_str;

typedef struct wngx_header {
    wngx_str name;
    wngx_str value;
} wngx_header;

typedef struct wngx_request {
    uint32_t n_headers;
    char_ptr buf_start;
    uint32_t total_size;

    wngx_str request_line;
    wngx_str method;
    wngx_str uri;
    wngx_str http_version;

    wngx_str uri_path;
    wngx_str uri_args;
    wngx_str uri_exten;

    wngx_header headers[];
} wngx_request;


#endif
