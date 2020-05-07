#ifndef wngx_structs_h
#define wngx_structs_h

#include <stdint.h>
#include <stddef.h>


#ifndef WASM_CODE
static const unsigned ptrsize = sizeof(void*);
#if ptrsize == 4
#define WASM_CODE 1
#else
#define WASM_CODE 0
#endif
#endif


#if WASM_CODE

typedef void *wngx_ptr;
typedef char *char_ptr;
typedef void (*wngx_func_ptr)();

#else

typedef uint32_t wngx_ptr;
typedef wngx_ptr char_ptr;
typedef wngx_ptr wngx_func_ptr;

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


struct wngx_callback_pun {
    wngx_func_ptr callback;
};

typedef struct wngx_subrequest_params {
    wngx_func_ptr callback;
    wngx_str uri;
    wngx_str args;
    uint32_t ref;
} wngx_subrequest_params;


#endif
