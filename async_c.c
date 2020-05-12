
#define WASM_CODE 1

#include "wngx_structs.h"

extern void wngx_log(unsigned level, char *msg, unsigned len);
extern unsigned wngx_subrequest(wngx_subrequest_params *parms);

#define wngx_lit_str(s) {.d=(s), .len=sizeof(s)}

#define log_k(s) wngx_log(0x100, (s), sizeof(s));

uint32_t on_callback(struct wngx_callback_pun *pun) {
    log_k("callback!");
    pun->callback(pun);

    return 0;
}

static void after_subreq(const wngx_subrequest_params *parms) {
    log_k("after_subreq!");
}

void on_content(void) {
    log_k("content!");

    wngx_subrequest_params params = {
        .callback = (wngx_func_ptr)after_subreq,
        .uri = wngx_lit_str("http://example.com"),
        .args = wngx_lit_str(""),
    };

    unsigned ref = wngx_subrequest(&params);

    log_k("queued...");
}
