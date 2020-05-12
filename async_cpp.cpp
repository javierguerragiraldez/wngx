#include <functional>
// #include <memory>
#include <string>

#define WASM_CODE 1

extern "C" {
    #include "wngx_structs.h"

    extern void wngx_log(unsigned level, char *msg, unsigned len);
    extern unsigned wngx_subrequest(wngx_subrequest_params *parms);

    uint32_t on_callback(struct wngx_callback_pun *pun);
    void on_content(void);
}

#define wngx_lit_str(s) {.d=(char*)(s), .len=sizeof(s)}

#define log_k(s) wngx_log(0x100, (char*)(s), sizeof(s));

uint32_t on_callback(struct wngx_callback_pun *pun) {
    log_k("callback!");
    pun->callback(pun);

    return 0;
}


struct subreq {
    wngx_subrequest_params parms;
    std::function<void(wngx_subrequest_params*)> f;

    subreq(std::string uri, std::string args) {
        parms = (wngx_subrequest_params){
            .callback = subreq::callback,
            .uri = (wngx_str){ .d = uri.data(), .len = (uint32_t)uri.size() },
            .args = (wngx_str){ .d = args.data(), .len = (uint32_t)args.size() },
        };
    }

    class Future {
    public:
        subreq &s;

        Future(subreq &_s) : s(_s) {}

        void then(void(*_f)(wngx_subrequest_params *p)) {
            s.f = _f;
        }
    };

    static Future q(std::string &&uri, std::string &&args = std::string()) {
        auto s = new subreq(uri, args);
        wngx_subrequest(&s->parms);

        return Future(*s);
    }

    static void callback(void *p) {
        auto s = (subreq *)p;
        s->f(&s->parms);
        log_k("done lambda");
        // todo: delete s;
//         log_k("deleted stuff");
    }
};

void on_content(void) {
    log_k("content!");

    subreq::q("http://example.com").then([](auto *p){ (void)p; log_k("lambda callback"); });

    log_k("queued...");
}
