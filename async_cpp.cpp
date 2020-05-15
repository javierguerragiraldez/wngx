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


class Future;
struct base_callbacker {
    virtual void set_future(Future _f) = 0;
};


class Future {
public:
    struct base_callbacker *cb;
    std::function<void*(void*)> func;

//     Future(struct base_callbacker *_cb) : cb(_cb), f(noop) {cb->set_future(*this); }
    Future(struct base_callbacker *_cb, std::function<void*(void*)>_f = noop) : cb(_cb), func(_f) {cb->set_future(*this);};

    static void* noop(void *p) {
        log_k ("nop");
        return p;
    }

    const Future then(std::function<void*(void*)> _f) const {
        log_k("setting function")

        auto fw = [=](void *p){
            return _f(func(p));
        };

        return Future(cb, fw);
    };
};

template <typename P>
struct callbacker : base_callbacker {
    P punned;
    Future fut;

    callbacker(P &&in) : punned(in), fut(this) {}

    static void callback(void *vp) {
        log_k("callbacker.callback");
        callbacker<P>* cb = (callbacker<P>*)vp;
        log_k("got cb");
        cb->fut.func(&cb->punned);
        log_k("done future");
    }

    virtual void set_future(Future _f) override {
        fut = _f; }
};

static Future subreq_f(std::string &&uri, std::string &&args = std::string()) {

    auto cb = new callbacker<wngx_subrequest_params>({
            .uri = (wngx_str){ .d = uri.data(), .len = (uint32_t)uri.size() },
            .args = (wngx_str){ .d = args.data(), .len = (uint32_t)args.size() },
        });

    cb->punned.callback = cb->callback;
    wngx_subrequest(&cb->punned);
    log_k("requested");

    return cb->fut;
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

    subreq_f("http://example.com").then([](void *p){ log_k("future callback"); return p; });

    log_k("queued...");
}
