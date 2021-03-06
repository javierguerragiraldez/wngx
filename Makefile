MAIN_DIR=$(abspath ../..)

NGX_DIR=$(MAIN_DIR)/nginx-1.16.1
NGX_OUTDIR=$(NGX_DIR)/out
MODULEPATH=$(MAIN_DIR)/nginx-modules/wasmdemo

NGX_MAKE=$(NGX_DIR)/objs/Makefile
NGX_EXE=$(NGX_DIR)/objs/nginx
NGX_INST=$(NGX_OUTDIR)/sbin/nginx

SRCS= \
	ngx_http_wasm_module.c \
	wngx_host.c \
	wngx_go_host.c \
	utils.c

HEADERS= \
	ngx_http_wasm_module.h \
	wngx_structs.h \
	wngx_host.h \
	wngx_go_host.h \
	gojs_values.c \
	utils.h



default: modules install

configure: $(NGX_MAKE)

build: $(NGX_EXE)

install: $(NGX_INST)

$(NGX_MAKE): config
	rm -f $(NGX_EXE)
	cd $(NGX_DIR) && ./configure --prefix=$(NGX_OUTDIR) --add-module=$(PWD)

$(NGX_EXE): $(SRCS) $(HEADERS) config
	cd $(NGX_DIR) && $(MAKE) build

$(NGX_INST): $(NGX_EXE)
	cd $(NGX_DIR) && $(MAKE) install






modules: demo_c.wasm demo_req.wasm async_c.wasm demo_go.wasm async_cpp.wasm

-include *.d

WASM_CC = /opt/wasi-sdk/bin/clang
WASM_CFLAGS = -MMD \
	-std=gnu2x \
	--target=wasm32-unknown-wasi \
	-nostartfiles \
	-Wl,--allow-undefined \
	-Wl,--no-entry \
	-Wl,--export-all

WASM_CPP = /opt/wasi-sdk/bin/clang++
WASM_CPPFLAGS = -MMD \
	-std=c++17 \
	-nostartfiles \
	-fno-exceptions \
	-Wl,--allow-undefined \
	-Wl,--no-entry \
	-Wl,--export-dynamic


%.wasm: %.c
	$(WASM_CC) $(WASM_CFLAGS) -o $@ $<

%.wasm: %.cpp
	$(WASM_CPP) $(WASM_CPPFLAGS) -o $@ $<

%.wasm: %.zig wngx.zig
	zig build-lib -target wasm32-freestanding $<

%.wasm: %.go
	GOOS=js GOARCH=wasm go build -o $@ $<
