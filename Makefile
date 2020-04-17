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
	utils.c

HEADERS= \
	wngx_structs.h \
	wngx_host.h \
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






modules: demo_c.wasm demo_req.wasm

WASM_CC = /opt/wasi-sdk/bin/clang
WASM_CFLAGS = --target=wasm32-unknown-wasi -nostartfiles -Wl,--allow-undefined -Wl,--no-entry -Wl,--export-all


%.wasm: %.c
	$(WASM_CC) $(WASM_CFLAGS) -o $@ $<

%.wasm: %.zig wngx.zig
	zig build-lib -target wasm32-freestanding $<
