
const unsigned buff_size = 1024;

char buffs[4][buff_size];
unsigned urilen = 0;

extern int wngx_get_uri(char *buf, unsigned len);
extern void wngx_add_header(char *key, unsigned key_len, char *val, unsigned val_len);

static void string_copy(char *dst, const char *src, unsigned len) {
    int i;
    for (i = 0; i < len; i++) {
        dst[i] = src[i];
    }
}


void rewrite() {}

void access () {
    urilen = wngx_get_uri(buffs[1], buff_size);
}

void header_filter() {
    string_copy(buffs[2], "X-hello", 7);
    wngx_add_header(buffs[2], 7, buffs[1], urilen);
}

void body_filter() {}

void do_log() {}
