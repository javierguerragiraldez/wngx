
const unsigned buff_size = 1024;
char buff[buff_size];
unsigned urilen = 0;

#define LIT_AND_LEN(s) (s), (sizeof(s)-1)

extern int wngx_get_uri(char *buf, unsigned len);
extern void wngx_add_header(const char *key, unsigned key_len, const char *val, unsigned val_len);


// void rewrite() {}

void req_access () {
    urilen = wngx_get_uri(buff, buff_size);
}

void res_header_filter() {
    wngx_add_header(LIT_AND_LEN("X-C-says-help"), buff, urilen);
}

// void res_body_filter() {}

// void on_log() {}
