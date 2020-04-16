const std = @import("std");


var allocator_arena = std.heap.ArenaAllocator.init(std.heap.page_allocator);
pub const default_allocator = &allocator_arena.allocator;


extern fn wngx_log(level: u32, msg: [*]const u8, msglen: u32) void;
extern fn wngx_request_size() u32;
extern fn wngx_get_request(buf: [*]u8, buflen: u32) void;
extern fn wngx_add_header(key: [*]const u8, key_len: u32, val: [*]const u8, val_len: u32) void;

pub fn log(level: u32, comptime fmt: []const u8, args: var) void {
    const bufsize = 4096;
    var buf: [bufsize]u8 = undefined;
    var ostrm = std.io.fixedBufferStream(&buf);

    ostrm.outStream().print(fmt, args) catch return;

    wngx_log(level, &buf, ostrm.pos);
}


const w_string = extern struct {
    d: ?[*]u8,
    len: u32,

    fn toSlice(self: w_string) ?[]const u8 {
        const d = self.d orelse return null;
        return d[0..self.len];
    }
};

const w_header = extern struct {
    name: w_string,
    value: w_string,
};

const w_request = extern struct {
    n_headers: u32,
    buf_start: *u8,
    total_size: u32,

    request_line: w_string,
    method: w_string,
    uri: w_string,
    http_version: w_string,

    uri_path: w_string,
    uri_args: w_string,
    uri_exten: w_string,
};

pub const Request = struct {
    request_line: []const u8,
    method: []const u8,
    uri: []const u8,
    http_version: []const u8,

    uri_path: []const u8,
    uri_args: []const u8,
    uri_exten: []const u8,

    const HeaderMap = std.StringHashMap([]const u8);

    headers: HeaderMap,

    pub fn init(allocator: *std.mem.Allocator) !Request {
        var request_bytes = try allocator.alignedAlloc(u8, @alignOf(w_request), wngx_request_size());
        wngx_get_request(request_bytes.ptr, request_bytes.len);
        var w_req = @ptrCast(*w_request, request_bytes.ptr);

        return Request {
            .request_line = w_req.request_line.toSlice() orelse "",
            .method = w_req.method.toSlice() orelse "",
            .uri = w_req.uri.toSlice() orelse "",
            .http_version = w_req.http_version.toSlice() orelse "",
            .uri_path = w_req.uri_path.toSlice() orelse "",
            .uri_args = w_req.uri_args.toSlice() orelse "",
            .uri_exten = w_req.uri_exten.toSlice() orelse "",

            .headers = HeaderMap.init(allocator),
        };
    }
};

pub fn add_header(key: []const u8, val: []const u8) void {
    wngx_add_header(key.ptr, key.len, val.ptr, val.len);
}
