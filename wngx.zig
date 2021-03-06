const std = @import("std");


var allocator_arena = std.heap.ArenaAllocator.init(std.heap.page_allocator);
pub const default_allocator = &allocator_arena.allocator;


extern fn wngx_log(level: u32, msg: [*]const u8, msglen: u32) void;
extern fn wngx_request_size() u32;
extern fn wngx_get_request(buf: [*]u8, buflen: u32) void;
extern fn wngx_add_header(key: [*]const u8, key_len: u32, val: [*]const u8, val_len: u32) void;
extern fn wngx_subrequest(req: *w_subrequest_params, cb: fn (req: *w_subrequest_params) u32) u32;

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

    fn new(s: []const u8) w_string {
        return w_string {
            .d = s.ptr,
            .len = s.len,
        };
    }

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
    const HeaderMap = std.StringHashMap([]const u8);

    request_line: []const u8,
    method: []const u8,
    uri: []const u8,
    http_version: []const u8,

    uri_path: []const u8,
    uri_args: []const u8,
    uri_exten: []const u8,

    headers: HeaderMap,

    pub fn init(allocator: *std.mem.Allocator) !Request {
        var request_bytes = try allocator.alignedAlloc(u8, @alignOf(w_request), wngx_request_size());
        wngx_get_request(request_bytes.ptr, request_bytes.len);
        var w_req = @ptrCast(*w_request, request_bytes.ptr);

        var w_hd = @ptrCast([*]w_header, request_bytes.ptr + @sizeOf(w_request))[0..w_req.n_headers];

        return Request {
            .request_line = w_req.request_line.toSlice() orelse "",
            .method = w_req.method.toSlice() orelse "",
            .uri = w_req.uri.toSlice() orelse "",
            .http_version = w_req.http_version.toSlice() orelse "",
            .uri_path = w_req.uri_path.toSlice() orelse "",
            .uri_args = w_req.uri_args.toSlice() orelse "",
            .uri_exten = w_req.uri_exten.toSlice() orelse "",

            .headers = header_hash(allocator, w_hd),
        };
    }

    fn header_hash(allocator: *std.mem.Allocator, w_hdrs: []const w_header) HeaderMap {
        var headers = HeaderMap.init(allocator);

        for (w_hdrs) |w_h| {
            const key = w_h.name.toSlice() orelse continue;
            const val = w_h.value.toSlice() orelse continue;
            _ = headers.put(key, val) catch return headers;
        }

        return headers;
    }
};

pub fn add_header(key: []const u8, val: []const u8) void {
    wngx_add_header(key.ptr, key.len, val.ptr, val.len);
}

export fn on_callback( w_d: ?*u8 ) u32 {
    log(0x100, "on_callback: w_d: {}", .{w_d});
    const d = @ptrCast(*w_subrequest_params, @alignCast(4, w_d));
    return d.callback.f(d);
}

const w_subrequest_params = extern struct {
    callback: *cb_wrapper,
    uri: w_string,
    args: w_string,
    ref: u32,
    data: *SubRequest,
};

const cb_wrapper = struct {
    f: fn (data: *w_subrequest_params) u32,
};

pub const SubRequest = struct {
    ref: u32,

    pub fn fetch(uri: []const u8, args: []const u8) !SubRequest {
        var self = SubRequest{};
        var params = w_subrequest_params {
            .callback = .{ .f = self.callback },
            .uri = w_string.new(uri),
            .args = w_string.new(args),
            .data = self,
        };

        self.ref = wngx_subrequest(&params);
        if (self.ref == 0) return error.SubRequestFail;

        return self;
    }

    pub fn callback(req: *w_subrequest_params) u32 {
        log(0x100, "callback req: {}, data: {}", .{req, data});
        return 1;
    }
};
