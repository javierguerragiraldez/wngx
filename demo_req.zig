const std = @import("std");
const wngx = @import("wngx.zig");

var req : ?wngx.Request = null;

export fn rewrite() void {}

export fn access() void {
    req = wngx.Request.init(wngx.default_allocator) catch return;
    wngx.log(0x100, "req: {}", .{req});
}

export fn header_filter() void {
    wngx.add_header("X-zig-here", req.?.uri);
}

export fn body_filter() void {}

export fn do_log() void {}
