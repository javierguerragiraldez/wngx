const std = @import("std");
const wngx = @import("wngx.zig");

var req : ?wngx.Request = null;


export fn req_access() void {
    req = wngx.Request.init(wngx.default_allocator) catch return;
    var r = req orelse return;

    wngx.log(0x100, "req: {}", .{r});
    var hdr_it = r.headers.iterator();
    while(hdr_it.next()) |kv| {
        wngx.log(0x100, "  - {}: {}", .{ kv.key, kv.value });
    }
}

export fn res_header_filter() void {
    wngx.add_header("X-zig-here", req.?.uri);
}
