const std = @import("std");
const wngx = @import("wngx.zig");

export fn rewrite() void {}

export fn access() void {
    wngx.log(0x100, "with an api?");
}

export fn header_filter() void {}

export fn body_filter() void {}

export fn do_log() void {}
