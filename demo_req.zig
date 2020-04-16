const std = @import("std");

pub extern fn wngx_log(level: u32, msg: *const u8, msglen: u32) void;

export fn rewrite() void {}

export fn access() void {
    const msg = "from access (zig/wasm)";
    wngx_log(0x100, &msg[0], msg.len);
}

export fn header_filter() void {}

export fn body_filter() void {}

export fn do_log() void {}
