
extern fn wngx_log(level: u32, msg: *const u8, msglen: u32) void;

pub fn log(level: u32, msg: []const u8) void {
    wngx_log(level, &msg[0], msg.len);
}
