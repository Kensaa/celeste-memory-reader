const std = @import("std");
const builtin = @import("builtin");

const os = builtin.os.tag;
pub const ProcessHandle = switch (os) {
    .windows => struct { handle: std.os.windows.HANDLE },
    .linux => struct { file: std.fs.File },
    else => @compileError("Unsupported Platform"),
};

const Impl = switch (builtin.os.tag) {
    .windows => @import("mem-windows.zig"),
    .linux => @import("mem-linux.zig"),
    else => @compileError("Unsupported Platform"),
};

pub const pid_t = switch (builtin.os.tag) {
    .windows => u32,
    .linux => std.os.linux.pid_t,
    else => @compileError("Unsupported Platform"),
};

pub fn searchProcess(name: []const u8) ?pid_t {
    return Impl.searchProcess(name);
}

pub fn openProcess(allocator: std.mem.Allocator, pid: pid_t) !*ProcessHandle {
    return Impl.openProcess(allocator, pid);
}

pub const ReadError = error{ ReadTooSmall, FailedToRead };
pub fn read(handle: *ProcessHandle, comptime T: type, address: u64) !T {
    return Impl.read(handle, T, address);
}
pub fn freeProcess(allocator: std.mem.Allocator, handle: *ProcessHandle) void {
    return Impl.freeProcess(allocator, handle);
}
