const std = @import("std");
const root = @import("mem.zig");
const ProcessHandle = root.ProcessHandle;
const pid_t = root.pid_t;

const max_path_bytes = std.fs.max_path_bytes;
pub fn searchProcess(target: []const u8) ?pid_t {
    var procDir = std.fs.openDirAbsolute("/proc", .{ .iterate = true }) catch return null;
    defer procDir.close();

    var iterator = procDir.iterate();

    var pathbuf: [max_path_bytes]u8 = undefined;
    var executablebuf: [max_path_bytes]u8 = undefined;
    while (iterator.next() catch null) |dirEntry| {
        const path = std.fmt.bufPrintZ(&pathbuf, "/proc/{s}/exe", .{dirEntry.name}) catch continue;
        const executable = std.fs.readLinkAbsoluteZ(path, &executablebuf) catch continue;

        if (std.mem.indexOf(u8, executable, target)) |_| {
            return std.fmt.parseInt(i32, dirEntry.name, 10) catch null;
        }
    }

    return null;
}

pub fn openProcess(allocator: std.mem.Allocator, pid: pid_t) !*ProcessHandle {
    var pathbuf: [max_path_bytes]u8 = undefined;

    const path = try std.fmt.bufPrintZ(&pathbuf, "/proc/{d}/mem", .{pid});
    const file = try std.fs.openFileAbsoluteZ(path, .{ .mode = .read_only });

    var handle = try allocator.create(ProcessHandle);
    handle.file = file;

    return handle;
}

pub fn read(handle: *ProcessHandle, comptime T: type, address: u64) !T {
    var file = handle.file;

    try file.seekTo(address);

    var res: T = undefined;
    const count = try file.read(&res);
    if (count != @sizeOf(T)) {
        return root.ReadError.ReadTooSmall;
    }
    return res;
}

pub fn freeProcess(allocator: std.mem.Allocator, handle: *ProcessHandle) void {
    var file = handle.file;
    file.close();
    allocator.destroy(handle);
}
