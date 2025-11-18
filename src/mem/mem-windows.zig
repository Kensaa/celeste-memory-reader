const std = @import("std");
const root = @import("mem.zig");
const ProcessHandle = root.ProcessHandle;
const pid_t = root.pid_t;

const windows = std.os.windows;

pub extern "kernel32" fn OpenProcess(dwDesiredAccess: windows.DWORD, bInheritHandle: windows.BOOL, dwProcessId: windows.DWORD) callconv(.winapi) windows.HANDLE;
pub extern "kernel32" fn EnumProcesses(lpidProcess: *windows.DWORD, cb: windows.DWORD, lpcbNeeded: *windows.DWORD) callconv(.winapi) windows.BOOL;

const PROCESS_QUERY_INFORMATION = 0x0400;
const PROCESS_VM_READ = 0x0010;

const WindowsProcessHandle = struct {};
pub fn searchProcess(_: []const u8) ?pid_t {
    // var processes: [1024]windows.DWORD = undefined;

    // EnumProcesses(&processes, 0, 0);

    // const res = OpenProcess(PROCESS_QUERY_INFORMATION |
    //     PROCESS_VM_READ, windows.FALSE, 0);

    // std.debug.print("aaa : {}\n", .{res});
    // return 1;
    unreachable;
}

pub fn openProcess(_: std.mem.Allocator, _: pid_t) !*ProcessHandle {
    unreachable;
}

pub fn read(_: *ProcessHandle, comptime T: type, _: u64) !T {
    unreachable;
}

pub fn freeProcess(_: std.mem.Allocator, _: *ProcessHandle) void {
    unreachable;
}
