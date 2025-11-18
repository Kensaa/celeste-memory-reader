const std = @import("std");
const root = @import("mem.zig");
const ProcessHandle = root.ProcessHandle;
const pid_t = root.pid_t;

const windows = std.os.windows;

pub extern "kernel32" fn OpenProcess(dwDesiredAccess: windows.DWORD, bInheritHandle: windows.BOOL, dwProcessId: windows.DWORD) callconv(.winapi) ?windows.HANDLE;
pub extern "kernel32" fn EnumProcesses(lpidProcess: *windows.DWORD, cb: windows.DWORD, lpcbNeeded: *windows.DWORD) callconv(.winapi) windows.BOOL;
pub extern "psapi" fn GetModuleBaseNameA(
    hProcess: windows.HANDLE,
    hModule: ?windows.HMODULE,
    lpBaseName: [*]u8,
    nSize: windows.DWORD,
) callconv(.winapi) windows.DWORD;
pub extern "kernel32" fn ReadProcessMemory(
    hProcess: windows.HANDLE,
    lpBaseAddress: windows.LPCVOID,
    lpBuffer: windows.LPVOID,
    nSize: windows.SIZE_T,
    lpNumberOfBytesRead: ?*windows.SIZE_T,
) callconv(.winapi) windows.BOOL;

const PROCESS_QUERY_INFORMATION = 0x0400;
const PROCESS_VM_READ = 0x0010;

pub fn searchProcess(target: []const u8) ?pid_t {
    var process_ids: [1024]windows.DWORD = undefined;
    var needed: windows.DWORD = 0;

    if (EnumProcesses(
        &process_ids[0],
        @sizeOf(@TypeOf(process_ids)),
        &needed,
    ) == 0)
        return null;

    const count: usize = @intCast(needed / @sizeOf(windows.DWORD));

    for (process_ids[0..count]) |pid| {
        if (pid == 0) continue;

        if (OpenProcess(
            PROCESS_QUERY_INFORMATION | PROCESS_VM_READ,
            windows.FALSE,
            pid,
        )) |handle| {
            if (handle == windows.INVALID_HANDLE_VALUE) continue;

            var name_buf: [260]u8 = undefined;
            const name_len = GetModuleBaseNameA(handle, @ptrFromInt(0), &name_buf, name_buf.len);

            if (name_len > 0) {
                const name = name_buf[0..name_len];
                // std.debug.print("name: {s}\n", .{name});
                if (std.mem.indexOf(u8, name, target)) |_| {
                    return pid;
                }
            }

            windows.CloseHandle(handle);
        }
    }

    return null;
}

const OpenError = error{InvalidHandle};
pub fn openProcess(allocator: std.mem.Allocator, pid: pid_t) !*ProcessHandle {
    const maybe_handle = OpenProcess(PROCESS_VM_READ, windows.FALSE, pid);
    if (maybe_handle) |handle| {
        if (handle == windows.INVALID_HANDLE_VALUE) {
            return OpenError.InvalidHandle;
        }

        var processHandle = try allocator.create(ProcessHandle);
        processHandle.handle = handle;
        return processHandle;
    }

    return OpenError.InvalidHandle;
}

pub fn read(handle: *ProcessHandle, comptime T: type, address: u64) !T {
    var res: T = undefined;
    var count: usize = undefined;
    const success = ReadProcessMemory(handle.handle, @ptrFromInt(address), &res, @sizeOf(T), &count);

    if (success == 0) return root.ReadError.FailedToRead;
    if (count != @sizeOf(T)) return root.ReadError.ReadTooSmall;

    return res;
}

pub fn freeProcess(allocator: std.mem.Allocator, handle: *ProcessHandle) void {
    windows.CloseHandle(handle.handle);
    allocator.destroy(handle);
}
