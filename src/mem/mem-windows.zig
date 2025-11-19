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
extern "psapi" fn EnumProcessModulesEx(
    hProcess: windows.HANDLE,
    lphModule: *windows.HMODULE,
    cb: windows.DWORD,
    lpcbNeeded: *windows.DWORD,
    dwFilterFlag: windows.DWORD,
) callconv(.winapi) windows.BOOL;
extern "psapi" fn GetModuleFileNameExW(
    hProcess: windows.HANDLE,
    hModule: windows.HMODULE,
    lpFilename: [*]u16,
    nSize: windows.DWORD,
) callconv(.winapi) windows.DWORD;

const PROCESS_QUERY_INFORMATION = 0x0400;
const PROCESS_VM_READ = 0x0010;
const PROCESS_VM_OPERATION = 0x0008;

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
    const maybe_handle = OpenProcess(PROCESS_VM_READ | PROCESS_VM_OPERATION | PROCESS_QUERY_INFORMATION, windows.FALSE, pid);
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

    if (success == 0) {
        std.debug.print("error : {d}\n", .{windows.GetLastError()});
        return root.ReadError.FailedToRead;
    }

    if (count != @sizeOf(T)) return root.ReadError.ReadTooSmall;

    return res;
}

pub fn freeProcess(allocator: std.mem.Allocator, handle: *ProcessHandle) void {
    windows.CloseHandle(handle.handle);
    allocator.destroy(handle);
}

const RootDomainError = error{RootDomainNotFound};
pub fn findMonoRootDomain(allocator: std.mem.Allocator, handle: *ProcessHandle) !u64 {
    var needed: windows.DWORD = 0;
    var modules_buf: [1024]windows.HMODULE = undefined;

    if (EnumProcessModulesEx(
        handle.handle,
        &modules_buf[0],
        @sizeOf(@TypeOf(modules_buf)),
        &needed,
        0x3, //LIST_MODULES_ALL
    ) == 0) {
        std.debug.print("EnumProcessModulesEx failed : {}\n", .{windows.GetLastError()});
        return RootDomainError.RootDomainNotFound;
    }

    const count = needed / @sizeOf(windows.HMODULE);
    std.debug.print("Found {d} modules\n", .{count});

    for (modules_buf[0..count]) |hModule| {
        var filename: [windows.MAX_PATH]u16 = undefined;

        const length = GetModuleFileNameExW(
            handle.handle,
            hModule,
            &filename,
            filename.len,
        );

        if (length == 0) {
            std.debug.print("Failed to get module name. Error: {}\n", .{windows.kernel32.GetLastError()});
            continue;
        }

        // Convert the UTF-16 module path to UTF-8 for printing
        const utf8_filename = try std.unicode.utf16LeToUtf8Alloc(allocator, filename[0..length]);
        defer allocator.free(utf8_filename);

        std.debug.print("Module: {s}\n", .{utf8_filename});
    }
    return 0;
}
