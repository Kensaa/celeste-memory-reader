const std = @import("std");
const windows = std.os.windows;
const Allocator = std.mem.Allocator;

const c = @cImport({
    @cInclude("dotnet_reflection.h");
});

const ReadError = error{ FailedToRead, ReadTooSmall };
pub const Field = struct {
    handle: *c.DotNetField,
    class: Class,
    pub fn getName(self: Field) []const u8 {
        const name = c.fieldGetName(self.handle);
        return std.mem.span(name);
    }
    pub fn getOffset(self: Field) u32 {
        const offset = c.fieldGetOffset(self.handle);
        return offset;
    }
    pub fn isStatic(self: Field) bool {
        const static = c.fieldIsStatic(self.handle);
        return static;
    }
    pub fn getTypeName(self: Field) []const u8 {
        const name = c.fieldGetTypeName(self.handle);
        return std.mem.span(name);
    }

    const ReadValueError = ReadError || error{FieldNotStatic};
    pub fn readValueFromMemory(self: Field, comptime T: type, instance_address: ?usize) !T {
        switch (@typeInfo(T)) {
            .int => {},
            else => @compileError("getValue type must be an Int"),
        }

        if (self.isStatic()) {
            var value: u64 = 0;
            const success = c.fieldGetStaticValue(self.class.process.handle, self.handle, &value);
            if (success) {
                return @intCast(value);
            } else {
                return ReadValueError.FailedToRead;
            }
        } else {
            if (instance_address) |address| {
                return readType(self.class.process, T, address + self.getOffset());
            } else {
                return ReadValueError.FieldNotStatic;
            }
        }
    }

    pub fn readValueFromBuffer(self: Field, comptime T: type, buffer: []u8) !T {
        const offset = self.getOffset();
        const size = @sizeOf(T);
        return switch (@typeInfo(T)) {
            .bool => blk: {
                break :blk buffer[offset] != 0;
            },
            else => blk: {
                var res: T = 0;
                for (0..size) |i| {
                    const addr = offset + (size - i - 1);
                    if (addr >= buffer.len) return ReadValueError.ReadTooSmall;
                    res = (res << 8) | (buffer[addr]);
                }
                break :blk res;
            },
        };
    }
};

pub const Class = struct {
    handle: *c.DotNetClass,
    process: Process,

    pub fn getName(self: Class) []const u8 {
        const name = c.classGetName(self.handle);
        return std.mem.span(name);
    }
    pub fn getNamespace(self: Class) []const u8 {
        const name = c.classGetNamespace(self.handle);
        return std.mem.span(name);
    }
    pub fn getFullName(self: Class) []const u8 {
        const name = c.classGetFullName(self.handle);
        return std.mem.span(name);
    }
    pub fn getSize(self: Class) u32 {
        const size = c.classGetSize(self.handle);
        return size;
    }

    const FindFieldError = error{FieldNotFound};
    pub fn findField(self: Class, field_name: []const u8) !Field {
        if (c.classFindField(self.handle, @ptrCast(@constCast(field_name)))) |field| {
            return Field{ .handle = field, .class = self };
        }
        return FindFieldError.FieldNotFound;
    }

    pub fn printFields(self: Class) void {
        std.debug.print("class size : {d}\n", .{self.getSize()});
        c.classPrintFields(self.handle);
    }

    pub fn readToBuffer(self: Class, allocator: Allocator, instance_address: usize) ![]u8 {
        var buffer = try allocator.alloc(u8, self.getSize());

        try readBuffer(self.process, &buffer, instance_address);
        return buffer;
    }
};

pub const Process = struct {
    pid: u32,
    handle: *c.DotNetProcess,
    const AttachError = error{FailedToAttach};
    pub fn attach(process_id: u32) !Process {
        if (c.openProcess(process_id)) |handle| {
            return Process{
                .pid = process_id,
                .handle = handle,
            };
        }
        return AttachError.FailedToAttach;
    }

    pub fn detach(self: Process) void {
        c.closeProcess(self.handle);
    }

    const FindClassError = error{ClassNotFound};
    pub fn findClass(self: Process, class_name: []const u8) !Class {
        if (c.findClass(self.handle, @ptrCast(@constCast(class_name)))) |class| {
            return .{ .handle = class, .process = self };
        }
        return FindClassError.ClassNotFound;
    }
};

pub fn openCeleste() !?Process {
    const processName = "Celeste.exe";
    const pid = c.findProcess(@ptrCast(@constCast(processName)));
    if (pid == 0) {
        return null;
    }

    return try Process.attach(pid);
}

pub extern "kernel32" fn ReadProcessMemory(
    hProcess: windows.HANDLE,
    lpBaseAddress: windows.LPCVOID,
    lpBuffer: windows.LPVOID,
    nSize: windows.SIZE_T,
    lpNumberOfBytesRead: ?*windows.SIZE_T,
) callconv(.winapi) windows.BOOL;

pub fn readBuffer(handle: Process, buffer: *[]u8, address: usize) !void {
    var count: usize = undefined;
    const success = ReadProcessMemory(c.getProcessHandle(handle.handle).?, @ptrFromInt(address), buffer.ptr, buffer.len, &count);

    if (success == 0) {
        std.debug.print("error : {d}\n", .{windows.GetLastError()});
        return ReadError.FailedToRead;
    }

    if (count != buffer.len) return ReadError.ReadTooSmall;
}
pub fn readType(handle: Process, comptime T: type, address: usize) !T {
    var res: T = undefined;
    var count: usize = undefined;
    const success = ReadProcessMemory(c.getProcessHandle(handle.handle).?, @ptrFromInt(address), &res, @sizeOf(T), &count);

    if (success == 0) {
        std.debug.print("error : {d}\n", .{windows.GetLastError()});
        return ReadError.FailedToRead;
    }

    if (count != @sizeOf(T)) return ReadError.ReadTooSmall;

    return res;
}
