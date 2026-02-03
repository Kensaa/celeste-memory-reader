const std = @import("std");
const Allocator = std.mem.Allocator;

pub const Field = struct {
    pub fn getName(self: Field) []const u8 {
        _ = self;
        @panic("not implemented");
    }
    pub fn getOffset(self: Field) u32 {
        _ = self;
        @panic("not implemented");
    }
    pub fn isStatic(self: Field) bool {
        _ = self;
        @panic("not implemented");
    }
    pub fn getTypeName(self: Field) []const u8 {
        _ = self;
        @panic("not implemented");
    }
    pub fn readValueFromMemory(self: Field, comptime T: type, instance_address: ?usize) !T {
        _ = self;
        _ = instance_address;
        @panic("not implemented");
    }
    pub fn readValueFromBuffer(self: Field, comptime T: type, buffer: []u8) !T {
        _ = self;
        _ = buffer;
        @panic("not implemented");
    }
};
pub const Class = struct {
    pub fn getName(self: Class) []const u8 {
        _ = self;
        @panic("not implemented");
    }
    pub fn getNamespace(self: Class) []const u8 {
        _ = self;
        @panic("not implemented");
    }
    pub fn getFullName(self: Class) []const u8 {
        _ = self;
        @panic("not implemented");
    }
    pub fn getSize(self: Class) u32 {
        _ = self;
        @panic("not implemented");
    }

    pub fn findField(self: Class, field_name: []const u8) !Field {
        _ = self;
        _ = field_name;
        @panic("not implemented");
    }
    pub fn printFields(self: Class) void {
        _ = self;
        @panic("not implemented");
    }
    pub fn readToBuffer(self: Class, allocator: Allocator, instance_address: usize) ![]u8 {
        _ = self;
        _ = allocator;
        _ = instance_address;
        @panic("not implemented");
    }
};
pub const Process = struct {
    pub fn attach(process_id: u32) !Process {
        _ = process_id;
        @panic("not implemented");
    }
    pub fn detach(self: Process) void {
        _ = self;
        @panic("not implemented");
    }
    pub fn findClass(self: Process, class_name: []const u8) !Class {
        _ = self;
        _ = class_name;
        @panic("not implemented");
    }
};

pub fn openCeleste() !?Process {
    @panic("not implemented");
}
