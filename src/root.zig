const std = @import("std");
const builtin = @import("builtin");
const Allocator = std.mem.Allocator;

pub const AutoSplitterInfo = extern struct {
    Chapter: i32 = undefined,
    Mode: i32 = undefined,
    Level: usize = undefined,
    TimerActive: bool = undefined,
    ChapterStarted: bool = undefined,
    ChapterComplete: bool = undefined,
    ChapterTime: i64 = undefined,
    ChapterStrawberries: i32 = undefined,
    ChapterCassette: bool = undefined,
    ChapterHeart: bool = undefined,
    FileTime: i64 = undefined,
    FileStrawberries: i32 = undefined,
    FileCassettes: i32 = undefined,
    FileHearts: i32 = undefined,
};

pub const celeste = switch (builtin.os.tag) {
    .linux => @import("linux/celeste.zig"),
    .windows => @import("windows/celeste.zig"),
    else => @compileError("Unsupported Platform"),
};

pub fn getASI(allocator: Allocator, asi_class: celeste.Class, asi_instance: usize) !AutoSplitterInfo {
    const buf = try asi_class.readToBuffer(allocator, asi_instance);

    var res: AutoSplitterInfo = .{};

    inline for (@typeInfo(AutoSplitterInfo).@"struct".fields) |field| {
        const class_field = try asi_class.findField(field.name);
        const val = try class_field.readValueFromBuffer(field.type, buf);
        @field(res, field.name) = val;
    }
    allocator.free(buf);
    return res;
}

// pub const Handle = switch (builtin.os.tag) {
//     .linux => @import("linux/celeste.zig").Handle,
//     .windows => @import("windows/celeste.zig").Process,
// };
