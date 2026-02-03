const std = @import("std");
const builtin = @import("builtin");
const celeste_memory_reader = @import("celeste_memory_reader");

pub fn main() !void {
    var gpa = std.heap.GeneralPurposeAllocator(.{}).init;
    const allocator = gpa.allocator();
    defer {
        const deinit_status = gpa.deinit();
        //fail test; can't try in defer as defer is executed after we return
        if (deinit_status == .leak) std.testing.expect(false) catch @panic("TEST FAIL");
    }
    if (try celeste_memory_reader.celeste.openCeleste()) |celeste| {
        defer celeste.detach();
        // std.debug.print("test2\n", .{});
        std.debug.print("pid: {d}\n", .{celeste.pid});
        const celesteClass = try celeste.findClass("Celeste.Celeste");
        // celesteClass.printFields();
        const asiClass = try celeste.findClass("Celeste.AutoSplitterInfo");
        // asiClass.printFields();

        // const instanceField = try celesteClass.findField("Instance");
        // const asiField = try celesteClass.findField("AutoSplitterInfo");
        const celesteInstance = try (try celesteClass.findField("Instance")).readValueFromMemory(u32, null);
        std.debug.print("celeste instance : 0x{X}\n", .{celesteInstance});
        const celesteASIField = try celesteClass.findField("AutoSplitterInfo");

        // const chapterField = try asiClass.findField("Chapter");
        // std.debug.print("asiInstance: 0x{X}\n", .{asiInstance});
        // std.debug.print("offset : 0x{X}\n", .{chapterField.getOffset()});
        // const chapterAddress = asiInstance + chapterField.getOffset();
        // while (true) {
        // const chapterMem = try chapterField.readValueFromMemory(i32, asiInstance);

        // std.debug.print("chapter addr 0x{X}\n", .{chapterAddress});
        // const modeField = try asiClass.findField("Mode");
        // std.debug.print("{d}\n", .{modeField.getOffset() - chapterField.getOffset()});
        // std.debug.print("current chapter (mem) : {}\n", .{chapterMem});

        while (true) {
            // const asiBuffer = try asiClass.readToBuffer(allocator, asiInstance);
            // defer allocator.free(asiBuffer);

            // const asiChapterField = try asiClass.findField("Chapter");
            // const chapterBuf = try asiChapterField.readValueFromBuffer(i32, asiBuffer);

            // const asi = try celeste_memory_reader.read(celeste, celeste_memory_reader.AutoSplitterInfo, asiInstance);
            const before = try std.time.Instant.now();
            const asiInstance = try celesteASIField.readValueFromMemory(u32, celesteInstance);
            const asi = try celeste_memory_reader.getASI(allocator, asiClass, asiInstance);
            const after = try std.time.Instant.now();
            std.debug.print("time : {d}us\n", .{(after.since(before)) / 1000});

            std.debug.print("asi address : 0x{X}\n", .{asiInstance});
            inline for (@typeInfo(celeste_memory_reader.AutoSplitterInfo).@"struct".fields) |field| {
                std.debug.print("{s} = {any}\n", .{ field.name, @field(asi, field.name) });
            }
            std.debug.print("\n", .{});
            var io = std.Io.Threaded.init_single_threaded;
            try std.Io.sleep(io.io(), std.Io.Duration.fromMilliseconds(1000), .awake);
        }
        // std.debug.print("Mode : {d}\n", .{asi.Mode});
        // std.debug.print("FileStrawberries : {d}\n", .    {asi.FileStrawberries});
    }
}
