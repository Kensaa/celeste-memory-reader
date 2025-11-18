const std = @import("std");
const builtin = @import("builtin");
const celeste_memory_reader = @import("celeste_memory_reader");

pub fn main() !void {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    const allocator = gpa.allocator();
    // const maybe_pid = celeste_memory_reader.mem.searchProcess("Celeste.bin.x86_64");

    const maybe_celeste = try celeste_memory_reader.findCeleste(allocator);
    defer if (maybe_celeste) |celeste| {
        celeste_memory_reader.mem.freeProcess(allocator, celeste);
    };

    if (maybe_celeste == null) {
        std.debug.print("Celeste not found\n", .{});
        return;
    }
    // const celeste = maybe_celeste;
}
