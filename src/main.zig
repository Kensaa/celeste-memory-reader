const std = @import("std");
const builtin = @import("builtin");
const celeste_memory_reader = @import("celeste_memory_reader");

pub fn main() !void {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    const allocator = gpa.allocator();
    // const maybe_pid = celeste_memory_reader.mem.searchProcess("Celeste.bin.x86_64");

    const celeste = celeste_memory_reader.findCeleste(allocator);
    defer if (celeste) |handle| {
        celeste_memory_reader.mem.freeProcess(allocator, handle);
    };
}
