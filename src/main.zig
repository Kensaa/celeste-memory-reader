const std = @import("std");
const celeste_memory_reader = @import("celeste_memory_reader");

pub fn main() !void {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    const allocator = gpa.allocator();
    const maybe_pid = celeste_memory_reader.mem.searchProcess("Celeste.bin.x86_64");
    // const maybe_pid = celeste_memory_reader.mem.searchProcess("brave");
    if (maybe_pid) |pid| {
        std.debug.print("Found process {d}\n", .{pid});

        _ = try celeste_memory_reader.mem.openProcess(allocator, pid);
    } else {
        std.debug.print("Process not found\n", .{});
    }
}
