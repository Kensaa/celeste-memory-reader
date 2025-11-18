//! By convention, root.zig is the root source file when making a library.
const std = @import("std");
const builtin = @import("builtin");
pub const mem = @import("mem/mem.zig");

const Allocator = std.mem.Allocator;

pub fn findCeleste(allocator: Allocator) ?*mem.ProcessHandle {
    const celesteName = switch (builtin.os.tag) {
        .linux => "Celeste.bin.x86_64",
        .windows => "Celeste.exe",
        else => @compileError("Unsupported Platform"),
    };

    const maybe_pid = mem.searchProcess(celesteName);
    if (maybe_pid) |pid| {
        // Celeste process found
        // TODO: better check
        const handle = mem.openProcess(allocator, pid) catch null;
        return handle;
    } else {
        // Celeste not found
        return null;
    }
}
