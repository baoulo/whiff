// Tide model in Zig
const std = @import("std");
const model = @import("model.zig");

pub const Tide = struct {
    hour: u8,
    height: f64,
};

pub fn average(tides: []const Tide) f64 {
    var sum: f64 = 0;
    for (tides) |t| sum += t.height;
    return sum / @as(f64, @floatFromInt(tides.len));
}
