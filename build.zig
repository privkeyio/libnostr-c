const std = @import("std");

pub fn build(b: *std.Build) void {
    const target = b.standardTargetOptions(.{});
    const optimize = b.standardOptimizeOption(.{});

    const mod = b.createModule(.{
        .target = target,
        .optimize = optimize,
        .link_libc = true,
    });

    const lib = b.addLibrary(.{
        .name = "nostr",
        .root_module = mod,
        .linkage = .static,
    });

    mod.addCSourceFiles(.{
        .files = &.{
            "src/event.c",
            "src/key.c",
            "src/utils.c",
            "src/config.c",
            "src/features.c",
            "src/bech32.c",
            "src/nip13.c",
            "src/zap.c",
            "src/relay_protocol.c",
        },
        .flags = &.{ "-std=c99", "-D_GNU_SOURCE" },
    });

    mod.addIncludePath(b.path("include"));
    mod.linkSystemLibrary("crypto", .{});
    mod.linkSystemLibrary("cjson", .{});
    mod.linkSystemLibrary("secp256k1", .{});

    b.installArtifact(lib);
}
