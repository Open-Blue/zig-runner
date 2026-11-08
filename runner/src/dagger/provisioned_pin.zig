//! The pre-provisioned default images the runner pulls instead of provisioning (provisioned.zig),
//! pinned by digest. Written by `.github/scripts/provisioned-pin.sh --update` after the
//! "provisioned image" workflow published them, never by hand. An empty digest pins none: the
//! runner provisions with apt, as it did before there was an image.

pub const root: Pin = .{
    .fingerprint = "",
    .digest = "",
};
pub const runner: Pin = .{
    .fingerprint = "",
    .digest = "",
};

/// One variant's image: the fingerprint the image was built for (provisioned.zig, `fingerprint`;
/// the tag, with `-root` or `-runner`), and the digest of its multi-arch index.
pub const Pin = struct {
    fingerprint: []const u8,
    digest: []const u8,
};
