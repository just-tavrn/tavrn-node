// SPDX-License-Identifier: AGPL-3.0-only
//! Upload categories (`protocol/PROTOCOL.md` §7a): which kinds of files a member may attach
//! in a conversation, and which files are executables the node refuses by default.
//!
//! A file falls into exactly one category: `images`, `audio`, `video`, `documents`, `archives` or `other`.
//! Plaintext uploads are classified by their content (magic bytes) first, then by the file name's
//! extension, then by the declared content type. Executables and other known-dangerous types (scripts,
//! installers, disk images, shortcuts …) count as `other` and are additionally flagged: they are refused
//! unless the node allows them (`TAVRN_UPLOAD_ALLOW_EXECUTABLES=true`) *and* the member may upload `other`.
//!
//! Who may upload what is a setting per role (`upload_categories`, a mask; unset = inherit), with
//! allow/deny masks on channel and category overrides, evaluated like permissions: the highest role with
//! a value wins (else `@everyone`), then the overrides on top. Encrypted uploads are ciphertext: the client
//! declares the category (`Tavrn-Upload-Category`) and the node checks the declaration (cooperative
//! enforcement; a modified client can lie, which the protocol documents).

use crate::permissions::{Override, SubjectType};

pub type Categories = u64;

pub const IMAGES: Categories = 1;
pub const AUDIO: Categories = 1 << 1;
pub const VIDEO: Categories = 1 << 2;
pub const DOCUMENTS: Categories = 1 << 3;
pub const ARCHIVES: Categories = 1 << 4;
pub const OTHER: Categories = 1 << 5;
pub const ALL: Categories = IMAGES | AUDIO | VIDEO | DOCUMENTS | ARCHIVES | OTHER;

/// Category names in API order, with their bit.
pub const NAMES: &[(&str, Categories)] = &[
    ("images", IMAGES),
    ("audio", AUDIO),
    ("video", VIDEO),
    ("documents", DOCUMENTS),
    ("archives", ARCHIVES),
    ("other", OTHER),
];

/// The default of `@everyone` in new rooms (and of DMs, `TAVRN_UPLOAD_DM_CATEGORIES`): everything. Safety
/// comes from the executable rule, which no role setting can lift on its own.
pub const DEFAULT_EVERYONE: Categories = ALL;

pub fn name_of(category: Categories) -> &'static str {
    NAMES.iter().find(|(_, bit)| *bit == category).map_or("other", |(n, _)| n)
}

pub fn names(mask: Categories) -> Vec<String> {
    NAMES.iter().filter(|(_, bit)| mask & bit != 0).map(|(n, _)| (*n).to_string()).collect()
}

/// Parses a list of category names; `None` if one is unknown.
pub fn parse_names<S: AsRef<str>>(list: &[S]) -> Option<Categories> {
    list.iter().try_fold(0, |acc, n| {
        let n = n.as_ref().trim().to_ascii_lowercase();
        NAMES.iter().find(|(name, _)| *name == n).map(|(_, bit)| acc | bit)
    })
}

/// File extensions that are executables, scripts, installers, disk images, shortcuts or otherwise known
/// to run code when opened (Windows, macOS, Linux, Android, Java, Office macros).
pub const DANGEROUS_EXTENSIONS: &[&str] = &[
    "exe",
    "msi",
    "msix",
    "msp",
    "appx",
    "appxbundle",
    "bat",
    "cmd",
    "com",
    "pif",
    "scr",
    "cpl",
    "hta",
    "reg",
    "lnk",
    "url",
    "inf",
    "ps1",
    "psm1",
    "psd1",
    "vbs",
    "vbe",
    "js",
    "jse",
    "mjs",
    "wsf",
    "wsh",
    "wsc",
    "sct",
    "jar",
    "class",
    "apk",
    "aab",
    "xapk",
    "ipa",
    "dmg",
    "pkg",
    "mpkg",
    "app",
    "command",
    "sh",
    "bash",
    "zsh",
    "csh",
    "ksh",
    "fish",
    "run",
    "bin",
    "elf",
    "deb",
    "rpm",
    "snap",
    "flatpakref",
    "appimage",
    "iso",
    "img",
    "vhd",
    "vhdx",
    "xll",
    "docm",
    "xlsm",
    "pptm",
    "dotm",
    "xltm",
    "potm",
    "ppam",
    "xlam",
    "gadget",
    "msc",
    "application",
    "scf",
    "dll",
    "sys",
    "drv",
    "ocx",
    "py",
    "pyw",
    "pl",
    "rb",
    "php",
    "desktop",
    "workflow",
    "action",
    "website",
    "settingcontent-ms",
];

const IMAGE_EXT: &[&str] =
    &["png", "jpg", "jpeg", "jfif", "gif", "webp", "avif", "bmp", "ico", "tif", "tiff", "heic", "heif"];
const AUDIO_EXT: &[&str] = &["mp3", "ogg", "oga", "opus", "wav", "flac", "m4a", "aac", "weba", "mid", "midi"];
const VIDEO_EXT: &[&str] = &["mp4", "m4v", "mov", "webm", "mkv", "avi", "ogv", "wmv", "flv", "3gp"];
const DOCUMENT_EXT: &[&str] = &[
    "pdf", "txt", "md", "markdown", "csv", "tsv", "json", "xml", "yaml", "yml", "toml", "ini", "cfg", "conf", "log",
    "rtf", "doc", "docx", "odt", "xls", "xlsx", "ods", "ppt", "pptx", "odp", "epub", "srt", "vtt",
    // SVG can carry scripts: a document (download only), never an inline image.
    "svg", "svgz",
];
const ARCHIVE_EXT: &[&str] = &["zip", "7z", "rar", "tar", "gz", "tgz", "bz2", "tbz2", "xz", "txz", "zst", "lz", "lzma"];

/// Is the lowercase extension `ext` in the dangerous list?
pub fn dangerous_extension(ext: &str) -> bool {
    DANGEROUS_EXTENSIONS.contains(&ext)
}

/// The lowercase last extension of a file name (`"a.tar.gz"` → `gz`), empty without one.
pub fn extension(name: &str) -> String {
    match name.trim().trim_end_matches(['.', ' ']).rsplit_once('.') {
        Some((stem, ext)) if !stem.is_empty() && !ext.is_empty() && ext.len() <= 24 => ext.to_ascii_lowercase(),
        _ => String::new(),
    }
}

fn category_of_extension(ext: &str) -> Option<Categories> {
    if IMAGE_EXT.contains(&ext) {
        Some(IMAGES)
    } else if AUDIO_EXT.contains(&ext) {
        Some(AUDIO)
    } else if VIDEO_EXT.contains(&ext) {
        Some(VIDEO)
    } else if DOCUMENT_EXT.contains(&ext) {
        Some(DOCUMENTS)
    } else if ARCHIVE_EXT.contains(&ext) {
        Some(ARCHIVES)
    } else {
        None
    }
}

fn category_of_mime(mime: &str) -> Option<Categories> {
    let mime = mime.split(';').next().unwrap_or("").trim().to_ascii_lowercase();
    let (top, sub) = mime.split_once('/')?;
    match top {
        "image" if sub == "svg+xml" => Some(DOCUMENTS),
        "image" => Some(IMAGES),
        "audio" => Some(AUDIO),
        "video" => Some(VIDEO),
        "text" => Some(DOCUMENTS),
        "application" => match sub {
            "pdf" | "json" | "xml" | "rtf" | "epub+zip" | "msword" | "vnd.ms-excel" | "vnd.ms-powerpoint" => {
                Some(DOCUMENTS)
            }
            s if s.starts_with("vnd.openxmlformats-officedocument.") || s.starts_with("vnd.oasis.opendocument.") => {
                Some(DOCUMENTS)
            }
            "zip" | "x-7z-compressed" | "vnd.rar" | "x-rar-compressed" | "x-tar" | "gzip" | "x-gzip" | "x-bzip2"
            | "x-xz" | "zstd" => Some(ARCHIVES),
            _ => None,
        },
        _ => None,
    }
}

/// What the magic bytes say: a category, or that the content is executable.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Sniffed {
    Category(Categories),
    Executable,
    /// A ZIP container: an archive unless the extension says it is a document (docx …) or an app (jar, apk).
    Zip,
}

fn sniff(data: &[u8]) -> Option<Sniffed> {
    let starts = |m: &[u8]| data.starts_with(m);
    let at = |offset: usize, m: &[u8]| data.get(offset..offset + m.len()) == Some(m);
    // Executables and scripts.
    if starts(b"MZ") || starts(b"\x7fELF") || starts(b"#!") || starts(b"\xCA\xFE\xBA\xBE") || starts(b"dex\n") {
        return Some(Sniffed::Executable);
    }
    if [b"\xFE\xED\xFA\xCE", b"\xFE\xED\xFA\xCF", b"\xCE\xFA\xED\xFE", b"\xCF\xFA\xED\xFE"].iter().any(|m| starts(*m)) {
        return Some(Sniffed::Executable);
    }
    // Windows shortcuts (OLE compound files, i.e. old Office documents and MSI installers alike, are
    // decided by the extension).
    if starts(b"L\x00\x00\x00\x01\x14\x02\x00") {
        return Some(Sniffed::Executable);
    }
    if at(0x8001, b"CD001") || at(0x8801, b"CD001") || at(0x9001, b"CD001") || starts(b"koly") {
        return Some(Sniffed::Executable);
    }
    // Images.
    if starts(b"\x89PNG\r\n\x1a\n")
        || starts(&[0xFF, 0xD8, 0xFF])
        || starts(b"GIF87a")
        || starts(b"GIF89a")
        || (starts(b"RIFF") && at(8, b"WEBP"))
        || starts(b"BM") && data.len() > 26 && at(14, &[40, 0, 0, 0])
        || (at(4, b"ftyp") && (at(8, b"avif") || at(8, b"heic") || at(8, b"mif1")))
    {
        return Some(Sniffed::Category(IMAGES));
    }
    // Audio.
    if starts(b"ID3")
        || starts(b"fLaC")
        || (starts(b"RIFF") && at(8, b"WAVE"))
        || (starts(b"OggS") && !data.windows(6).take(128).any(|w| w == b"theora"))
        || (data.len() > 2 && data[0] == 0xFF && (data[1] & 0xE0) == 0xE0 && (data[1] & 0x06) != 0)
        || (at(4, b"ftyp") && (at(8, b"M4A ") || at(8, b"M4B ")))
        || starts(b"MThd")
    {
        return Some(Sniffed::Category(AUDIO));
    }
    // Video (ISO base media that is not an image or audio, Matroska/WebM, AVI).
    if at(4, b"ftyp") || starts(&[0x1A, 0x45, 0xDF, 0xA3]) || (starts(b"RIFF") && at(8, b"AVI ")) || starts(b"OggS") {
        return Some(Sniffed::Category(VIDEO));
    }
    if starts(b"%PDF-") || looks_like_svg(data) {
        return Some(Sniffed::Category(DOCUMENTS));
    }
    if starts(b"PK\x03\x04") || starts(b"PK\x05\x06") {
        return Some(Sniffed::Zip);
    }
    if starts(b"7z\xBC\xAF\x27\x1C")
        || starts(b"Rar!\x1A\x07")
        || starts(&[0x1F, 0x8B])
        || starts(b"BZh")
        || starts(&[0xFD, b'7', b'z', b'X', b'Z', 0x00])
        || starts(&[0x28, 0xB5, 0x2F, 0xFD])
        || at(257, b"ustar")
    {
        return Some(Sniffed::Category(ARCHIVES));
    }
    None
}

/// SVG markup in the first KiB (`<svg`, possibly after an XML declaration, comments or a doctype).
fn looks_like_svg(data: &[u8]) -> bool {
    let head = &data[..data.len().min(1024)];
    let text = String::from_utf8_lossy(head).to_ascii_lowercase();
    let trimmed = text.trim_start_matches('\u{feff}').trim_start();
    trimmed.starts_with('<') && trimmed.contains("<svg")
}

/// Is a plaintext upload an SVG image (by content, extension or declared type)? SVG is a document that is
/// only ever downloaded, never shown inline; the node stores it as `image/svg+xml`.
pub fn is_svg(data: &[u8], name: &str, mime: &str) -> bool {
    let mime = mime.split(';').next().unwrap_or("").trim().to_ascii_lowercase();
    looks_like_svg(data) || matches!(extension(name).as_str(), "svg" | "svgz") || mime == "image/svg+xml"
}

/// The category of an upload and whether it is an executable.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Classified {
    pub category: Categories,
    pub executable: bool,
}

/// Classifies a plaintext upload by content, extension and declared type (see the module docs).
pub fn classify(data: &[u8], name: &str, mime: &str) -> Classified {
    let ext = extension(name);
    let dangerous_ext = dangerous_extension(&ext);
    let sniffed = sniff(data);
    let mime_lc = mime.to_ascii_lowercase();
    let dangerous_mime = [
        "application/x-msdownload",
        "application/x-msdos-program",
        "application/x-ms-installer",
        "application/x-executable",
        "application/x-sh",
        "application/x-bat",
        "application/java-archive",
        "application/vnd.android.package-archive",
        "application/x-apple-diskimage",
        "application/x-iso9660-image",
        "application/javascript",
        "text/javascript",
        "application/hta",
        "application/x-ms-shortcut",
    ]
    .iter()
    .any(|d| mime_lc.starts_with(d));
    if dangerous_ext || dangerous_mime || sniffed == Some(Sniffed::Executable) {
        return Classified { category: OTHER, executable: true };
    }
    let category = match sniffed {
        Some(Sniffed::Category(c)) => c,
        Some(Sniffed::Zip) => match category_of_extension(&ext) {
            Some(DOCUMENTS) => DOCUMENTS,
            _ => ARCHIVES,
        },
        _ => category_of_extension(&ext).or_else(|| category_of_mime(mime)).unwrap_or(OTHER),
    };
    Classified { category, executable: false }
}

/// The category an encrypted upload declares in `Tavrn-Upload-Category` (`images` … `other`, or
/// `executable`); a missing header means `other`.
pub fn declared(header: Option<&str>) -> Option<Classified> {
    match header.map(|h| h.trim().to_ascii_lowercase()) {
        None => Some(Classified { category: OTHER, executable: false }),
        Some(h) if h.is_empty() => Some(Classified { category: OTHER, executable: false }),
        Some(h) if h == "executable" => Some(Classified { category: OTHER, executable: true }),
        Some(h) => {
            parse_names(&[h]).filter(|c| c.count_ones() == 1).map(|category| Classified { category, executable: false })
        }
    }
}

/// A role as the evaluation needs it: id, position, its category setting (`None` = inherit).
pub struct RoleCategories<'a> {
    pub id: &'a str,
    pub position: i64,
    pub categories: Option<Categories>,
}

/// An override's upload masks.
pub struct UploadOverride<'a> {
    pub subject_type: SubjectType,
    pub subject_id: &'a str,
    pub allow: Categories,
    pub deny: Categories,
}

impl<'a> UploadOverride<'a> {
    pub fn of(o: &'a Override, allow: Categories, deny: Categories) -> Self {
        Self { subject_type: o.subject_type, subject_id: &o.subject_id, allow, deny }
    }
}

/// Effective categories of a member: the highest role with a setting wins (else `@everyone`), then the
/// override layers on top in order (the category's, then the channel's own; protocol permissions.md "Upload
/// categories"), each as `@everyone` override, all role overrides (deny, then allow), the member's own override.
/// A category a layer neither allows nor denies keeps the value of the layer below. Owners, node admins and
/// administrators may upload every category.
pub fn effective(
    privileged: bool,
    everyone_id: &str,
    everyone: Categories,
    member_roles: &[RoleCategories<'_>],
    layers: &[&[UploadOverride<'_>]],
    user_id: &str,
) -> Categories {
    if privileged {
        return ALL;
    }
    let mut cats = member_roles
        .iter()
        .filter_map(|r| r.categories.map(|c| (r.position, r.id, c)))
        .max_by(|a, b| a.0.cmp(&b.0).then_with(|| b.1.cmp(a.1)))
        .map_or(everyone, |(_, _, c)| c);
    for overrides in layers {
        if let Some(o) = overrides.iter().find(|o| o.subject_type == SubjectType::Role && o.subject_id == everyone_id) {
            cats = (cats & !o.deny) | o.allow;
        }
        let (mut allow, mut deny) = (0, 0);
        for o in overrides.iter().filter(|o| o.subject_type == SubjectType::Role) {
            if member_roles.iter().any(|r| r.id == o.subject_id) {
                allow |= o.allow;
                deny |= o.deny;
            }
        }
        cats = (cats & !deny) | allow;
        if let Some(o) = overrides.iter().find(|o| o.subject_type == SubjectType::Member && o.subject_id == user_id) {
            cats = (cats & !o.deny) | o.allow;
        }
    }
    cats & ALL
}

#[cfg(test)]
mod tests {
    use super::*;

    fn class(data: &[u8], name: &str, mime: &str) -> (&'static str, bool) {
        let c = classify(data, name, mime);
        (name_of(c.category), c.executable)
    }

    #[test]
    fn content_extension_and_type_classify() {
        assert_eq!(class(b"\x89PNG\r\n\x1a\nrest", "x.dat", "application/octet-stream"), ("images", false));
        assert_eq!(class(b"\x89PNGfake", "bild.png", "image/png"), ("images", false));
        assert_eq!(class(b"ID3\x03rest", "song", ""), ("audio", false));
        assert_eq!(class(b"\x00\x00\x00\x18ftypisom", "clip.mp4", "video/mp4"), ("video", false));
        assert_eq!(class(b"%PDF-1.7", "a", ""), ("documents", false));
        assert_eq!(class(b"hello", "notes.txt", "text/plain"), ("documents", false));
        assert_eq!(class(b"PK\x03\x04....", "mod.zip", "application/zip"), ("archives", false));
        assert_eq!(class(b"PK\x03\x04....", "report.docx", ""), ("documents", false));
        assert_eq!(class(b"\x1f\x8b\x08", "save.tar.gz", ""), ("archives", false));
        assert_eq!(class(b"whatever", "level.sav", "application/octet-stream"), ("other", false));
        assert_eq!(class(b"whatever", "noext", "text/csv"), ("documents", false));
    }

    #[test]
    fn svg_is_a_document_never_an_image() {
        let svg = b"<svg xmlns='http://www.w3.org/2000/svg'><script>alert(1)</script></svg>";
        assert_eq!(class(svg, "logo.svg", "image/svg+xml"), ("documents", false));
        assert_eq!(class(svg, "logo.png", "image/png"), ("documents", false), "content wins over a fake name");
        assert_eq!(class(b"<?xml version='1.0'?>\n<!-- x -->\n<svg/>", "x", ""), ("documents", false));
        assert_eq!(class(b"\xEF\xBB\xBF  <SVG></SVG>", "x.dat", ""), ("documents", false), "BOM and case");
        assert_eq!(class(b"anything", "drawing.svg", ""), ("documents", false), "by extension");
        assert_eq!(class(b"anything", "drawing", "image/svg+xml"), ("documents", false), "by type");
        assert_eq!(class(b"\x89PNG\r\n\x1a\n", "x.png", "image/png"), ("images", false));
        assert!(is_svg(svg, "a.png", "image/png"));
        assert!(is_svg(b"x", "a.SVG", ""));
        assert!(is_svg(b"x", "a", "image/svg+xml; charset=utf-8"));
        assert!(!is_svg(b"\x89PNG\r\n\x1a\n", "a.png", "image/png"));
        assert!(!is_svg(b"plain text mentioning <svg", "notes.txt", "text/plain"), "markup must lead");
    }

    #[test]
    fn executables_are_flagged_by_content_extension_or_type() {
        assert_eq!(class(b"MZ\x90\x00", "setup.png", "image/png"), ("other", true), "content wins over a fake name");
        assert_eq!(class(b"\x7fELF\x02", "tool", ""), ("other", true));
        assert_eq!(class(b"#!/bin/sh\nrm -rf /", "run.txt", "text/plain"), ("other", true));
        assert_eq!(class(b"\x89PNG\r\n\x1a\n", "virus.exe", "image/png"), ("other", true), "extension wins too");
        assert_eq!(class(b"PK\x03\x04", "app.jar", ""), ("other", true));
        assert_eq!(class(b"PK\x03\x04", "app.apk", ""), ("other", true));
        assert_eq!(class(b"echo hi", "x.bat", ""), ("other", true));
        assert_eq!(class(b"Write-Host", "x.PS1", ""), ("other", true), "case-insensitive");
        assert_eq!(class(b"alert(1)", "x.js", ""), ("other", true));
        assert_eq!(class(b"data", "x.dat", "application/x-msdownload"), ("other", true));
        for ext in ["msi", "cmd", "sh", "scr", "vbs", "dmg", "com", "pif", "cpl", "hta", "reg", "lnk", "iso"] {
            assert!(classify(b"x", &format!("f.{ext}"), "").executable, "{ext}");
        }
        assert_eq!(extension("archive.tar.gz"), "gz");
        assert_eq!(extension(".bashrc"), "");
        assert_eq!(extension("trailing.exe. "), "exe", "Windows ignores trailing dots and spaces");
    }

    #[test]
    fn declared_categories_of_encrypted_uploads() {
        assert_eq!(declared(None), Some(Classified { category: OTHER, executable: false }));
        assert_eq!(declared(Some("Images")), Some(Classified { category: IMAGES, executable: false }));
        assert_eq!(declared(Some("executable")), Some(Classified { category: OTHER, executable: true }));
        assert_eq!(declared(Some("nonsense")), None);
        assert_eq!(parse_names(&["images", "video"]), Some(IMAGES | VIDEO));
        assert_eq!(parse_names(&["x"]), None);
        assert_eq!(names(IMAGES | OTHER), vec!["images".to_string(), "other".to_string()]);
    }

    #[test]
    fn highest_role_wins_then_overrides() {
        let roles = [
            RoleCategories { id: "low", position: 1, categories: Some(ALL) },
            RoleCategories { id: "high", position: 5, categories: Some(IMAGES) },
            RoleCategories { id: "unset", position: 9, categories: None },
        ];
        assert_eq!(effective(false, "e", DOCUMENTS, &roles, &[], "u"), IMAGES, "highest role with a value");
        assert_eq!(effective(false, "e", DOCUMENTS, &[], &[], "u"), DOCUMENTS, "else @everyone");
        assert_eq!(effective(true, "e", 0, &[], &[], "u"), ALL, "owner/admin");
        let overrides = [
            UploadOverride { subject_type: SubjectType::Role, subject_id: "e", allow: VIDEO, deny: IMAGES },
            UploadOverride { subject_type: SubjectType::Role, subject_id: "high", allow: AUDIO, deny: 0 },
            UploadOverride { subject_type: SubjectType::Role, subject_id: "other-role", allow: OTHER, deny: 0 },
        ];
        assert_eq!(effective(false, "e", DOCUMENTS, &roles, &[&overrides], "u"), VIDEO | AUDIO);
        let member = [UploadOverride { subject_type: SubjectType::Member, subject_id: "u", allow: 0, deny: VIDEO }];
        assert_eq!(effective(false, "e", VIDEO | AUDIO, &[], &[&member], "u"), AUDIO);
        assert_eq!(effective(false, "e", VIDEO | AUDIO, &[], &[&member], "someone-else"), VIDEO | AUDIO);
    }

    #[test]
    fn override_layers_category_then_channel() {
        // The category denies video to everyone and allows audio to a member; the channel allows video back and
        // says nothing about audio, which the member keeps from the category.
        let category = [
            UploadOverride { subject_type: SubjectType::Role, subject_id: "e", allow: 0, deny: VIDEO },
            UploadOverride { subject_type: SubjectType::Member, subject_id: "u", allow: AUDIO, deny: 0 },
        ];
        let channel = [UploadOverride { subject_type: SubjectType::Role, subject_id: "e", allow: VIDEO, deny: 0 }];
        assert_eq!(effective(false, "e", IMAGES | VIDEO, &[], &[&category], "u"), IMAGES | AUDIO);
        assert_eq!(effective(false, "e", IMAGES | VIDEO, &[], &[&category, &channel], "u"), IMAGES | AUDIO | VIDEO);
        // A channel deny wins over a category member allow.
        let deny = [UploadOverride { subject_type: SubjectType::Role, subject_id: "e", allow: 0, deny: AUDIO }];
        assert_eq!(effective(false, "e", IMAGES, &[], &[&category, &deny], "u"), IMAGES);
    }
}
