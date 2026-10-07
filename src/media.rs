// SPDX-License-Identifier: AGPL-3.0-only
//! Media pipeline (PLAN.md 4.9): avatars, profile headers, room icons and voice backgrounds.
//!
//! Every upload is checked before anything decodes it: at most [`MAX_INPUT_BYTES`], the format is sniffed
//! from the magic bytes (the client's content type is ignored; SVG, HTML and everything else unknown is
//! refused), dimensions and duration are probed and limited. Conversion runs ffmpeg (`TAVRN_MEDIA_FFMPEG`)
//! without a shell, without network protocols (the demuxer is forced from the sniffed format and only
//! the `file`/`pipe` protocols are allowed), with an empty environment, in a private temporary directory
//! and with a 30-second budget per job; at most `TAVRN_MEDIA_WORKERS` jobs run at once and a few more
//! wait. Results are WebP: a still image (the first frame for animated input) and, for animated input,
//! an animated WebP of at most [`LOOP_SECS`] seconds. Metadata (EXIF, XMP, comments) never survives:
//! ffmpeg drops it (`-map_metadata -1`, WebP output without metadata chunks); without ffmpeg only PNG,
//! JPEG and simple WebP stills are accepted and their metadata chunks are removed here.
//!
//! ffmpeg cannot decode animated WebP; those are decoded with `image-webp` and piped into ffmpeg as raw
//! frames resampled to a fixed frame rate.

use std::{
    io::Cursor,
    path::{Path, PathBuf},
    process::Stdio,
    sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    },
    time::{Duration, Instant},
};

use axum::body::Bytes;
use tokio::{io::AsyncWriteExt, sync::Semaphore};

use crate::{config::Config, error::ApiError};

/// Largest accepted upload.
pub const MAX_INPUT_BYTES: usize = 20 * 1024 * 1024;
/// Longest accepted animated or video input.
pub const MAX_INPUT_SECS: f64 = 30.0;
/// Animated results loop at most this long.
pub const LOOP_SECS: u32 = 10;
/// Budget of one job (probe and all conversion attempts).
pub const JOB_TIMEOUT: Duration = Duration::from_secs(30);
/// Largest accepted width or height of an input image or video.
pub const MAX_INPUT_SIDE: u32 = 4096;
/// Largest accepted canvas of an animated WebP (its frames are piped raw into ffmpeg).
pub const MAX_ANIMATED_WEBP_SIDE: u32 = 1024;
/// How long an upload waits for a free worker before `503 media.busy` (short: the whole request has the
/// node's 30-second limit, and a dropped request kills its ffmpeg).
pub const QUEUE_WAIT: Duration = Duration::from_secs(10);
/// Jobs waiting per worker beyond the running ones.
pub const QUEUE_PER_WORKER: usize = 4;

/// What an image is used for; decides geometry and output limits.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MediaKind {
    /// User avatar: 256 × 256, ≤ 1 MB per variant.
    Avatar,
    /// Room icon: like avatars.
    Icon,
    /// Profile header: 1200 × 400, ≤ 2 MB per variant.
    Header,
    /// Voice/video background: at most 1280 px on the longer side, ≤ 2 MB per variant.
    Background,
    /// Link preview image (PLAN.md 4.13 item 7): still only, at most 400 px on the longer side, ≤ 40 KiB.
    Preview,
    /// Custom emoji (room or personal, PLAN.md 4.13): at most 128 px on the longer side, ≤ 256 KiB per
    /// variant, animations cut to [`EMOJI_LOOP_SECS`] seconds and [`EMOJI_MAX_FRAMES`] frames. Images only
    /// (no MP4/WebM), animated input at most [`EMOJI_MAX_ANIMATED_SIDE`] px and [`EMOJI_MAX_INPUT_FRAMES`] frames.
    Emoji,
}

/// Longest animated emoji.
pub const EMOJI_LOOP_SECS: u32 = 5;
/// Most frames of an animated emoji.
pub const EMOJI_MAX_FRAMES: u32 = 60;
/// Largest side of an animated emoji input (decompression bombs: checked before ffmpeg decodes it).
pub const EMOJI_MAX_ANIMATED_SIDE: u32 = 1024;
/// Most frames of an animated GIF emoji input (counted from the file structure before ffmpeg runs).
pub const EMOJI_MAX_INPUT_FRAMES: usize = 1000;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Geometry {
    /// Scaled to cover the box and center-cropped (no manual crop needed).
    Cover(u32, u32),
    /// Scaled down to fit into a square of this side, aspect kept.
    Fit(u32),
}

impl MediaKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Avatar => "avatar",
            Self::Icon => "icon",
            Self::Header => "header",
            Self::Background => "background",
            Self::Preview => "preview",
            Self::Emoji => "emoji",
        }
    }

    /// Largest stored file per variant (still and animated each).
    pub fn max_output_bytes(self) -> usize {
        match self {
            Self::Avatar | Self::Icon => 1024 * 1024,
            Self::Header | Self::Background => 2 * 1024 * 1024,
            Self::Preview => 40 * 1024,
            Self::Emoji => 256 * 1024,
        }
    }

    fn geometry(self) -> Geometry {
        match self {
            Self::Avatar | Self::Icon => Geometry::Cover(256, 256),
            Self::Header => Geometry::Cover(1200, 400),
            Self::Background => Geometry::Fit(1280),
            Self::Emoji => Geometry::Fit(128),
            Self::Preview => Geometry::Fit(400),
        }
    }

    /// Whether animated input also gets an animated variant (link previews keep the first frame only).
    fn keeps_animation(self) -> bool {
        self != Self::Preview
    }

    /// Quality ladder of the still variant: each attempt is smaller than the one before.
    fn still_qualities(self) -> &'static [u32] {
        match self {
            Self::Preview => &[60, 40, 25],
            _ => STILL_QUALITY,
        }
    }

    /// Length of animated results in seconds.
    fn loop_secs(self) -> u32 {
        if self == Self::Emoji { EMOJI_LOOP_SECS } else { LOOP_SECS }
    }

    /// Frame cap of animated results.
    fn max_frames(self) -> Option<u32> {
        (self == Self::Emoji).then_some(EMOJI_MAX_FRAMES)
    }

    /// Largest accepted width or height of the input.
    fn max_input_side(self, animated: bool) -> u32 {
        if self == Self::Emoji && animated { EMOJI_MAX_ANIMATED_SIDE } else { MAX_INPUT_SIDE }
    }

    /// Whether `format` is accepted for this kind (emojis are images: no videos).
    fn accepts(self, format: Format) -> bool {
        !(self == Self::Emoji && matches!(format, Format::Mp4 | Format::WebM))
    }
}

/// Input formats recognized by their magic bytes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Format {
    Png,
    /// PNG with an `acTL` chunk before the image data.
    Apng,
    Jpeg,
    Gif,
    /// A GIF with a single frame.
    GifStill,
    WebP,
    WebPAnimated,
    /// MP4/MOV (ISO base media, `ftyp`).
    Mp4,
    /// WebM/Matroska (EBML header).
    WebM,
}

impl Format {
    /// Animated or video input (needs ffmpeg).
    pub fn is_animated(self) -> bool {
        matches!(self, Self::Apng | Self::Gif | Self::WebPAnimated | Self::Mp4 | Self::WebM)
    }

    /// The ffmpeg demuxer forced for this format (never auto-detected: no playlists, no concat lists).
    fn demuxer(self) -> &'static str {
        match self {
            Self::Png => "png_pipe",
            Self::Apng => "apng",
            Self::Jpeg => "jpeg_pipe",
            Self::Gif | Self::GifStill => "gif",
            Self::WebP | Self::WebPAnimated => "webp_pipe",
            Self::Mp4 => "mov",
            Self::WebM => "matroska",
        }
    }
}

/// The format of `data` from its magic bytes, `None` for anything else (SVG, HTML, archives …).
pub fn sniff(data: &[u8]) -> Option<Format> {
    if data.starts_with(b"\x89PNG\r\n\x1a\n") {
        return Some(if png_is_animated(data) { Format::Apng } else { Format::Png });
    }
    if data.starts_with(&[0xFF, 0xD8, 0xFF]) {
        return Some(Format::Jpeg);
    }
    if data.starts_with(b"GIF87a") || data.starts_with(b"GIF89a") {
        return Some(if gif_frame_count(data, 2) > 1 { Format::Gif } else { Format::GifStill });
    }
    if data.len() >= 12 && &data[0..4] == b"RIFF" && &data[8..12] == b"WEBP" {
        return Some(if webp_is_animated(data) { Format::WebPAnimated } else { Format::WebP });
    }
    if data.len() >= 12 && &data[4..8] == b"ftyp" {
        return Some(Format::Mp4);
    }
    if data.starts_with(&[0x1A, 0x45, 0xDF, 0xA3]) {
        return Some(Format::WebM);
    }
    None
}

/// Iterates the chunks of a PNG: `(type, data)` until IEND or malformed data.
fn png_chunks(data: &[u8]) -> impl Iterator<Item = (&[u8], &[u8], &[u8])> {
    let mut pos = 8usize;
    std::iter::from_fn(move || {
        let len = u32::from_be_bytes(data.get(pos..pos + 4)?.try_into().ok()?) as usize;
        let end = pos.checked_add(12)?.checked_add(len)?;
        let whole = data.get(pos..end)?;
        let kind = &whole[4..8];
        let body = &whole[8..8 + len];
        pos = end;
        Some((kind, body, whole))
    })
}

fn png_is_animated(data: &[u8]) -> bool {
    for (kind, _, _) in png_chunks(data) {
        match kind {
            b"acTL" => return true,
            b"IDAT" | b"IEND" => return false,
            _ => {}
        }
    }
    false
}

/// Counts the image descriptors of a GIF, stopping at `stop` (malformed data ends the count).
pub fn gif_frame_count(data: &[u8], stop: usize) -> usize {
    let Some(flags) = data.get(10) else { return 0 };
    let mut pos = 13usize;
    if flags & 0x80 != 0 {
        pos += 3 * (1usize << ((flags & 0x07) + 1));
    }
    let skip_sub_blocks = |mut p: usize| -> Option<usize> {
        loop {
            let n = *data.get(p)? as usize;
            p += 1;
            if n == 0 {
                return Some(p);
            }
            p += n;
        }
    };
    let mut frames = 0;
    while frames < stop {
        match data.get(pos) {
            Some(0x2C) => {
                let Some(f) = data.get(pos + 9) else { return frames };
                pos += 10;
                if f & 0x80 != 0 {
                    pos += 3 * (1usize << ((f & 0x07) + 1));
                }
                pos += 1; // LZW minimum code size
                let Some(p) = skip_sub_blocks(pos) else { return frames };
                pos = p;
                frames += 1;
            }
            Some(0x21) => {
                let Some(p) = skip_sub_blocks(pos + 2) else { return frames };
                pos = p;
            }
            _ => return frames,
        }
    }
    frames
}

fn webp_is_animated(data: &[u8]) -> bool {
    image_webp::WebPDecoder::new(Cursor::new(data)).is_ok_and(|d| d.is_animated())
}

/// The result of a job: the still (WebP, or PNG/JPEG/WebP as uploaded without ffmpeg) and, for animated
/// input, the animated WebP.
#[derive(Debug, Clone)]
pub struct Processed {
    pub still: Vec<u8>,
    pub still_mime: &'static str,
    pub animated: Option<Vec<u8>>,
}

fn too_large(max: usize, code: &'static str, what: &str) -> ApiError {
    ApiError::PayloadTooLarge {
        code,
        detail: format!("{what}: at most {} MB", max / (1024 * 1024)),
        meta: serde_json::json!({ "max_bytes": max }),
    }
}

pub fn input_too_large() -> ApiError {
    too_large(MAX_INPUT_BYTES, "media.too_large", "File too large")
}

fn type_not_allowed() -> ApiError {
    ApiError::UnsupportedMedia {
        code: "media.type_not_allowed",
        detail: "Allowed are PNG, JPEG, GIF, WebP and short MP4 and WebM videos".into(),
    }
}

fn conversion_unavailable() -> ApiError {
    ApiError::UnsupportedMedia {
        code: "media.conversion_unavailable",
        detail:
            "Without image conversion (ffmpeg is turned off) this node only accepts PNG, JPEG and simple WebP images"
                .into(),
    }
}

fn animation_unavailable() -> ApiError {
    ApiError::UnsupportedMedia {
        code: "media.animation_unavailable",
        detail:
            "This node does not convert animated images and videos (ffmpeg is turned off); please use a PNG or JPEG"
                .into(),
    }
}

fn invalid(detail: &str) -> ApiError {
    ApiError::BadRequest { code: "media.invalid", detail: detail.into() }
}

fn too_long() -> ApiError {
    ApiError::BadRequest {
        code: "media.too_long",
        detail: format!("Animations and videos may be at most {MAX_INPUT_SECS:.0} seconds long"),
    }
}

fn dimensions_too_large(max: u32) -> ApiError {
    ApiError::BadRequest { code: "media.dimensions", detail: format!("At most {max} × {max} pixels") }
}

fn busy() -> ApiError {
    ApiError::Pending {
        code: "media.busy",
        detail: "Image conversion is busy right now, please try again shortly".into(),
        retry_after_secs: 10,
    }
}

fn timed_out() -> ApiError {
    ApiError::BadRequest {
        code: "media.timeout",
        detail: "The conversion took too long; please use a smaller or shorter file".into(),
    }
}

/// The pipeline: ffmpeg (if any), the worker slots and the temporary directory.
pub struct Pipeline {
    ffmpeg: Option<PathBuf>,
    workers: Arc<Semaphore>,
    waiting: AtomicUsize,
    max_waiting: usize,
    tmp_root: PathBuf,
}

/// Finds an executable named `name` in `PATH`.
fn which(name: &str) -> Option<PathBuf> {
    let path = std::env::var_os("PATH")?;
    std::env::split_paths(&path).map(|dir| dir.join(name)).find(|p| p.is_file())
}

/// `TAVRN_MEDIA_FFMPEG` resolved: `None` for `off` and for `auto` without ffmpeg in `PATH`.
pub fn resolve_ffmpeg(config: &Config) -> Option<PathBuf> {
    match config.media_ffmpeg.trim() {
        crate::config::MEDIA_FFMPEG_OFF => None,
        crate::config::MEDIA_FFMPEG_AUTO => which("ffmpeg"),
        path => Some(PathBuf::from(path)),
    }
}

/// Startup check: an explicitly configured ffmpeg must exist.
pub fn check_binary(config: &Config) -> anyhow::Result<()> {
    let setting = config.media_ffmpeg.trim();
    if setting != crate::config::MEDIA_FFMPEG_AUTO
        && setting != crate::config::MEDIA_FFMPEG_OFF
        && !Path::new(setting).is_file()
    {
        anyhow::bail!(
            "TAVRN_MEDIA_FFMPEG={setting} does not exist (auto, off or a path to ffmpeg; `just ffmpeg-install`)"
        );
    }
    Ok(())
}

/// Removes the job's temporary directory when the job ends (also on errors and timeouts).
struct TempDir(PathBuf);

impl Drop for TempDir {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

impl Pipeline {
    pub fn new(config: &Config) -> Self {
        let ffmpeg = resolve_ffmpeg(config);
        let workers = config.media_workers.clamp(1, 8) as usize;
        match &ffmpeg {
            Some(p) => tracing::debug!(ffmpeg = %p.display(), workers, "media pipeline"),
            None => tracing::info!("media pipeline without ffmpeg: only PNG, JPEG and WebP stills are accepted"),
        }
        Self {
            ffmpeg,
            workers: Arc::new(Semaphore::new(workers)),
            waiting: AtomicUsize::new(0),
            max_waiting: workers * QUEUE_PER_WORKER,
            tmp_root: Path::new(&config.data_dir).join("tmp").join("media"),
        }
    }

    /// Whether animated and video input can be converted.
    pub fn animated(&self) -> bool {
        self.ffmpeg.is_some()
    }

    /// Converts an upload for `kind`.
    pub async fn process(&self, kind: MediaKind, input: Bytes) -> Result<Processed, ApiError> {
        if input.is_empty() {
            return Err(invalid("Empty file"));
        }
        if input.len() > MAX_INPUT_BYTES {
            return Err(input_too_large());
        }
        let format = sniff(&input).filter(|f| kind.accepts(*f)).ok_or_else(type_not_allowed)?;
        // Link previews take still images and the first frame of GIF/APNG only, never video.
        if !kind.keeps_animation() && matches!(format, Format::WebPAnimated | Format::Mp4 | Format::WebM) {
            return Err(type_not_allowed());
        }
        // Decompression bombs: an emoji GIF with absurdly many frames is refused before anything decodes it.
        if kind == MediaKind::Emoji
            && format == Format::Gif
            && gif_frame_count(&input, EMOJI_MAX_INPUT_FRAMES + 1) > EMOJI_MAX_INPUT_FRAMES
        {
            return Err(too_long());
        }
        let Some(ffmpeg) = self.ffmpeg.clone() else {
            if format.is_animated() {
                return Err(animation_unavailable());
            }
            return passthrough(kind, format, &input);
        };
        // Queue: a bounded number of jobs waits, the rest is refused at once.
        if self.waiting.fetch_add(1, Ordering::SeqCst) >= self.max_waiting {
            self.waiting.fetch_sub(1, Ordering::SeqCst);
            return Err(busy());
        }
        let permit = tokio::time::timeout(QUEUE_WAIT, self.workers.clone().acquire_owned()).await;
        self.waiting.fetch_sub(1, Ordering::SeqCst);
        let _permit = match permit {
            Ok(Ok(p)) => p,
            _ => return Err(busy()),
        };
        let deadline = Instant::now() + JOB_TIMEOUT;
        let dir = self.tmp_root.join(crate::util::ulid());
        tokio::fs::create_dir_all(&dir).await.map_err(|e| ApiError::Internal(e.into()))?;
        let _cleanup = TempDir(dir.clone());
        let job = Job { ffmpeg: &ffmpeg, dir: &dir, kind, deadline };
        let started = Instant::now();
        let result = job.run(format, input).await;
        tracing::info!(
            kind = kind.as_str(),
            format = ?format,
            ms = started.elapsed().as_millis() as u64,
            result = result.as_ref().map(|_| "ok").unwrap_or_else(|e| e.code()),
            "media job"
        );
        result
    }
}

/// Without ffmpeg: PNG and JPEG with their metadata removed, simple WebP (no metadata chunks possible)
/// as they are, after the dimension and size checks.
fn passthrough(kind: MediaKind, format: Format, input: &[u8]) -> Result<Processed, ApiError> {
    let (data, mime, (w, h)) = match format {
        Format::Png => {
            let (data, dims) = sanitize_png(input).ok_or_else(|| invalid("Corrupt PNG"))?;
            (data, "image/png", dims)
        }
        Format::Jpeg => {
            let (data, dims) = sanitize_jpeg(input).ok_or_else(|| invalid("Corrupt JPEG"))?;
            (data, "image/jpeg", dims)
        }
        Format::WebP => {
            let d = image_webp::WebPDecoder::new(Cursor::new(input)).map_err(|_| invalid("Corrupt WebP"))?;
            // VP8X files may carry EXIF/XMP: only the simple formats pass without ffmpeg.
            if input.get(12..16) == Some(b"VP8X") {
                return Err(conversion_unavailable());
            }
            (input.to_vec(), "image/webp", d.dimensions())
        }
        _ => return Err(conversion_unavailable()),
    };
    if w == 0 || h == 0 || w > MAX_INPUT_SIDE || h > MAX_INPUT_SIDE {
        return Err(dimensions_too_large(MAX_INPUT_SIDE));
    }
    if data.len() > kind.max_output_bytes() {
        return Err(too_large(
            kind.max_output_bytes(),
            "media.output_too_large",
            "Ohne Umwandlung ist die Datei zu groß",
        ));
    }
    Ok(Processed { still: data, still_mime: mime, animated: None })
}

/// Keeps the chunks needed to render a still PNG (critical chunks plus transparency, gamma and color
/// space) and drops text, EXIF, time and unknown ancillary chunks. Returns the file and its size.
pub fn sanitize_png(data: &[u8]) -> Option<(Vec<u8>, (u32, u32))> {
    const KEEP: &[&[u8]] =
        &[b"PLTE", b"IDAT", b"IEND", b"tRNS", b"gAMA", b"cHRM", b"sRGB", b"iCCP", b"sBIT", b"pHYs", b"bKGD"];
    let mut out = data.get(..8)?.to_vec();
    let mut dims = None;
    let mut ended = false;
    for (kind, body, whole) in png_chunks(data) {
        if kind == b"IHDR" {
            let w = u32::from_be_bytes(body.get(0..4)?.try_into().ok()?);
            let h = u32::from_be_bytes(body.get(4..8)?.try_into().ok()?);
            dims = Some((w, h));
            out.extend_from_slice(whole);
        } else if KEEP.contains(&kind) {
            out.extend_from_slice(whole);
        } else if kind[0].is_ascii_uppercase() {
            // An unknown critical chunk (or APNG's acTL is ancillary): refuse rather than guess.
            return None;
        }
        if kind == b"IEND" {
            ended = true;
            break;
        }
    }
    (ended && dims.is_some()).then(|| (out, dims.unwrap_or_default()))
}

/// Drops APP1–APP15 (EXIF, XMP, ICC containers of cameras …) and comments from a JPEG; the entropy-coded
/// data after the start of scan is copied unchanged. Returns the file and its size from the frame header.
pub fn sanitize_jpeg(data: &[u8]) -> Option<(Vec<u8>, (u32, u32))> {
    let mut out = vec![0xFF, 0xD8];
    let mut pos = 2usize;
    let mut dims = None;
    loop {
        if *data.get(pos)? != 0xFF {
            return None;
        }
        let marker = *data.get(pos + 1)?;
        if marker == 0xFF {
            pos += 1;
            continue;
        }
        let len = u16::from_be_bytes([*data.get(pos + 2)?, *data.get(pos + 3)?]) as usize;
        let segment = data.get(pos..pos + 2 + len)?;
        match marker {
            0xE1..=0xEF | 0xFE => {}
            0xC0..=0xC3 | 0xC5..=0xC7 | 0xC9..=0xCB | 0xCD..=0xCF => {
                let h = u16::from_be_bytes([*segment.get(5)?, *segment.get(6)?]) as u32;
                let w = u16::from_be_bytes([*segment.get(7)?, *segment.get(8)?]) as u32;
                dims = Some((w, h));
                out.extend_from_slice(segment);
            }
            0xDA => {
                out.extend_from_slice(&data[pos..]);
                return dims.map(|d| (out, d));
            }
            _ => out.extend_from_slice(segment),
        }
        pos += 2 + len;
    }
}

/// What `ffmpeg -i` reports about an input.
#[derive(Debug, Clone, Copy, PartialEq, Default)]
pub struct Probe {
    pub duration_secs: Option<f64>,
    pub width: u32,
    pub height: u32,
}

/// Parses the stream summary ffmpeg prints for an input (`Duration: 00:00:02.00` and the first video
/// stream's `, 320x240`).
pub fn parse_probe(stderr: &str) -> Option<Probe> {
    let mut probe = Probe::default();
    for line in stderr.lines() {
        let line = line.trim();
        if let Some(rest) = line.strip_prefix("Duration: ") {
            let value = rest.split(',').next().unwrap_or("").trim();
            if value != "N/A" {
                let mut secs = 0.0;
                for part in value.split(':') {
                    secs = secs * 60.0 + part.parse::<f64>().ok()?;
                }
                probe.duration_secs = Some(secs);
            }
        }
        if probe.width == 0 && line.starts_with("Stream #") && line.contains("Video:") {
            for token in line.split(", ") {
                let token = token.split_whitespace().next().unwrap_or("");
                if let Some((w, h)) = token.split_once('x')
                    && let (Ok(w), Ok(h)) = (w.parse::<u32>(), h.parse::<u32>())
                {
                    probe.width = w;
                    probe.height = h;
                    break;
                }
            }
        }
    }
    (probe.width > 0 && probe.height > 0).then_some(probe)
}

/// Resamples an animation with per-frame durations to a constant rate of `fps` frames per second,
/// limited to `max_ms`: [`Ticker::next`] says how often each frame is repeated. Durations below 20 ms
/// count as 100 ms, like browsers do.
pub struct Ticker {
    fps: u64,
    max_ms: u64,
    start: u64,
    tick: u64,
}

impl Ticker {
    pub fn new(fps: u32, max_ms: u64) -> Self {
        Self { fps: u64::from(fps.max(1)), max_ms, start: 0, tick: 0 }
    }

    fn at(&self, tick: u64) -> u64 {
        tick * 1000 / self.fps
    }

    /// Repeats of the next frame (shown for `duration_ms`); `None` once the time is up.
    pub fn next(&mut self, duration_ms: u32) -> Option<u32> {
        if self.at(self.tick) >= self.max_ms {
            return None;
        }
        let end = self.start + u64::from(if duration_ms < 20 { 100 } else { duration_ms });
        let mut n = 0;
        while self.at(self.tick) < end && self.at(self.tick) < self.max_ms {
            n += 1;
            self.tick += 1;
        }
        self.start = end;
        Some(n)
    }
}

/// [`Ticker`] over a list of durations.
pub fn resample(durations_ms: &[u32], fps: u32, max_ms: u64) -> Vec<u32> {
    let mut ticker = Ticker::new(fps, max_ms);
    durations_ms.iter().map_while(|d| ticker.next(*d)).collect()
}

/// One conversion job inside its temporary directory.
struct Job<'a> {
    ffmpeg: &'a Path,
    dir: &'a Path,
    kind: MediaKind,
    deadline: Instant,
}

/// Quality ladders: each attempt is smaller than the one before.
const STILL_QUALITY: &[u32] = &[80, 60, 40];
const ANIMATED_STEPS: &[(u32, u32)] = &[(70, 15), (50, 12), (30, 10)];

impl Job<'_> {
    fn remaining(&self) -> Result<Duration, ApiError> {
        self.deadline.checked_duration_since(Instant::now()).filter(|d| !d.is_zero()).ok_or_else(timed_out)
    }

    fn command(&self) -> tokio::process::Command {
        let mut cmd = tokio::process::Command::new(self.ffmpeg);
        cmd.env_clear()
            .current_dir(self.dir)
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::piped())
            .kill_on_drop(true)
            .args(["-nostdin", "-hide_banner", "-max_alloc", "268435456", "-threads", "2"]);
        cmd
    }

    /// Runs ffmpeg with `args`; returns stderr (capped) or the timeout error.
    async fn run_ffmpeg(&self, args: &[String]) -> Result<(bool, String), ApiError> {
        let mut cmd = self.command();
        cmd.args(args);
        let child = cmd.spawn().map_err(|e| ApiError::Internal(anyhow::anyhow!("cannot start ffmpeg: {e}")))?;
        match tokio::time::timeout(self.remaining()?, child.wait_with_output()).await {
            Ok(Ok(out)) => {
                let mut err = String::from_utf8_lossy(&out.stderr).into_owned();
                err.truncate(16 * 1024);
                Ok((out.status.success(), err))
            }
            Ok(Err(e)) => Err(ApiError::Internal(anyhow::anyhow!("ffmpeg: {e}"))),
            Err(_) => Err(timed_out()),
        }
    }

    fn input_args(format: Format) -> Vec<String> {
        ["-protocol_whitelist", "file,pipe", "-f", format.demuxer(), "-i", "in"].iter().map(|s| s.to_string()).collect()
    }

    fn filter(&self, fps: Option<u32>) -> String {
        let geometry = match self.kind.geometry() {
            Geometry::Cover(w, h) => {
                format!("scale={w}:{h}:force_original_aspect_ratio=increase:flags=lanczos,crop={w}:{h}")
            }
            Geometry::Fit(max) => {
                format!("scale=w='min({max},iw)':h='min({max},ih)':force_original_aspect_ratio=decrease:flags=lanczos")
            }
        };
        match fps {
            Some(fps) => format!("fps={fps},{geometry}"),
            None => geometry,
        }
    }

    async fn read_output(&self, name: &str) -> Result<Option<Vec<u8>>, ApiError> {
        match tokio::fs::read(self.dir.join(name)).await {
            Ok(data) if data.len() >= 12 && &data[0..4] == b"RIFF" && &data[8..12] == b"WEBP" => Ok(Some(data)),
            Ok(_) => Ok(None),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
            Err(e) => Err(ApiError::Internal(e.into())),
        }
    }

    async fn run(&self, format: Format, input: Bytes) -> Result<Processed, ApiError> {
        if format == Format::WebPAnimated {
            return self.run_animated_webp(input).await;
        }
        tokio::fs::write(self.dir.join("in"), &input).await.map_err(|e| ApiError::Internal(e.into()))?;
        // Probe first: nothing is transcoded before the limits are checked.
        let mut probe_args = Self::input_args(format);
        probe_args.insert(0, "info".into());
        probe_args.insert(0, "-loglevel".into());
        let (_, stderr) = self.run_ffmpeg(&probe_args).await?;
        let probe = parse_probe(&stderr).ok_or_else(|| invalid("The file could not be read"))?;
        let max_side = self.kind.max_input_side(format.is_animated());
        if probe.width > max_side || probe.height > max_side {
            return Err(dimensions_too_large(max_side));
        }
        let animated = format.is_animated() && self.kind.keeps_animation();
        if animated && probe.duration_secs.is_some_and(|d| d > MAX_INPUT_SECS) {
            return Err(too_long());
        }
        let still = self.still_from(Self::input_args(format)).await?;
        let animated = if animated { Some(self.animated_from(Self::input_args(format), None).await?) } else { None };
        Ok(Processed { still, still_mime: "image/webp", animated })
    }

    async fn still_from(&self, input: Vec<String>) -> Result<Vec<u8>, ApiError> {
        let max = self.kind.max_output_bytes();
        for q in self.kind.still_qualities() {
            let mut args = vec!["-loglevel".to_string(), "error".into(), "-y".into()];
            args.extend(input.iter().cloned());
            args.extend(
                ["-frames:v", "1", "-an", "-sn", "-dn", "-map_metadata", "-1", "-vf"].iter().map(|s| s.to_string()),
            );
            args.push(self.filter(None));
            args.extend(["-c:v", "libwebp", "-quality"].iter().map(|s| s.to_string()));
            args.push(q.to_string());
            args.extend(["-fs".to_string(), (max * 2).to_string(), "-f".into(), "webp".into(), "still.webp".into()]);
            let (ok, stderr) = self.run_ffmpeg(&args).await?;
            if !ok {
                tracing::debug!(stderr, "ffmpeg still failed");
                return Err(invalid("The file could not be converted"));
            }
            match self.read_output("still.webp").await? {
                Some(data) if data.len() <= max => return Ok(data),
                Some(_) => continue,
                None => return Err(invalid("The file could not be converted")),
            }
        }
        Err(too_large(max, "media.output_too_large", "Das Ergebnis bleibt zu groß"))
    }

    /// Animated WebP from `input`; `raw` = the input is a raw frame stream on stdin (animated WebP
    /// sources), fed by the closure for each attempt.
    async fn animated_from(&self, input: Vec<String>, raw: Option<&RawFrames>) -> Result<Vec<u8>, ApiError> {
        let max = self.kind.max_output_bytes();
        for &(q, fps) in ANIMATED_STEPS {
            let mut args = vec!["-loglevel".to_string(), "error".into(), "-y".into()];
            args.extend(input.iter().cloned());
            args.extend([
                "-t".to_string(),
                self.kind.loop_secs().to_string(),
                "-an".into(),
                "-sn".into(),
                "-dn".into(),
            ]);
            if let Some(frames) = self.kind.max_frames() {
                args.extend(["-frames:v".to_string(), frames.to_string()]);
            }
            args.extend(["-map_metadata", "-1", "-vf"].iter().map(|s| s.to_string()));
            // Raw input already arrives at the target rate.
            args.push(self.filter(if raw.is_some() { None } else { Some(fps) }));
            args.extend(["-c:v", "libwebp_anim", "-loop", "0", "-quality"].iter().map(|s| s.to_string()));
            args.push(q.to_string());
            args.extend(["-fs".to_string(), (max * 2).to_string(), "-f".into(), "webp".into(), "anim.webp".into()]);
            let ok = match raw {
                None => {
                    let (ok, stderr) = self.run_ffmpeg(&args).await?;
                    if !ok {
                        tracing::debug!(stderr, "ffmpeg animation failed");
                    }
                    ok
                }
                Some(frames) => self.pipe_frames(&args, frames, fps).await?,
            };
            if !ok {
                return Err(invalid("The animation could not be converted"));
            }
            match self.read_output("anim.webp").await? {
                Some(data) if data.len() <= max => return Ok(data),
                Some(_) => continue,
                None => return Err(invalid("The animation could not be converted")),
            }
        }
        Err(too_large(max, "media.output_too_large", "Die Animation bleibt zu groß"))
    }

    /// Animated WebP input: frames decoded with `image-webp`, resampled to a constant rate, piped raw.
    async fn run_animated_webp(&self, input: Bytes) -> Result<Processed, ApiError> {
        let max_side = self.kind.max_input_side(true).min(MAX_ANIMATED_WEBP_SIDE);
        let frames = tokio::task::spawn_blocking(move || RawFrames::decode(input, max_side))
            .await
            .map_err(|e| ApiError::Internal(e.into()))??;
        // The still: the first frame as a single raw image.
        tokio::fs::write(self.dir.join("first.raw"), &frames.first).await.map_err(|e| ApiError::Internal(e.into()))?;
        let still = self.still_from(frames.raw_args(1, "first.raw")).await?;
        let animated = self.animated_from(frames.raw_args(15, "pipe:0"), Some(&frames)).await?;
        Ok(Processed { still, still_mime: "image/webp", animated: Some(animated) })
    }

    /// Runs ffmpeg reading raw frames from stdin at `fps`, written by a blocking decoder thread.
    async fn pipe_frames(&self, args: &[String], frames: &RawFrames, fps: u32) -> Result<bool, ApiError> {
        // Rewrite the input rate of the raw demuxer for this attempt.
        let mut args = args.to_vec();
        if let Some(i) = args.iter().position(|a| a == "-framerate") {
            args[i + 1] = fps.to_string();
        }
        let mut cmd = self.command();
        cmd.stdin(Stdio::piped()).args(&args);
        let mut child = cmd.spawn().map_err(|e| ApiError::Internal(anyhow::anyhow!("cannot start ffmpeg: {e}")))?;
        let mut stdin =
            child.stdin.take().ok_or_else(|| ApiError::Internal(anyhow::anyhow!("ffmpeg without stdin")))?;
        let (tx, mut rx) = tokio::sync::mpsc::channel::<Vec<u8>>(2);
        let source = frames.source.clone();
        let max_ms = u64::from(self.kind.loop_secs()) * 1000;
        let decoder = tokio::task::spawn_blocking(move || RawFrames::stream(&source, fps, max_ms, &tx));
        let writer = async {
            while let Some(frame) = rx.recv().await {
                if stdin.write_all(&frame).await.is_err() {
                    break;
                }
            }
            drop(stdin);
        };
        let work = async {
            writer.await;
            child.wait_with_output().await
        };
        let out = match tokio::time::timeout(self.remaining()?, work).await {
            Ok(Ok(out)) => out,
            Ok(Err(e)) => return Err(ApiError::Internal(anyhow::anyhow!("ffmpeg: {e}"))),
            Err(_) => {
                decoder.abort();
                return Err(timed_out());
            }
        };
        decoder.await.map_err(|e| ApiError::Internal(e.into()))??;
        if !out.status.success() {
            tracing::debug!(stderr = %String::from_utf8_lossy(&out.stderr), "ffmpeg raw animation failed");
        }
        Ok(out.status.success())
    }
}

/// An animated WebP source decoded with `image-webp`.
struct RawFrames {
    source: Bytes,
    width: u32,
    height: u32,
    /// `rgba` or `rgb24`.
    pix_fmt: &'static str,
    first: Vec<u8>,
}

impl RawFrames {
    fn decoder(source: &Bytes) -> Result<image_webp::WebPDecoder<Cursor<Bytes>>, ApiError> {
        let mut d = image_webp::WebPDecoder::new(Cursor::new(source.clone())).map_err(|_| invalid("Corrupt WebP"))?;
        d.set_memory_limit(64 * 1024 * 1024);
        Ok(d)
    }

    /// Checks the limits and decodes the first frame.
    fn decode(source: Bytes, max_side: u32) -> Result<Self, ApiError> {
        let mut d = Self::decoder(&source)?;
        let (width, height) = d.dimensions();
        if width == 0 || height == 0 || width > max_side || height > max_side {
            return Err(dimensions_too_large(max_side));
        }
        if d.loop_duration() as f64 > MAX_INPUT_SECS * 1000.0 || d.num_frames() > 3000 {
            return Err(too_long());
        }
        let size = d.output_buffer_size().ok_or_else(|| dimensions_too_large(MAX_ANIMATED_WEBP_SIDE))?;
        let mut first = vec![0; size];
        d.read_frame(&mut first).map_err(|_| invalid("Corrupt WebP"))?;
        let pix_fmt = if d.has_alpha() { "rgba" } else { "rgb24" };
        Ok(Self { source, width, height, pix_fmt, first })
    }

    fn raw_args(&self, fps: u32, input: &str) -> Vec<String> {
        [
            "-protocol_whitelist",
            "file,pipe",
            "-f",
            "rawvideo",
            "-pix_fmt",
            self.pix_fmt,
            "-video_size",
            &format!("{}x{}", self.width, self.height),
            "-framerate",
            &fps.to_string(),
            "-i",
            input,
        ]
        .iter()
        .map(|s| s.to_string())
        .collect()
    }

    /// Decodes all frames again and sends them, repeated to a constant `fps`, for at most `max_ms`.
    fn stream(source: &Bytes, fps: u32, max_ms: u64, tx: &tokio::sync::mpsc::Sender<Vec<u8>>) -> Result<(), ApiError> {
        let mut d = Self::decoder(source)?;
        let size = d.output_buffer_size().ok_or_else(|| invalid("Corrupt WebP"))?;
        let mut ticker = Ticker::new(fps, max_ms);
        loop {
            let mut frame = vec![0; size];
            let duration = match d.read_frame(&mut frame) {
                Ok(ms) => ms,
                Err(image_webp::DecodingError::NoMoreFrames) => break,
                Err(_) => return Err(invalid("Corrupt WebP")),
            };
            let Some(repeats) = ticker.next(duration) else { break };
            for _ in 0..repeats {
                if tx.blocking_send(frame.clone()).is_err() {
                    return Ok(());
                }
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used)]
    use super::*;

    fn png(chunks: &[(&[u8; 4], &[u8])]) -> Vec<u8> {
        let mut out = b"\x89PNG\r\n\x1a\n".to_vec();
        for (kind, body) in chunks {
            out.extend_from_slice(&(body.len() as u32).to_be_bytes());
            out.extend_from_slice(*kind);
            out.extend_from_slice(body);
            out.extend_from_slice(&[0, 0, 0, 0]); // CRC is not checked here
        }
        out
    }

    fn ihdr(w: u32, h: u32) -> Vec<u8> {
        let mut b = w.to_be_bytes().to_vec();
        b.extend_from_slice(&h.to_be_bytes());
        b.extend_from_slice(&[8, 6, 0, 0, 0]);
        b
    }

    #[test]
    fn formats_are_sniffed_from_magic_bytes() {
        let still = png(&[(b"IHDR", &ihdr(2, 2)), (b"IDAT", b"x"), (b"IEND", b"")]);
        assert_eq!(sniff(&still), Some(Format::Png));
        let apng = png(&[(b"IHDR", &ihdr(2, 2)), (b"acTL", &[0; 8]), (b"IDAT", b"x"), (b"IEND", b"")]);
        assert_eq!(sniff(&apng), Some(Format::Apng));
        assert_eq!(sniff(&[0xFF, 0xD8, 0xFF, 0xE0, 0, 0]), Some(Format::Jpeg));
        assert_eq!(sniff(b"\0\0\0\x18ftypmp42\0\0\0\0"), Some(Format::Mp4));
        assert_eq!(sniff(&[0x1A, 0x45, 0xDF, 0xA3, 1, 2]), Some(Format::WebM));
        // SVG, HTML and scripts are never images here, whatever the client claims.
        for bad in [&b"<svg xmlns='http://www.w3.org/2000/svg'/>"[..], b"<!DOCTYPE html>", b"#!/bin/sh", b"", b"RIFF"] {
            assert_eq!(sniff(bad), None, "{bad:?}");
        }
    }

    #[test]
    fn gif_frames_are_counted() {
        // Header, logical screen (no global table), one image of 1×1 with a tiny LZW stream, trailer.
        let frame = [0x2C, 0, 0, 0, 0, 1, 0, 1, 0, 0, 0x02, 0x02, 0x44, 0x01, 0x00];
        let mut one = b"GIF89a\x01\x00\x01\x00\x00\x00\x00".to_vec();
        one.extend_from_slice(&frame);
        one.push(0x3B);
        assert_eq!(gif_frame_count(&one, 10), 1);
        let mut two = b"GIF89a\x01\x00\x01\x00\x00\x00\x00".to_vec();
        // Graphic control extension between the frames.
        two.extend_from_slice(&frame);
        two.extend_from_slice(&[0x21, 0xF9, 0x04, 0, 10, 0, 0, 0]);
        two.extend_from_slice(&frame);
        two.push(0x3B);
        assert_eq!(gif_frame_count(&two, 10), 2);
        assert_eq!(gif_frame_count(&two, 1), 1, "stops early");
        assert_eq!(gif_frame_count(b"GIF89a", 10), 0, "truncated");
    }

    #[test]
    fn png_metadata_is_removed() {
        let input = png(&[
            (b"IHDR", &ihdr(16, 8)),
            (b"tEXt", b"Comment\0secret"),
            (b"eXIf", b"MM\0*gps"),
            (b"sRGB", &[0]),
            (b"IDAT", b"data"),
            (b"tIME", &[0; 7]),
            (b"IEND", b""),
        ]);
        let (out, dims) = sanitize_png(&input).unwrap();
        assert_eq!(dims, (16, 8));
        let kinds: Vec<&[u8]> = png_chunks(&out).map(|(k, _, _)| k).collect();
        assert_eq!(kinds, vec![&b"IHDR"[..], b"sRGB", b"IDAT", b"IEND"]);
        assert!(!out.windows(6).any(|w| w == b"secret"));
        // Truncated files and unknown critical chunks are refused.
        assert!(sanitize_png(&input[..input.len() - 6]).is_none());
        assert!(sanitize_png(&png(&[(b"IHDR", &ihdr(1, 1)), (b"ZZZZ", b""), (b"IEND", b"")])).is_none());
    }

    #[test]
    fn jpeg_metadata_is_removed() {
        let mut input = vec![0xFF, 0xD8];
        input.extend_from_slice(&[0xFF, 0xE0, 0, 4, b'J', b'F']); // APP0 kept
        input.extend_from_slice(&[0xFF, 0xE1, 0, 8, b'E', b'x', b'i', b'f', b'g', b'p']); // APP1 (EXIF) dropped
        input.extend_from_slice(&[0xFF, 0xFE, 0, 5, b'h', b'i', b'!']); // comment dropped
        input.extend_from_slice(&[0xFF, 0xC0, 0, 11, 8, 0, 20, 0, 30, 1, 1, 0x11, 0]); // SOF0 20×30 (h×w)
        input.extend_from_slice(&[0xFF, 0xDA, 0, 2, 0xAB, 0xCD, 0xFF, 0xD9]); // scan + EOI
        let (out, dims) = sanitize_jpeg(&input).unwrap();
        assert_eq!(dims, (30, 20));
        assert!(!out.windows(4).any(|w| w == b"Exif"));
        assert!(!out.windows(3).any(|w| w == b"hi!"));
        assert!(out.ends_with(&[0xAB, 0xCD, 0xFF, 0xD9]));
        assert!(sanitize_jpeg(&[0xFF, 0xD8, 0x00]).is_none());
    }

    #[test]
    fn probe_output_is_parsed() {
        let gif = "Input #0, gif, from 'in':\n  Duration: 00:00:02.50, start: 0.000000, bitrate: 87 kb/s\n  Stream #0:0: Video: gif, bgra, 120x80 [SAR 64:64 DAR 3:2], 10 fps, 10 tbr, 100 tbn\n";
        assert_eq!(parse_probe(gif), Some(Probe { duration_secs: Some(2.5), width: 120, height: 80 }));
        let mp4 = "  Duration: 00:01:05.00, start: 0.0, bitrate: 1 kb/s\n  Stream #0:0[0x1](und): Video: h264 (High) (avc1 / 0x31637661), yuv420p(progressive), 320x240 [SAR 1:1 DAR 4:3], 25 fps\n";
        assert_eq!(parse_probe(mp4), Some(Probe { duration_secs: Some(65.0), width: 320, height: 240 }));
        let png =
            "  Duration: N/A, bitrate: N/A\n  Stream #0:0: Video: png, rgba(pc, gbr/unknown/unknown), 64x48, 25 fps\n";
        assert_eq!(parse_probe(png), Some(Probe { duration_secs: None, width: 64, height: 48 }));
        assert_eq!(parse_probe("in: Invalid data found when processing input"), None);
    }

    #[test]
    fn frames_are_resampled_to_a_constant_rate() {
        // 10 fps output: a 250 ms frame covers 3 ticks (0, 100, 200), the next 100 ms frame one (300).
        assert_eq!(resample(&[250, 100], 10, 10_000), vec![3, 1]);
        // Zero and tiny delays count as 100 ms.
        assert_eq!(resample(&[0, 5], 10, 10_000), vec![1, 1]);
        // Capped at max_ms: 3 frames of 1 s at 2 fps, but only 1.5 s allowed.
        assert_eq!(resample(&[1000, 1000, 1000], 2, 1500), vec![2, 1]);
        // The first frame always starts at tick 0; short frames between ticks get none.
        assert_eq!(resample(&[30, 30, 30], 1, 10_000), vec![1, 0, 0]);
    }

    // ---- with ffmpeg (fixtures generated by ffmpeg itself; skipped without ffmpeg) ----------------

    /// A fixture made by `ffmpeg -f lavfi`, or `None` when ffmpeg (with lavfi) is not installed.
    fn fixture(source: &str, out_args: &[&str]) -> Option<Vec<u8>> {
        let ffmpeg = which("ffmpeg")?;
        let dir = tempfile::tempdir().ok()?;
        let path = dir.path().join("fixture");
        let status = std::process::Command::new(ffmpeg)
            .args(["-hide_banner", "-loglevel", "error", "-y", "-f", "lavfi", "-i", source])
            .args(out_args)
            .arg(&path)
            .status()
            .ok()?;
        if !status.success() {
            return None;
        }
        std::fs::read(path).ok()
    }

    /// `TAVRN_TEST_FFMPEG` runs the conversions with another binary (e.g. the image's minimal build).
    fn pipeline(ffmpeg: &str) -> (Pipeline, tempfile::TempDir) {
        let dir = tempfile::tempdir().unwrap();
        let ffmpeg = match std::env::var("TAVRN_TEST_FFMPEG") {
            Ok(path) if ffmpeg == "auto" => path,
            _ => ffmpeg.to_string(),
        };
        let config =
            Config { media_ffmpeg: ffmpeg, data_dir: dir.path().to_string_lossy().into(), ..Config::default() };
        (Pipeline::new(&config), dir)
    }

    fn webp_info(data: &[u8]) -> ((u32, u32), bool) {
        let d = image_webp::WebPDecoder::new(Cursor::new(data)).expect("valid WebP");
        (d.dimensions(), d.is_animated())
    }

    macro_rules! skip_without_ffmpeg {
        ($fixture:expr) => {
            match $fixture {
                Some(f) => f,
                None => {
                    eprintln!("ffmpeg not installed: skipped");
                    return;
                }
            }
        };
    }

    #[tokio::test]
    async fn still_images_become_webp_of_the_target_size() {
        let input = skip_without_ffmpeg!(fixture(
            "testsrc=size=640x480:rate=1",
            &["-frames:v", "1", "-f", "image2", "-c:v", "png"]
        ));
        let (p, _dir) = pipeline("auto");
        let avatar = p.process(MediaKind::Avatar, input.clone().into()).await.unwrap();
        assert_eq!(avatar.still_mime, "image/webp");
        assert_eq!(webp_info(&avatar.still), ((256, 256), false));
        assert!(avatar.animated.is_none());
        let header = p.process(MediaKind::Header, input.clone().into()).await.unwrap();
        assert_eq!(webp_info(&header.still).0, (1200, 400));
        let background = p.process(MediaKind::Background, input.into()).await.unwrap();
        assert_eq!(webp_info(&background.still).0, (640, 480), "never upscaled beyond the input");
    }

    #[tokio::test]
    async fn animated_gif_gets_a_still_and_an_animated_webp() {
        let input = skip_without_ffmpeg!(fixture("testsrc=size=120x80:rate=10:duration=2", &["-f", "gif"]));
        assert_eq!(sniff(&input), Some(Format::Gif));
        let (p, _dir) = pipeline("auto");
        let out = p.process(MediaKind::Icon, input.into()).await.unwrap();
        assert_eq!(webp_info(&out.still), ((256, 256), false), "the still is the first frame");
        let animated = out.animated.expect("animated variant");
        assert_eq!(webp_info(&animated), ((256, 256), true));
        assert!(animated.len() <= MediaKind::Icon.max_output_bytes());
    }

    #[tokio::test]
    async fn animated_webp_and_video_input_are_converted() {
        let webp = skip_without_ffmpeg!(fixture(
            "testsrc=size=96x96:rate=8:duration=2",
            &["-c:v", "libwebp_anim", "-loop", "0", "-f", "webp"]
        ));
        assert_eq!(sniff(&webp), Some(Format::WebPAnimated));
        let (p, _dir) = pipeline("auto");
        let out = p.process(MediaKind::Avatar, webp.into()).await.unwrap();
        assert_eq!(webp_info(&out.still), ((256, 256), false));
        assert_eq!(webp_info(&out.animated.unwrap()), ((256, 256), true));

        let mp4 =
            skip_without_ffmpeg!(fixture("testsrc=size=160x90:rate=10:duration=3", &["-c:v", "mpeg4", "-f", "mp4"]));
        assert_eq!(sniff(&mp4), Some(Format::Mp4));
        let out = p.process(MediaKind::Header, mp4.into()).await.unwrap();
        assert_eq!(webp_info(&out.animated.unwrap()), ((1200, 400), true));
    }

    #[tokio::test]
    async fn limits_are_checked_before_converting() {
        let long = skip_without_ffmpeg!(fixture("testsrc=size=32x32:rate=1:duration=40", &["-f", "gif"]));
        let (p, _dir) = pipeline("auto");
        let err = p.process(MediaKind::Avatar, long.into()).await.unwrap_err();
        assert_eq!(err.code(), "media.too_long");
        let huge = skip_without_ffmpeg!(fixture(
            "color=c=red:size=5000x16:rate=1",
            &["-frames:v", "1", "-f", "image2", "-c:v", "png"]
        ));
        assert_eq!(p.process(MediaKind::Avatar, huge.into()).await.unwrap_err().code(), "media.dimensions");
        let svg = b"<svg xmlns='http://www.w3.org/2000/svg'><script>alert(1)</script></svg>".to_vec();
        assert_eq!(p.process(MediaKind::Avatar, svg.into()).await.unwrap_err().code(), "media.type_not_allowed");
        assert_eq!(
            p.process(MediaKind::Avatar, vec![0u8; MAX_INPUT_BYTES + 1].into()).await.unwrap_err().code(),
            "media.too_large"
        );
        // Garbage behind a valid magic: refused by the probe, nothing crashes.
        let mut broken = b"GIF89a".to_vec();
        broken.extend_from_slice(&[0x55; 64]);
        assert_eq!(p.process(MediaKind::Avatar, broken.into()).await.unwrap_err().code(), "media.invalid");
    }

    #[tokio::test]
    async fn exif_never_survives_the_conversion() {
        let jpeg = skip_without_ffmpeg!(fixture(
            "testsrc=size=64x64:rate=1",
            &["-frames:v", "1", "-f", "image2", "-c:v", "mjpeg"]
        ));
        // Insert an EXIF segment with a fake GPS marker right after SOI.
        let mut input = jpeg[..2].to_vec();
        input.extend_from_slice(&[0xFF, 0xE1, 0, 14]);
        input.extend_from_slice(b"Exif  GPS-XY");
        input.extend_from_slice(&jpeg[2..]);
        let (p, _dir) = pipeline("auto");
        let out = p.process(MediaKind::Avatar, input.clone().into()).await.unwrap();
        assert!(!out.still.windows(6).any(|w| w == b"GPS-XY"));
        let (off, _dir2) = pipeline("off");
        let out = off.process(MediaKind::Avatar, input.into()).await.unwrap();
        assert_eq!(out.still_mime, "image/jpeg");
        assert!(!out.still.windows(6).any(|w| w == b"GPS-XY"), "stripped without ffmpeg too");
    }

    #[tokio::test]
    async fn without_ffmpeg_only_stills_pass() {
        let (p, _dir) = pipeline("off");
        assert!(!p.animated());
        let still = png(&[(b"IHDR", &ihdr(64, 64)), (b"IDAT", b"x"), (b"IEND", b"")]);
        let out = p.process(MediaKind::Avatar, still.into()).await.unwrap();
        assert_eq!(out.still_mime, "image/png");
        let gif = skip_without_ffmpeg!(fixture("testsrc=size=32x32:rate=5:duration=1", &["-f", "gif"]));
        assert_eq!(p.process(MediaKind::Avatar, gif.into()).await.unwrap_err().code(), "media.animation_unavailable");
        let big = png(&[(b"IHDR", &ihdr(5000, 10)), (b"IDAT", b"x"), (b"IEND", b"")]);
        assert_eq!(p.process(MediaKind::Avatar, big.into()).await.unwrap_err().code(), "media.dimensions");
    }

    #[test]
    fn kinds_have_their_limits() {
        assert_eq!(MediaKind::Avatar.max_output_bytes(), 1024 * 1024);
        assert_eq!(MediaKind::Header.max_output_bytes(), 2 * 1024 * 1024);
        assert_eq!(MediaKind::Icon.geometry(), Geometry::Cover(256, 256));
        assert_eq!(MediaKind::Header.geometry(), Geometry::Cover(1200, 400));
        assert_eq!(MediaKind::Background.geometry(), Geometry::Fit(1280));
        assert_eq!(MediaKind::Preview.geometry(), Geometry::Fit(400));
        assert_eq!(MediaKind::Preview.max_output_bytes(), 40 * 1024);
        assert!(!MediaKind::Preview.keeps_animation());
    }

    #[tokio::test]
    async fn link_previews_are_small_stills() {
        let input = skip_without_ffmpeg!(fixture(
            "testsrc=size=1280x720:rate=1",
            &["-frames:v", "1", "-f", "image2", "-c:v", "png"]
        ));
        let (p, _dir) = pipeline("auto");
        let out = p.process(MediaKind::Preview, input.into()).await.unwrap();
        assert_eq!(webp_info(&out.still), ((400, 225), false));
        assert!(out.still.len() <= 40 * 1024, "{} bytes", out.still.len());
        assert!(out.animated.is_none());
        let gif = skip_without_ffmpeg!(fixture("testsrc=size=120x80:rate=10:duration=2", &["-f", "gif"]));
        let out = p.process(MediaKind::Preview, gif.into()).await.unwrap();
        assert!(out.animated.is_none(), "only the first frame");
        let video = skip_without_ffmpeg!(fixture("testsrc=size=64x64:rate=5:duration=1", &["-f", "webm"]));
        assert_eq!(p.process(MediaKind::Preview, video.into()).await.unwrap_err().code(), "media.type_not_allowed");
    }
}
