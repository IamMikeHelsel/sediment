use sediment_engine::flv_demux::{codec_comment, demux_flv, FlvDemux, FlvError, FlvKind};

macro_rules! fx { ($n:literal) => { include_bytes!(concat!("flv_demux_fixtures/", $n)) as &[u8] } }
fn ok(b: &[u8]) -> FlvDemux { demux_flv(b, 1 << 20).unwrap() }
// (suffix, tags, comment, bytes) with bytes = what `7zz x` (26.04) wrote; tags/comment from `7zz l -slt` Blocks/Comment.
fn check(d: &FlvDemux, want: &[(&str, u32, &str, &[u8])]) {
    let got: Vec<(&str, u32, &str, &[u8])> =
        d.streams.iter().map(|s| (s.suffix.as_str(), s.tags, s.comment.as_str(), &s.data[..])).collect();
    assert_eq!(got, want);
}

#[test]
fn two_streams_become_flv_files() {
    let d = ok(fx!("av.flv"));
    assert!(!d.trailing);
    check(&d, &[(".audio.flv", 3, "mp3 44 kHz 16-bit stereo", fx!("expected/av.audio.flv")),
                (".video.flv", 3, "h263", fx!("expected/av.video.flv"))]);
    assert_eq!((d.streams[0].kind, d.streams[1].kind), (FlvKind::Audio, FlvKind::Video));
    let d = ok(fx!("va.flv")); // first appearance order; audio codec change allowed with two streams
    check(&d, &[(".video.flv", 2, "h263", fx!("expected/va.video.flv")),
                (".audio.flv", 3, "mp3 44 kHz 16-bit stereo", fx!("expected/va.audio.flv"))]);
}

#[test]
fn single_stream_is_raw() {
    check(&ok(fx!("mp3.flv")), &[(".mp3", 4, "mp3 44 kHz 16-bit stereo", fx!("expected/mp3.mp3"))]);
    check(&ok(fx!("aac.flv")), &[(".aac", 2, "aac 44 kHz 16-bit stereo", fx!("expected/aac.aac"))]);
    check(&ok(fx!("avc.flv")), &[(".avc", 2, "avc", fx!("expected/avc.avc"))]);
}

#[test]
fn stops_at_first_bad_tag() {
    for n in ["tr_sid", "tr_cut"] {
        let b: &[u8] = if n == "tr_sid" { fx!("tr_sid.flv") } else { fx!("tr_cut.flv") };
        let d = ok(b);
        assert!(d.trailing, "{n}");
        check(&d, &[(".mp3", 1, "mp3 44 kHz 16-bit stereo", fx!("expected/tr_sid.mp3"))]);
    }
    for b in [fx!("tr_empty.flv"), fx!("tr_prev.flv"), fx!("tr_type.flv"), fx!("tr_junk.flv")] {
        let d = ok(b);
        assert!(d.trailing);
        assert_eq!((d.streams.len(), d.streams[0].data.len()), (1, 24));
    }
}

#[test]
fn open_errors() {
    assert_eq!(demux_flv(fx!("mix_audio.flv"), 1 << 20), Err(FlvError::MixedCodecs));
    assert_eq!(demux_flv(fx!("mix_video.flv"), 1 << 20), Err(FlvError::MixedCodecs));
    assert_eq!(demux_flv(fx!("meta_only.flv"), 1 << 20), Err(FlvError::NoStreams));
    assert_eq!(demux_flv(fx!("no_tags.flv"), 1 << 20), Err(FlvError::NoStreams));
    for b in [fx!("bad_ver.flv"), fx!("bad_hsize.flv"), fx!("bad_prev0.flv")] {
        assert_eq!(demux_flv(b, 1 << 20), Err(FlvError::BadHeader));
    }
    assert_eq!(demux_flv(&fx!("av.flv")[..12], 1 << 20), Err(FlvError::BadHeader));
    assert_eq!(demux_flv(b"", 1 << 20), Err(FlvError::BadHeader));
}

#[test]
fn output_limit() {
    assert_eq!(demux_flv(fx!("av.flv"), 283), Err(FlvError::LimitExceeded));
    assert_eq!(ok(fx!("av.flv")).streams.iter().map(|s| s.data.len()).sum::<usize>(), 284);
    assert!(demux_flv(fx!("av.flv"), 284).is_ok());
}

#[test]
fn comments_match_7zz() {
    let a = [(0x00, "pcm 5.5 kHz 8-bit mono"), (0x05, "pcm 11 kHz 8-bit stereo"), (0x2A, "mp3 22 kHz 16-bit mono"),
             (0x3F, "pcm_le 44 kHz 16-bit stereo"), (0x4F, "nellymoser16 44 kHz 16-bit stereo"),
             (0x6F, "nellymoser 44 kHz 16-bit stereo"), (0x7F, "g711a 44 kHz 16-bit stereo"),
             (0x9F, "audio9 44 kHz 16-bit stereo"), (0xBF, "speex 44 kHz 16-bit stereo"), (0xEF, "mp3 44 kHz 16-bit stereo"),
             (0xFF, "audio15 44 kHz 16-bit stereo"), (0x1F, "adpcm 44 kHz 16-bit stereo"), (0x8F, "g711m 44 kHz 16-bit stereo")];
    for (b, s) in a { assert_eq!(codec_comment(FlvKind::Audio, b), s); }
    let v = [(0x10, "video0"), (0x21, "jpeg"), (0x13, "screen"), (0x14, "vp6"), (0x25, "vp6alpha"), (0x16, "screen2"),
             (0x17, "avc"), (0x18, "video8"), (0x2F, "video15")];
    for (b, s) in v { assert_eq!(codec_comment(FlvKind::Video, b), s); }
}

#[test]
fn hostile_never_panics() {
    let base = fx!("av.flv");
    let mut seed = 0x1357_9bdfu32;
    for _ in 0..500 {
        let mut v = base.to_vec();
        for _ in 0..4 {
            seed = seed.wrapping_mul(1_103_515_245).wrapping_add(12345);
            let i = (seed >> 8) as usize % v.len();
            v[i] = (seed >> 24) as u8;
        }
        let cut = (seed as usize) % (v.len() + 1);
        let _ = demux_flv(&v[..cut], 1 << 16);
        let _ = demux_flv(&v, 64);
    }
}
