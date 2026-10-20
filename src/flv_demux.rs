/// Error types for FLV demuxing.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FlvError { BadHeader, NoStreams, MixedCodecs, LimitExceeded }

/// Audio or video stream kind.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FlvKind { Audio, Video }

/// A single demuxed stream.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FlvStream {
    pub kind: FlvKind,
    pub tags: u32,
    pub comment: String,
    pub suffix: String,
    pub data: Vec<u8>,
}

/// Demux result with optional trailing bytes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FlvDemux {
    pub streams: Vec<FlvStream>,
    pub trailing: bool,
}

/// Produce a human-readable codec comment for the first data byte of a tag.
pub fn codec_comment(kind: FlvKind, first: u8) -> String {
    match kind {
        FlvKind::Audio => {
            let format = first >> 4;
            let rate = ["5.5", "11", "22", "44"][((first >> 2) & 3) as usize];
            let bits = if first & 2 != 0 { 16 } else { 8 };
            let ch = if first & 1 != 0 { "stereo" } else { "mono" };
            let name = match format {
                0 => "pcm", 1 => "adpcm", 2 => "mp3", 3 => "pcm_le",
                4 => "nellymoser16", 5 => "nellymoser8", 6 => "nellymoser",
                7 => "g711a", 8 => "g711m", 9 => "audio9", 10 => "aac",
                11 => "speex", 12 => "audio12", 13 => "audio13", 14 => "mp3",
                15 => "audio15",
                _ => return format!("audio{}", format),
            };
            format!("{} {} kHz {}-bit {}", name, rate, bits, ch)
        }
        FlvKind::Video => {
            let codec = first & 15;
            match codec {
                0 => "video0", 1 => "jpeg", 2 => "h263", 3 => "screen",
                4 => "vp6", 5 => "vp6alpha", 6 => "screen2", 7 => "avc",
                8 => "video8",
                _ => return format!("video{}", codec),
            }.to_string()
        }
    }
}

fn codec_suffix_name(kind: FlvKind, first: u8) -> &'static str {
    match kind {
        FlvKind::Audio => match first >> 4 {
            0 => "pcm", 1 => "adpcm", 2 => "mp3", 3 => "pcm_le",
            4 => "nellymoser16", 5 => "nellymoser8", 6 => "nellymoser",
            7 => "g711a", 8 => "g711m", 9 => "audio9", 10 => "aac",
            11 => "speex", 12 => "audio12", 13 => "audio13", 14 => "mp3",
            15 => "audio15", _ => "audio",
        },
        FlvKind::Video => match first & 15 {
            0 => "video0", 1 => "jpeg", 2 => "h263", 3 => "screen",
            4 => "vp6", 5 => "vp6alpha", 6 => "screen2", 7 => "avc",
            8 => "video8", _ => "video",
        },
    }
}

/// Demux an FLV file into its audio and video streams.
pub fn demux_flv(data: &[u8], max_output: usize) -> Result<FlvDemux, FlvError> {
    // 1. Header validation (13 bytes)
    if data.len() < 13
        || &data[0..3] != b"FLV"
        || data[3] != 1
        || u32::from_be_bytes([data[5], data[6], data[7], data[8]]) != 9
        || u32::from_be_bytes([data[9], data[10], data[11], data[12]]) != 0
    {
        return Err(FlvError::BadHeader);
    }

    let len = data.len();
    let mut pos: usize = 13;

    // Collect valid audio/video tags in order
    let mut audio_ts: Vec<u32> = Vec::new();
    let mut audio_data: Vec<Vec<u8>> = Vec::new();
    let mut video_ts: Vec<u32> = Vec::new();
    let mut video_data: Vec<Vec<u8>> = Vec::new();
    let mut order: Vec<FlvKind> = Vec::new();
    let mut seen_audio = false;
    let mut seen_video = false;

    while pos < len {
        // Need at least 15 bytes: 11 tag header + 1 data byte + 4 prev tag
        if pos + 15 > len { break; }

        let tag_type = data[pos];
        let data_size = u32::from_be_bytes([0, data[pos + 1], data[pos + 2], data[pos + 3]]) as usize;
        let timestamp = u32::from_be_bytes([0, data[pos + 4], data[pos + 5], data[pos + 6]]);
        let stream_id = u32::from_be_bytes([0, data[pos + 8], data[pos + 9], data[pos + 10]]);

        // Check if whole tag fits: 11 header + data_size + 4 prev tag
        let total_tag = 11usize + data_size + 4;
        if pos + total_tag > len { break; }

        // Stop conditions (in spec order)
        if data_size == 0 { break; }
        if stream_id != 0 { break; }
        let prev_tag_size = u32::from_be_bytes([
            data[pos + 11 + data_size],
            data[pos + 12 + data_size],
            data[pos + 13 + data_size],
            data[pos + 14 + data_size],
        ]);
        if prev_tag_size != (11 + data_size) as u32 { break; }
        if tag_type != 8 && tag_type != 9 && tag_type != 18 { break; }

        // Record audio(8) or video(9) tags; script(18) is ignored
        let tag_data = data[pos + 11..pos + 11 + data_size].to_vec();
        if tag_type == 8 {
            if !seen_audio { seen_audio = true; order.push(FlvKind::Audio); }
            audio_ts.push(timestamp);
            audio_data.push(tag_data);
        } else if tag_type == 9 {
            if !seen_video { seen_video = true; order.push(FlvKind::Video); }
            video_ts.push(timestamp);
            video_data.push(tag_data);
        }

        pos += total_tag;
    }

    let trailing = pos < len;
    let has_audio = !audio_data.is_empty();
    let has_video = !video_data.is_empty();

    if !has_audio && !has_video { return Err(FlvError::NoStreams); }

    let single = (has_audio && !has_video) || (!has_audio && has_video);

    // Codec consistency check for single-stream case
    if single && has_audio {
        let fc = audio_data[0][0] >> 4;
        for d in &audio_data[1..] { if d[0] >> 4 != fc { return Err(FlvError::MixedCodecs); } }
    }
    if single && has_video {
        let fc = video_data[0][0] & 15;
        for d in &video_data[1..] { if d[0] & 15 != fc { return Err(FlvError::MixedCodecs); } }
    }

    // 5. Compute total output size before allocating
    let mut total_output: usize = 0;
    if single {
        let datas = if has_audio { &audio_data } else { &video_data };
        for d in datas { total_output = total_output.saturating_add(d.len().saturating_sub(1)); }
    } else {
        if has_audio {
            let sz: usize = audio_data.iter().map(|d| 11 + d.len() + 4).sum();
            total_output = total_output.saturating_add(13).saturating_add(sz);
        }
        if has_video {
            let sz: usize = video_data.iter().map(|d| 11 + d.len() + 4).sum();
            total_output = total_output.saturating_add(13).saturating_add(sz);
        }
    }

    if total_output > max_output { return Err(FlvError::LimitExceeded); }

    // Build streams
    let mut streams: Vec<FlvStream> = Vec::new();

    for kind in &order {
        let (tags, tag_datas, tag_timestamps): (u32, Vec<Vec<u8>>, Vec<u32>) =
            if *kind == FlvKind::Audio {
                (audio_data.len() as u32, audio_data.clone(), audio_ts.clone())
            } else {
                (video_data.len() as u32, video_data.clone(), video_ts.clone())
            };

        let first_data = &tag_datas[0];
        let comment = codec_comment(*kind, first_data[0]);

        if single {
            let mut out: Vec<u8> = Vec::with_capacity(total_output);
            for d in &tag_datas { if d.len() > 1 { out.extend_from_slice(&d[1..]); } }
            let sn = codec_suffix_name(*kind, first_data[0]);
            streams.push(FlvStream { kind: *kind, tags, comment, suffix: format!(".{}", sn), data: out });
        } else {
            let flags_byte = if *kind == FlvKind::Audio { 4u8 } else { 1u8 };
            let tag_type = if *kind == FlvKind::Audio { 8u8 } else { 9u8 };
            let suffix = if *kind == FlvKind::Audio { ".audio.flv" } else { ".video.flv" };

            let mut out: Vec<u8> = Vec::with_capacity(total_output);
            out.extend_from_slice(b"FLV");
            out.push(1);
            out.push(flags_byte);
            out.extend_from_slice(&9u32.to_be_bytes());
            out.extend_from_slice(&0u32.to_be_bytes());

            for (i, d) in tag_datas.iter().enumerate() {
                let ds = d.len() as u32;
                let ts = tag_timestamps[i];
                out.push(tag_type);
                out.push((ds >> 16) as u8); out.push((ds >> 8) as u8); out.push(ds as u8);
                out.push((ts >> 16) as u8); out.push((ts >> 8) as u8); out.push(ts as u8);
                out.push(0);
                out.extend_from_slice(&0u32.to_be_bytes()[1..]);
                out.extend_from_slice(d);
                out.extend_from_slice(&((11 + d.len()) as u32).to_be_bytes());
            }

            streams.push(FlvStream { kind: *kind, tags, comment, suffix: suffix.to_string(), data: out });
        }
    }

    Ok(FlvDemux { streams, trailing })
}
