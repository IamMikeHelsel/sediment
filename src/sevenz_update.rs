// SPDX-License-Identifier: MIT OR Apache-2.0
//! Rewrite a 7z archive according to an [`EditPlan`].
//!
//! Spec source: the public "7z Format" description (`7zFormat.txt`, LZMA SDK
//! `DOC/`): signature header, `NUMBER` encoding, PackInfo / UnpackInfo
//! (Folder coder records, bind pairs, packed-stream indices,
//! CodersUnpackSize, folder digests) / SubStreamsInfo (NumUnpackStream,
//! sizes, digests of streams not covered by a single-substream folder CRC) /
//! FilesInfo (EmptyStream, EmptyFile and Anti bit vectors over the empty
//! streams, UTF-16LE names, FILETIME times, attributes) and the
//! EncodedHeader indirection. No 7-Zip source code was consulted.
//!
//! A folder (solid block) whose files are all kept, possibly renamed, is
//! copied verbatim: its packed streams, coder records (whatever the
//! methods, including ones Sediment cannot decode), unpack sizes, CRCs and
//! substream layout. Renames only touch FilesInfo. A folder that loses a
//! member (delete or replace) is decoded and its surviving members are
//! re-encoded, together with replacements and additions, by
//! [`crate::sevenz_write::write_7z`] into a scratch archive whose folders
//! are then copied the same way. Empty-stream items (directories, empty
//! files, anti-items) keep their flags, times and attributes.
//!
//! File order in the output: kept original files in their original order,
//! then re-encoded and new files. Stream files stay in folder order as the
//! format requires. The header is LZMA-compressed when
//! `compress_header` is set and that makes it smaller. Archive properties,
//! additional streams and FilesInfo comment/start-position records are not
//! carried over.

use crate::archive_open::SevenZCodecs;
use crate::archive_update::{EditPlan, EntryAction, ExistingEntry, UpdateError, UpdateLimits};
use crate::crc32::crc32;
use crate::fs_collect::{ArchiveEntry, EntryKind};
use crate::lzma_encode::{LzmaEncoderOptions, effective_dictionary_size, encode_lzma_raw, props_byte};
use crate::sevenz_header::{
    Folder, Header, SIGNATURE, SevenZLimits, SevenZReadError, method_id, pack_stream_ranges,
    property_id as pid,
};
use crate::sevenz_read::{SevenZArchive, filetime_to_unix};
use crate::sevenz_write::{
    SevenZItem, SevenZWriteError, SevenZWriteLimits, SevenZWriteOptions, unix_attributes, unix_to_filetime, write_7z,
    write_number,
};

const SIG_SIZE: usize = 32;

fn map_read(e: SevenZReadError) -> UpdateError {
    match e {
        SevenZReadError::LimitExceeded => UpdateError::LimitExceeded,
        SevenZReadError::Allocation => UpdateError::Allocation,
        SevenZReadError::Unsupported | SevenZReadError::UnsupportedMethod => UpdateError::Unsupported,
        _ => UpdateError::InvalidArchive,
    }
}

fn map_write(e: SevenZWriteError) -> UpdateError {
    match e {
        SevenZWriteError::InvalidName => UpdateError::InvalidName,
        SevenZWriteError::LimitExceeded => UpdateError::LimitExceeded,
        SevenZWriteError::Allocation => UpdateError::Allocation,
        _ => UpdateError::EncodeFailed,
    }
}

fn codecs(limits: &UpdateLimits) -> (SevenZCodecs, SevenZLimits) {
    let sl = SevenZLimits {
        max_files: limits.max_entries,
        max_unpack_bytes: limits.max_total_bytes,
        ..SevenZLimits::default()
    };
    (SevenZCodecs { max_output: limits.max_total_bytes }, sl)
}

fn open<'a>(bytes: &'a [u8], limits: &UpdateLimits) -> Result<SevenZArchive<'a>, UpdateError> {
    let (c, sl) = codecs(limits);
    SevenZArchive::open(bytes, &c, sl).map_err(map_read)
}

/// List the entries of a 7z archive for planning (empty input = no archive).
pub fn sevenz_entries(bytes: &[u8], limits: &UpdateLimits) -> Result<Vec<ExistingEntry>, UpdateError> {
    if bytes.is_empty() {
        return Ok(Vec::new());
    }
    let a = open(bytes, limits)?;
    Ok(a.entries()
        .iter()
        .map(|e| ExistingEntry {
            name: e.name.as_bytes().to_vec(),
            is_dir: e.is_dir || e.has_dir_attribute(),
            mtime: e.mtime.map(|t| filetime_to_unix(t).0),
            time_resolution: 1,
        })
        .collect())
}

/// One output file record.
struct FileOut {
    name: String,
    has_stream: bool,
    is_empty_file: bool,
    is_anti: bool,
    attributes: Option<u32>,
    ctime: Option<u64>,
    atime: Option<u64>,
    mtime: Option<u64>,
}

/// One output folder with everything needed to describe it.
struct FolderOut<'a> {
    folder: &'a Folder,
    packs: Vec<&'a [u8]>,
    pack_crcs: Vec<Option<u32>>,
    sub_sizes: &'a [u64],
    sub_crcs: &'a [Option<u32>],
}

/// Collect the folders of `header` selected by `keep` from archive `bytes`.
fn folders_of<'a>(
    bytes: &'a [u8],
    header: &'a Header,
    keep: impl Fn(usize) -> bool,
    out: &mut Vec<FolderOut<'a>>,
) -> Result<(), UpdateError> {
    let ms = &header.main_streams;
    let ranges = pack_stream_ranges(bytes.len(), &ms.pack_info).map_err(map_read)?;
    let mut pack = 0usize;
    let mut sub = 0usize;
    for (k, f) in ms.folders.iter().enumerate() {
        let np = f.packed_streams.len();
        let ns = *ms.substreams.num_unpack_streams.get(k).ok_or(UpdateError::InvalidArchive)?;
        let sub_end = sub.checked_add(ns).ok_or(UpdateError::InvalidArchive)?;
        if keep(k) && ns > 0 {
            let mut packs = Vec::new();
            let mut crcs = Vec::new();
            for p in pack..pack + np {
                let &(s, e) = ranges.get(p).ok_or(UpdateError::InvalidArchive)?;
                packs.push(&bytes[s..e]);
                crcs.push(ms.pack_info.crcs.get(p).copied().flatten());
            }
            out.push(FolderOut {
                folder: f,
                packs,
                pack_crcs: crcs,
                sub_sizes: ms.substreams.sizes.get(sub..sub_end).ok_or(UpdateError::InvalidArchive)?,
                sub_crcs: ms.substreams.crcs.get(sub..sub_end).ok_or(UpdateError::InvalidArchive)?,
            });
        }
        pack += np;
        sub = sub_end;
    }
    Ok(())
}

fn write_bits(out: &mut Vec<u8>, bits: &[bool]) {
    let mut cur = 0u8;
    for (i, &b) in bits.iter().enumerate() {
        if b {
            cur |= 0x80 >> (i % 8);
        }
        if i % 8 == 7 {
            out.push(cur);
            cur = 0;
        }
    }
    if !bits.len().is_multiple_of(8) {
        out.push(cur);
    }
}

/// `AllAreDefined` byte plus optional bit vector.
fn write_defined(out: &mut Vec<u8>, defined: &[bool]) {
    if defined.iter().all(|&d| d) {
        out.push(1);
    } else {
        out.push(0);
        write_bits(out, defined);
    }
}

fn write_digests(out: &mut Vec<u8>, crcs: &[Option<u32>]) {
    write_defined(out, &crcs.iter().map(Option::is_some).collect::<Vec<_>>());
    for c in crcs.iter().flatten() {
        out.extend_from_slice(&c.to_le_bytes());
    }
}

fn write_folder(out: &mut Vec<u8>, f: &Folder) -> Result<(), UpdateError> {
    write_number(out, f.coders.len() as u64);
    for c in &f.coders {
        if c.method_id.len() > 15 {
            return Err(UpdateError::Unsupported);
        }
        let complex = c.num_in_streams != 1 || c.num_out_streams != 1;
        let mut flags = c.method_id.len() as u8;
        if complex {
            flags |= 0x10;
        }
        if !c.properties.is_empty() {
            flags |= 0x20;
        }
        out.push(flags);
        out.extend_from_slice(&c.method_id);
        if complex {
            write_number(out, c.num_in_streams as u64);
            write_number(out, c.num_out_streams as u64);
        }
        if !c.properties.is_empty() {
            write_number(out, c.properties.len() as u64);
            out.extend_from_slice(&c.properties);
        }
    }
    for bp in &f.bind_pairs {
        write_number(out, bp.in_index as u64);
        write_number(out, bp.out_index as u64);
    }
    if f.packed_streams.len() > 1 {
        for &p in &f.packed_streams {
            write_number(out, p as u64);
        }
    }
    Ok(())
}

fn write_streams(out: &mut Vec<u8>, folders: &[FolderOut<'_>]) -> Result<(), UpdateError> {
    out.push(pid::MAIN_STREAMS_INFO);
    out.push(pid::PACK_INFO);
    write_number(out, 0);
    let packs: Vec<(&[u8], Option<u32>)> =
        folders.iter().flat_map(|f| f.packs.iter().copied().zip(f.pack_crcs.iter().copied())).collect();
    write_number(out, packs.len() as u64);
    out.push(pid::SIZE);
    for (p, _) in &packs {
        write_number(out, p.len() as u64);
    }
    if packs.iter().any(|(_, c)| c.is_some()) {
        out.push(pid::CRC);
        write_digests(out, &packs.iter().map(|(_, c)| *c).collect::<Vec<_>>());
    }
    out.push(pid::END);

    out.push(pid::UNPACK_INFO);
    out.push(pid::FOLDER);
    write_number(out, folders.len() as u64);
    out.push(0); // not external
    for f in folders {
        write_folder(out, f.folder)?;
    }
    out.push(pid::CODERS_UNPACK_SIZE);
    for f in folders {
        for &s in &f.folder.unpack_sizes {
            write_number(out, s);
        }
    }
    if folders.iter().any(|f| f.folder.unpack_crc.is_some()) {
        out.push(pid::CRC);
        write_digests(out, &folders.iter().map(|f| f.folder.unpack_crc).collect::<Vec<_>>());
    }
    out.push(pid::END);

    out.push(pid::SUBSTREAMS_INFO);
    if folders.iter().any(|f| f.sub_sizes.len() != 1) {
        out.push(pid::NUM_UNPACK_STREAM);
        for f in folders {
            write_number(out, f.sub_sizes.len() as u64);
        }
    }
    if folders.iter().any(|f| f.sub_sizes.len() > 1) {
        out.push(pid::SIZE);
        for f in folders {
            for &s in f.sub_sizes.iter().take(f.sub_sizes.len().saturating_sub(1)) {
                write_number(out, s);
            }
        }
    }
    let mut digests: Vec<Option<u32>> = Vec::new();
    for f in folders {
        if !(f.sub_sizes.len() == 1 && f.folder.unpack_crc.is_some()) {
            digests.extend_from_slice(f.sub_crcs);
        }
    }
    if digests.iter().any(Option::is_some) {
        out.push(pid::CRC);
        write_digests(out, &digests);
    }
    out.push(pid::END);
    out.push(pid::END);
    Ok(())
}

fn write_prop(out: &mut Vec<u8>, id: u8, data: &[u8]) {
    out.push(id);
    write_number(out, data.len() as u64);
    out.extend_from_slice(data);
}

fn write_files(out: &mut Vec<u8>, files: &[FileOut]) {
    out.push(pid::FILES_INFO);
    write_number(out, files.len() as u64);
    let empty: Vec<bool> = files.iter().map(|f| !f.has_stream).collect();
    if empty.iter().any(|&b| b) {
        let mut v = Vec::new();
        write_bits(&mut v, &empty);
        write_prop(out, pid::EMPTY_STREAM, &v);
        let ef: Vec<bool> = files.iter().filter(|f| !f.has_stream).map(|f| f.is_empty_file).collect();
        if ef.iter().any(|&b| b) {
            let mut v = Vec::new();
            write_bits(&mut v, &ef);
            write_prop(out, pid::EMPTY_FILE, &v);
        }
        let anti: Vec<bool> = files.iter().filter(|f| !f.has_stream).map(|f| f.is_anti).collect();
        if anti.iter().any(|&b| b) {
            let mut v = Vec::new();
            write_bits(&mut v, &anti);
            write_prop(out, pid::ANTI, &v);
        }
    }
    let mut names = vec![0u8];
    for f in files {
        for u in f.name.encode_utf16() {
            names.extend_from_slice(&u.to_le_bytes());
        }
        names.extend_from_slice(&[0, 0]);
    }
    write_prop(out, pid::NAME, &names);
    type Get = fn(&FileOut) -> Option<u64>;
    let times: [(u8, Get); 3] = [(pid::CTIME, |f| f.ctime), (pid::ATIME, |f| f.atime), (pid::MTIME, |f| f.mtime)];
    for (id, get) in times {
        let vals: Vec<Option<u64>> = files.iter().map(get).collect();
        if vals.iter().all(Option::is_none) {
            continue;
        }
        let mut v = Vec::new();
        write_defined(&mut v, &vals.iter().map(Option::is_some).collect::<Vec<_>>());
        v.push(0);
        for t in vals.iter().flatten() {
            v.extend_from_slice(&t.to_le_bytes());
        }
        write_prop(out, id, &v);
    }
    let attrs: Vec<Option<u32>> = files.iter().map(|f| f.attributes).collect();
    if attrs.iter().any(Option::is_some) {
        let mut v = Vec::new();
        write_defined(&mut v, &attrs.iter().map(Option::is_some).collect::<Vec<_>>());
        v.push(0);
        for a in attrs.iter().flatten() {
            v.extend_from_slice(&a.to_le_bytes());
        }
        write_prop(out, pid::WIN_ATTRIBUTES, &v);
    }
    out.push(pid::END);
}

/// LZMA-compress the raw header; returns (packed bytes, EncodedHeader record).
fn encode_header(raw: &[u8], pack_pos: u64) -> Result<(Vec<u8>, Vec<u8>), UpdateError> {
    let mut o = LzmaEncoderOptions::preset(5).map_err(|_| UpdateError::EncodeFailed)?;
    o.dictionary_size = 1 << 20;
    let dict = effective_dictionary_size(o.dictionary_size, raw.len());
    let packed = encode_lzma_raw(raw, &o, false).map_err(|_| UpdateError::EncodeFailed)?;
    let mut enc = vec![pid::ENCODED_HEADER, pid::PACK_INFO];
    write_number(&mut enc, pack_pos);
    write_number(&mut enc, 1);
    enc.push(pid::SIZE);
    write_number(&mut enc, packed.len() as u64);
    enc.push(pid::END);
    enc.push(pid::UNPACK_INFO);
    enc.push(pid::FOLDER);
    write_number(&mut enc, 1);
    enc.push(0);
    write_number(&mut enc, 1); // one coder
    enc.push(method_id::LZMA.len() as u8 | 0x20);
    enc.extend_from_slice(method_id::LZMA);
    write_number(&mut enc, 5);
    enc.push(props_byte(o.lc, o.lp, o.pb));
    enc.extend_from_slice(&dict.to_le_bytes());
    enc.push(pid::CODERS_UNPACK_SIZE);
    write_number(&mut enc, raw.len() as u64);
    enc.push(pid::CRC);
    enc.push(1);
    enc.extend_from_slice(&crc32(raw).to_le_bytes());
    enc.push(pid::END);
    enc.push(pid::END);
    Ok((packed, enc))
}

fn finish_signature(out: &mut [u8], next_offset: u64, next_size: u64, next_crc: u32) {
    out[..6].copy_from_slice(&SIGNATURE);
    out[6] = 0;
    out[7] = 4;
    out[12..20].copy_from_slice(&next_offset.to_le_bytes());
    out[20..28].copy_from_slice(&next_size.to_le_bytes());
    out[28..32].copy_from_slice(&next_crc.to_le_bytes());
    let c = crc32(&out[12..32]);
    out[8..12].copy_from_slice(&c.to_le_bytes());
}

/// Owned data for one re-encoded or new item.
struct FreshItem {
    name: String,
    data: Vec<u8>,
    is_dir: bool,
    attributes: Option<u32>,
    mtime: Option<u64>,
    ctime: Option<u64>,
    atime: Option<u64>,
}

fn fresh_from_entry(e: &ArchiveEntry<'_>) -> Result<FreshItem, UpdateError> {
    let name = std::str::from_utf8(e.name).map_err(|_| UpdateError::InvalidName)?.to_owned();
    let data = match e.kind {
        EntryKind::File => e.data,
        EntryKind::Directory => &[][..],
        EntryKind::Symlink => {
            if e.link_target.is_empty() {
                return Err(UpdateError::EncodeFailed);
            }
            e.link_target
        }
    };
    let mut d = Vec::new();
    d.try_reserve_exact(data.len()).map_err(|_| UpdateError::Allocation)?;
    d.extend_from_slice(data);
    Ok(FreshItem {
        name,
        data: d,
        is_dir: e.kind == EntryKind::Directory,
        attributes: Some(unix_attributes(e.kind, e.mode)),
        mtime: unix_to_filetime(e.mtime, 0),
        ctime: None,
        atime: None,
    })
}

/// Apply `plan` to the 7z archive `bytes` (empty = start a new archive).
/// `opts` controls how re-encoded and new members are compressed and
/// whether the header is compressed.
pub fn apply_7z(
    bytes: &[u8],
    plan: &EditPlan<'_>,
    opts: &SevenZWriteOptions,
    limits: &UpdateLimits,
) -> Result<Vec<u8>, UpdateError> {
    let (codec, _) = codecs(limits);
    let empty_header = Header::default();
    let archive = if bytes.is_empty() { None } else { Some(open(bytes, limits)?) };
    let header: &Header = archive.as_ref().map_or(&empty_header, |a| a.header());
    let n_files = header.files.len();
    if plan.actions.len() != n_files {
        return Err(UpdateError::InvalidArchive);
    }
    let n_folders = header.main_streams.folders.len();
    let entries = archive.as_ref().map_or(&[][..], |a| a.entries());

    // A folder is dirty when any of its members is deleted or replaced.
    let mut dirty = vec![false; n_folders];
    for (e, a) in entries.iter().zip(&plan.actions) {
        if let (Some(f), EntryAction::Delete | EntryAction::Replace(_)) = (e.folder_index, a) {
            *dirty.get_mut(f).ok_or(UpdateError::InvalidArchive)? = true;
        }
    }

    let new_name = |i: usize| -> Result<String, UpdateError> {
        match &plan.actions[i] {
            EntryAction::Rename(n) => String::from_utf8(n.clone()).map_err(|_| UpdateError::InvalidName),
            _ => Ok(entries[i].name.clone()),
        }
    };

    // Kept files and survivors of dirty folders.
    let mut files: Vec<FileOut> = Vec::new();
    let mut fresh: Vec<FreshItem> = Vec::new();
    let mut decoded: Option<(usize, Vec<Vec<u8>>)> = None;
    let mut total: u64 = 0;
    for (i, a) in plan.actions.iter().enumerate() {
        if matches!(a, EntryAction::Delete | EntryAction::Replace(_)) {
            continue;
        }
        let e = &entries[i];
        let fi = &header.files[i];
        match (e.folder_index, e.index_in_folder) {
            (Some(f), Some(k)) if dirty[f] => {
                let arch = archive.as_ref().ok_or(UpdateError::InvalidArchive)?;
                if decoded.as_ref().is_none_or(|(df, _)| *df != f) {
                    // Release the previous folder before decoding the next.
                    drop(decoded.take());
                    decoded = Some((f, arch.extract_folder(f, &codec).map_err(map_read)?));
                }
                let parts = &decoded.as_ref().ok_or(UpdateError::InvalidArchive)?.1;
                let part = parts.get(k).ok_or(UpdateError::InvalidArchive)?;
                total = total.saturating_add(part.len() as u64);
                if total > limits.max_total_bytes {
                    return Err(UpdateError::LimitExceeded);
                }
                let mut data = Vec::new();
                data.try_reserve_exact(part.len()).map_err(|_| UpdateError::Allocation)?;
                data.extend_from_slice(part);
                fresh.push(FreshItem {
                    name: new_name(i)?,
                    data,
                    is_dir: false,
                    attributes: fi.attributes,
                    mtime: fi.mtime,
                    ctime: fi.ctime,
                    atime: fi.atime,
                });
            }
            _ => files.push(FileOut {
                name: new_name(i)?,
                has_stream: fi.has_stream,
                is_empty_file: fi.is_empty_file,
                is_anti: fi.is_anti,
                attributes: fi.attributes,
                ctime: fi.ctime,
                atime: fi.atime,
                mtime: fi.mtime,
            }),
        }
    }
    drop(decoded);
    for a in &plan.actions {
        if let EntryAction::Replace(e) = a {
            total = total.saturating_add(e.data.len() as u64);
            fresh.push(fresh_from_entry(e)?);
        }
    }
    for e in &plan.additions {
        total = total.saturating_add(e.data.len() as u64);
        fresh.push(fresh_from_entry(e)?);
    }
    if total > limits.max_total_bytes {
        return Err(UpdateError::LimitExceeded);
    }
    if files.len().saturating_add(fresh.len()) > limits.max_entries {
        return Err(UpdateError::LimitExceeded);
    }
    // Encode the fresh items into a scratch archive.
    let scratch = if fresh.is_empty() {
        Vec::new()
    } else {
        let items: Vec<SevenZItem<'_>> = fresh
            .iter()
            .map(|f| SevenZItem {
                name: &f.name,
                data: &f.data,
                is_dir: f.is_dir,
                attributes: f.attributes,
                mtime: f.mtime,
                ctime: f.ctime,
                atime: f.atime,
            })
            .collect();
        let mut o = *opts;
        o.compress_header = false;
        let wl = SevenZWriteLimits {
            max_entries: limits.max_entries,
            max_input_bytes: limits.max_total_bytes,
            max_output_bytes: limits.max_output_bytes,
            ..SevenZWriteLimits::default()
        };
        write_7z(&items, &o, wl).map_err(map_write)?
    };
    drop(fresh);
    let scratch_arch = if scratch.is_empty() { None } else { Some(open(&scratch, limits)?) };

    let mut folders: Vec<FolderOut<'_>> = Vec::new();
    if let Some(a) = &archive {
        folders_of(bytes, a.header(), |k| !dirty[k], &mut folders)?;
    }
    if let Some(s) = &scratch_arch {
        folders_of(&scratch, s.header(), |_| true, &mut folders)?;
        for fi in &s.header().files {
            files.push(FileOut {
                name: fi.name.clone(),
                has_stream: fi.has_stream,
                is_empty_file: fi.is_empty_file,
                is_anti: fi.is_anti,
                attributes: fi.attributes,
                ctime: fi.ctime,
                atime: fi.atime,
                mtime: fi.mtime,
            });
        }
    }
    // Every stream file must map onto a substream.
    let streams: usize = folders.iter().map(|f| f.sub_sizes.len()).sum();
    if streams != files.iter().filter(|f| f.has_stream).count() {
        return Err(UpdateError::InvalidArchive);
    }

    let max = limits.max_output_bytes;
    let mut out = vec![0u8; SIG_SIZE];
    for f in &folders {
        for p in &f.packs {
            if (out.len() as u64).saturating_add(p.len() as u64) > max {
                return Err(UpdateError::LimitExceeded);
            }
            out.try_reserve(p.len()).map_err(|_| UpdateError::Allocation)?;
            out.extend_from_slice(p);
        }
    }
    if files.is_empty() {
        finish_signature(&mut out, 0, 0, 0);
        return Ok(out);
    }
    let mut raw = vec![pid::HEADER];
    if !folders.is_empty() {
        write_streams(&mut raw, &folders)?;
    }
    write_files(&mut raw, &files);
    raw.push(pid::END);
    drop(folders);

    let next = if opts.compress_header {
        let (packed, enc) = encode_header(&raw, (out.len() - SIG_SIZE) as u64)?;
        if packed.len() + enc.len() < raw.len() {
            out.try_reserve(packed.len()).map_err(|_| UpdateError::Allocation)?;
            out.extend_from_slice(&packed);
            enc
        } else {
            raw
        }
    } else {
        raw
    };
    let next_offset = (out.len() - SIG_SIZE) as u64;
    if (out.len() as u64).saturating_add(next.len() as u64) > max {
        return Err(UpdateError::LimitExceeded);
    }
    out.try_reserve(next.len()).map_err(|_| UpdateError::Allocation)?;
    out.extend_from_slice(&next);
    finish_signature(&mut out, next_offset, next.len() as u64, crc32(&next));
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bits_layout() {
        let mut v = Vec::new();
        write_bits(&mut v, &[true, false, false, false, false, false, false, false, true]);
        assert_eq!(v, vec![0x80, 0x80]);
        let mut d = Vec::new();
        write_digests(&mut d, &[Some(1), None]);
        assert_eq!(d, vec![0, 0x80, 1, 0, 0, 0]);
    }
}
