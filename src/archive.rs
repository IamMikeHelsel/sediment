//! Independently implemented archive operations. No WinRAR or unRAR source.
use anyhow::{Context, Result, anyhow, bail};
use flate2::bufread::GzDecoder;
use std::{
    collections::HashSet,
    fs::{self, File},
    io::{self, BufRead, BufReader, BufWriter, Read, Seek, SeekFrom, Write},
    path::{Component, Path, PathBuf},
    sync::{
        Arc, Mutex,
        atomic::{AtomicBool, AtomicU64, Ordering},
    },
};
use zip::{ZipArchive, ZipWriter, write::SimpleFileOptions};

const MAX_ENTRIES: usize = 100_000;
const MAX_EXPANDED: u64 = 20 * 1024 * 1024 * 1024;
const MAX_RATIO: u64 = 1000;
#[derive(Clone, Debug)]
pub struct Entry {
    pub name: String,
    pub size: u64,
    pub compressed_size: u64,
    pub is_dir: bool,
}
#[derive(Clone, Debug)]
pub struct ArchiveInfo {
    pub entries: Vec<Entry>,
    pub format: String,
    pub total_size: u64,
    pub compressed_size: u64,
}

fn safe_path(name: &str) -> Result<PathBuf> {
    // Treat both platform separators identically; reject Windows drive/ADS syntax everywhere.
    if name.contains('\\') || name.contains(':') || name.contains('\0') {
        bail!("Unsafe archive path: {name}");
    }
    let path = Path::new(name);
    if path.as_os_str().is_empty()
        || path.is_absolute()
        || path
            .components()
            .any(|c| !matches!(c, Component::Normal(_) | Component::CurDir))
    {
        bail!("Unsafe archive path: {name}");
    }
    if path.components().count() > 256 {
        bail!("Archive path exceeds 256 components");
    }
    let clean: PathBuf = path
        .components()
        .filter(|c| matches!(c, Component::Normal(_)))
        .collect();
    if clean.as_os_str().is_empty() {
        bail!("Empty archive path");
    }
    Ok(clean)
}
fn format(path: &Path) -> Result<&'static str> {
    let mut file = open_archive(path).context("Cannot open archive")?;
    let mut magic = [0; 4];
    let count = file.read(&mut magic)?;
    if count >= 4 && (&magic == b"PK\x03\x04" || &magic == b"PK\x05\x06" || &magic == b"PK\x07\x08")
    {
        return Ok("ZIP");
    }
    if count >= 2 && magic[..2] == [0x1f, 0x8b] {
        return Ok("TAR.GZ");
    }
    if path
        .extension()
        .is_some_and(|s| s.eq_ignore_ascii_case("tar"))
    {
        return Ok("TAR");
    }
    bail!(
        "Unsupported archive. Sediment supports ZIP, TAR and TAR.GZ; RAR creation and extraction are not included."
    )
}
const BUFFER_SIZE: usize = 64 * 1024;
#[derive(Clone, Debug, Default)]
pub struct Progress {
    pub phase: String,
    pub bytes: u64,
    pub total_bytes: Option<u64>,
    pub entries: usize,
}
#[derive(Clone, Default)]
pub struct OperationControl {
    cancelled: Arc<AtomicBool>,
    progress: Arc<Mutex<Progress>>,
}
#[derive(Debug)]
pub struct Cancelled;
impl std::fmt::Display for Cancelled {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("Operation cancelled")
    }
}
impl std::error::Error for Cancelled {}
impl OperationControl {
    pub fn cancel(&self) {
        let state = self.progress.lock().unwrap_or_else(|e| e.into_inner());
        if state.phase != "Complete" {
            self.cancelled.store(true, Ordering::Release);
        }
    }
    pub fn is_cancelled(&self) -> bool {
        self.cancelled.load(Ordering::Acquire)
    }
    pub fn snapshot(&self) -> Progress {
        self.progress
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .clone()
    }
    fn check(&self) -> Result<()> {
        if self.is_cancelled() {
            return Err(Cancelled.into());
        }
        Ok(())
    }
    fn phase(&self, phase: &str, total_bytes: Option<u64>) -> Result<()> {
        self.check()?;
        *self.progress.lock().unwrap_or_else(|e| e.into_inner()) = Progress {
            phase: phase.into(),
            total_bytes,
            ..Progress::default()
        };
        tracing::debug!(phase, "archive phase");
        Ok(())
    }
    fn advance(&self, bytes: u64) {
        self.progress
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .bytes += bytes;
    }
    fn entry(&self) {
        self.progress
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .entries += 1;
    }
    fn finish<T>(&self, result: Result<T>) -> Result<T> {
        if self.is_cancelled() {
            return Err(Cancelled.into());
        }
        if result.is_ok() {
            let mut progress = self.progress.lock().unwrap_or_else(|e| e.into_inner());
            progress.phase = "Complete".into();
            tracing::debug!(
                bytes = progress.bytes,
                entries = progress.entries,
                "archive operation complete"
            );
        }
        result
    }
    // Serialize the commit point against cancel(): once publication starts, cancellation
    // cannot be acknowledged until the operation is already successfully complete.
    fn publish<T>(&self, action: impl FnOnce() -> Result<T>) -> Result<T> {
        let mut progress = self.progress.lock().unwrap_or_else(|e| e.into_inner());
        self.check()?;
        progress.phase = "Publishing".into();
        let result = action()?;
        progress.phase = "Complete".into();
        Ok(result)
    }
}
struct ControlledReader<R> {
    inner: R,
    control: OperationControl,
    track: bool,
}
impl<R: Read> Read for ControlledReader<R> {
    fn read(&mut self, buffer: &mut [u8]) -> io::Result<usize> {
        if self.control.is_cancelled() {
            return Err(io::Error::other(Cancelled));
        }
        let limit = buffer.len().min(BUFFER_SIZE);
        let count = self.inner.read(&mut buffer[..limit])?;
        if self.track {
            self.control.advance(count as u64);
        }
        Ok(count)
    }
}
impl<R: Seek> Seek for ControlledReader<R> {
    fn seek(&mut self, position: SeekFrom) -> io::Result<u64> {
        if self.control.is_cancelled() {
            return Err(io::Error::other(Cancelled));
        }
        self.inner.seek(position)
    }
}
fn buffered_file(
    path: &Path,
    control: &OperationControl,
    track: bool,
) -> Result<BufReader<ControlledReader<File>>> {
    Ok(BufReader::with_capacity(
        BUFFER_SIZE,
        ControlledReader {
            inner: open_archive(path)?,
            control: control.clone(),
            track,
        },
    ))
}
struct SingleGzip<R: BufRead> {
    decoder: GzDecoder<R>,
}
impl<R: BufRead> Read for SingleGzip<R> {
    fn read(&mut self, buffer: &mut [u8]) -> io::Result<usize> {
        if buffer.is_empty() {
            return Ok(0);
        }
        let count = self.decoder.read(buffer)?;
        if count == 0 && !self.decoder.get_mut().fill_buf()?.is_empty() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "Trailing bytes or multiple gzip members are not supported",
            ));
        }
        Ok(count)
    }
}
const MAX_TAR_EXTENSION: u64 = 1024 * 1024;
// The TAR crate expands GNU/PAX metadata before yielding an entry. Inspect its
// framing first so attacker-controlled extension lengths cannot allocate freely.
// Honor PAX size overrides, including when GNU long-name headers intervene.
struct TarMetadataGuard<R> {
    inner: R,
    header: [u8; 512],
    header_used: usize,
    remaining: u64,
    data_remaining: u64,
    pax_data: Option<Vec<u8>>,
    pax_size: Option<u64>,
    entries: usize,
    ended: bool,
}
impl<R> TarMetadataGuard<R> {
    fn new(inner: R) -> Self {
        Self {
            inner,
            header: [0; 512],
            header_used: 0,
            remaining: 0,
            data_remaining: 0,
            pax_data: None,
            pax_size: None,
            entries: 0,
            ended: false,
        }
    }
    fn invalid(message: &str) -> io::Error {
        io::Error::new(io::ErrorKind::InvalidData, message)
    }
    fn finish_pax(&mut self) -> io::Result<()> {
        if let Some(data) = self.pax_data.take() {
            for extension in tar::PaxExtensions::new(&data) {
                let extension = extension?;
                if extension.key_bytes() == b"size" {
                    let value = extension
                        .value()
                        .map_err(|_| Self::invalid("Invalid PAX size"))?;
                    self.pax_size = Some(
                        value
                            .parse()
                            .map_err(|_| Self::invalid("Invalid PAX size"))?,
                    );
                    break;
                }
            }
        }
        Ok(())
    }
}
impl<R: Read> Read for TarMetadataGuard<R> {
    fn read(&mut self, buffer: &mut [u8]) -> io::Result<usize> {
        if buffer.is_empty() {
            return Ok(0);
        }
        if self.ended {
            return self.inner.read(buffer);
        }
        if self.remaining > 0 {
            let capacity = (buffer.len() as u64).min(self.remaining) as usize;
            let count = self.inner.read(&mut buffer[..capacity])?;
            if count == 0 {
                return Err(io::Error::new(
                    io::ErrorKind::UnexpectedEof,
                    "Truncated TAR payload or padding",
                ));
            }
            if let Some(data) = &mut self.pax_data {
                let data_count = (count as u64).min(self.data_remaining) as usize;
                data.extend_from_slice(&buffer[..data_count]);
            }
            self.data_remaining = self.data_remaining.saturating_sub(count as u64);
            self.remaining -= count as u64;
            if self.remaining == 0 {
                self.finish_pax()?;
            }
            return Ok(count);
        }
        let capacity = buffer.len().min(512 - self.header_used);
        let count = self.inner.read(&mut buffer[..capacity])?;
        self.header[self.header_used..self.header_used + count].copy_from_slice(&buffer[..count]);
        self.header_used += count;
        if self.header_used == 512 {
            self.header_used = 0;
            if self.header.iter().all(|byte| *byte == 0) {
                self.ended = true;
                return Ok(count);
            }
            self.entries += 1;
            if self.entries > MAX_ENTRIES {
                return Err(Self::invalid("Too many TAR headers"));
            }
            let header = tar::Header::from_byte_slice(&self.header);
            let kind = header.entry_type();
            if kind.is_gnu_sparse() {
                return Err(Self::invalid("Sparse TAR entries are not supported"));
            }
            let extension = kind.is_gnu_longname()
                || kind.is_gnu_longlink()
                || kind.is_pax_local_extensions()
                || kind.is_pax_global_extensions();
            let mut size = header.entry_size()?;
            if extension && size > MAX_TAR_EXTENSION {
                return Err(Self::invalid(
                    "TAR extension metadata exceeds 1 MiB safety limit",
                ));
            }
            if !extension {
                size = self.pax_size.take().unwrap_or(size);
            }
            if size > MAX_EXPANDED {
                return Err(Self::invalid(
                    "TAR entry exceeds expanded-size safety limit",
                ));
            }
            if kind.is_pax_local_extensions()
                && (header.as_gnu().is_some() || header.as_ustar().is_some())
            {
                self.pax_data = Some(Vec::new());
            }
            self.data_remaining = size;
            self.remaining = size
                .checked_add(511)
                .ok_or_else(|| Self::invalid("TAR size overflow"))?
                & !511;
            if self.remaining == 0 {
                self.finish_pax()?;
            }
        }
        Ok(count)
    }
}
fn tar_reader(
    path: &Path,
    kind: &str,
    control: &OperationControl,
    track: bool,
) -> Result<Box<dyn Read>> {
    let file = buffered_file(path, control, track)?;
    let reader: Box<dyn Read> = if kind == "TAR.GZ" {
        Box::new(SingleGzip {
            decoder: GzDecoder::new(file),
        })
    } else {
        Box::new(file)
    };
    // Also poll outside the decoder: highly compressible input may produce many
    // output chunks before the next underlying compressed-file read.
    Ok(Box::new(ControlledReader {
        inner: TarMetadataGuard::new(reader),
        control: control.clone(),
        track: false,
    }))
}
fn drain_padding(reader: &mut impl Read, control: &OperationControl) -> Result<()> {
    let mut buffer = [0u8; BUFFER_SIZE];
    let mut total = 0usize;
    loop {
        control.check()?;
        let count = reader.read(&mut buffer)?;
        if count == 0 {
            return Ok(());
        }
        total += count;
        if total > 16 * 1024 * 1024 {
            bail!("Excessive data after TAR end marker");
        }
        if buffer[..count].iter().any(|byte| *byte != 0) {
            bail!("Nonzero data after TAR end marker");
        }
    }
}
const MAX_ZIP_METADATA: u64 = 64 * 1024 * 1024;
struct MetadataBudget<R> {
    inner: R,
    remaining: Arc<AtomicU64>,
}
impl<R: Read> Read for MetadataBudget<R> {
    fn read(&mut self, buffer: &mut [u8]) -> io::Result<usize> {
        let budget = self.remaining.load(Ordering::Relaxed);
        if budget == u64::MAX {
            return self.inner.read(buffer);
        }
        if buffer.is_empty() {
            return Ok(0);
        }
        if budget == 0 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "ZIP metadata exceeds 64 MiB safety limit",
            ));
        }
        let capacity = (buffer.len() as u64).min(budget) as usize;
        let count = self.inner.read(&mut buffer[..capacity])?;
        self.remaining.fetch_sub(count as u64, Ordering::Relaxed);
        Ok(count)
    }
}
impl<R: Seek> Seek for MetadataBudget<R> {
    fn seek(&mut self, position: SeekFrom) -> io::Result<u64> {
        self.inner.seek(position)
    }
}
type SafeZipReader = MetadataBudget<BufReader<ControlledReader<File>>>;
fn zip_metadata_preflight(
    reader: &mut (impl Read + Seek),
    control: &OperationControl,
) -> Result<()> {
    control.check()?;
    let length = reader.seek(SeekFrom::End(0))?;
    let tail_length = length.min(65_535 + 22) as usize;
    reader.seek(SeekFrom::End(-(tail_length as i64)))?;
    let mut tail = vec![0; tail_length];
    reader.read_exact(&mut tail)?;
    let position = (0..tail_length.saturating_sub(21))
        .rev()
        .find(|&position| {
            tail[position..].starts_with(b"PK\x05\x06")
                && position
                    + 22
                    + u16::from_le_bytes([tail[position + 20], tail[position + 21]]) as usize
                    == tail_length
        })
        .ok_or_else(|| anyhow!("ZIP end record is missing or has trailing data"))?;
    let end = &tail[position..];
    let mut entries = u16::from_le_bytes([end[10], end[11]]) as u64;
    let mut metadata_size = u32::from_le_bytes(end[12..16].try_into().unwrap()) as u64;
    let offset = length - tail_length as u64 + position as u64;
    // A ZIP64 locator may appear even when the legacy fields are not saturated.
    if offset >= 20 {
        reader.seek(SeekFrom::Start(offset - 20))?;
        let mut locator = [0; 20];
        reader.read_exact(&mut locator)?;
        if locator.starts_with(b"PK\x06\x07") {
            let zip64_offset = u64::from_le_bytes(locator[8..16].try_into().unwrap());
            if zip64_offset > length.saturating_sub(56) {
                bail!("Invalid ZIP64 end-record offset");
            }
            reader.seek(SeekFrom::Start(zip64_offset))?;
            let mut record = [0; 56];
            reader.read_exact(&mut record)?;
            if !record.starts_with(b"PK\x06\x06") {
                bail!("Invalid ZIP64 end record");
            }
            entries = u64::from_le_bytes(record[32..40].try_into().unwrap());
            metadata_size = u64::from_le_bytes(record[40..48].try_into().unwrap());
            if u64::from_le_bytes(record[4..12].try_into().unwrap()) > MAX_ZIP_METADATA {
                bail!("ZIP64 metadata exceeds safety limit");
            }
        } else if entries == u16::MAX as u64 || metadata_size == u32::MAX as u64 {
            bail!("ZIP64 locator is missing");
        }
    }
    if entries > MAX_ENTRIES as u64 {
        bail!("Archive exceeds the 100,000-entry safety limit");
    }
    if metadata_size > MAX_ZIP_METADATA {
        bail!("ZIP metadata exceeds 64 MiB safety limit");
    }
    reader.seek(SeekFrom::Start(0))?;
    Ok(())
}
fn open_zip(path: &Path, control: &OperationControl) -> Result<ZipArchive<SafeZipReader>> {
    let mut reader = buffered_file(path, control, false)?;
    zip_metadata_preflight(&mut reader, control)?;
    let remaining = Arc::new(AtomicU64::new(MAX_ZIP_METADATA));
    let archive = ZipArchive::with_config(
        zip::read::Config {
            archive_offset: zip::read::ArchiveOffset::Known(0),
        },
        MetadataBudget {
            inner: reader,
            remaining: remaining.clone(),
        },
    )?;
    remaining.store(u64::MAX, Ordering::Relaxed);
    Ok(archive)
}
fn check_limits(count: usize, total: u64, compressed: u64) -> Result<()> {
    if count > MAX_ENTRIES {
        bail!("Archive exceeds the 100,000-entry safety limit");
    }
    if total > MAX_EXPANDED {
        bail!("Archive exceeds the 20 GiB expanded-size safety limit");
    }
    if total > 64 * 1024 * 1024 && total / compressed.max(1) > MAX_RATIO {
        bail!("Archive exceeds the expansion-ratio safety limit");
    }
    Ok(())
}
fn zip_entry_safe<R: Read>(file: &zip::read::ZipFile<'_, R>) -> Result<()> {
    if file.is_dir() && file.size() != 0 {
        bail!("Directory entry contains unexpected data");
    }
    if file.unix_mode().is_some_and(|mode| {
        let kind = mode & 0o170000;
        kind != 0 && kind != 0o100000 && kind != 0o040000
    }) {
        bail!(
            "Links and special files are not supported: {}",
            file.name()?
        );
    }
    Ok(())
}

fn inspect_impl(path: &Path, control: &OperationControl) -> Result<ArchiveInfo> {
    control.phase("Scanning", None)?;
    let kind = format(path)?;
    let compressed_size = fs::metadata(path)?.len();
    let mut entries = Vec::new();
    let mut total_size = 0u64;
    let mut seen = HashSet::new();
    if kind == "ZIP" {
        let mut archive = open_zip(path, control)?;
        if archive.len() > MAX_ENTRIES {
            bail!("Too many archive entries");
        }
        for i in 0..archive.len() {
            control.check()?;
            control.entry();
            let file = archive
                .by_index(i)
                .context("Cannot read ZIP entry (encrypted ZIPs are not supported)")?;
            zip_entry_safe(&file)?;
            let clean = safe_path(&file.name()?)?;
            if !seen.insert(clean) {
                bail!("Duplicate archive path: {}", file.name()?);
            }
            total_size = total_size
                .checked_add(file.size())
                .ok_or_else(|| anyhow!("Archive size overflow"))?;
            check_limits(i + 1, total_size, compressed_size)?;
            entries.push(Entry {
                name: file.name()?.into_owned(),
                size: file.size(),
                compressed_size: file.compressed_size(),
                is_dir: file.is_dir(),
            });
        }
    } else {
        let mut archive = tar::Archive::new(tar_reader(path, kind, control, true)?);
        for (raw_index, item) in archive.entries()?.enumerate() {
            control.check()?;
            control.entry();
            check_limits(raw_index + 1, total_size, compressed_size)?;
            let file = item?;
            let typ = file.header().entry_type();
            if !typ.is_file() && !typ.is_dir() {
                bail!("Links and special TAR entries are not supported");
            }
            if typ.is_dir() && file.size() != 0 {
                bail!("Directory entry contains unexpected data");
            }
            let name = file
                .path()?
                .to_str()
                .ok_or_else(|| anyhow!("Non-Unicode archive path"))?
                .to_owned();
            if typ.is_dir()
                && Path::new(&name)
                    .components()
                    .all(|c| matches!(c, Component::CurDir))
            {
                continue;
            }
            let clean = safe_path(&name)?;
            if !seen.insert(clean) {
                bail!("Duplicate archive path: {name}");
            }
            let size = file.size();
            total_size = total_size
                .checked_add(size)
                .ok_or_else(|| anyhow!("Archive size overflow"))?;
            check_limits(entries.len() + 1, total_size, compressed_size)?;
            entries.push(Entry {
                name,
                size,
                compressed_size: size,
                is_dir: typ.is_dir(),
            });
        }
        drain_padding(&mut archive.into_inner(), control)?;
    }
    Ok(ArchiveInfo {
        entries,
        format: kind.into(),
        total_size,
        compressed_size,
    })
}
#[cfg(unix)]
fn set_permissions(file: &File, mode: u32) -> Result<()> {
    use std::os::unix::fs::PermissionsExt;
    file.set_permissions(fs::Permissions::from_mode(mode & 0o777))?;
    Ok(())
}
#[cfg(not(unix))]
fn set_permissions(_file: &File, _mode: u32) -> Result<()> {
    Ok(())
}
fn copy_controlled(
    reader: &mut impl Read,
    writer: &mut impl Write,
    limit: u64,
    control: &OperationControl,
) -> Result<u64> {
    let mut buffer = [0u8; BUFFER_SIZE];
    let mut copied = 0u64;
    while copied < limit {
        control.check()?;
        let capacity = (limit - copied).min(BUFFER_SIZE as u64) as usize;
        let count = reader.read(&mut buffer[..capacity])?;
        if count == 0 {
            break;
        }
        control.check()?;
        writer.write_all(&buffer[..count])?;
        copied += count as u64;
        control.advance(count as u64);
    }
    control.check()?;
    Ok(copied)
}
fn copy_checked(
    reader: &mut impl Read,
    writer: &mut impl Write,
    expected: u64,
    control: &OperationControl,
) -> Result<()> {
    let copied = copy_controlled(reader, writer, expected.saturating_add(1), control)?;
    if copied != expected {
        bail!("Archive entry size does not match its header");
    }
    Ok(())
}
fn check_entry(
    info: &ArchiveInfo,
    index: usize,
    name: &str,
    size: u64,
    is_dir: bool,
) -> Result<()> {
    let expected = info
        .entries
        .get(index)
        .ok_or_else(|| anyhow!("Archive changed during operation"))?;
    if expected.name != name || expected.size != size || expected.is_dir != is_dir {
        bail!("Archive changed during operation");
    }
    Ok(())
}
fn consume(
    path: &Path,
    info: &ArchiveInfo,
    staging: Option<&Path>,
    control: &OperationControl,
) -> Result<usize> {
    control.phase(
        if staging.is_some() {
            "Extracting"
        } else {
            "Verifying"
        },
        Some(info.total_size),
    )?;
    let mut count = 0;
    if info.format == "ZIP" {
        let mut archive = open_zip(path, control)?;
        if archive.len() != info.entries.len() {
            bail!("Archive changed during operation");
        }
        for index in 0..archive.len() {
            control.check()?;
            control.entry();
            let mut file = archive.by_index(index)?;
            zip_entry_safe(&file)?;
            check_entry(info, index, &file.name()?, file.size(), file.is_dir())?;
            let relative = safe_path(&file.name()?)?;
            if let Some(root) = staging {
                let output = root.join(relative);
                if file.is_dir() {
                    fs::create_dir_all(output)?;
                } else {
                    fs::create_dir_all(output.parent().unwrap())?;
                    let mut writer = File::options().write(true).create_new(true).open(output)?;
                    let mode = file.unix_mode().unwrap_or(0o644);
                    let size = file.size();
                    copy_checked(&mut file, &mut writer, size, control)?;
                    set_permissions(&writer, mode)?;
                    count += 1;
                }
            } else if !file.is_dir() {
                let size = file.size();
                copy_checked(&mut file, &mut io::sink(), size, control)?;
                count += 1;
            }
        }
    } else {
        let mut archive = tar::Archive::new(tar_reader(path, &info.format, control, false)?);
        let mut entries_read = 0usize;
        for (raw_index, item) in archive.entries()?.enumerate() {
            control.check()?;
            control.entry();
            check_limits(raw_index + 1, info.total_size, info.compressed_size)?;
            let mut file = item?;
            let typ = file.header().entry_type();
            if !typ.is_file() && !typ.is_dir() {
                bail!("Links and special files are not supported");
            }
            if typ.is_dir() && file.size() != 0 {
                bail!("Directory entry contains unexpected data");
            }
            let name = file
                .path()?
                .to_str()
                .ok_or_else(|| anyhow!("Non-Unicode path"))?
                .to_owned();
            if typ.is_dir()
                && Path::new(&name)
                    .components()
                    .all(|c| matches!(c, Component::CurDir))
            {
                continue;
            }
            check_entry(info, entries_read, &name, file.size(), typ.is_dir())?;
            entries_read += 1;
            let relative = safe_path(&name)?;
            if let Some(root) = staging {
                let output = root.join(relative);
                if typ.is_dir() {
                    fs::create_dir_all(output)?;
                } else {
                    fs::create_dir_all(output.parent().unwrap())?;
                    let mut writer = File::options().write(true).create_new(true).open(output)?;
                    let mode = file.header().mode()?;
                    let size = file.size();
                    copy_checked(&mut file, &mut writer, size, control)?;
                    set_permissions(&writer, mode)?;
                    count += 1;
                }
            } else if typ.is_file() {
                let size = file.size();
                copy_checked(&mut file, &mut io::sink(), size, control)?;
                count += 1;
            }
        }
        if entries_read != info.entries.len() {
            bail!("Archive changed during operation");
        }
        // Read the gzip footer too, so its checksum is verified. Bound trailing padding.
        drain_padding(&mut archive.into_inner(), control)?;
    }
    Ok(count)
}
fn verify_impl(path: &Path, control: &OperationControl) -> Result<usize> {
    let info = inspect_impl(path, control)?;
    consume(path, &info, None, control)
}

/// Destination must not exist. Fully validate and stage before publishing.
fn extract_impl(path: &Path, destination: &Path, control: &OperationControl) -> Result<usize> {
    control.check()?;
    if destination.symlink_metadata().is_ok() {
        bail!("Destination already exists; choose a new folder");
    }
    let info = inspect_impl(path, control)?;
    let parent = destination
        .parent()
        .filter(|p| !p.as_os_str().is_empty())
        .unwrap_or(Path::new("."));
    let staging = tempfile::Builder::new()
        .prefix(".sediment-")
        .tempdir_in(parent)?;
    let payload = staging.path().join("payload");
    fs::create_dir(&payload)?;
    let count = consume(path, &info, Some(&payload), control)?;
    // Reserve the destination exclusively; never replace a user-owned directory.
    control.publish(|| {
        fs::create_dir(destination).context("Cannot reserve new destination folder")?;
        if let Err(error) = fs::rename(&payload, destination) {
            let _ = fs::remove_dir(destination);
            return Err(error).context("Cannot publish extracted archive");
        }
        Ok(count)
    })
}
fn validate_identity(expected: &fs::Metadata, current: &fs::Metadata) -> Result<()> {
    if current.file_type().is_symlink()
        || expected.is_dir() != current.is_dir()
        || expected.is_file() != current.is_file()
    {
        bail!("Input type changed during operation");
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        if expected.dev() != current.dev() || expected.ino() != current.ino() {
            bail!("Input identity changed during operation");
        }
    }
    if expected.is_file()
        && (expected.len() != current.len() || expected.modified().ok() != current.modified().ok())
    {
        bail!("Input contents changed during operation");
    }
    Ok(())
}
fn open_archive(path: &Path) -> Result<File> {
    let metadata = fs::symlink_metadata(path)?;
    if !metadata.is_file() || metadata.file_type().is_symlink() {
        bail!("Archive input must be a regular file, not a link or special file");
    }
    open_input(path, &metadata)
}
fn open_input(path: &Path, expected: &fs::Metadata) -> Result<File> {
    let mut options = File::options();
    options.read(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK);
    }
    let file = options.open(path)?;
    let metadata = file.metadata()?;
    if !metadata.is_file() {
        bail!("Input changed to a non-regular file");
    }
    validate_identity(expected, &metadata)?;
    Ok(file)
}
fn collect(
    input: &Path,
    name: &Path,
    files: &mut Vec<(PathBuf, String, bool, fs::Metadata)>,
    control: &OperationControl,
) -> Result<()> {
    control.check()?;
    control.entry();
    let metadata = fs::symlink_metadata(input)?;
    if metadata.file_type().is_symlink() || (!metadata.is_file() && !metadata.is_dir()) {
        bail!(
            "Links and special input files are not supported: {}",
            input.display()
        );
    }
    let name_text = name
        .to_str()
        .ok_or_else(|| anyhow!("Non-Unicode input filename"))?
        .to_owned();
    safe_path(&name_text)?;
    files.push((input.into(), name_text, metadata.is_dir(), metadata.clone()));
    if files.len() > MAX_ENTRIES {
        bail!("Too many input files");
    }
    if metadata.is_dir() {
        let mut children = Vec::new();
        for child in fs::read_dir(input)? {
            control.check()?;
            children.push(child?);
            if children.len() + files.len() > MAX_ENTRIES {
                bail!("Too many input files");
            }
        }
        children.sort_by_key(|entry| entry.file_name());
        for child in children {
            collect(&child.path(), &name.join(child.file_name()), files, control)?;
        }
    }
    Ok(())
}
fn create_zip_impl(inputs: &[PathBuf], output: &Path, control: &OperationControl) -> Result<usize> {
    control.phase("Collecting", None)?;
    if inputs.is_empty() {
        bail!("Select at least one input file or folder");
    }
    if output.symlink_metadata().is_ok() {
        bail!("Output already exists; choose a new filename");
    }
    let mut files = Vec::new();
    let mut names = HashSet::new();
    for input in inputs {
        let name = input
            .file_name()
            .ok_or_else(|| anyhow!("Input needs a filename"))?;
        if !names.insert(name.to_owned()) {
            bail!("Inputs have duplicate top-level names");
        }
        collect(input, Path::new(name), &mut files, control)?;
    }
    let parent = output
        .parent()
        .filter(|p| !p.as_os_str().is_empty())
        .unwrap_or(Path::new("."));
    let temporary = tempfile::NamedTempFile::new_in(parent)?;
    let mut zip = ZipWriter::new(BufWriter::with_capacity(BUFFER_SIZE, temporary.reopen()?));
    let total_bytes = files.iter().filter(|(_, _, dir, _)| !*dir).try_fold(
        0u64,
        |total, (_, _, _, metadata)| -> Result<u64> {
            control.check()?;
            total
                .checked_add(metadata.len())
                .ok_or_else(|| anyhow!("Input size overflow"))
        },
    )?;
    if total_bytes > MAX_EXPANDED {
        bail!("Inputs exceed 20 GiB safety limit");
    }
    control.phase("Compressing", Some(total_bytes))?;
    let options = SimpleFileOptions::default()
        .compression_method(zip::CompressionMethod::Deflated)
        .unix_permissions(0o644);
    let mut count = 0;
    let mut total = 0u64;
    for (input, name, is_dir, metadata) in files {
        control.check()?;
        control.entry();
        validate_identity(&metadata, &fs::symlink_metadata(&input)?)?;
        if is_dir {
            zip.add_directory(
                format!("{name}/"),
                SimpleFileOptions::default().unix_permissions(0o755),
            )?;
        } else {
            let mut file_options = options;
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                file_options = file_options.unix_permissions(metadata.permissions().mode() & 0o777);
            }
            zip.start_file(name, file_options)?;
            let mut input_file = open_input(&input, &metadata)?;
            let copied = copy_controlled(
                &mut input_file,
                &mut zip,
                metadata.len().saturating_add(1),
                control,
            )?;
            if copied != metadata.len() {
                bail!("Input size changed during operation");
            }
            validate_identity(&metadata, &input_file.metadata()?)?;
            total = total
                .checked_add(copied)
                .ok_or_else(|| anyhow!("Input size overflow"))?;
            if total > MAX_EXPANDED {
                bail!("Inputs exceed 20 GiB safety limit");
            }
            count += 1;
        }
    }
    control.check()?;
    let mut writer = zip.finish()?;
    writer.flush()?;
    writer.get_ref().sync_all()?;
    control.publish(|| {
        temporary
            .persist_noclobber(output)
            .map_err(|e| e.error)
            .context("Cannot save archive without overwriting")?;
        Ok(count)
    })
}

pub fn inspect(path: &Path) -> Result<ArchiveInfo> {
    inspect_with_control(path, &OperationControl::default())
}
pub fn inspect_with_control(path: &Path, control: &OperationControl) -> Result<ArchiveInfo> {
    control.finish(inspect_impl(path, control))
}
pub fn verify(path: &Path) -> Result<usize> {
    verify_with_control(path, &OperationControl::default())
}
pub fn verify_with_control(path: &Path, control: &OperationControl) -> Result<usize> {
    control.finish(verify_impl(path, control))
}
pub fn extract(path: &Path, destination: &Path) -> Result<usize> {
    extract_with_control(path, destination, &OperationControl::default())
}
pub fn extract_with_control(
    path: &Path,
    destination: &Path,
    control: &OperationControl,
) -> Result<usize> {
    control.finish(extract_impl(path, destination, control))
}
pub fn create_zip(inputs: &[PathBuf], output: &Path) -> Result<usize> {
    create_zip_with_control(inputs, output, &OperationControl::default())
}
pub fn create_zip_with_control(
    inputs: &[PathBuf],
    output: &Path,
    control: &OperationControl,
) -> Result<usize> {
    control.finish(create_zip_impl(inputs, output, control))
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn zip_round_trip_and_no_overwrite() -> Result<()> {
        let root = tempfile::tempdir()?;
        let input = root.path().join("hello.txt");
        fs::write(&input, b"hello sediment")?;
        let zip = root.path().join("sample.zip");
        assert_eq!(create_zip(&[input], &zip)?, 1);
        assert_eq!(inspect(&zip)?.total_size, 14);
        assert_eq!(verify(&zip)?, 1);
        let output = root.path().join("output");
        assert_eq!(extract(&zip, &output)?, 1);
        assert_eq!(fs::read(output.join("hello.txt"))?, b"hello sediment");
        assert!(extract(&zip, &output).is_err());
        Ok(())
    }
    #[test]
    fn rejects_traversal_without_publishing() -> Result<()> {
        let root = tempfile::tempdir()?;
        let path = root.path().join("bad.zip");
        let mut zip = ZipWriter::new(File::create(&path)?);
        zip.start_file("../escape", SimpleFileOptions::default())?;
        zip.write_all(b"bad")?;
        zip.finish()?;
        let output = root.path().join("output");
        assert!(extract(&path, &output).is_err());
        assert!(!output.exists());
        assert!(!root.path().join("escape").exists());
        Ok(())
    }
    #[test]
    fn rejects_ambiguous_paths() {
        for path in [
            "/absolute",
            "../evil",
            "a/../../evil",
            "C:/evil",
            "a\\evil",
            ".",
            "",
        ] {
            assert!(safe_path(path).is_err(), "{path}");
        }
    }
    #[test]
    fn tar_round_trip() -> Result<()> {
        let root = tempfile::tempdir()?;
        let path = root.path().join("archive.tar");
        let mut builder = tar::Builder::new(File::create(&path)?);
        let mut header = tar::Header::new_gnu();
        header.set_size(5);
        header.set_mode(0o644);
        header.set_cksum();
        builder.append_data(&mut header, "nested/file.txt", &b"hello"[..])?;
        builder.finish()?;
        assert_eq!(verify(&path)?, 1);
        let output = root.path().join("out");
        extract(&path, &output)?;
        assert_eq!(fs::read(output.join("nested/file.txt"))?, b"hello");
        Ok(())
    }

    #[test]
    fn corrupt_zip_rolls_back() -> Result<()> {
        let root = tempfile::tempdir()?;
        let path = root.path().join("corrupt.zip");
        let mut zip = ZipWriter::new(File::create(&path)?);
        zip.start_file(
            "file",
            SimpleFileOptions::default().compression_method(zip::CompressionMethod::Stored),
        )?;
        zip.write_all(b"unique-payload")?;
        zip.finish()?;
        let mut data = fs::read(&path)?;
        let offset = data
            .windows(14)
            .position(|w| w == b"unique-payload")
            .unwrap();
        data[offset] ^= 1;
        fs::write(&path, data)?;
        assert!(verify(&path).is_err());
        let output = root.path().join("out");
        assert!(extract(&path, &output).is_err());
        assert!(!output.exists());
        Ok(())
    }
    #[test]
    fn tar_gzip_footer_is_verified_and_root_directory_allowed() -> Result<()> {
        let root = tempfile::tempdir()?;
        let path = root.path().join("test.tar.gz");
        let encoder =
            flate2::write::GzEncoder::new(File::create(&path)?, flate2::Compression::default());
        let mut builder = tar::Builder::new(encoder);
        let mut dir = tar::Header::new_gnu();
        dir.set_size(0);
        dir.set_mode(0o755);
        dir.set_entry_type(tar::EntryType::Directory);
        dir.set_cksum();
        builder.append_data(&mut dir, "./", io::empty())?;
        let mut file = tar::Header::new_gnu();
        file.set_size(5);
        file.set_mode(0o644);
        file.set_cksum();
        builder.append_data(&mut file, "./hello.txt", &b"hello"[..])?;
        builder.into_inner()?.finish()?;
        assert_eq!(verify(&path)?, 1);
        let mut data = fs::read(&path)?;
        data.truncate(data.len() - 4);
        fs::write(&path, data)?;
        assert!(verify(&path).is_err());
        let output = root.path().join("out");
        assert!(extract(&path, &output).is_err());
        assert!(!output.exists());
        Ok(())
    }
    #[test]
    fn rejects_tar_symlinks() -> Result<()> {
        let root = tempfile::tempdir()?;
        let path = root.path().join("link.tar");
        let mut builder = tar::Builder::new(File::create(&path)?);
        let mut header = tar::Header::new_gnu();
        header.set_size(0);
        header.set_mode(0o777);
        header.set_entry_type(tar::EntryType::Symlink);
        header.set_link_name("../../escape")?;
        header.set_cksum();
        builder.append_data(&mut header, "link", io::empty())?;
        builder.finish()?;
        assert!(verify(&path).is_err());
        Ok(())
    }
    #[test]
    fn rejects_tar_duplicate_paths() -> Result<()> {
        let root = tempfile::tempdir()?;
        let path = root.path().join("duplicate.tar");
        let mut builder = tar::Builder::new(File::create(&path)?);
        for _ in 0..2 {
            let mut header = tar::Header::new_gnu();
            header.set_size(1);
            header.set_mode(0o644);
            header.set_cksum();
            builder.append_data(&mut header, "file", &b"x"[..])?;
        }
        builder.finish()?;
        assert!(inspect(&path).is_err());
        Ok(())
    }
    #[test]
    fn unicode_and_empty_directories_survive() -> Result<()> {
        let root = tempfile::tempdir()?;
        let input = root.path().join("café");
        fs::create_dir(&input)?;
        fs::create_dir(input.join("empty"))?;
        fs::write(input.join("雪.txt"), b"snow")?;
        let archive = root.path().join("test.zip");
        create_zip(&[input], &archive)?;
        let output = root.path().join("out");
        extract(&archive, &output)?;
        assert!(output.join("café/empty").is_dir());
        assert_eq!(fs::read(output.join("café/雪.txt"))?, b"snow");
        Ok(())
    }
    #[test]
    fn refuses_output_replacement() -> Result<()> {
        let root = tempfile::tempdir()?;
        let input = root.path().join("file");
        fs::write(&input, b"input")?;
        let output = root.path().join("existing.zip");
        fs::write(&output, b"preserve")?;
        assert!(create_zip(&[input], &output).is_err());
        assert_eq!(fs::read(output)?, b"preserve");
        Ok(())
    }

    #[test]
    fn safety_limit_boundaries() {
        assert!(check_limits(MAX_ENTRIES, 0, 0).is_ok());
        assert!(check_limits(MAX_ENTRIES + 1, 0, 0).is_err());
        assert!(check_limits(1, MAX_EXPANDED, MAX_EXPANDED).is_ok());
        assert!(check_limits(1, MAX_EXPANDED + 1, MAX_EXPANDED).is_err());
        let compressed = 1024 * 1024;
        assert!(check_limits(1, compressed * MAX_RATIO, compressed).is_ok());
        assert!(check_limits(1, compressed * (MAX_RATIO + 1), compressed).is_err());
        let grace = 64 * 1024 * 1024;
        assert!(check_limits(1, grace, 0).is_ok());
        assert!(check_limits(1, grace + 1, 0).is_err());
    }
    #[test]
    fn path_depth_boundary() {
        let accepted = std::iter::repeat_n("folder", 256)
            .collect::<Vec<_>>()
            .join("/");
        assert!(safe_path(&accepted).is_ok());
        assert!(safe_path(&format!("{accepted}/extra")).is_err());
    }

    fn cancel_during<T: Send + 'static>(
        phase: &'static str,
        operation: impl FnOnce(OperationControl) -> Result<T> + Send + 'static,
    ) -> Result<T> {
        let control = OperationControl::default();
        let worker_control = control.clone();
        let worker = std::thread::spawn(move || operation(worker_control));
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(10);
        let mut observed = false;
        while !worker.is_finished() && std::time::Instant::now() < deadline {
            let progress = control.snapshot();
            if progress.phase == phase && progress.bytes > 0 {
                observed = true;
                control.cancel();
                break;
            }
            std::thread::yield_now();
        }
        if !observed {
            control.cancel();
        }
        let result = worker.join().expect("archive worker panicked");
        assert!(
            observed,
            "operation must be cancelled after real {phase} work; error: {:?}",
            result.as_ref().err().map(|error| format!("{error:#}"))
        );
        assert!(
            result
                .as_ref()
                .is_err_and(|error| error.downcast_ref::<Cancelled>().is_some()),
            "expected typed cancellation"
        );
        result
    }
    #[test]
    fn cancellation_during_compression_removes_temporary_output() -> Result<()> {
        let root = tempfile::tempdir()?;
        let source = root.path().join("source");
        File::create(&source)?.set_len(128 * 1024 * 1024)?;
        let output = root.path().join("cancelled.zip");
        let task_output = output.clone();
        let _ = cancel_during("Compressing", move |control| {
            create_zip_with_control(&[source], &task_output, &control)
        });
        assert!(!output.exists());
        assert_eq!(
            fs::read_dir(root.path())?.count(),
            1,
            "temporary files must be removed"
        );
        Ok(())
    }
    fn large_stored_zip(path: &Path) -> Result<()> {
        let mut writer = ZipWriter::new(BufWriter::new(File::create(path)?));
        writer.start_file(
            "payload",
            SimpleFileOptions::default().compression_method(zip::CompressionMethod::Stored),
        )?;
        let block = [42; BUFFER_SIZE];
        for _ in 0..1024 {
            writer.write_all(&block)?;
        }
        writer.finish()?.flush()?;
        Ok(())
    }
    #[test]
    fn cancellation_during_extraction_rolls_back_staging() -> Result<()> {
        let root = tempfile::tempdir()?;
        let archive = root.path().join("large.zip");
        large_stored_zip(&archive)?;
        let output = root.path().join("output");
        let task_output = output.clone();
        let _ = cancel_during("Extracting", move |control| {
            extract_with_control(&archive, &task_output, &control)
        });
        assert!(!output.exists());
        assert_eq!(
            fs::read_dir(root.path())?.count(),
            1,
            "staging directories must be removed"
        );
        Ok(())
    }
    #[test]
    fn cancellation_during_verification_is_typed() -> Result<()> {
        let root = tempfile::tempdir()?;
        let archive = root.path().join("large.zip");
        large_stored_zip(&archive)?;
        let _ = cancel_during("Verifying", move |control| {
            verify_with_control(&archive, &control)
        });
        Ok(())
    }
    #[test]
    fn cancellation_interrupts_tar_scan_skipping_payload() -> Result<()> {
        let root = tempfile::tempdir()?;
        let path = root.path().join("large.tar.gz");
        let encoder = flate2::write::GzEncoder::new(
            BufWriter::new(File::create(&path)?),
            flate2::Compression::fast(),
        );
        let mut builder = tar::Builder::new(encoder);
        let mut header = tar::Header::new_gnu();
        header.set_size(64 * 1024 * 1024);
        header.set_mode(0o644);
        header.set_cksum();
        builder.append_data(&mut header, "payload", io::repeat(0).take(64 * 1024 * 1024))?;
        builder.into_inner()?.finish()?.flush()?;
        let _ = cancel_during("Scanning", move |control| {
            inspect_with_control(&path, &control)
        });
        Ok(())
    }
    #[test]
    fn completed_progress_matches_payload_and_late_cancel_does_not_reverse_commit() -> Result<()> {
        let root = tempfile::tempdir()?;
        let source = root.path().join("source");
        fs::write(&source, b"hello")?;
        let output = root.path().join("output.zip");
        let control = OperationControl::default();
        create_zip_with_control(&[source], &output, &control)?;
        let progress = control.snapshot();
        assert_eq!(progress.phase, "Complete");
        assert_eq!(progress.bytes, 5);
        assert_eq!(progress.total_bytes, Some(5));
        assert_eq!(progress.entries, 1);
        control.cancel();
        assert!(!control.is_cancelled());
        assert!(output.exists());
        Ok(())
    }
    #[test]
    fn rejects_nonzero_tar_trailer_and_extra_gzip_member() -> Result<()> {
        let root = tempfile::tempdir()?;
        let tar_path = root.path().join("trailer.tar");
        let mut builder = tar::Builder::new(File::create(&tar_path)?);
        builder.finish()?;
        drop(builder);
        File::options()
            .append(true)
            .open(&tar_path)?
            .write_all(b"hidden payload")?;
        assert!(inspect(&tar_path).is_err());
        let gzip_path = root.path().join("members.tar.gz");
        let encoder =
            flate2::write::GzEncoder::new(File::create(&gzip_path)?, flate2::Compression::fast());
        let mut builder = tar::Builder::new(encoder);
        builder.finish()?;
        builder.into_inner()?.finish()?;
        let encoder = flate2::write::GzEncoder::new(
            File::options().append(true).open(&gzip_path)?,
            flate2::Compression::fast(),
        );
        encoder.finish()?;
        assert!(
            inspect(&gzip_path).is_err(),
            "even an empty second gzip member must be rejected"
        );
        Ok(())
    }
    #[cfg(unix)]
    #[test]
    fn source_replaced_by_symlink_or_different_inode_is_rejected() -> Result<()> {
        use std::os::unix::fs::symlink;
        let root = tempfile::tempdir()?;
        let source = root.path().join("source");
        fs::write(&source, b"original")?;
        let expected = fs::symlink_metadata(&source)?;
        let other = root.path().join("other");
        fs::write(&other, b"private!")?;
        fs::remove_file(&source)?;
        symlink(&other, &source)?;
        assert!(open_input(&source, &expected).is_err());
        fs::remove_file(&source)?;
        fs::hard_link(&other, &source)?;
        assert!(open_input(&source, &expected).is_err());
        Ok(())
    }
    #[cfg(unix)]
    #[test]
    fn executable_permissions_survive_but_special_bits_do_not() -> Result<()> {
        use std::os::unix::fs::PermissionsExt;
        let root = tempfile::tempdir()?;
        let path = root.path().join("permissions.zip");
        let mut writer = ZipWriter::new(File::create(&path)?);
        writer.start_file(
            "script",
            SimpleFileOptions::default().unix_permissions(0o6751),
        )?;
        writer.write_all(b"#!/bin/sh\n")?;
        writer.finish()?;
        let output = root.path().join("out");
        extract(&path, &output)?;
        assert_eq!(
            fs::metadata(output.join("script"))?.permissions().mode() & 0o7777,
            0o751
        );
        Ok(())
    }
    #[test]
    fn precancelled_operations_do_not_touch_filesystem() -> Result<()> {
        let root = tempfile::tempdir()?;
        let control = OperationControl::default();
        control.cancel();
        let missing = root.path().join("missing.zip");
        let output = root.path().join("out");
        assert!(
            inspect_with_control(&missing, &control)
                .unwrap_err()
                .downcast_ref::<Cancelled>()
                .is_some()
        );
        assert!(
            extract_with_control(&missing, &output, &control)
                .unwrap_err()
                .downcast_ref::<Cancelled>()
                .is_some()
        );
        assert!(
            create_zip_with_control(&[missing], &output, &control)
                .unwrap_err()
                .downcast_ref::<Cancelled>()
                .is_some()
        );
        assert_eq!(fs::read_dir(root.path())?.count(), 0);
        Ok(())
    }

    #[test]
    fn oversized_tar_extensions_are_rejected_before_payload_allocation() -> Result<()> {
        let root = tempfile::tempdir()?;
        for kind in [
            tar::EntryType::XHeader,
            tar::EntryType::XGlobalHeader,
            tar::EntryType::GNULongName,
            tar::EntryType::GNULongLink,
        ] {
            let path = root.path().join("oversized.tar");
            let mut header = tar::Header::new_gnu();
            header.set_entry_type(kind);
            header.set_size(MAX_TAR_EXTENSION + 1);
            header.set_path("extension")?;
            header.set_mode(0o644);
            header.set_cksum();
            fs::write(&path, header.as_bytes())?;
            let error = inspect(&path).unwrap_err();
            assert!(
                format!("{error:#}").contains("extension metadata exceeds"),
                "{error:#}"
            );
        }
        Ok(())
    }
    #[test]
    fn legitimate_gnu_long_names_and_pax_size_overrides_work() -> Result<()> {
        let root = tempfile::tempdir()?;
        let path = root.path().join("long.tar");
        let long_name = format!("{}/file.txt", "segment/".repeat(30));
        let mut builder = tar::Builder::new(File::create(&path)?);
        builder.append_pax_extensions([("size", &b"5"[..]), ("mtime", &b"1234567890"[..])])?;
        let mut header = tar::Header::new_gnu();
        header.set_size(0);
        header.set_mode(0o644);
        header.set_cksum();
        builder.append_data(&mut header, &long_name, &b"hello"[..])?;
        builder.finish()?;
        drop(builder);
        let info = inspect(&path)?;
        assert_eq!(info.entries[0].size, 5);
        assert_eq!(info.entries[0].name, long_name);
        let output = root.path().join("out");
        extract(&path, &output)?;
        assert_eq!(fs::read(output.join(&long_name))?, b"hello");
        Ok(())
    }
    #[cfg(unix)]
    #[test]
    fn archive_symlinks_and_fifos_are_rejected_without_opening() -> Result<()> {
        use std::{
            ffi::CString,
            os::unix::{ffi::OsStrExt, fs::symlink},
        };
        let root = tempfile::tempdir()?;
        let source = root.path().join("source");
        fs::write(&source, b"data")?;
        let link = root.path().join("link.zip");
        symlink(&source, &link)?;
        assert!(inspect(&link).is_err());
        let fifo = root.path().join("pipe.zip");
        let name = CString::new(fifo.as_os_str().as_bytes())?;
        // SAFETY: name is a valid nul-terminated owned path and mkfifo does not retain it.
        assert_eq!(unsafe { libc::mkfifo(name.as_ptr(), 0o600) }, 0);
        assert!(inspect(&fifo).is_err());
        assert!(open_archive(&fifo).is_err());
        Ok(())
    }

    #[test]
    fn zip_metadata_preflight_rejects_oversized_directory_and_zip64_count() -> Result<()> {
        let control = OperationControl::default();
        let mut end = [0u8; 22];
        end[..4].copy_from_slice(b"PK\x05\x06");
        end[12..16].copy_from_slice(&((MAX_ZIP_METADATA + 1) as u32).to_le_bytes());
        assert!(zip_metadata_preflight(&mut io::Cursor::new(end), &control).is_err());
        end[12..16].fill(0);
        end[10..12].copy_from_slice(&u16::MAX.to_le_bytes());
        let mut record = [0u8; 56];
        record[..4].copy_from_slice(b"PK\x06\x06");
        record[4..12].copy_from_slice(&44u64.to_le_bytes());
        record[32..40].copy_from_slice(&(MAX_ENTRIES as u64 + 1).to_le_bytes());
        let mut locator = [0u8; 20];
        locator[..4].copy_from_slice(b"PK\x06\x07");
        locator[16..20].copy_from_slice(&1u32.to_le_bytes());
        let mut archive = Vec::new();
        archive.extend_from_slice(&record);
        archive.extend_from_slice(&locator);
        archive.extend_from_slice(&end);
        assert!(zip_metadata_preflight(&mut io::Cursor::new(archive.clone()), &control).is_err());
        archive[32..40].copy_from_slice(&0u64.to_le_bytes());
        assert!(zip_metadata_preflight(&mut io::Cursor::new(archive), &control).is_ok());
        Ok(())
    }
    #[test]
    fn zip_parser_metadata_budget_stops_reads() {
        let mut reader = MetadataBudget {
            inner: io::Cursor::new([1u8, 2, 3]),
            remaining: Arc::new(AtomicU64::new(2)),
        };
        let mut bytes = Vec::new();
        assert!(reader.read_to_end(&mut bytes).is_err());
        assert_eq!(bytes, [1, 2]);
    }
}
