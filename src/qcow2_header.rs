//! QCOW2 v2/v3 header parsing and cluster mapping (uncompressed, unencrypted).
//! Spec: QEMU docs/interop/qcow2.txt. All integers are big-endian.

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Qcow2Error {
    Truncated,
    BadMagic,
    UnsupportedVersion,
    BadHeader,
    BadClusterBits,
    Encrypted,
    UnsupportedFeature,
    BadL1,
    BadL2,
    Compressed,
    OutOfRange,
    LimitExceeded,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Qcow2Header {
    pub version: u32,
    pub backing_file_offset: u64,
    pub backing_file_size: u32,
    pub cluster_bits: u32,
    pub size: u64,
    pub crypt_method: u32,
    pub l1_size: u32,
    pub l1_table_offset: u64,
    pub refcount_table_offset: u64,
    pub refcount_table_clusters: u32,
    pub nb_snapshots: u32,
    pub snapshots_offset: u64,
    pub incompatible_features: u64,
    pub compatible_features: u64,
    pub autoclear_features: u64,
    pub refcount_order: u32,
    pub header_length: u32,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ClusterMapping {
    Data(u64),
    Zero,
    Unallocated,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Qcow2Image {
    pub header: Qcow2Header,
    pub l1: Vec<u64>,
}

fn rd_u32(d: &[u8], o: usize) -> Result<u32, Qcow2Error> {
    if o + 4 > d.len() { return Err(Qcow2Error::Truncated); }
    Ok(u32::from_be_bytes([d[o], d[o+1], d[o+2], d[o+3]]))
}
fn rd_u64(d: &[u8], o: usize) -> Result<u64, Qcow2Error> {
    if o + 8 > d.len() { return Err(Qcow2Error::Truncated); }
    Ok(u64::from_be_bytes([d[o],d[o+1],d[o+2],d[o+3],d[o+4],d[o+5],d[o+6],d[o+7]]))
}

pub fn parse_header(data: &[u8]) -> Result<Qcow2Header, Qcow2Error> {
    if data.len() < 72 { return Err(Qcow2Error::Truncated); }
    if &data[0..4] != b"QFI\xfb" { return Err(Qcow2Error::BadMagic); }
    let version = rd_u32(data, 4)?;
    if version != 2 && version != 3 { return Err(Qcow2Error::UnsupportedVersion); }
    let bfo = rd_u64(data, 8)?;
    let bfs = rd_u32(data, 16)?;
    let cb = rd_u32(data, 20)?;
    let sz = rd_u64(data, 24)?;
    let cm = rd_u32(data, 32)?;
    let l1s = rd_u32(data, 36)?;
    let l1o = rd_u64(data, 40)?;
    let rfo = rd_u64(data, 48)?;
    let rfc = rd_u32(data, 56)?;
    let ns = rd_u32(data, 60)?;
    let so = rd_u64(data, 64)?;
    if version == 3 {
        if data.len() < 104 { return Err(Qcow2Error::Truncated); }
        let if_ = rd_u64(data, 72)?;
        let cf = rd_u64(data, 80)?;
        let af = rd_u64(data, 88)?;
        let ro = rd_u32(data, 96)?;
        let hl = rd_u32(data, 100)?;
        if hl < 104 { return Err(Qcow2Error::BadHeader); }
        if cb < 9 || cb > 21 { return Err(Qcow2Error::BadClusterBits); }
        if cm != 0 { return Err(Qcow2Error::Encrypted); }
        if if_ & !1u64 != 0 { return Err(Qcow2Error::UnsupportedFeature); }
        Ok(Qcow2Header { version, backing_file_offset: bfo, backing_file_size: bfs,
            cluster_bits: cb, size: sz, crypt_method: cm, l1_size: l1s, l1_table_offset: l1o,
            refcount_table_offset: rfo, refcount_table_clusters: rfc, nb_snapshots: ns,
            snapshots_offset: so, incompatible_features: if_, compatible_features: cf,
            autoclear_features: af, refcount_order: ro, header_length: hl, })
    } else {
        if cb < 9 || cb > 21 { return Err(Qcow2Error::BadClusterBits); }
        if cm != 0 { return Err(Qcow2Error::Encrypted); }
        Ok(Qcow2Header { version, backing_file_offset: bfo, backing_file_size: bfs,
            cluster_bits: cb, size: sz, crypt_method: cm, l1_size: l1s, l1_table_offset: l1o,
            refcount_table_offset: rfo, refcount_table_clusters: rfc, nb_snapshots: ns,
            snapshots_offset: so, incompatible_features: 0, compatible_features: 0,
            autoclear_features: 0, refcount_order: 4, header_length: 72, })
    }
}

pub fn open_qcow2(image: &[u8], max_l1_entries: u32) -> Result<Qcow2Image, Qcow2Error> {
    let h = parse_header(image)?;
    let cs = 1u64 << h.cluster_bits;
    let l2e = cs / 8;
    if h.l1_size > max_l1_entries { return Err(Qcow2Error::LimitExceeded); }
    let min_l1 = if h.size == 0 { 0u64 } else { (h.size + cs * l2e - 1) / (cs * l2e) };
    if (h.l1_size as u64) < min_l1 { return Err(Qcow2Error::BadL1); }
    if h.l1_table_offset % cs != 0 { return Err(Qcow2Error::BadL1); }
    let l1_end = h.l1_table_offset.checked_add((h.l1_size as u64) * 8)
        .ok_or(Qcow2Error::Truncated)?;
    if l1_end as usize > image.len() { return Err(Qcow2Error::Truncated); }
    let mut l1 = Vec::with_capacity(h.l1_size as usize);
    for i in 0..h.l1_size {
        let off = (h.l1_table_offset + (i as u64) * 8) as usize;
        l1.push(rd_u64(image, off)?);
    }
    Ok(Qcow2Image { header: h, l1 })
}

impl Qcow2Image {
    pub fn cluster_size(&self) -> u64 { 1u64 << self.header.cluster_bits }

    pub fn map_offset(&self, image: &[u8], guest_offset: u64) -> Result<ClusterMapping, Qcow2Error> {
        if guest_offset >= self.header.size { return Err(Qcow2Error::OutOfRange); }
        let cs = self.cluster_size();
        let l2_bits = self.header.cluster_bits - 3;
        let l2e = cs / 8;
        let mask = 0x00FF_FFFF_FFFF_FE00u64;
        let l1i = guest_offset >> (self.header.cluster_bits + l2_bits);
        let l2i = (guest_offset >> self.header.cluster_bits) & (l2e - 1);
        if (l1i as usize) >= self.l1.len() { return Err(Qcow2Error::BadL1); }
        let le = self.l1[l1i as usize];
        if le & 0x7F00_0000_0000_01FF != 0 { return Err(Qcow2Error::BadL1); }
        let lo = le & mask;
        if lo == 0 { return Ok(ClusterMapping::Unallocated); }
        if lo % cs != 0 { return Err(Qcow2Error::BadL1); }
        let l2o = (lo + 8 * l2i) as usize;
        if l2o + 8 > image.len() { return Err(Qcow2Error::Truncated); }
        let de = u64::from_be_bytes([image[l2o],image[l2o+1],image[l2o+2],image[l2o+3],
                                     image[l2o+4],image[l2o+5],image[l2o+6],image[l2o+7]]);
        if de & (1 << 62) != 0 { return Err(Qcow2Error::Compressed); }
        if de & 0x3F00_0000_0000_01FE != 0 { return Err(Qcow2Error::BadL2); }
        let host = de & mask;
        if de & 1 != 0 { return Ok(ClusterMapping::Zero); }
        if host == 0 { return Ok(ClusterMapping::Unallocated); }
        if host % cs != 0 { return Err(Qcow2Error::BadL2); }
        if host + cs > image.len() as u64 { return Err(Qcow2Error::Truncated); }
        Ok(ClusterMapping::Data(host + (guest_offset % cs)))
    }

    pub fn cluster_map(&self, image: &[u8], max_clusters: u64) -> Result<Vec<ClusterMapping>, Qcow2Error> {
        let cs = self.cluster_size();
        let n = if self.header.size == 0 { 0u64 } else { (self.header.size + cs - 1) / cs };
        if n > max_clusters { return Err(Qcow2Error::LimitExceeded); }
        let mut r = Vec::with_capacity(n as usize);
        for i in 0..n { r.push(self.map_offset(image, i * cs)?); }
        Ok(r)
    }

    pub fn read_at(&self, image: &[u8], offset: u64, len: usize) -> Result<Vec<u8>, Qcow2Error> {
        if len == 0 { return Ok(Vec::new()); }
        let end = offset.checked_add(len as u64).ok_or(Qcow2Error::OutOfRange)?;
        if end > self.header.size { return Err(Qcow2Error::OutOfRange); }
        let cs = self.cluster_size();
        let mut out = Vec::with_capacity(len);
        let mut pos = offset;
        let mut rem = len;
        while rem > 0 {
            let m = self.map_offset(image, pos)?;
            let coff = pos % cs;
            let cre = cs - coff;
            let cl = rem.min(cre as usize);
            match m {
                ClusterMapping::Data(h) => {
                    let he = h + cre as u64;
                    if he as usize > image.len() { return Err(Qcow2Error::Truncated); }
                    out.extend_from_slice(&image[h as usize..he as usize]);
                }
                ClusterMapping::Zero | ClusterMapping::Unallocated => {
                    out.extend_from_slice(&vec![0u8; cl]);
                }
            }
            pos += cl as u64;
            rem -= cl;
        }
        Ok(out)
    }
}
