//! Sediment archive engine. Capability tickets; no parity claim.
pub mod crc32;
pub mod reader;
pub mod archive_path;
pub mod zip;
pub mod bit_reader;
pub mod zip_local;
pub mod zip_central;
pub mod zip_ranges;
pub mod zip_index;
pub mod archive_name;
pub mod adler32;
pub mod zip_payload;
pub mod huffman;
pub mod deflate_tables;
pub mod lz77;
pub mod deflate_stored;
pub mod huffman_decode;
