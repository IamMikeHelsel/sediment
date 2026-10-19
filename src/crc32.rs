// SPDX-License-Identifier: MIT OR Apache-2.0
#[derive(Clone, Debug, Default)] pub struct Crc32 {}
impl Crc32 { pub fn new()->Self{Self{}} pub fn update(&mut self,_bytes:&[u8]){} pub fn finalize(self)->u32{0} }
pub fn crc32(_bytes:&[u8])->u32{0}
