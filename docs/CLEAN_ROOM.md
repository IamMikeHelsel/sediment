# sediment implementation provenance

Reviewed 2026-10-15. sediment is an independently authored archive application in Rust, with an original interface. It is not affiliated with WinRAR or RARLAB. It does not claim complete WinRAR compatibility, and its archive codecs are existing third-party dependencies, not newly invented cleanroom codecs.

## Boundary

The implementation work uses public feature descriptions and public APIs of independently licensed dependencies. No WinRAR or UnRAR implementation source, disassembly, extracted assets, or product code is used. This is an engineering provenance statement, not a formal independently audited legal cleanroom certification.

WinRAR's public feature list describes archive creation, extraction, browsing, encryption, split volumes, recovery, and many formats. sediment's first preview concentrates on browsing, integrity checking, extraction, and ZIP creation. RAR compression, recovery records, split archives, encryption, shell extensions, and full format parity are outside the preview. The current README is the shipped capability inventory.

RAR support must not be implied merely by the product comparison. The RAR5 public format note specifies containers but directs readers to UnRAR source for algorithm details. We did not follow that direction. The `unrar` Rust crate embeds the RARLAB C/C++ library; `unrar-rs` describes itself as a Rust port of reference UnRAR. Neither meets this project's independent-code boundary. The Apache-licensed `rars` project's author describes deriving its specification partly through binary reverse engineering; it is not adopted for this preview. A license label alone is not provenance evidence.

Future RAR work requires a separate, documented provenance and compatibility review before dependency adoption. No independent compressed-RAR implementation is promised for this first release.

## Public sources consulted

- [WinRAR public capabilities](https://www.rarlab.com/rar_archiver.htm).
- [RAR/WinRAR license](https://www.rarlab.com/license.htm), including restrictions concerning proprietary code and compression implementation.
- [RAR5 public container specification](https://www.rarlab.com/technote.htm).
- [`unrar` public API and license summary](https://docs.rs/unrar/latest/unrar/).
- [`unrar-rs` public project description](https://docs.rs/unrar-rs/latest/unrar_rs/).
- [`rars` public README](https://github.com/bitplane/rars) and [author's provenance account](https://bitplane.net/log/2026/05/rars/).

Only descriptions, specifications, licensing statements, and provenance prose were consulted for this review; excluded implementation source was not inspected.
