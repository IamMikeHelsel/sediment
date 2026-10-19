use sediment_engine::size_parse::{SizeError, Switch, Threads, parse_dict_size, parse_size, parse_switch};

#[test]
fn sizes_with_suffixes() {
    assert_eq!(parse_size("1500b"), Ok(1500));
    assert_eq!(parse_size("1500B"), Ok(1500));
    assert_eq!(parse_size("1500"), Ok(1500));
    assert_eq!(parse_size("0"), Ok(0));
    assert_eq!(parse_size("007"), Ok(7));
    assert_eq!(parse_size("10k"), Ok(10240));
    assert_eq!(parse_size("100m"), Ok(104857600));
    assert_eq!(parse_size("100M"), Ok(104857600));
    assert_eq!(parse_size("1g"), Ok(1073741824));
    assert_eq!(parse_size("3G"), Ok(3221225472));
}

#[test]
fn size_boundaries_and_overflow() {
    assert_eq!(parse_size("18446744073709551615"), Ok(u64::MAX));
    assert_eq!(parse_size("18446744073709551616"), Err(SizeError::Overflow));
    assert_eq!(parse_size("99999999999999999999999999"), Err(SizeError::Overflow));
    assert_eq!(parse_size("17179869183g"), Ok(17179869183u64 * 1073741824));
    assert_eq!(parse_size("17179869184g"), Err(SizeError::Overflow));
    assert_eq!(parse_size("18014398509481984k"), Err(SizeError::Overflow));
    assert_eq!(parse_size("18014398509481983k"), Ok(18014398509481983u64 * 1024));
}

#[test]
fn size_malformed() {
    assert_eq!(parse_size(""), Err(SizeError::Empty));
    assert_eq!(parse_size("m"), Err(SizeError::BadNumber));
    assert_eq!(parse_size("-5"), Err(SizeError::BadNumber));
    assert_eq!(parse_size("+5"), Err(SizeError::BadNumber));
    assert_eq!(parse_size(" 5"), Err(SizeError::BadNumber));
    assert_eq!(parse_size("10x"), Err(SizeError::BadSuffix));
    assert_eq!(parse_size("10mb"), Err(SizeError::BadSuffix));
    assert_eq!(parse_size("1.5g"), Err(SizeError::BadSuffix));
    assert_eq!(parse_size("10 m"), Err(SizeError::BadSuffix));
    assert_eq!(parse_size("10t"), Err(SizeError::BadSuffix));
    assert_eq!(parse_size("5\u{e9}"), Err(SizeError::BadSuffix));
    assert_eq!(parse_size("\u{663}"), Err(SizeError::BadNumber));
}

#[test]
fn dict_sizes() {
    assert_eq!(parse_dict_size("24"), Ok(16777216));
    assert_eq!(parse_dict_size("0"), Ok(1));
    assert_eq!(parse_dict_size("63"), Ok(1u64 << 63));
    assert_eq!(parse_dict_size("64"), Err(SizeError::Overflow));
    assert_eq!(parse_dict_size("99999999999999999999"), Err(SizeError::Overflow));
    assert_eq!(parse_dict_size("64m"), Ok(67108864));
    assert_eq!(parse_dict_size("1536k"), Ok(1572864));
    assert_eq!(parse_dict_size("4096b"), Ok(4096));
    assert_eq!(parse_dict_size("0m"), Ok(0));
    assert_eq!(parse_dict_size(""), Err(SizeError::Empty));
    assert_eq!(parse_dict_size("m"), Err(SizeError::BadNumber));
    assert_eq!(parse_dict_size("24q"), Err(SizeError::BadSuffix));
}

#[test]
fn volume_switch() {
    assert_eq!(parse_switch("-v100m"), Ok(Switch::Volume(104857600)));
    assert_eq!(parse_switch("-v1g"), Ok(Switch::Volume(1073741824)));
    assert_eq!(parse_switch("-v1500b"), Ok(Switch::Volume(1500)));
    assert_eq!(parse_switch("-v1500"), Ok(Switch::Volume(1500)));
    assert_eq!(parse_switch("-V1G"), Ok(Switch::Volume(1073741824)));
    assert_eq!(parse_switch("-v"), Err(SizeError::Empty));
    assert_eq!(parse_switch("-v0"), Err(SizeError::Zero));
    assert_eq!(parse_switch("-v0m"), Err(SizeError::Zero));
    assert_eq!(parse_switch("-v=1m"), Err(SizeError::BadNumber));
    assert_eq!(parse_switch("-v10q"), Err(SizeError::BadSuffix));
    assert_eq!(parse_switch("-v99999999999g"), Err(SizeError::Overflow));
}

#[test]
fn level_switch() {
    assert_eq!(parse_switch("-mx=9"), Ok(Switch::Level(9)));
    assert_eq!(parse_switch("-mx9"), Ok(Switch::Level(9)));
    assert_eq!(parse_switch("-mx=0"), Ok(Switch::Level(0)));
    assert_eq!(parse_switch("-MX=5"), Ok(Switch::Level(5)));
    assert_eq!(parse_switch("-mx="), Err(SizeError::Empty));
    assert_eq!(parse_switch("-mx"), Err(SizeError::Empty));
    assert_eq!(parse_switch("-mx=10"), Err(SizeError::BadValue));
    assert_eq!(parse_switch("-mx=9m"), Err(SizeError::BadValue));
    assert_eq!(parse_switch("-mx=x"), Err(SizeError::BadNumber));
    assert_eq!(parse_switch("-mx==9"), Err(SizeError::BadNumber));
    assert_eq!(parse_switch("-mx=99999999999999999999"), Err(SizeError::Overflow));
}

#[test]
fn dictionary_switch() {
    assert_eq!(parse_switch("-md=64m"), Ok(Switch::Dictionary(67108864)));
    assert_eq!(parse_switch("-md64m"), Ok(Switch::Dictionary(67108864)));
    assert_eq!(parse_switch("-md=24"), Ok(Switch::Dictionary(16777216)));
    assert_eq!(parse_switch("-MD=1G"), Ok(Switch::Dictionary(1073741824)));
    assert_eq!(parse_switch("-md=0m"), Err(SizeError::Zero));
    assert_eq!(parse_switch("-md=64"), Err(SizeError::Overflow));
    assert_eq!(parse_switch("-md="), Err(SizeError::Empty));
    assert_eq!(parse_switch("-md=1z"), Err(SizeError::BadSuffix));
}

#[test]
fn threads_switch() {
    assert_eq!(parse_switch("-mmt=4"), Ok(Switch::Threads(Threads::Count(4))));
    assert_eq!(parse_switch("-mmt4"), Ok(Switch::Threads(Threads::Count(4))));
    assert_eq!(parse_switch("-mmt"), Ok(Switch::Threads(Threads::On)));
    assert_eq!(parse_switch("-mmt="), Ok(Switch::Threads(Threads::On)));
    assert_eq!(parse_switch("-mmt=on"), Ok(Switch::Threads(Threads::On)));
    assert_eq!(parse_switch("-mmt+"), Ok(Switch::Threads(Threads::On)));
    assert_eq!(parse_switch("-mmt=off"), Ok(Switch::Threads(Threads::Off)));
    assert_eq!(parse_switch("-MMT=OFF"), Ok(Switch::Threads(Threads::Off)));
    assert_eq!(parse_switch("-mmt-"), Ok(Switch::Threads(Threads::Off)));
    assert_eq!(parse_switch("-mmt=4294967295"), Ok(Switch::Threads(Threads::Count(u32::MAX))));
    assert_eq!(parse_switch("-mmt=4294967296"), Err(SizeError::Overflow));
    assert_eq!(parse_switch("-mmt=0"), Err(SizeError::Zero));
    assert_eq!(parse_switch("-mmt=4x"), Err(SizeError::BadValue));
    assert_eq!(parse_switch("-mmt=yes"), Err(SizeError::BadNumber));
}

#[test]
fn unknown_switches() {
    for s in ["", "-", "-x", "mx=9", "--v1m", "-m", "-mz=1", "v100m"] {
        assert_eq!(parse_switch(s), Err(SizeError::BadSwitch), "{s:?}");
    }
}

#[test]
fn never_panics_on_odd_input() {
    for s in ["-v\u{0}", "-mmt\u{1F600}", "-md=\u{e9}", "-mx=\u{663}", "-v18446744073709551615", "-md=18446744073709551615b"] {
        let _ = parse_switch(s);
    }
    assert_eq!(parse_switch("-v18446744073709551615"), Ok(Switch::Volume(u64::MAX)));
    assert_eq!(parse_switch("-md=18446744073709551615b"), Ok(Switch::Dictionary(u64::MAX)));
}
