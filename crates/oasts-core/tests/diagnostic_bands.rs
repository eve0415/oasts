use std::collections::{BTreeMap, BTreeSet};
use std::ffi::OsStr;
use std::fs;
use std::path::Path;

use oasts_core::diag::{Category, Diagnostic};

const CONFIG_CODES: &[&str] = &[
    "OASTS0011",
    "OASTS0031",
    "OASTS0041",
    "OASTS0042",
    "OASTS0051",
    "OASTS0061",
    "OASTS0071",
    "OASTS0072",
    "OASTS0081",
    "OASTS0091",
    "OASTS0101",
    "OASTS0102",
    "OASTS0103",
    "OASTS0111",
    "OASTS0112",
    "OASTS0113",
    "OASTS0121",
    "OASTS0131",
    "OASTS0151",
    "OASTS0152",
    "OASTS0161",
    "OASTS0162",
    "OASTS0163",
    "OASTS0164",
    "OASTS0171",
    "OASTS0172",
    "OASTS0181",
    "OASTS0201",
    "OASTS0202",
    "OASTS0211",
    "OASTS0221",
    "OASTS0241",
    "OASTS0242",
    "OASTS0251",
    "OASTS0252",
    "OASTS0253",
    "OASTS0261",
    "OASTS0262",
    "OASTS0263",
    "OASTS1001",
    "OASTS1002",
    "OASTS1003",
    "OASTS1011",
    "OASTS1012",
    "OASTS1013",
    "OASTS1014",
    "OASTS1021",
    "OASTS9001",
    "OASTS9002",
    "OASTS9003",
    "OASTS9004",
];

const INPUT_CODES: &[&str] = &[
    "OASTS2001",
    "OASTS2002",
    "OASTS2003",
    "OASTS2004",
    "OASTS2005",
    "OASTS2006",
    "OASTS2007",
    "OASTS2011",
    "OASTS2012",
    "OASTS2013",
    "OASTS2014",
    "OASTS2101",
    "OASTS2102",
    "OASTS2103",
    "OASTS2104",
    "OASTS2105",
    "OASTS2106",
    "OASTS2107",
    "OASTS2111",
    "OASTS2112",
    "OASTS2113",
    "OASTS2114",
    "OASTS2115",
    "OASTS2121",
    "OASTS2122",
    "OASTS2123",
    "OASTS2201",
    "OASTS2202",
    "OASTS2203",
    "OASTS2204",
    "OASTS2205",
    "OASTS2211",
    "OASTS2212",
    "OASTS2213",
    "OASTS2214",
    "OASTS2215",
    "OASTS2216",
    "OASTS2221",
    "OASTS3001",
    "OASTS3002",
    "OASTS3003",
    "OASTS3101",
    "OASTS3102",
    "OASTS3103",
    "OASTS3104",
    "OASTS3201",
    "OASTS3202",
    "OASTS3203",
    "OASTS3204",
    "OASTS4001",
    "OASTS4002",
    "OASTS4101",
    "OASTS4102",
    "OASTS4103",
    "OASTS4104",
    "OASTS4105",
    "OASTS4201",
    "OASTS4202",
    "OASTS4203",
    "OASTS4204",
    "OASTS4205",
    "OASTS4206",
    "OASTS4207",
    "OASTS4301",
    "OASTS4302",
    "OASTS5001",
    "OASTS5002",
    "OASTS5003",
    "OASTS5004",
    "OASTS5005",
    "OASTS5006",
    "OASTS5101",
    "OASTS5102",
    "OASTS5103",
    "OASTS5104",
    "OASTS5105",
    "OASTS5106",
    "OASTS5107",
    "OASTS5108",
    "OASTS5109",
    "OASTS5111",
    "OASTS5112",
    "OASTS5113",
    "OASTS5201",
    "OASTS5202",
    "OASTS5203",
    "OASTS5204",
    "OASTS5205",
    "OASTS5206",
    "OASTS5301",
    "OASTS5401",
    "OASTS5402",
    "OASTS5403",
    "OASTS5404",
    "OASTS5405",
    "OASTS5406",
    "OASTS5407",
    "OASTS5408",
    "OASTS5409",
    "OASTS5411",
    "OASTS6001",
    "OASTS6002",
    "OASTS6003",
    "OASTS6004",
    "OASTS6101",
    "OASTS6102",
    "OASTS6201",
    "OASTS6202",
    "OASTS6203",
    "OASTS6204",
    "OASTS6205",
    "OASTS6206",
    "OASTS6207",
    "OASTS6301",
    "OASTS6302",
    "OASTS6303",
    "OASTS9201",
];

#[test]
fn every_diagnostic_code_matches_its_stage_category() {
    let mut inventory = BTreeMap::new();
    for (category, codes) in [
        (Category::Config, CONFIG_CODES),
        (Category::Input, INPUT_CODES),
    ] {
        for &code in codes {
            assert_eq!(category_for_band(code), category, "{code}");
            let diagnostic = match category {
                Category::Config => Diagnostic::config(code, "inventory"),
                Category::Input => Diagnostic::input(code, "inventory"),
            };
            assert_eq!(diagnostic.category, category, "{code}");
            assert!(
                inventory.insert(code.to_owned(), category).is_none(),
                "{code}"
            );
        }
    }

    let source_codes = workspace_source_codes();
    let inventory_codes = inventory.into_keys().collect::<BTreeSet<_>>();
    let unclassified = source_codes
        .difference(&inventory_codes)
        .collect::<Vec<_>>();
    let absent = inventory_codes
        .difference(&source_codes)
        .collect::<Vec<_>>();
    assert!(
        unclassified.is_empty() && absent.is_empty(),
        "unclassified source codes: {unclassified:?}; inventory codes absent from source: {absent:?}"
    );
}

#[test]
fn diagnostic_category_has_only_its_two_constructor_writes() {
    let mut config_writes = 0;
    let mut input_writes = 0;
    for source in workspace_sources() {
        assert!(!has_category_mutation(&source), "category mutation found");
        let production = source.split("\n#[cfg(test)]").next().unwrap_or(&source);
        config_writes += production.matches("category: Category::Config").count();
        input_writes += production.matches("category: Category::Input").count();
    }
    assert_eq!(config_writes, 1);
    assert_eq!(input_writes, 1);
}

fn category_for_band(code: &str) -> Category {
    let bytes = code.as_bytes();
    assert_eq!(bytes.len(), 9, "{code}");
    assert_eq!(&bytes[..5], b"OASTS", "{code}");
    assert!(bytes[5..].iter().all(u8::is_ascii_digit), "{code}");
    let stage = if bytes[5] == b'9' {
        assert_ne!(
            bytes[6], b'9',
            "test sentinel in production inventory: {code}"
        );
        bytes[6]
    } else {
        bytes[5]
    };
    match stage {
        b'0' | b'1' => Category::Config,
        b'2'..=b'6' => Category::Input,
        _ => panic!("unassigned diagnostic stage in {code}"),
    }
}

fn workspace_source_codes() -> BTreeSet<String> {
    workspace_sources()
        .into_iter()
        .flat_map(|source| {
            source
                .as_bytes()
                .windows(9)
                .filter(|window| {
                    &window[..5] == b"OASTS"
                        && window[5..].iter().all(u8::is_ascii_digit)
                        && !(window[5] == b'9' && window[6] == b'9')
                })
                .map(|window| String::from_utf8(window.to_vec()).expect("ASCII diagnostic code"))
                .collect::<Vec<_>>()
        })
        .collect()
}

fn workspace_sources() -> Vec<String> {
    let crates = Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .expect("oasts-core is inside crates")
        .to_owned();
    let mut paths = Vec::new();
    for entry in fs::read_dir(crates).expect("workspace crates should be readable") {
        let source = entry
            .expect("crate entry should be readable")
            .path()
            .join("src");
        if source.is_dir() {
            rust_source_paths(&source, &mut paths);
        }
    }
    paths.sort();
    paths
        .into_iter()
        .map(|path| fs::read_to_string(path).expect("Rust source should be UTF-8"))
        .collect()
}

fn rust_source_paths(directory: &Path, paths: &mut Vec<std::path::PathBuf>) {
    for entry in fs::read_dir(directory).expect("source directory should be readable") {
        let path = entry.expect("source entry should be readable").path();
        if path.is_dir() {
            rust_source_paths(&path, paths);
        } else if path.extension() == Some(OsStr::new("rs")) {
            paths.push(path);
        }
    }
}

fn has_category_mutation(source: &str) -> bool {
    source.match_indices(".category").any(|(offset, marker)| {
        let remainder = source[offset + marker.len()..].trim_start();
        remainder.starts_with('=') && !remainder.starts_with("==")
    })
}
