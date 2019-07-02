use serde::{Deserialize, Serialize};
use crate::utils::Hash;
use crate::filters::network::FilterError;

bitflags! {
    #[derive(Serialize, Deserialize)]
    pub struct CosmeticFilterMask: u8 {
        const UNHIDE = 1 << 0;
        const SCRIPT_INJECT = 1 << 1;
        const IS_UNICODE = 1 << 2;
        const IS_CLASS_SELECTOR = 1 << 3;
        const IS_ID_SELECTOR = 1 << 4;
        const IS_HREF_SELECTOR = 1 << 5;

        // Careful with checking for NONE - will always match
        const NONE = 0;
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CosmeticFilter {
    pub entities: Option<Vec<Hash>>,
    pub hostnames: Option<Vec<Hash>>,
    pub mask: CosmeticFilterMask,
    pub not_entities: Option<Vec<Hash>>,
    pub not_hostnames: Option<Vec<Hash>>,
    pub raw_line: Option<String>,
    pub selector: String,
    pub style: Option<String>,
}

impl CosmeticFilter {
    pub fn parse(line: &str, debug: bool) -> Result<CosmeticFilter, FilterError> {
        let mut mask = CosmeticFilterMask::NONE;
        if let Some(sharp_index) = line.find('#') {
            let after_sharp_index = sharp_index + 1;
            let mut suffix_start_index = after_sharp_index + 1;
            if line[after_sharp_index..].starts_with("@") {
                mask |= CosmeticFilterMask::UNHIDE;
                suffix_start_index += 1;
            }

            let (entities, not_entities, hostnames, not_hostnames) = if sharp_index > 0 {
                let mut entities_vec = vec![];
                let mut not_entities_vec = vec![];
                let mut hostnames_vec = vec![];
                let mut not_hostnames_vec = vec![];

                let parts = line[0..sharp_index].split(',');
                for part in parts {
                    let mut hostname = String::new();
                    if part.is_ascii() {
                        hostname.push_str(&part);
                    } else {
                        mask |= CosmeticFilterMask::IS_UNICODE;
                        let decode_flags = idna::uts46::Flags {
                            use_std3_ascii_rules: true,
                            transitional_processing: true,
                            verify_dns_length: true,
                        };
                        match idna::uts46::to_ascii(&part, decode_flags) {
                            Ok(x) => hostname.push_str(&x),
                            Err(_) => return Err(FilterError::PunycodeError),
                        }
                    }
                    let negation = hostname.starts_with('~');
                    let entity = hostname.ends_with(".*");
                    let start = if negation {
                        1
                    } else {
                        0
                    };
                    let end = if entity {
                        hostname.len() - 2
                    } else {
                        hostname.len()
                    };
                    let hash = crate::utils::fast_hash(&hostname[start..end]);
                    match (negation, entity) {
                        (true, true) => not_entities_vec.push(hash),
                        (true, false) => not_hostnames_vec.push(hash),
                        (false, true) => entities_vec.push(hash),
                        (false, false) => hostnames_vec.push(hash),
                    }
                };

                let entities = if !entities_vec.is_empty() {
                    entities_vec.sort();
                    Some(entities_vec)
                } else {
                    None
                };

                let hostnames = if !hostnames_vec.is_empty() {
                    hostnames_vec.sort();
                    Some(hostnames_vec)
                } else {
                    None
                };

                let not_entities = if !not_entities_vec.is_empty() {
                    not_entities_vec.sort();
                    Some(not_entities_vec)
                } else {
                    None
                };

                let not_hostnames = if !not_hostnames_vec.is_empty() {
                    not_hostnames_vec.sort();
                    Some(not_hostnames_vec)
                } else {
                    None
                };

                (entities, not_entities, hostnames, not_hostnames)
            } else {
                (None, None, None, None)
            };

            let mut selector = &line[suffix_start_index..];
            if line.len() - suffix_start_index > 7 && line[suffix_start_index..].starts_with("script:") {
                mask |= CosmeticFilterMask::SCRIPT_INJECT;
                // TODO
            } else if line.len() - suffix_start_index > 4 && line[suffix_start_index..].starts_with("+js(") {
                mask |= CosmeticFilterMask::SCRIPT_INJECT;
                // TODO
            } else {
                let mut index_after_colon = suffix_start_index;
                while let Some(colon_index) = line[index_after_colon..].find(':') {
                    index_after_colon += colon_index + 1;
                    if line[index_after_colon..].starts_with("style") {
                        // TODO
                    } else if false /* TODO */ {
                        // TODO
                    }
                }
            }

            if !selector.is_ascii() {
                mask |= CosmeticFilterMask::IS_UNICODE;
            }

            if !mask.contains(CosmeticFilterMask::SCRIPT_INJECT) {
                if selector.starts_with('.') && is_simple_selector(selector) {
                    mask |= CosmeticFilterMask::IS_CLASS_SELECTOR;
                } else if selector.starts_with('#') && is_simple_selector(selector) {
                    mask |= CosmeticFilterMask::IS_ID_SELECTOR;
                } else if selector.starts_with("a[h") && is_simple_href_selector(selector, 2) {
                    mask |= CosmeticFilterMask::IS_HREF_SELECTOR;
                } else if selector.starts_with("[h") && is_simple_href_selector(selector, 1) {
                    mask |= CosmeticFilterMask::IS_HREF_SELECTOR;
                }
            }

            Ok(CosmeticFilter {
                entities,
                hostnames,
                mask,
                not_entities,
                not_hostnames,
                raw_line: if debug {
                    Some(String::from(line))
                } else {
                    None
                },
                selector: String::from(selector),
                style: None,
            })
        } else {
            Err(FilterError::FilterParseError)
        }
    }
}

fn is_simple_selector(selector: &str) -> bool {
    // TODO
    true
}

fn is_simple_href_selector(selector: &str, start: usize) -> bool {
    // TODO
    true
}
