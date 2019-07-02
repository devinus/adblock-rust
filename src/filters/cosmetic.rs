use serde::{Deserialize, Serialize};
use crate::utils::Hash;

bitflags! {
    #[derive(Serialize, Deserialize)]
    pub struct CosmeticFilterMask: u32 {
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
    pub fn parse(line: &str, _debug: bool) -> Result<CosmeticFilter, crate::filters::network::FilterError> {
        // TODO: unimplemented, just return rule as a string
        Ok(CosmeticFilter {
            entities: None,
            hostnames: None,
            mask: CosmeticFilterMask::NONE,
            not_entities: None,
            not_hostnames: None,
            raw_line: Some(String::from(line)),
            selector: String::from(line),
            style: None,
        })
    }
}
