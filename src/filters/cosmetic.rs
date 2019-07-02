pub struct CosmeticFilter(String);

impl CosmeticFilter {
    pub fn parse(line: &str, _debug: bool) -> Result<CosmeticFilter, crate::filters::network::FilterError> {
        // TODO: unimplemented, just return rule as a string
        Ok(CosmeticFilter(String::from(line)))
    }
}
