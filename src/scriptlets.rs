use std::collections::HashMap;
use regex::Regex;
use serde::{Deserialize, Serialize};

lazy_static! {
    static ref TEMPLATE_ARGUMENT_RE: Regex = Regex::new(r"\{\{\d\}\}").unwrap();
}

#[derive(Serialize, Deserialize, Debug, PartialEq, Default)]
pub struct Scriptlets {
    scriptlets: HashMap<String, Scriptlet>
}

#[derive(Serialize, Deserialize, Debug, PartialEq, Default)]
pub struct Scriptlet {
    parts: Vec<ScriptletPart>
}

#[derive(Serialize, Deserialize, Debug, PartialEq)]
pub enum ScriptletPart {
    Literal(String),
    Argument(usize),
}
