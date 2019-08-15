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

impl Scriptlet {
    pub fn parse(data: &str) -> Self {
        let mut parts = vec![];
        let mut last_end_index = 0;

        for cap in TEMPLATE_ARGUMENT_RE.captures_iter(&data) {
            // `unwrap` is safe because the 0th match will always be available.
            let cap = cap.get(0).unwrap();

            if last_end_index != cap.start() {
                let literal = data[last_end_index..cap.start()].to_string();
                parts.push(ScriptletPart::Literal(literal));
            }

            // `unwrap` is safe because the 3rd character of the regex must be a digit.
            let argnum = data[cap.start()+2..cap.start()+3].parse::<usize>().unwrap();
            parts.push(ScriptletPart::Argument(argnum));

            last_end_index = cap.end();
        }

        if last_end_index != data.len() {
            parts.push(ScriptletPart::Literal(data[last_end_index..].to_string()));
        }

        Self { parts }
    }
}
