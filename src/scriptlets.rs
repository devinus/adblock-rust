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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_empty_scriptlet() {
        let scriptlet = Scriptlet::parse("");
        assert!(scriptlet.parts.is_empty());
    }

    #[test]
    fn parses_simple_scriptlet() {
        let js_template = r###"literal {{1}} and {{2}}."###;

        let scriptlet = Scriptlet::parse(&js_template);

        assert_eq!(scriptlet.parts, vec![
            ScriptletPart::Literal("literal ".to_owned()),
            ScriptletPart::Argument(1),
            ScriptletPart::Literal(" and ".to_owned()),
            ScriptletPart::Argument(2),
            ScriptletPart::Literal(".".to_owned()),
        ]);
    }

    #[test]
    fn parses_simple_scriptlet_without_end_literal() {
        let js_template = r###"literal {{1}} and {{2}}"###;

        let scriptlet = Scriptlet::parse(&js_template);

        assert_eq!(scriptlet.parts, vec![
            ScriptletPart::Literal("literal ".to_owned()),
            ScriptletPart::Argument(1),
            ScriptletPart::Literal(" and ".to_owned()),
            ScriptletPart::Argument(2),
        ]);
    }

    #[test]
    fn parses_consecutive_scriptlet_arguments() {
        let js_template = r###"Here are lots of arguments: {{1}}{{1}}{{2}}{{1}}{{3}} {{2}}"###;

        let scriptlet = Scriptlet::parse(&js_template);

        assert_eq!(scriptlet.parts, vec![
            ScriptletPart::Literal("Here are lots of arguments: ".to_owned()),
            ScriptletPart::Argument(1),
            ScriptletPart::Argument(1),
            ScriptletPart::Argument(2),
            ScriptletPart::Argument(1),
            ScriptletPart::Argument(3),
            ScriptletPart::Literal(" ".to_owned()),
            ScriptletPart::Argument(2),
        ]);
    }

    #[test]
    fn parses_scriptlet_starting_with_argument() {
        let js_template = r###"{{1}} argument is at the beginning"###;

        let scriptlet = Scriptlet::parse(&js_template);

        assert_eq!(scriptlet.parts, vec![
            ScriptletPart::Argument(1),
            ScriptletPart::Literal(" argument is at the beginning".to_owned()),
        ]);
    }

    #[test]
    fn parses_real_scriptlet() {
        let js_template = r###"(function() {
    const target = '{{1}}';
    if ( target === '' || target === '{{1}}' ) { return; }
    const needle = '{{2}}';
    let reText = '.?';
    if ( needle !== '' && needle !== '{{2}}' ) {
        reText = /^\/.+\/$/.test(needle)
            ? needle.slice(1,-1)
            : needle.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
    }
    const thisScript = document.currentScript;
    const re = new RegExp(reText);
    const chain = target.split('.');
    let owner = window;
    let prop;
    for (;;) {
        prop = chain.shift();
        if ( chain.length === 0 ) { break; }
        owner = owner[prop];
        if ( owner instanceof Object === false ) { return; }
    }
    const desc = Object.getOwnPropertyDescriptor(owner, prop);
    if ( desc && desc.get !== undefined ) { return; }
    const magic = String.fromCharCode(Date.now() % 26 + 97) +
                  Math.floor(Math.random() * 982451653 + 982451653).toString(36);
    let value = owner[prop];
    const validate = function() {
        const e = document.currentScript;
        if (
            e instanceof HTMLScriptElement &&
            e.src === '' &&
            e !== thisScript &&
            re.test(e.textContent)
        ) {
            throw new ReferenceError(magic);
        }
    };
    Object.defineProperty(owner, prop, {
        get: function() {
            validate();
            return value;
        },
        set: function(a) {
            validate();
            value = a;
        }
    });
    const oe = window.onerror;
    window.onerror = function(msg) {
        if ( typeof msg === 'string' && msg.indexOf(magic) !== -1 ) {
            return true;
        }
        if ( oe instanceof Function ) {
            return oe.apply(this, arguments);
        }
    }.bind();
})();"###.to_owned();

        let scriptlet = Scriptlet::parse(&js_template);

        let expected_parts = vec![
            ScriptletPart::Literal(
                r###"(function() {
    const target = '"###.to_owned()
            ),
            ScriptletPart::Argument(1),
            ScriptletPart::Literal(
                r###"';
    if ( target === '' || target === '"###.to_owned()
            ),
            ScriptletPart::Argument(1),
            ScriptletPart::Literal(
                r###"' ) { return; }
    const needle = '"###.to_owned()
            ),
            ScriptletPart::Argument(2),
            ScriptletPart::Literal(
                r###"';
    let reText = '.?';
    if ( needle !== '' && needle !== '"###.to_owned()
            ),
            ScriptletPart::Argument(2),
            ScriptletPart::Literal(
                r###"' ) {
        reText = /^\/.+\/$/.test(needle)
            ? needle.slice(1,-1)
            : needle.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
    }
    const thisScript = document.currentScript;
    const re = new RegExp(reText);
    const chain = target.split('.');
    let owner = window;
    let prop;
    for (;;) {
        prop = chain.shift();
        if ( chain.length === 0 ) { break; }
        owner = owner[prop];
        if ( owner instanceof Object === false ) { return; }
    }
    const desc = Object.getOwnPropertyDescriptor(owner, prop);
    if ( desc && desc.get !== undefined ) { return; }
    const magic = String.fromCharCode(Date.now() % 26 + 97) +
                  Math.floor(Math.random() * 982451653 + 982451653).toString(36);
    let value = owner[prop];
    const validate = function() {
        const e = document.currentScript;
        if (
            e instanceof HTMLScriptElement &&
            e.src === '' &&
            e !== thisScript &&
            re.test(e.textContent)
        ) {
            throw new ReferenceError(magic);
        }
    };
    Object.defineProperty(owner, prop, {
        get: function() {
            validate();
            return value;
        },
        set: function(a) {
            validate();
            value = a;
        }
    });
    const oe = window.onerror;
    window.onerror = function(msg) {
        if ( typeof msg === 'string' && msg.indexOf(magic) !== -1 ) {
            return true;
        }
        if ( oe instanceof Function ) {
            return oe.apply(this, arguments);
        }
    }.bind();
})();"###.to_owned()
            ),
        ];

        assert_eq!(scriptlet.parts, expected_parts);
    }
}
