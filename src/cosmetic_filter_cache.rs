use crate::filters::cosmetic::CosmeticFilter;
use crate::filters::cosmetic::CosmeticFilterMask;
use crate::utils::Hash;

use std::collections::{HashSet, HashMap};
use std::cell::RefCell;

use psl::Psl;

lazy_static! {
    static ref PUBLIC_SUFFIXES: psl::List = psl::List::new();
}

fn rules_to_stylesheet(rules: &[CosmeticFilter]) -> String {
    if rules.is_empty() {
        "".into()
    } else {
        let mut styled_rules = Vec::with_capacity(10);

        let mut stylesheet = String::with_capacity(100 * rules.len());
        stylesheet += &rules[0].selector;
        rules.iter()
            .skip(1)
            .for_each(|rule| {
                if rule.style.is_some() {
                    styled_rules.push(rule);
                } else {
                    stylesheet += ",";
                    stylesheet += &rule.selector;
                }
            });
        stylesheet += "{display:none !important;}\n";

        styled_rules.iter()
            .for_each(|rule| {
                stylesheet += &rule.selector;
                stylesheet += " {";
                stylesheet += rule.style.as_ref().unwrap();
                stylesheet += "}\n";
            });

        stylesheet
    }
}

pub struct CosmeticFilterCache {
    simple_class_rules: HashSet<String>,
    simple_id_rules: HashSet<String>,
    complex_class_rules: HashMap<String, Vec<String>>,
    complex_id_rules: HashMap<String, Vec<String>>,

    specific_rules: Vec<CosmeticFilter>,

    misc_rules: Vec<CosmeticFilter>,
    // The base stylesheet can be invalidated if a new miscellaneous rule is added. RefCell is used
    // to regenerate and cache the base stylesheet behind an immutable reference if necessary.
    base_stylesheet: RefCell<Option<String>>,
}

impl CosmeticFilterCache {
    pub fn new(rules: Vec<CosmeticFilter>) -> Self {
        let mut self_ = CosmeticFilterCache {
            simple_class_rules: HashSet::with_capacity(rules.len() / 2),
            simple_id_rules: HashSet::with_capacity(rules.len() / 2),
            complex_class_rules: HashMap::with_capacity(rules.len() / 2),
            complex_id_rules: HashMap::with_capacity(rules.len() / 2),

            specific_rules: Vec::with_capacity(rules.len() / 2),
            //specific_scripts = HashMap<String, Vec<String>>

            misc_rules: Vec::with_capacity(rules.len() / 30),
            base_stylesheet: RefCell::new(None),
        };

        for rule in rules {
            self_.add_filter(rule)
        }

        self_.regen_base_stylesheet();

        self_
    }

    /// Rebuilds and caches the base stylesheet if necessary.
    /// This operation can be done for free if the stylesheet has not already been invalidated.
    fn regen_base_stylesheet(&self) {
        if self.base_stylesheet.borrow().is_none() {
            let stylesheet = rules_to_stylesheet(&self.misc_rules);
            self.base_stylesheet.replace(Some(stylesheet));
        }
    }

    pub fn add_filter(&mut self, rule: CosmeticFilter) {
        //TODO deal with script inject and unhide rules
        if rule.mask.contains(CosmeticFilterMask::SCRIPT_INJECT) ||
            rule.mask.contains(CosmeticFilterMask::UNHIDE)
        {
            return;
        }

        if rule.has_hostname_constraint() {
            self.specific_rules.push(rule);
        } else {
            if rule.mask.contains(CosmeticFilterMask::IS_CLASS_SELECTOR) {
                if let Some(key) = &rule.key {
                    let key = key.clone();
                    if rule.mask.contains(CosmeticFilterMask::IS_SIMPLE) {
                        self.simple_class_rules.insert(key);
                    } else {
                        if let Some(bucket) = self.complex_class_rules.get_mut(&key) {
                            bucket.push(rule.selector);
                        } else {
                            self.complex_class_rules.insert(key, vec![rule.selector]);
                        }
                    }
                }
            } else if rule.mask.contains(CosmeticFilterMask::IS_ID_SELECTOR) {
                if let Some(key) = &rule.key {
                    let key = key.clone();
                    if rule.mask.contains(CosmeticFilterMask::IS_SIMPLE) {
                        self.simple_id_rules.insert(key);
                    } else {
                        if let Some(bucket) = self.complex_id_rules.get_mut(&key) {
                            bucket.push(rule.selector);
                        } else {
                            self.complex_id_rules.insert(key, vec![rule.selector]);
                        }
                    }
                }
            } else {
                self.misc_rules.push(rule);
                self.base_stylesheet.replace(None);
            }
        }
    }

    pub fn class_id_stylesheet(&self, classes: &[String], ids: &[String]) -> Option<String> {
        let mut simple_classes = vec![];
        let mut simple_ids = vec![];
        let mut complex_selectors = vec![];

        classes.iter().for_each(|class| {
            if !self.simple_class_rules.contains(class) {
                return;
            }
            if let Some(bucket) = self.complex_class_rules.get(class) {
                complex_selectors.extend_from_slice(&bucket[..]);
            } else {
                simple_classes.push(class);
            }
        });
        ids.iter().for_each(|id| {
            if !self.simple_id_rules.contains(id) {
                return;
            }
            if let Some(bucket) = self.complex_id_rules.get(id) {
                complex_selectors.extend_from_slice(&bucket[..]);
            } else {
                simple_ids.push(id);
            }
        });

        if simple_classes.is_empty() && simple_ids.is_empty() && complex_selectors.is_empty() {
            return None;
        }

        let mut stylesheet = String::with_capacity(100 * (simple_classes.len() + simple_ids.len() + complex_selectors.len()));
        let mut first = true;
        for class in simple_classes {
            if !first {
                stylesheet += ",";
            } else {
                first = false;
            }
            stylesheet += ".";
            stylesheet += class;
        }
        for id in simple_ids {
            if !first {
                stylesheet += ",";
            } else {
                first = false;
            }
            stylesheet += "#";
            stylesheet += id;
        }
        for selector in complex_selectors {
            if !first {
                stylesheet += ",";
            } else {
                first = false;
            }
            stylesheet += &selector;
        }
        stylesheet += "{display:none !important;}";
        Some(stylesheet)
    }

    pub fn hostname_stylesheet(&self, hostname: &str) -> String {
        let domain = match PUBLIC_SUFFIXES.domain(hostname) {
            Some(domain) => domain,
            None => return String::new(),
        };
        let domain_str = domain.to_str();

        let (request_entities, request_hostnames) = hostname_domain_hashes(hostname, domain_str);

        // TODO it would probably be better to use hashmaps here
        rules_to_stylesheet(&self.specific_rules
            .iter()
            .filter(|rule| rule.matches(&request_entities[..], &request_hostnames[..]))
            .cloned()
            .collect::<Vec<_>>())

        // TODO Investigate using something like a HostnameBasedDB for this.
    }

    pub fn base_stylesheet(&self) -> String {
        self.regen_base_stylesheet();
        // Unwrap is safe because the stylesheet is regenerated above if it is None
        self.base_stylesheet.borrow().as_ref().unwrap().clone()
    }
}

fn hostname_domain_hashes(hostname: &str, domain: &str) -> (Vec<Hash>, Vec<Hash>) {
    let request_entities = crate::filters::cosmetic::get_entity_hashes_from_labels(hostname, domain);
    let request_hostnames = crate::filters::cosmetic::get_hostname_hashes_from_labels(hostname, domain);

    (request_entities, request_hostnames)
}
