use serde::{Deserialize, Serialize};
use crate::utils::Hash;

#[derive(Debug, PartialEq)]
pub enum CosmeticFilterError {
    PunycodeError,
    InvalidStyleSpecifier,
    UnsupportedSyntax,
    MissingSharp,
    InvalidCssStyle,
    InvalidCssSelector,
}

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
    pub fn parse(line: &str, debug: bool) -> Result<CosmeticFilter, CosmeticFilterError> {
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
                            Err(_) => return Err(CosmeticFilterError::PunycodeError),
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
            let mut style = None;
            if line.len() - suffix_start_index > 7 && line[suffix_start_index..].starts_with("script:") {
                let script_method_index = suffix_start_index + 7;
                let mut script_selector_index_start = script_method_index;
                let script_selector_index_end = line.len() - 1;

                if line[script_method_index..].starts_with("inject(") {
                    mask |= CosmeticFilterMask::SCRIPT_INJECT;
                    script_selector_index_start += 7;
                }

                selector = &line[script_selector_index_start..script_selector_index_end];
            } else if line.len() - suffix_start_index > 4 && line[suffix_start_index..].starts_with("+js(") {
                mask |= CosmeticFilterMask::SCRIPT_INJECT;
                selector = &line[suffix_start_index + 4..line.len() - 1];
            } else {
                let mut index_after_colon = suffix_start_index;
                while let Some(colon_index) = line[index_after_colon..].find(':') {
                    let colon_index = colon_index + index_after_colon;
                    index_after_colon = colon_index + 1;
                    if line[index_after_colon..].starts_with("style") {
                        if line.chars().nth(index_after_colon + 5) == Some('(') && line.chars().nth(line.len() - 1) == Some(')') {
                            selector = &line[suffix_start_index..colon_index];
                            style = Some(line[index_after_colon + 6..line.len()-1].to_string());
                        } else {
                            return Err(CosmeticFilterError::InvalidStyleSpecifier);
                        }
                    } else if line[index_after_colon..].starts_with("-abp-")
                    || line[index_after_colon..].starts_with("contains")
                    || line[index_after_colon..].starts_with("has")
                    || line[index_after_colon..].starts_with("if")
                    || line[index_after_colon..].starts_with("if-not")
                    || line[index_after_colon..].starts_with("matches-css")
                    || line[index_after_colon..].starts_with("matches-css-after")
                    || line[index_after_colon..].starts_with("matches-css-before")
                    || line[index_after_colon..].starts_with("properties")
                    || line[index_after_colon..].starts_with("subject")
                    || line[index_after_colon..].starts_with("xpath")
                    {
                        return Err(CosmeticFilterError::UnsupportedSyntax);
                    }
                }
            }

            if !mask.contains(CosmeticFilterMask::SCRIPT_INJECT) && !is_valid_css_selector(selector) {
                return Err(CosmeticFilterError::InvalidCssSelector);
            } else if let Some(ref style) = style {
                if !is_valid_css_style(style) {
                    return Err(CosmeticFilterError::InvalidCssStyle);
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
                style,
            })
        } else {
            Err(CosmeticFilterError::MissingSharp)
        }
    }
}

fn is_valid_css_selector(_selector: &str) -> bool {
    // TODO
    true
}

fn is_valid_css_style(_style: &str) -> bool {
    // TODO
    true
}

fn is_simple_selector(selector: &str) -> bool {
    for (i, c) in selector.chars().enumerate().skip(1) {
        if !(c == '-'
            || c == '_'
            || (c >= '0' && c <= '9')
            || (c >= 'A' && c <= 'Z')
            || (c >= 'a' && c <= 'z'))
        {
            if i < selector.len() - 1 {
                // Unwrap is safe here because of the range check above
                let next = selector.chars().nth(i + 1).unwrap();
                if c == '['
                    || (c == ' '
                        && (next == '>'
                            || next == '+'
                            || next == '~'
                            || next == '.'
                            || next == '#'))
                {
                    return true;
                }
            }
            return false;
        }
    }
    true
}

fn is_simple_href_selector(selector: &str, start: usize) -> bool {
    selector[start..].starts_with("href^=\"")
        || selector[start..].starts_with("href*=\"")
        || selector[start..].starts_with("href=\"")
}

#[cfg(test)]
mod parse_tests {
    use super::*;

    #[derive(Debug, PartialEq)]
    struct CosmeticFilterBreakdown {
        entities: Option<Vec<Hash>>,
        hostnames: Option<Vec<Hash>>,
        not_entities: Option<Vec<Hash>>,
        not_hostnames: Option<Vec<Hash>>,
        selector: String,
        style: Option<String>,

        unhide: bool,
        script_inject: bool,
        is_unicode: bool,
        is_class_selector: bool,
        is_id_selector: bool,
        is_href_selector: bool,
    }

    impl From<&CosmeticFilter> for CosmeticFilterBreakdown {
        fn from(filter: &CosmeticFilter) -> CosmeticFilterBreakdown {
            CosmeticFilterBreakdown {
                entities: filter.entities.as_ref().cloned(),
                hostnames: filter.hostnames.as_ref().cloned(),
                not_entities: filter.not_entities.as_ref().cloned(),
                not_hostnames: filter.not_hostnames.as_ref().cloned(),
                selector: filter.selector.clone(),
                style: filter.style.as_ref().cloned(),

                unhide: filter.mask.contains(CosmeticFilterMask::UNHIDE),
                script_inject: filter.mask.contains(CosmeticFilterMask::SCRIPT_INJECT),
                is_unicode: filter.mask.contains(CosmeticFilterMask::IS_UNICODE),
                is_class_selector: filter.mask.contains(CosmeticFilterMask::IS_CLASS_SELECTOR),
                is_id_selector: filter.mask.contains(CosmeticFilterMask::IS_ID_SELECTOR),
                is_href_selector: filter.mask.contains(CosmeticFilterMask::IS_HREF_SELECTOR),
            }
        }
    }

    impl Default for CosmeticFilterBreakdown {
        fn default() -> Self {
            CosmeticFilterBreakdown {
                entities: None,
                hostnames: None,
                not_entities: None,
                not_hostnames: None,
                selector: "".to_string(),
                style: None,

                unhide: false,
                script_inject: false,
                is_unicode: false,
                is_class_selector: false,
                is_id_selector: false,
                is_href_selector: false,
            }
        }
    }

    fn check_parse_result(rule: &str, expected: CosmeticFilterBreakdown) {
        let filter: CosmeticFilterBreakdown = (&CosmeticFilter::parse(rule, false).unwrap()).into();
        assert_eq!(expected, filter);
    }

    #[test]
    fn simple_selectors() {
        check_parse_result(
            "##div.popup",
            CosmeticFilterBreakdown {
                selector: "div.popup".to_string(),
                ..Default::default()
            }
        );
        check_parse_result(
            "###selector",
            CosmeticFilterBreakdown {
                selector: "#selector".to_string(),
                is_id_selector: true,
                ..Default::default()
            }
        );
        check_parse_result(
            "##.selector",
            CosmeticFilterBreakdown {
                selector: ".selector".to_string(),
                is_class_selector: true,
                ..Default::default()
            }
        );
        check_parse_result(
            "##a[href=\"foo.com\"]",
            CosmeticFilterBreakdown {
                selector: "a[href=\"foo.com\"]".to_string(),
                is_href_selector: true,
                ..Default::default()
            }
        );
        check_parse_result(
            "##[href=\"foo.com\"]",
            CosmeticFilterBreakdown {
                selector: "[href=\"foo.com\"]".to_string(),
                is_href_selector: true,
                ..Default::default()
            }
        );
    }

    /// Produces a sorted vec of the hashes of all the given domains.
    ///
    /// For convenience, the return value is wrapped in a `Some()` to be consumed by a
    /// `CosmeticFilterBreakdown`.
    fn sort_hash_domains(domains: Vec<&str>) -> Option<Vec<Hash>> {
        let mut hashes: Vec<_> = domains.iter().map(|d| crate::utils::fast_hash(d)).collect();
        hashes.sort();
        Some(hashes)
    }

    #[test]
    fn hostnames() {
        check_parse_result(
            r#"u00p.com##div[class^="adv-box"]"#,
            CosmeticFilterBreakdown {
                selector: r#"div[class^="adv-box"]"#.to_string(),
                hostnames: sort_hash_domains(vec!["u00p.com"]),
                ..Default::default()
            }
        );
        check_parse_result(
            r#"distractify.com##div[class*="AdInArticle"]"#,
            CosmeticFilterBreakdown {
                selector: r#"div[class*="AdInArticle"]"#.to_string(),
                hostnames: sort_hash_domains(vec!["distractify.com"]),
                ..Default::default()
            }
        );
        check_parse_result(
            r#"soundtrackcollector.com,the-numbers.com##a[href^="http://affiliates.allposters.com/"]"#,
            CosmeticFilterBreakdown {
                selector: r#"a[href^="http://affiliates.allposters.com/"]"#.to_string(),
                is_href_selector: true,
                hostnames: sort_hash_domains(vec!["soundtrackcollector.com", "the-numbers.com"]),
                ..Default::default()
            }
        );
        check_parse_result(
            r#"thelocal.at,thelocal.ch,thelocal.de,thelocal.dk,thelocal.es,thelocal.fr,thelocal.it,thelocal.no,thelocal.se##div[class*="-widget"]"#,
            CosmeticFilterBreakdown {
                selector: r#"div[class*="-widget"]"#.to_string(),
                hostnames: sort_hash_domains(vec![
                     "thelocal.at",
                     "thelocal.ch",
                     "thelocal.de",
                     "thelocal.dk",
                     "thelocal.es",
                     "thelocal.fr",
                     "thelocal.it",
                     "thelocal.no",
                     "thelocal.se",
                ]),
                ..Default::default()
            }
        );
        check_parse_result(
            r#"base64decode.org,base64encode.org,beautifyjson.org,minifyjson.org,numgen.org,pdfmrg.com,pdfspl.com,prettifycss.com,pwdgen.org,strlength.com,strreverse.com,uglifyjs.net,urldecoder.org##div[class^="banner_"]"#,
            CosmeticFilterBreakdown {
                selector: r#"div[class^="banner_"]"#.to_string(),
                hostnames: sort_hash_domains(vec![
                     "base64decode.org",
                     "base64encode.org",
                     "beautifyjson.org",
                     "minifyjson.org",
                     "numgen.org",
                     "pdfmrg.com",
                     "pdfspl.com",
                     "prettifycss.com",
                     "pwdgen.org",
                     "strlength.com",
                     "strreverse.com",
                     "uglifyjs.net",
                     "urldecoder.org"
                ]),
                ..Default::default()
            }
        );
        check_parse_result(
            r#"adforum.com,alliednews.com,americustimesrecorder.com,andovertownsman.com,athensreview.com,batesvilleheraldtribune.com,bdtonline.com,channel24.pk,chickashanews.com,claremoreprogress.com,cleburnetimesreview.com,clintonherald.com,commercejournal.com,commercial-news.com,coopercrier.com,cordeledispatch.com,corsicanadailysun.com,crossville-chronicle.com,cullmantimes.com,dailyiowegian.com,dailyitem.com,daltondailycitizen.com,derrynews.com,duncanbanner.com,eagletribune.com,edmondsun.com,effinghamdailynews.com,enewscourier.com,enidnews.com,farmtalknewspaper.com,fayettetribune.com,flasharcade.com,flashgames247.com,flyergroup.com,foxsportsasia.com,gainesvilleregister.com,gloucestertimes.com,goshennews.com,greensburgdailynews.com,heraldbanner.com,heraldbulletin.com,hgazette.com,homemagonline.com,itemonline.com,jacksonvilleprogress.com,jerusalemonline.com,joplinglobe.com,journal-times.com,journalexpress.net,kexp.org,kokomotribune.com,lockportjournal.com,mankatofreepress.com,mcalesternews.com,mccrearyrecord.com,mcleansborotimesleader.com,meadvilletribune.com,meridianstar.com,mineralwellsindex.com,montgomery-herald.com,mooreamerican.com,moultrieobserver.com,muskogeephoenix.com,ncnewsonline.com,newburyportnews.com,newsaegis.com,newsandtribune.com,niagara-gazette.com,njeffersonnews.com,normantranscript.com,opposingviews.com,orangeleader.com,oskaloosa.com,ottumwacourier.com,outlookmoney.com,palestineherald.com,panews.com,paulsvalleydailydemocrat.com,pellachronicle.com,pharostribune.com,pressrepublican.com,pryordailytimes.com,randolphguide.com,record-eagle.com,register-herald.com,register-news.com,reporter.net,rockwallheraldbanner.com,roysecityheraldbanner.com,rushvillerepublican.com,salemnews.com,sentinel-echo.com,sharonherald.com,shelbyvilledailyunion.com,siteslike.com,standardmedia.co.ke,starbeacon.com,stwnewspress.com,suwanneedemocrat.com,tahlequahdailypress.com,theadanews.com,theawesomer.com,thedailystar.com,thelandonline.com,themoreheadnews.com,thesnaponline.com,tiftongazette.com,times-news.com,timesenterprise.com,timessentinel.com,timeswv.com,tonawanda-news.com,tribdem.com,tribstar.com,unionrecorder.com,valdostadailytimes.com,washtimesherald.com,waurikademocrat.com,wcoutlook.com,weatherforddemocrat.com,woodwardnews.net,wrestlinginc.com##div[style="width:300px; height:250px;"]"#,
            CosmeticFilterBreakdown {
                selector: r#"div[style="width:300px; height:250px;"]"#.to_string(),
                hostnames: sort_hash_domains(vec![
                    "adforum.com",
                    "alliednews.com",
                    "americustimesrecorder.com",
                    "andovertownsman.com",
                    "athensreview.com",
                    "batesvilleheraldtribune.com",
                    "bdtonline.com",
                    "channel24.pk",
                    "chickashanews.com",
                    "claremoreprogress.com",
                    "cleburnetimesreview.com",
                    "clintonherald.com",
                    "commercejournal.com",
                    "commercial-news.com",
                    "coopercrier.com",
                    "cordeledispatch.com",
                    "corsicanadailysun.com",
                    "crossville-chronicle.com",
                    "cullmantimes.com",
                    "dailyiowegian.com",
                    "dailyitem.com",
                    "daltondailycitizen.com",
                    "derrynews.com",
                    "duncanbanner.com",
                    "eagletribune.com",
                    "edmondsun.com",
                    "effinghamdailynews.com",
                    "enewscourier.com",
                    "enidnews.com",
                    "farmtalknewspaper.com",
                    "fayettetribune.com",
                    "flasharcade.com",
                    "flashgames247.com",
                    "flyergroup.com",
                    "foxsportsasia.com",
                    "gainesvilleregister.com",
                    "gloucestertimes.com",
                    "goshennews.com",
                    "greensburgdailynews.com",
                    "heraldbanner.com",
                    "heraldbulletin.com",
                    "hgazette.com",
                    "homemagonline.com",
                    "itemonline.com",
                    "jacksonvilleprogress.com",
                    "jerusalemonline.com",
                    "joplinglobe.com",
                    "journal-times.com",
                    "journalexpress.net",
                    "kexp.org",
                    "kokomotribune.com",
                    "lockportjournal.com",
                    "mankatofreepress.com",
                    "mcalesternews.com",
                    "mccrearyrecord.com",
                    "mcleansborotimesleader.com",
                    "meadvilletribune.com",
                    "meridianstar.com",
                    "mineralwellsindex.com",
                    "montgomery-herald.com",
                    "mooreamerican.com",
                    "moultrieobserver.com",
                    "muskogeephoenix.com",
                    "ncnewsonline.com",
                    "newburyportnews.com",
                    "newsaegis.com",
                    "newsandtribune.com",
                    "niagara-gazette.com",
                    "njeffersonnews.com",
                    "normantranscript.com",
                    "opposingviews.com",
                    "orangeleader.com",
                    "oskaloosa.com",
                    "ottumwacourier.com",
                    "outlookmoney.com",
                    "palestineherald.com",
                    "panews.com",
                    "paulsvalleydailydemocrat.com",
                    "pellachronicle.com",
                    "pharostribune.com",
                    "pressrepublican.com",
                    "pryordailytimes.com",
                    "randolphguide.com",
                    "record-eagle.com",
                    "register-herald.com",
                    "register-news.com",
                    "reporter.net",
                    "rockwallheraldbanner.com",
                    "roysecityheraldbanner.com",
                    "rushvillerepublican.com",
                    "salemnews.com",
                    "sentinel-echo.com",
                    "sharonherald.com",
                    "shelbyvilledailyunion.com",
                    "siteslike.com",
                    "standardmedia.co.ke",
                    "starbeacon.com",
                    "stwnewspress.com",
                    "suwanneedemocrat.com",
                    "tahlequahdailypress.com",
                    "theadanews.com",
                    "theawesomer.com",
                    "thedailystar.com",
                    "thelandonline.com",
                    "themoreheadnews.com",
                    "thesnaponline.com",
                    "tiftongazette.com",
                    "times-news.com",
                    "timesenterprise.com",
                    "timessentinel.com",
                    "timeswv.com",
                    "tonawanda-news.com",
                    "tribdem.com",
                    "tribstar.com",
                    "unionrecorder.com",
                    "valdostadailytimes.com",
                    "washtimesherald.com",
                    "waurikademocrat.com",
                    "wcoutlook.com",
                    "weatherforddemocrat.com",
                    "woodwardnews.net",
                    "wrestlinginc.com",
                ]),
                ..Default::default()
            }
        );
    }

    #[test]
    fn href() {
        check_parse_result(
            r#"##a[href$="/vghd.shtml"]"#,
            CosmeticFilterBreakdown {
                selector: r#"a[href$="/vghd.shtml"]"#.to_string(),
                ..Default::default()
            }
        );
        check_parse_result(
            r#"##a[href*=".adk2x.com/"]"#,
            CosmeticFilterBreakdown {
                selector: r#"a[href*=".adk2x.com/"]"#.to_string(),
                is_href_selector: true,
                ..Default::default()
            }
        );
        check_parse_result(
            r#"##a[href^="//40ceexln7929.com/"]"#,
            CosmeticFilterBreakdown {
                selector: r#"a[href^="//40ceexln7929.com/"]"#.to_string(),
                is_href_selector: true,
                ..Default::default()
            }
        );
        check_parse_result(
            r#"##a[href*=".trust.zone"]"#,
            CosmeticFilterBreakdown {
                selector: r#"a[href*=".trust.zone"]"#.to_string(),
                is_href_selector: true,
                ..Default::default()
            }
        );
        check_parse_result(
            r#"tf2maps.net##a[href="http://forums.tf2maps.net/payments.php"]"#,
            CosmeticFilterBreakdown {
                selector: r#"a[href="http://forums.tf2maps.net/payments.php"]"#.to_string(),
                hostnames: sort_hash_domains(vec!["tf2maps.net"]),
                is_href_selector: true,
                ..Default::default()
            }
        );
        check_parse_result(
            r#"rarbg.to,rarbg.unblockall.org,rarbgaccess.org,rarbgmirror.com,rarbgmirror.org,rarbgmirror.xyz,rarbgproxy.com,rarbgproxy.org,rarbgunblock.com##a[href][target="_blank"] > button"#,
            CosmeticFilterBreakdown {
                selector: r#"a[href][target="_blank"] > button"#.to_string(),
                hostnames: sort_hash_domains(vec![
                     "rarbg.to",
                     "rarbg.unblockall.org",
                     "rarbgaccess.org",
                     "rarbgmirror.com",
                     "rarbgmirror.org",
                     "rarbgmirror.xyz",
                     "rarbgproxy.com",
                     "rarbgproxy.org",
                     "rarbgunblock.com",
                ]),
                ..Default::default()
            }
        );
    }

    #[test]
    fn entities() {
        check_parse_result(
            r#"monova.*##+js(nowebrtc.js)"#,
            CosmeticFilterBreakdown {
                selector: r#"nowebrtc.js"#.to_string(),
                entities: sort_hash_domains(vec!["monova"]),
                script_inject: true,
                ..Default::default()
            }
        );
        check_parse_result(
            r#"monova.*##tr.success.desktop"#,
            CosmeticFilterBreakdown {
                selector: r#"tr.success.desktop"#.to_string(),
                entities: sort_hash_domains(vec!["monova"]),
                ..Default::default()
            }
        );
        check_parse_result(
            r#"monova.*#@#script + [class] > [class]:first-child"#,
            CosmeticFilterBreakdown {
                selector: r#"script + [class] > [class]:first-child"#.to_string(),
                entities: sort_hash_domains(vec!["monova"]),
                unhide: true,
                ..Default::default()
            }
        );
        check_parse_result(
            r#"adshort.im,adsrt.*#@#[id*="ScriptRoot"]"#,
            CosmeticFilterBreakdown {
                selector: r#"[id*="ScriptRoot"]"#.to_string(),
                hostnames: sort_hash_domains(vec!["adshort.im"]),
                entities: sort_hash_domains(vec!["adsrt"]),
                unhide: true,
                ..Default::default()
            }
        );
        check_parse_result(
            r#"downloadsource.*##.date:not(dt):style(display: block !important;)"#,
            CosmeticFilterBreakdown {
                selector: r#".date:not(dt)"#.to_string(),
                entities: sort_hash_domains(vec!["downloadsource"]),
                style: Some("display: block !important;".into()),
                ..Default::default()
            }
        );
    }
}
