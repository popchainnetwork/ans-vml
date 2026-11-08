// SPDX-License-Identifier: Apache-2.0
//! Computed writing forms (codepoints, Morse, Polish Braille, ASCII fold) and
//! letter crystals built from the pinned Unicode UCD 17.0.0 snapshot.
use crate::{Crystal, CrystalKind, Leaf};
use anyhow::{anyhow, Result};
use serde_json::{json, Map, Value};

pub const UCD: &str = "https://www.unicode.org/Public/17.0.0/ucd/";
pub const ITU_MORSE: &str = "https://www.itu.int/rec/R-REC-M.1677-1-200910-I/en";
pub const PL_BRAILLE: &str = "https://en.wikipedia.org/wiki/Polish_Braille";

/// Lowercase and strip common Latin diacritics (lossy; for lookup only, not romanization).
pub fn fold(s: &str) -> String {
    s.trim().to_lowercase().chars().flat_map(|c| {
        let r: &str = match c {
            'à'|'á'|'â'|'ã'|'ä'|'å'|'ą'|'ā'|'ă' => "a", 'ç'|'ć'|'č'|'ĉ' => "c", 'ď'|'đ' => "d",
            'è'|'é'|'ê'|'ë'|'ę'|'ě'|'ē' => "e", 'ì'|'í'|'î'|'ï'|'ī' => "i", 'ł'|'ľ'|'ĺ' => "l",
            'ñ'|'ń'|'ň' => "n", 'ò'|'ó'|'ô'|'õ'|'ö'|'ø'|'ō'|'ő' => "o", 'ŕ'|'ř' => "r",
            'ś'|'š'|'ş'|'ș' => "s", 'ß' => "ss", 'ť'|'ţ'|'ț' => "t", 'ù'|'ú'|'û'|'ü'|'ů'|'ū'|'ű' => "u",
            'ý'|'ÿ' => "y", 'ź'|'ż'|'ž' => "z", 'æ' => "ae", 'œ' => "oe",
            _ => return vec![c],
        };
        r.chars().collect()
    }).collect()
}

pub fn codepoints(s: &str) -> String { s.chars().map(|c| format!("U+{:04X}", c as u32)).collect::<Vec<_>>().join(" ") }

/// ITU-R M.1677-1 letters and digits.
pub fn morse(c: char) -> Option<&'static str> {
    const T: [&str; 26] = [".-","-...","-.-.","-..",".","..-.","--.","....","..",".---","-.-",".-..","--","-.","---",".--.","--.-",".-.","...","-","..-","...-",".--","-..-","-.--","--.."];
    const D: [&str; 10] = ["-----",".----","..---","...--","....-",".....","-....","--...","---..","----."];
    match c { 'a'..='z' => Some(T[c as usize - 'a' as usize]), '0'..='9' => Some(D[c as usize - '0' as usize]), _ => None }
}

/// Polish uncontracted Braille (dots bitmask -> U+2800 block).
pub fn polish_braille(c: char) -> Option<char> {
    let dots: u32 = match c {
        'a'=>0x01,'b'=>0x03,'c'=>0x09,'d'=>0x19,'e'=>0x11,'f'=>0x0b,'g'=>0x1b,'h'=>0x13,'i'=>0x0a,'j'=>0x1a,
        'k'=>0x05,'l'=>0x07,'m'=>0x0d,'n'=>0x1d,'o'=>0x15,'p'=>0x0f,'q'=>0x1f,'r'=>0x17,'s'=>0x0e,'t'=>0x1e,
        'u'=>0x25,'v'=>0x27,'w'=>0x3a,'x'=>0x2d,'y'=>0x3d,'z'=>0x35,
        'ą'=>0x21,'ć'=>0x29,'ę'=>0x23,'ł'=>0x31,'ń'=>0x39,'ó'=>0x2c,'ś'=>0x2a,'ź'=>0x2e,'ż'=>0x3e,
        _ => return None,
    };
    char::from_u32(0x2800 + dots)
}

/// Pinned UCD tables (UnicodeData.txt, Blocks.txt, Scripts.txt).
pub struct Ucd { data: String, blocks: String, scripts: String }
impl Ucd {
    pub fn new(data: String, blocks: String, scripts: String) -> Ucd { Ucd { data, blocks, scripts } }
    pub fn load(dir: &std::path::Path) -> Result<Ucd> {
        let r = |n: &str| std::fs::read_to_string(dir.join(n)).map_err(|e| anyhow!("{n}: {e}"));
        Ok(Ucd::new(r("UnicodeData.txt")?, r("Blocks.txt")?, r("Scripts.txt")?))
    }
    fn row(&self, cp: u32) -> Option<Vec<&str>> {
        let key = format!("{cp:04X};");
        self.data.lines().find(|l| l.starts_with(&key)).map(|l| l.split(';').collect())
    }
    fn range(text: &str, cp: u32) -> Option<String> {
        text.lines().find_map(|line| {
            let line = line.split('#').next()?.trim();
            let (code, value) = line.split_once(';')?;
            let mut b = code.trim().split("..");
            let lo = u32::from_str_radix(b.next()?, 16).ok()?;
            let hi = b.next().map(|h| u32::from_str_radix(h, 16).ok()).unwrap_or(Some(lo))?;
            (lo <= cp && cp <= hi).then(|| value.trim().to_string())
        })
    }
    /// Letter crystal, same leaf set as core/tools/crystals/letters.py (port to Rust).
    pub fn letter(&self, c: char) -> Result<Crystal> {
        let cp = c as u32;
        let row = self.row(cp).ok_or_else(|| anyhow!("U+{cp:04X} not in UCD"))?;
        let block = Self::range(&self.blocks, cp).ok_or_else(|| anyhow!("no block"))?;
        let script = Self::range(&self.scripts, cp).ok_or_else(|| anyhow!("no script"))?;
        let ud = format!("{UCD}UnicodeData.txt");
        let (cps, s) = (format!("U+{cp:04X}"), c.to_string());
        let mut leaves = vec![
            Leaf::new(&[("kind","character"),("value",&s),("codepoint",&cps),("name",row[1]),("category",row[2]),("source",&ud)]),
            Leaf::new(&[("kind","block"),("value",&block),("source",&format!("{UCD}Blocks.txt"))]),
            Leaf::new(&[("kind","script"),("value",&script),("source",&format!("{UCD}Scripts.txt"))]),
            Leaf::new(&[("kind","identity"),("value",&s),("schema",crate::CHAR_SCHEMA),("scope","finite Unicode metadata and Polish forms, not universal cross-script equivalence"),("ucd_version","17.0.0"),("ucd_license","Unicode-3.0"),("lexical_license","CC-BY-SA-4.0; Wikipedia contributors for Polish Braille reference")]),
        ];
        if let Some(u) = row.get(12).filter(|u| !u.is_empty()).and_then(|u| u32::from_str_radix(u, 16).ok()).and_then(char::from_u32) {
            leaves.push(Leaf::new(&[("kind","form"),("form","uppercase"),("value",&u.to_string()),("source",&ud)]));
        }
        if let Some(b) = polish_braille(c) {
            leaves.push(Leaf::new(&[("kind","form"),("form","Polish_Braille_uncontracted"),("value",&b.to_string()),("source",PL_BRAILLE)]));
        }
        if !row[5].is_empty() {
            let d = row[5].split_whitespace().map(|n| format!("U+{n}")).collect::<Vec<_>>().join(" ");
            leaves.push(Leaf::new(&[("kind","form"),("form","canonical_decomposition"),("value",&d),("source",&ud)]));
        }
        if let Some(m) = morse(c) {
            leaves.push(Leaf::new(&[("kind","form"),("form","International_Morse"),("value",m),("source",ITU_MORSE)]));
        } else if let Some(m) = fold(&s).chars().next().filter(|f| *f != c).and_then(morse) {
            let method = format!("lossy {c} -> {}; not exact Polish {c} Morse", fold(&s));
            leaves.push(Leaf::new(&[("kind","form"),("form","International_Morse_of_ASCII_fold"),("value",m),("source",ITU_MORSE),("method",&method)]));
        }
        let meta: Map<String, Value> = json!({"complete":false,"minted":false,"signed":false,"gaps":[
            "No cross-script equivalence guessed: UCD script metadata does not establish transliteration or phonetic equivalence.",
            "No phonetic value inferred; letter pronunciation depends on language."]}).as_object().unwrap().clone();
        Crystal::build(CrystalKind::Letter, &s, leaves, meta)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn computed_forms() {
        assert_eq!(fold("Rdzeń"), "rdzen");
        assert_eq!(fold("Straße"), "strasse");
        assert_eq!(codepoints("ń"), "U+0144");
        assert_eq!(morse('r'), Some(".-."));
        assert_eq!(polish_braille('ń'), Some('⠹'));
    }
    #[test]
    fn letters_from_ucd_match_pinned_crystals() {
        let dir = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../tools/crystals");
        let ucd = Ucd::load(&dir).unwrap();
        for (c, f) in [('r',"u0072"),('d',"u0064"),('z',"u007a"),('e',"u0065"),('ń',"u0144")] {
            let pinned = Crystal::parse(&crate::tests::asset(&format!("{f}.crystal.json"))).unwrap();
            let built = ucd.letter(c).unwrap();
            assert_eq!(built.root, pinned.root, "letter {c}");
            assert_eq!(built.file_name(), format!("{f}.crystal.json"));
        }
    }
}
