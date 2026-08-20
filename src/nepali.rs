//! Nepali (Devanagari) text recovery.
//!
//! Two independent problems, both common in Nepali PDFs and both invisible to
//! the generic decode path:
//!
//! 1. **Legacy 8-bit fonts** (Preeti, Fontasy Himali, Kantipur, PCS Nepali,
//!    Sagarmatha and their clones) ship no `/ToUnicode` and declare
//!    `/WinAnsiEncoding`, so the raw keyboard bytes survive extraction as Latin
//!    mojibake — `g]kfn` for `नेपाल`. Recovery is a byte table plus an ordered
//!    set of rewrites that reassemble the composed forms the keyboard layout
//!    splits apart. See [`legacy_table`] and [`decode_legacy`].
//!
//! 2. **Visual glyph order.** Devanagari PDFs routinely emit glyphs in the
//!    order they are drawn, not the order Unicode stores them: the reph sits
//!    after its cluster and the i-matra before its consonant. Fixing that is
//!    [`reorder_devanagari`], which the CID path applies once a glyph run has
//!    been resolved to codepoints.
//!
//! Only the first half is actually Nepali — the keyboard layouts are a Nepali
//! typesetting convention. From [`devanagari_glyph_map`] down, everything keys
//! on the Devanagari block alone and serves Hindi, Marathi and Sanskrit just as
//! well. Adding another Devanagari language means adding its keyboard tables
//! here, not a parallel module; the script half already covers it.

use std::collections::HashMap;

use once_cell::sync::Lazy;
use regex::Regex;

use crate::nepali_tables::{FONTASY_HIMALI, KANTIPUR, PCS_NEPALI, POST_RULES, PREETI, SAGARMATHA};

/// Devanagari codepoints the reordering rules pivot on.
const VIRAMA: char = '\u{094D}';
const RA: char = '\u{0930}';
const I_MATRA: char = '\u{093F}';
const DANDA: char = '\u{0964}';

type LegacyTable = &'static [(u8, &'static str)];

static COMPILED_POST_RULES: Lazy<Vec<(Regex, &'static str)>> = Lazy::new(|| {
    POST_RULES
        .iter()
        .map(|&(pattern, replacement)| {
            let regex = Regex::new(pattern).unwrap_or_else(|e| {
                panic!("nepali post-rule {pattern:?} is not a valid regex: {e}")
            });
            (regex, replacement)
        })
        .collect()
});

/// Match a `/BaseFont` name against the legacy Nepali layouts.
///
/// Matching is on the font name alone and deliberately outranks any
/// `/ToUnicode` the file carries: these fonts either omit it or ship a Latin
/// identity map that decodes to gibberish, so the name is the stronger
/// evidence. Names are compared with the subset prefix, case, separators, and
/// the weight/variant suffixes foundries tack on all removed, which is what
/// collapses `CICECD+FONTASYHIMALITTNORMAL` and `Fontasy Himali` onto one
/// table.
///
/// The Preeti list is longer than its name suggests: Nepali publishers ship a
/// crowd of relabelled clones that share the layout exactly. Membership here is
/// measured, not assumed — the two layouts swap the digit row against a set of
/// consonants, so decoding a sample both ways says plainly which one a font
/// wants (`ARAP002` yields `नेपाल राष्ट्र बैंक` under Preeti and mojibake under
/// Himali; `FontasyHimali` is the other way round).
///
// ponytail: names only, so an unlisted clone falls through and shows as Latin.
// That is the intended failure — visibly untranslated beats silently wrong
// Devanagari. To add one, decode a sample under both tables and follow the
// digit row. Auto-detecting per font would mean scoring a whole page's text
// before decoding any of it; worth doing only if the list starts churning.
pub(crate) fn legacy_table(base_font: &str) -> Option<LegacyTable> {
    let name = normalize_font_name(base_font);
    match name.as_str() {
        "preeti" | "ganesh" | "ganess" | "aakar" | "arap002" | "himalb" | "himalli" => Some(PREETI),
        "fontasyhimali" => Some(FONTASY_HIMALI),
        "kantipur" => Some(KANTIPUR),
        "pcsnepali" => Some(PCS_NEPALI),
        "sagarmatha" => Some(SAGARMATHA),
        _ => None,
    }
}

/// `/CICECD+FONTASYHIMALITTNORMAL` and `/Fontasy#20Himali` → `fontasyhimali`.
fn normalize_font_name(base_font: &str) -> String {
    let stem = base_font
        .rsplit_once('+')
        .map_or(base_font, |(_, stripped)| stripped);
    let mut name: String = decode_name_escapes(stem)
        .chars()
        .filter(|c| c.is_ascii_alphanumeric())
        .flat_map(char::to_lowercase)
        .collect();

    // Weight and flavour suffixes vary per foundry but never change the layout.
    for suffix in ["normal", "regular", "bold", "italic", "mt", "ps", "tt"] {
        while let Some(trimmed) = name.strip_suffix(suffix) {
            if trimmed.is_empty() {
                break;
            }
            name = trimmed.to_string();
        }
    }
    name
}

/// Resolve `#XX` escapes in a PDF name, so `Fontasy#20Himali` does not
/// normalize to `fontasy20himali` and miss its table. A no-op once the parser
/// has already unescaped the name.
fn decode_name_escapes(name: &str) -> std::borrow::Cow<'_, str> {
    if !name.contains('#') {
        return std::borrow::Cow::Borrowed(name);
    }
    let bytes = name.as_bytes();
    let mut out = String::with_capacity(name.len());
    let mut i = 0;
    while i < bytes.len() {
        let hex = (bytes[i] == b'#' && i + 2 < bytes.len())
            .then(|| std::str::from_utf8(&bytes[i + 1..i + 3]).ok())
            .flatten()
            .and_then(|h| u8::from_str_radix(h, 16).ok());
        match hex {
            Some(byte) => {
                out.push(byte as char);
                i += 3;
            }
            None => {
                out.push(bytes[i] as char);
                i += 1;
            }
        }
    }
    std::borrow::Cow::Owned(out)
}

/// Substitute a legacy-font string operand byte-for-byte.
///
/// `bytes` are the raw content-stream bytes; the tables are keyed by cp1252
/// code unit, which is what `/WinAnsiEncoding` makes them. Bytes with no table
/// entry pass through unchanged so embedded ASCII (digits, `%`, Latin
/// abbreviations) survives.
///
/// The output is *not* yet well-formed Devanagari: matras still sit on the
/// side the keyboard put them and the composition markers (`{`, `m`) are still
/// loose. [`apply_post_rules`] finishes the job — but only once whole words are
/// assembled, since a Nepali word is routinely split across several text-show
/// operators and rewriting a fragment strands its matra on the wrong syllable.
pub(crate) fn decode_legacy(bytes: &[u8], table: LegacyTable) -> String {
    let mut out = String::with_capacity(bytes.len() * 2);
    for &byte in bytes {
        match table.binary_search_by_key(&byte, |&(code, _)| code) {
            Ok(idx) => out.push_str(table[idx].1),
            // Unmapped: keep the cp1252 reading so Latin runs stay legible.
            Err(_) => out.push(cp1252_char(byte)),
        }
    }
    out
}

/// Reassemble legacy-decoded text into well-formed Devanagari.
///
/// Runs the layout's ordered rewrites per whitespace-delimited word: several
/// are anchored, and unbounded they would reach across a word boundary and
/// pull a matra onto the wrong syllable. Call this on merged items, never on
/// individual operands.
pub(crate) fn apply_post_rules(text: &str) -> String {
    let mut out = String::with_capacity(text.len());
    for token in text.split_inclusive(char::is_whitespace) {
        let (word, trailing) = match token.find(char::is_whitespace) {
            Some(idx) => token.split_at(idx),
            None => (token, ""),
        };
        if !word.is_empty() {
            let mut mapped = std::borrow::Cow::from(word);
            for (regex, replacement) in COMPILED_POST_RULES.iter() {
                if let std::borrow::Cow::Owned(rewritten) = regex.replace_all(&mapped, *replacement)
                {
                    mapped = std::borrow::Cow::Owned(rewritten);
                }
            }
            out.push_str(&restore_decimal_points(&mapped));
        }
        out.push_str(trailing);
    }
    out
}

/// Put back the decimal points the keyboard tables turn into dandas.
///
/// On these layouts the period key types `।`, which is right for ending a
/// sentence and wrong inside a number: the tariff's rates are typed `19.78`
/// and print `१९.७८`, but decode to `१९।७८`. A danda is sentence-final
/// punctuation and never separates two digits, so a danda with a digit on each
/// side is always a decimal point that was mapped through the wrong key.
fn restore_decimal_points(text: &str) -> String {
    if !text.contains(DANDA) {
        return text.to_string();
    }
    let chars: Vec<char> = text.chars().collect();
    chars
        .iter()
        .enumerate()
        .map(|(i, &c)| {
            let flanked = i > 0
                && is_decimal_digit(chars[i - 1])
                && chars.get(i + 1).copied().is_some_and(is_decimal_digit);
            if c == DANDA && flanked {
                '.'
            } else {
                c
            }
        })
        .collect()
}

fn is_decimal_digit(c: char) -> bool {
    c.is_ascii_digit() || matches!(c, '\u{0966}'..='\u{096F}')
}

/// cp1252 reading of a byte, for the codes the tables leave unmapped.
fn cp1252_char(byte: u8) -> char {
    match byte {
        0x80 => '\u{20AC}',
        0x82 => '\u{201A}',
        0x83 => '\u{0192}',
        0x84 => '\u{201E}',
        0x85 => '\u{2026}',
        0x86 => '\u{2020}',
        0x87 => '\u{2021}',
        0x88 => '\u{02C6}',
        0x89 => '\u{2030}',
        0x8A => '\u{0160}',
        0x8B => '\u{2039}',
        0x8C => '\u{0152}',
        0x8E => '\u{017D}',
        0x91 => '\u{2018}',
        0x92 => '\u{2019}',
        0x93 => '\u{201C}',
        0x94 => '\u{201D}',
        0x95 => '\u{2022}',
        0x96 => '\u{2013}',
        0x97 => '\u{2014}',
        0x98 => '\u{02DC}',
        0x99 => '\u{2122}',
        0x9A => '\u{0161}',
        0x9B => '\u{203A}',
        0x9C => '\u{0153}',
        0x9E => '\u{017E}',
        0x9F => '\u{0178}',
        _ => byte as char,
    }
}

/// Smallest number of Devanagari glyphs an embedded font must expose before we
/// treat it as a Devanagari font. Low enough for a heavily subset font, high
/// enough that a Latin font carrying a stray Devanagari glyph does not qualify.
const MIN_DEVANAGARI_GLYPHS: usize = 8;

/// Build a glyph-id → Unicode map for an embedded Devanagari font.
///
/// Devanagari CID fonts produced by common Office and DTP pipelines routinely
/// carry a `/ToUnicode` generated from glyph *indices* rather than from the
/// font's character map. The result still decodes to Devanagari, so nothing
/// downstream flags it, but individual letters land on their neighbours — an
/// i-matra that reports itself as `क्त`, say. The font's own cmap is the direct
/// statement of what each glyph is, so it is the better authority.
///
/// The cmap alone only reaches glyphs that have a codepoint. Conjuncts are
/// reachable only through GSUB, so ligature substitutions are walked in reverse
/// to decompose a conjunct glyph back into its components, and single
/// substitutions are reversed to find the glyph a variant was derived from.
///
/// Returns `None` unless the font really is Devanagari — this must never
/// second-guess the `/ToUnicode` of a font in any other script.
pub(crate) fn devanagari_glyph_map(font_data: &[u8]) -> Option<HashMap<u16, String>> {
    let face = ttf_parser::Face::parse(font_data, 0).ok()?;

    let mut resolved: HashMap<u16, String> = HashMap::new();
    for subtable in face.tables().cmap.iter().flat_map(|cmap| cmap.subtables) {
        if !subtable.is_unicode() {
            continue;
        }
        subtable.codepoints(|cp| {
            if let (Some(ch), Some(gid)) = (char::from_u32(cp), subtable.glyph_index(cp)) {
                resolved.entry(gid.0).or_insert_with(|| ch.to_string());
            }
        });
    }

    let devanagari = resolved
        .values()
        .filter(|text| text.chars().all(is_devanagari_char))
        .count();
    if devanagari < MIN_DEVANAGARI_GLYPHS || devanagari * 2 < resolved.len() {
        return None;
    }

    remap_disguised_latin_digits(&face, &mut resolved);

    let (ligatures, single_sources) = collect_gsub_reversals(&face);

    // Conjunct glyphs carry no codepoint, so they are absent from the map above
    // and have to be reached through the substitutions that built them.
    let derived: Vec<(u16, String)> = (0..face.number_of_glyphs())
        .filter(|gid| !resolved.contains_key(gid))
        .filter_map(|gid| {
            resolve_glyph(gid, &resolved, &ligatures, &single_sources, 0).map(|text| (gid, text))
        })
        .collect();
    resolved.extend(derived);

    Some(resolved)
}

/// Outline metrics used to tell whether two glyph slots hold the same drawing.
type GlyphMetrics = (u16, ttf_parser::Rect);

/// How many of the ten digit slots must match before the Latin row is judged a
/// disguise. A font could coincidentally match one or two; matching most of the
/// row only happens when the slots really do hold the same drawings.
const DISGUISED_DIGIT_QUORUM: usize = 7;

/// Repoint Latin digit slots that actually contain Devanagari digits.
///
/// Some Devanagari fonts fill their `zero`–`nine` slots with Devanagari
/// outlines, so a PDF that asks for the `two` glyph prints `२` while the cmap
/// still reports U+0032. Extraction that trusts the cmap emits `८2` for a page
/// that plainly reads `८२` — right value, wrong script.
///
/// A slot is a disguise when its advance and bounding box match its Devanagari
/// counterpart: a genuine Latin digit is far narrower than a Devanagari one and
/// lacks the headline bar, so the boxes disagree well beyond the tolerance.
/// The whole row has to agree before any of it is rewritten.
fn remap_disguised_latin_digits(face: &ttf_parser::Face<'_>, resolved: &mut HashMap<u16, String>) {
    let units_per_em = f32::from(face.units_per_em());
    if units_per_em <= 0.0 {
        return;
    }
    let tolerance = units_per_em / 50.0;

    let mut candidates: Vec<(u16, char)> = Vec::new();
    for offset in 0..10u32 {
        let (Some(latin), Some(devanagari)) = (
            char::from_u32('0' as u32 + offset),
            char::from_u32(0x0966 + offset),
        ) else {
            continue;
        };
        let (Some(latin_gid), Some(devanagari_gid)) =
            (face.glyph_index(latin), face.glyph_index(devanagari))
        else {
            continue;
        };
        if latin_gid == devanagari_gid {
            continue; // Already one slot; nothing to repoint.
        }
        let (Some(latin_metrics), Some(devanagari_metrics)) = (
            glyph_metrics(face, latin_gid),
            glyph_metrics(face, devanagari_gid),
        ) else {
            continue;
        };
        if metrics_match(latin_metrics, devanagari_metrics, tolerance) {
            candidates.push((latin_gid.0, devanagari));
        }
    }

    if candidates.len() >= DISGUISED_DIGIT_QUORUM {
        for (gid, devanagari) in candidates {
            resolved.insert(gid, devanagari.to_string());
        }
    }
}

fn glyph_metrics(face: &ttf_parser::Face<'_>, gid: ttf_parser::GlyphId) -> Option<GlyphMetrics> {
    Some((face.glyph_hor_advance(gid)?, face.glyph_bounding_box(gid)?))
}

/// Whether two glyphs advance the same and draw the same shape, within
/// `tolerance` font units.
///
/// Compares the size of the bounding box and its vertical placement, but not
/// its horizontal position: a disguised slot is routinely the same drawing
/// sitting on a different left side bearing, which shifts `x_min` and `x_max`
/// together while the shape is untouched. Vertical extent is the discriminating
/// axis anyway — Devanagari digits hang from a headline bar that Latin ones
/// have no equivalent of.
fn metrics_match(left: GlyphMetrics, right: GlyphMetrics, tolerance: f32) -> bool {
    let close = |a: i16, b: i16| (f32::from(a) - f32::from(b)).abs() <= tolerance;
    let width = |rect: ttf_parser::Rect| f32::from(rect.x_max) - f32::from(rect.x_min);
    f32::from(left.0.abs_diff(right.0)) <= tolerance
        && (width(left.1) - width(right.1)).abs() <= tolerance
        && close(left.1.y_min, right.1.y_min)
        && close(left.1.y_max, right.1.y_max)
}

type GsubReversals = (HashMap<u16, Vec<u16>>, HashMap<u16, u16>);

/// Invert the GSUB substitutions that can be run backwards: ligatures (one
/// glyph ← several) and single substitutions (one glyph ← one).
fn collect_gsub_reversals(face: &ttf_parser::Face<'_>) -> GsubReversals {
    use ttf_parser::gsub::{SingleSubstitution, SubstitutionSubtable};

    let mut ligatures: HashMap<u16, Vec<u16>> = HashMap::new();
    let mut single_sources: HashMap<u16, u16> = HashMap::new();

    let Some(gsub) = face.tables().gsub else {
        return (ligatures, single_sources);
    };

    for index in 0..gsub.lookups.len() {
        let Some(lookup) = gsub.lookups.get(index) else {
            continue;
        };
        for subtable in lookup.subtables.into_iter::<SubstitutionSubtable>() {
            match subtable {
                SubstitutionSubtable::Ligature(table) => {
                    for (coverage_index, first) in coverage_glyphs(&table.coverage) {
                        let Some(set) = table.ligature_sets.get(coverage_index) else {
                            continue;
                        };
                        for i in 0..set.len() {
                            let Some(ligature) = set.get(i) else { continue };
                            // The covered glyph is the ligature's first
                            // component; `components` holds only the rest.
                            let mut parts = vec![first];
                            parts.extend(ligature.components.into_iter().map(|g| g.0));
                            ligatures.entry(ligature.glyph.0).or_insert(parts);
                        }
                    }
                }
                SubstitutionSubtable::Single(SingleSubstitution::Format1 { coverage, delta }) => {
                    for (_, glyph) in coverage_glyphs(&coverage) {
                        // The spec defines this as modular arithmetic.
                        let substitute = (glyph as i32 + delta as i32) as u16;
                        single_sources.entry(substitute).or_insert(glyph);
                    }
                }
                SubstitutionSubtable::Single(SingleSubstitution::Format2 {
                    coverage,
                    substitutes,
                }) => {
                    for (coverage_index, glyph) in coverage_glyphs(&coverage) {
                        if let Some(substitute) = substitutes.get(coverage_index) {
                            single_sources.entry(substitute.0).or_insert(glyph);
                        }
                    }
                }
                _ => {}
            }
        }
    }

    (ligatures, single_sources)
}

/// The `(coverage index, glyph id)` pairs a coverage table lists.
fn coverage_glyphs(coverage: &ttf_parser::opentype_layout::Coverage<'_>) -> Vec<(u16, u16)> {
    use ttf_parser::opentype_layout::Coverage;
    match coverage {
        Coverage::Format1 { glyphs } => glyphs
            .into_iter()
            .enumerate()
            .map(|(i, glyph)| (i as u16, glyph.0))
            .collect(),
        Coverage::Format2 { records } => records
            .into_iter()
            .flat_map(|record| {
                (record.start.0..=record.end.0)
                    .enumerate()
                    .map(move |(offset, glyph)| (record.value.saturating_add(offset as u16), glyph))
            })
            .collect(),
    }
}

/// Walk a glyph back through the substitutions that produced it until it lands
/// on glyphs the cmap can name. The depth cap both bounds the work and breaks
/// the reference cycles a hand-edited GSUB table can contain.
fn resolve_glyph(
    gid: u16,
    resolved: &HashMap<u16, String>,
    ligatures: &HashMap<u16, Vec<u16>>,
    single_sources: &HashMap<u16, u16>,
    depth: u8,
) -> Option<String> {
    if depth > 8 {
        return None;
    }
    if let Some(text) = resolved.get(&gid) {
        return Some(text.clone());
    }
    if let Some(parts) = ligatures.get(&gid) {
        let mut out = String::new();
        for &part in parts {
            out.push_str(&resolve_glyph(
                part,
                resolved,
                ligatures,
                single_sources,
                depth + 1,
            )?);
        }
        return Some(fix_rakar(&out));
    }
    if let Some(&source) = single_sources.get(&gid) {
        return resolve_glyph(source, resolved, ligatures, single_sources, depth + 1);
    }
    None
}

/// Tell a rakar (subjoined `र`) apart from a reph (the hook drawn above).
///
/// A font stores both as the same `र` + virama pair, but they mean opposite
/// things and sit on opposite sides of their consonant. Inside a ligature the
/// pair is a rakar when it hangs off a consonant — `प` + `र` + virama is `प्र`,
/// not `पर्` — and a reph when it follows a matra, in which case it belongs at
/// the front of the whole cluster.
fn fix_rakar(text: &str) -> String {
    let chars: Vec<char> = text.chars().collect();
    let is_ra_virama_tail =
        chars.len() > 2 && chars[chars.len() - 2] == RA && chars[chars.len() - 1] == VIRAMA;
    if !is_ra_virama_tail {
        return text.to_string();
    }
    let head: String = chars[..chars.len() - 2].iter().collect();
    if is_consonant(chars[chars.len() - 3]) {
        format!("{head}{VIRAMA}{RA}")
    } else {
        format!("{RA}{VIRAMA}{head}")
    }
}

fn is_consonant(c: char) -> bool {
    matches!(c, '\u{0915}'..='\u{0939}' | '\u{0958}'..='\u{095F}' | '\u{0979}' | '\u{097A}')
}

/// Rewrite a Devanagari run from visual glyph order into Unicode logical order.
///
/// Two moves, both driven by how a PDF emits glyphs rather than by the text:
///
/// * a reph (`र` + virama) is drawn above the cluster it belongs to and so is
///   emitted *after* it — it has to move to the front of that cluster;
/// * an i-matra is drawn to the left of its consonant and so is emitted
///   *before* it — it has to move after.
///
/// This is **not** safe to run on text that is already in logical order:
/// `मिलेर` legitimately spells an i-matra ahead of `ल`, and a second pass would
/// walk the matra off its syllable. Apply it only to text decoded straight from
/// glyph ids — [`devanagari_glyph_map`]'s output — never to a `/ToUnicode`
/// result, which is logical by definition.
pub(crate) fn reorder_devanagari(text: &str) -> String {
    let chars: Vec<char> = text.chars().collect();
    let mut out: Vec<char> = Vec::with_capacity(chars.len());
    let mut i = 0;

    while i < chars.len() {
        // Reph: emitted after the cluster it crowns.
        if chars[i] == RA && chars.get(i + 1) == Some(&VIRAMA) {
            let start = cluster_start(&out);
            out.insert(start, VIRAMA);
            out.insert(start, RA);
            i += 2;
            continue;
        }

        // i-matra: emitted before the consonant it follows.
        if chars[i] == I_MATRA {
            let (next, cluster) = take_cluster(&chars, i + 1);
            if !cluster.is_empty() {
                out.extend(cluster);
                out.push(I_MATRA);
                i = next;
                continue;
            }
        }

        out.push(chars[i]);
        i += 1;
    }

    out.into_iter().collect()
}

/// Consume exactly one orthographic cluster at `start`: a consonant plus any
/// virama-joined consonants hanging off it.
///
/// Taking more than one is the classic i-matra bug — it walks the matra past
/// the syllable it belongs to and silently rewrites the word.
fn take_cluster(chars: &[char], start: usize) -> (usize, Vec<char>) {
    if start >= chars.len() {
        return (start, Vec::new());
    }
    let mut cluster = vec![chars[start]];
    let mut i = start + 1;
    while i + 1 < chars.len() && chars[i] == VIRAMA {
        cluster.push(chars[i]);
        cluster.push(chars[i + 1]);
        i += 2;
    }
    (i, cluster)
}

/// Index in `out` where the trailing consonant cluster begins.
fn cluster_start(out: &[char]) -> usize {
    if out.is_empty() {
        return 0;
    }
    let mut i = out.len() - 1;
    while i > 0 && is_combining_mark(out[i]) {
        i -= 1;
    }
    while i >= 2 && out[i - 1] == VIRAMA {
        i -= 2;
    }
    i
}

pub(crate) fn is_combining_mark(c: char) -> bool {
    matches!(c, '\u{0900}'..='\u{0903}' | '\u{093A}'..='\u{094F}' | '\u{0951}'..='\u{0957}')
}

/// True when `c` is a Devanagari letter, matra, or sign.
pub(crate) fn is_devanagari_char(c: char) -> bool {
    matches!(c, '\u{0900}'..='\u{097F}' | '\u{A8E0}'..='\u{A8FF}')
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Every shipped post-rule has to compile, or the Lazy panics at runtime on
    /// the first Nepali page rather than here.
    #[test]
    fn post_rules_compile() {
        assert_eq!(COMPILED_POST_RULES.len(), POST_RULES.len());
    }

    #[test]
    fn tables_are_sorted_for_binary_search() {
        for table in [PREETI, FONTASY_HIMALI, KANTIPUR, PCS_NEPALI, SAGARMATHA] {
            assert!(table.windows(2).all(|w| w[0].0 < w[1].0));
        }
    }

    #[test]
    fn font_names_normalize_onto_tables() {
        assert!(legacy_table("CICEGE+Preeti").is_some());
        assert!(legacy_table("EDZXFL+Ganesh").is_some());
        assert!(legacy_table("PCS NEPALI").is_some());
        // `#XX` escapes must resolve, or the name misses its table.
        assert!(legacy_table("Fontasy#20Himali").is_some());
        // Relabelled Preeti clones, each confirmed by decoding a sample.
        for clone in ["NTKZBT+ARAP002", "Himalli", "JVKBXB+Himalb", "DEKRRN+Aakar"] {
            assert!(
                std::ptr::eq(legacy_table(clone).unwrap(), PREETI),
                "{clone}"
            );
        }
        // Fontasy Himali is the one observed name that wants the other layout.
        assert!(std::ptr::eq(
            legacy_table("CICECD+FONTASYHIMALITTNORMAL").unwrap(),
            FONTASY_HIMALI
        ));
        // Unicode Devanagari fonts must not be routed through a keyboard table.
        assert!(legacy_table("Mangal").is_none());
        assert!(legacy_table("BCDHEE+Kokila").is_none());
        assert!(legacy_table("Kalimati").is_none());
        assert!(legacy_table("TimesNewRomanPSMT").is_none());
    }

    /// `decode_legacy` + `apply_post_rules` is the full legacy pipeline; the
    /// split exists only so words can be reassembled in between.
    fn preeti(bytes: &[u8]) -> String {
        apply_post_rules(&decode_legacy(bytes, legacy_table("Preeti").unwrap()))
    }

    #[test]
    fn preeti_decodes_words() {
        // "g]kfn" is how Preeti stores नेपाल.
        assert_eq!(preeti(b"g]kfn"), "नेपाल");
        // Composed vowel: "cf" is the आ ligature, not अ + ा.
        assert_eq!(preeti(b"cf"), "आ");
        // Digits map to Devanagari numerals.
        assert_eq!(preeti(b"@)^$"), "२०६४");
    }

    #[test]
    fn preeti_reorders_i_matra_within_a_word() {
        // The i-matra byte 'l' precedes its consonant in the keyboard layout;
        // in Unicode it has to follow it.
        assert_eq!(preeti(b"gLlt"), "नीति");
        // 'Q' is the त्त conjunct, so the matra hops the whole cluster.
        assert_eq!(preeti(b"ljQ"), "वित्त");
    }

    #[test]
    fn danda_between_digits_is_a_decimal_point() {
        // "19.78" typed on the Himali layout: the digits become Devanagari and
        // the period key would otherwise land as a sentence-ending danda.
        let table = legacy_table("FontasyHimali").unwrap();
        assert_eq!(apply_post_rules(&decode_legacy(b"19.78", table)), "१९.७८");
        // A danda that actually ends a sentence is left alone.
        assert_eq!(restore_decimal_points("यो हो ।"), "यो हो ।");
        assert_eq!(restore_decimal_points("१९।७८ र २४।३० ।"), "१९.७८ र २४.३० ।");
    }

    #[test]
    fn post_rules_do_not_reach_across_words() {
        assert_eq!(preeti(b"g]kfn g]kfn"), "नेपाल नेपाल");
        // Whitespace is preserved verbatim, including runs and the trailing one.
        assert_eq!(preeti(b"g]kfn  g]kfn "), "नेपाल  नेपाल ");
    }

    #[test]
    fn word_split_across_operands_needs_both_fragments() {
        let table = legacy_table("Preeti").unwrap();
        // राष्ट्रिय arrives as three separate text-show operands. Substituting
        // each is fine; rewriting each in isolation is not.
        let joined: String = [&b"/fli6"[..], b"\xab", b"o"]
            .iter()
            .map(|part| decode_legacy(part, table))
            .collect();
        assert_eq!(apply_post_rules(&joined), "राष्ट्रिय");
    }

    #[test]
    fn reorder_moves_reph_before_its_cluster() {
        // "गद" + reph, as drawn, is "गर्द" in logical order.
        let visual = format!("ग\u{0926}{RA}{VIRAMA}");
        assert_eq!(reorder_devanagari(&visual), "ग\u{0930}\u{094D}\u{0926}");
    }

    #[test]
    fn reorder_moves_i_matra_after_one_cluster() {
        // ि म ल → म ि ल, and the matra must not jump past ल.
        let visual = format!("{I_MATRA}मल");
        assert_eq!(reorder_devanagari(&visual), format!("म{I_MATRA}ल"));
    }

    #[test]
    fn reorder_keeps_conjunct_clusters_together() {
        // ि + क्त is one cluster: the matra lands after the whole conjunct.
        let visual = format!("{I_MATRA}क{VIRAMA}त");
        assert_eq!(reorder_devanagari(&visual), format!("क{VIRAMA}त{I_MATRA}"));
    }

    #[test]
    fn reorder_leaves_text_without_reph_or_i_matra_untouched() {
        let text = "नेपाल सरकार";
        assert_eq!(reorder_devanagari(text), text);
    }

    /// Guards the contract in `reorder_devanagari`'s docs: it is a glyph-order
    /// fixer, not an idempotent normalizer. Running it on logical text moves the
    /// matra off its syllable, which is why the caller must gate on provenance.
    #[test]
    fn reorder_is_not_idempotent_on_logical_text() {
        let logical = "मिलेर";
        assert_ne!(reorder_devanagari(logical), logical);
    }

    /// The glyph-level path keys on the Devanagari block, not on Nepali, so the
    /// same reordering has to hold for Hindi, Marathi and Sanskrit. Only the
    /// legacy keyboard tables are Nepali-specific.
    #[test]
    fn reorder_handles_devanagari_beyond_nepali() {
        // Hindi हिन्दी: the i-matra is drawn before ह and must land after it.
        let visual = format!("{I_MATRA}ह\u{0928}{VIRAMA}\u{0926}\u{0940}");
        assert_eq!(reorder_devanagari(&visual), "हिन्दी");

        // Hindi कार्य: the reph is drawn after the cluster it crowns.
        let visual = format!("का\u{092F}{RA}{VIRAMA}");
        assert_eq!(reorder_devanagari(&visual), "कार्य");

        // Marathi ळ (U+0933) counts as a consonant, so a rakar subjoins to it
        // rather than being read as a reph.
        assert_eq!(
            fix_rakar(&format!("\u{0933}{RA}{VIRAMA}")),
            format!("\u{0933}{VIRAMA}{RA}")
        );
    }

    /// Hindi's legacy 8-bit fonts (Kruti Dev, DevLys, Chanakya, …) use different
    /// keyboard layouts from the Nepali ones and have no table here, so they must
    /// fall through rather than be decoded with a Nepali layout.
    #[test]
    fn hindi_legacy_fonts_are_not_claimed_by_nepali_tables() {
        for font in ["Kruti Dev 010", "DevLys 010", "Chanakya", "Shusha", "AGRA"] {
            assert!(legacy_table(font).is_none(), "{font}");
        }
    }

    /// The digit-disguise test has to accept a slot that is the same drawing
    /// and reject one that merely sits nearby. A real Latin digit in a
    /// Devanagari font is markedly narrower and has no headline bar.
    #[test]
    fn metrics_match_separates_a_disguise_from_a_real_latin_digit() {
        let rect = |x_min, y_min, x_max, y_max| ttf_parser::Rect {
            x_min,
            y_min,
            x_max,
            y_max,
        };
        let tolerance = 2048.0 / 50.0;
        // Kalimati's uni0968 and its `two` slot: same drawing, shifted 30 units
        // by a different side bearing, one unit apart in advance.
        let devanagari = (1486, rect(173, -143, 1190, 1577));
        let disguise = (1485, rect(203, -143, 1220, 1577));
        assert!(metrics_match(disguise, devanagari, tolerance));
        // The same font's `eight`, shifted 110 units — still the same drawing.
        assert!(metrics_match(
            (1485, rect(203, 82, 1489, 1372)),
            (1485, rect(93, 82, 1379, 1372)),
            tolerance
        ));
        // A genuine Latin digit: narrower advance, narrower box, and no
        // headline bar, so it fails on every axis that matters.
        let latin = (1000, rect(60, 0, 900, 950));
        assert!(!metrics_match(latin, devanagari, tolerance));
    }

    #[test]
    fn fix_rakar_distinguishes_subjoined_ra_from_reph() {
        // प + र + virama inside a ligature is "pra": the ra subjoins.
        assert_eq!(
            fix_rakar(&format!("प{RA}{VIRAMA}")),
            format!("प{VIRAMA}{RA}")
        );
        // After a matra the same pair is a reph and belongs at the front.
        assert_eq!(
            fix_rakar(&format!("द\u{0948}{RA}{VIRAMA}")),
            format!("{RA}{VIRAMA}द\u{0948}")
        );
    }
}
