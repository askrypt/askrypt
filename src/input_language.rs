//! Which language an answer could be typed in, to catch a wrong keyboard
//! layout while the answer itself is hidden.
//!
//! Only four alphabets are known: English, German, Russian and Ukrainian.
//! Characters outside all of them (digits, spaces, punctuation, `é`, …) say
//! nothing and are skipped. Latin and Cyrillic letters are judged separately:
//! within a script, a language counts only if its alphabet holds *every*
//! letter of that script typed; the two scripts' answers are then combined.

/// A language whose alphabet the hint knows.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Language {
    English,
    German,
    Russian,
    Ukrainian,
}

impl Language {
    /// Every language, in the order the hint lists them.
    pub const ALL: [Language; 4] = [
        Language::English,
        Language::German,
        Language::Russian,
        Language::Ukrainian,
    ];

    pub fn name(self) -> &'static str {
        match self {
            Language::English => "English",
            Language::German => "German",
            Language::Russian => "Russian",
            Language::Ukrainian => "Ukrainian",
        }
    }

    /// Whether this language's alphabet holds `c`, which must be lowercase.
    fn has(self, c: char) -> bool {
        match self {
            Language::English => c.is_ascii_lowercase(),
            Language::German => c.is_ascii_lowercase() || matches!(c, 'ä' | 'ö' | 'ü' | 'ß'),
            Language::Russian => ('а'..='я').contains(&c) || c == 'ё',
            Language::Ukrainian => {
                (('а'..='я').contains(&c) && !matches!(c, 'ъ' | 'ы' | 'э'))
                    || matches!(c, 'ґ' | 'є' | 'і' | 'ї')
            }
        }
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum Script {
    Latin,
    Cyrillic,
}

impl Script {
    fn of(language: Language) -> Script {
        match language {
            Language::English | Language::German => Script::Latin,
            Language::Russian | Language::Ukrainian => Script::Cyrillic,
        }
    }
}

/// The languages `value` could be written in; empty when it holds no letter
/// of a known alphabet.
pub fn detect(value: &str) -> Vec<Language> {
    // Per language: still possible, and seen at least one letter of its script.
    let mut possible = [true; Language::ALL.len()];
    let mut seen = [false; 2];

    for c in value.chars().flat_map(char::to_lowercase) {
        let holders: Vec<Language> = Language::ALL
            .into_iter()
            .filter(|language| language.has(c))
            .collect();
        let Some(&first) = holders.first() else {
            continue;
        };
        let script = Script::of(first);
        seen[script as usize] = true;
        for (i, language) in Language::ALL.into_iter().enumerate() {
            if Script::of(language) == script && !holders.contains(&language) {
                possible[i] = false;
            }
        }
    }

    Language::ALL
        .into_iter()
        .enumerate()
        .filter(|&(i, language)| possible[i] && seen[Script::of(language) as usize])
        .map(|(_, language)| language)
        .collect()
}

/// The line shown under an answer field, or `None` when there is nothing to
/// say.
pub fn hint(value: &str) -> Option<String> {
    let languages = detect(value);
    if languages.is_empty() {
        return None;
    }
    let names: Vec<&str> = languages.into_iter().map(Language::name).collect();
    Some(format!("Language: {}", names.join(", ")))
}

#[cfg(test)]
mod tests {
    use super::Language::*;
    use super::*;

    #[test]
    fn latin_letters_fit_english_and_german() {
        assert_eq!(detect("abc"), vec![English, German]);
    }

    #[test]
    fn german_letters_are_german_only() {
        assert_eq!(detect("straße"), vec![German]);
        assert_eq!(detect("ä"), vec![German]);
    }

    #[test]
    fn shared_cyrillic_fits_russian_and_ukrainian() {
        assert_eq!(detect("привет"), vec![Russian, Ukrainian]);
    }

    #[test]
    fn russian_only_letters() {
        assert_eq!(detect("ёж"), vec![Russian]);
        assert_eq!(detect("мы"), vec![Russian]);
    }

    #[test]
    fn ukrainian_only_letters() {
        assert_eq!(detect("їжак"), vec![Ukrainian]);
        assert_eq!(detect("ґанок"), vec![Ukrainian]);
    }

    #[test]
    fn contradictory_cyrillic_fits_nothing() {
        assert_eq!(detect("ы і"), vec![]);
        assert_eq!(hint("ыі"), None);
    }

    #[test]
    fn mixed_scripts_list_each_scripts_languages() {
        assert_eq!(
            detect("abc привет"),
            vec![English, German, Russian, Ukrainian]
        );
        assert_eq!(detect("ä ё"), vec![German, Russian]);
    }

    #[test]
    fn non_letters_say_nothing() {
        assert_eq!(detect("123 -_!"), vec![]);
        assert_eq!(detect("é"), vec![]);
        assert_eq!(hint(""), None);
        assert_eq!(detect("a1"), vec![English, German]);
    }

    #[test]
    fn uppercase_counts() {
        assert_eq!(detect("ÄБ"), vec![German, Russian, Ukrainian]);
        assert_eq!(detect("Ї"), vec![Ukrainian]);
    }

    #[test]
    fn hint_lists_names() {
        assert_eq!(hint("abc").as_deref(), Some("Language: English, German"));
        assert_eq!(hint("ы").as_deref(), Some("Language: Russian"));
    }
}
