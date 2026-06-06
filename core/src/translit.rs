/// Transliterates a lowercase Russian/Ukrainian string to lowercase Latin (QWERTY-compatible)
/// using BGN/PCGN.
pub fn transliterate(input: &str) -> String {
    let mut result = String::with_capacity(input.len() * 2);
    let chars: Vec<char> = input.chars().collect();
    let len = chars.len();
    let mut i = 0;

    while i < len {
        let ch = chars[i];
        let mapped = match ch {
            // Russian
            'а' => "a",
            'б' => "b",
            'в' => "v",
            'г' => "g",
            'д' => "d",
            'е' => "e",
            'ё' => "yo",
            'ж' => "zh",
            'з' => "z",
            'и' => "i",
            'й' => "y",
            'к' => "k",
            'л' => "l",
            'м' => "m",
            'н' => "n",
            'о' => "o",
            'п' => "p",
            'р' => "r",
            'с' => "s",
            'т' => "t",
            'у' => "u",
            'ф' => "f",
            'х' => "kh",
            'ц' => "ts",
            'ч' => "ch",
            'ш' => "sh",
            'щ' => "shch",
            'ъ' | 'ь' => "",
            'ы' => "y",
            'э' => "e",
            'ю' => "yu",
            'я' => "ya",
            // Ukrainian
            'ґ' => "g",
            'є' => "ye",
            'і' => "i",
            'ї' => "yi",
            _ => {
                result.push(ch);
                i += 1;
                continue;
            }
        };

        result.push_str(mapped);
        i += 1;
    }

    result
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_simple_words() {
        assert_eq!(transliterate("москва"), "moskva");
        assert_eq!(transliterate("россия"), "rossiya");
    }

    #[test]
    fn test_ye() {
        assert_eq!(transliterate("екатеринбург"), "ekaterinburg");
        assert_eq!(transliterate("елена"), "elena");
    }

    #[test]
    fn test_yo() {
        assert_eq!(transliterate("ёж"), "yozh");
        assert_eq!(transliterate("пётр"), "pyotr");
    }

    #[test]
    fn test_zh_ch_sh_shch() {
        assert_eq!(transliterate("жук"), "zhuk");
        assert_eq!(transliterate("чай"), "chay");
        assert_eq!(transliterate("шум"), "shum");
        assert_eq!(transliterate("щука"), "shchuka");
    }

    #[test]
    fn test_kh_ts_yu_ya() {
        assert_eq!(transliterate("хлеб"), "khleb");
        assert_eq!(transliterate("царь"), "tsar");
        assert_eq!(transliterate("юг"), "yug");
        assert_eq!(transliterate("яма"), "yama");
    }

    #[test]
    fn test_hard_and_soft_signs_removed() {
        assert_eq!(transliterate("объект"), "obekt");
        assert_eq!(transliterate("мальчик"), "malchik");
    }

    #[test]
    fn test_ts() {
        assert_eq!(transliterate("братство"), "bratstvo");
        assert_eq!(transliterate("царь"), "tsar");
    }

    #[test]
    fn test_passthrough_non_cyrillic() {
        assert_eq!(transliterate("hello мир!"), "hello mir!");
        assert_eq!(transliterate("123"), "123");
    }

    #[test]
    fn test_empty() {
        assert_eq!(transliterate(""), "");
    }

    #[test]
    fn test_full_russian_alphabet() {
        assert_eq!(
            transliterate("абвгдежзийклмнопрстуфхцчшщъыьэюя"),
            "abvgdezhziyklmnoprstufkhtschshshchyeyuya"
        );
    }

    #[test]
    fn test_ukrainian_unique_letters() {
        assert_eq!(transliterate("ґ"), "g");
        assert_eq!(transliterate("є"), "ye");
        assert_eq!(transliterate("і"), "i");
        assert_eq!(transliterate("ї"), "yi");
    }

    #[test]
    fn test_ukrainian_words() {
        assert_eq!(transliterate("київ"), "kiyiv");
        assert_eq!(transliterate("україна"), "ukrayina");
        assert_eq!(transliterate("їжак"), "yizhak");
        assert_eq!(transliterate("ґанок"), "ganok");
    }
}
