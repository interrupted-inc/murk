//! Computed codenames for vault files.
//!
//! Deterministically derives a memorable name (e.g. "breezy-mocha-goblin")
//! from file contents. Same bytes → same name. Different bytes → different name.
//! Format: adjective-color-animal.

use sha2::{Digest, Sha256};

const ADJECTIVES: &[&str] = &[
    "ancient", "bold", "breezy", "bright", "calm", "clever", "cosmic", "crisp", "daring", "dusty",
    "eager", "faded", "fierce", "gentle", "golden", "gusty", "hasty", "hidden", "hollow", "icy",
    "jolly", "keen", "lazy", "lively", "lucky", "mighty", "misty", "narrow", "nimble", "noble",
    "noisy", "odd", "pale", "plain", "proud", "quick", "quiet", "rapid", "rocky", "rosy", "rough",
    "rusty", "sandy", "sharp", "shy", "silent", "sleek", "snowy", "solar", "spicy", "steep",
    "stormy", "stout", "sunny", "swift", "tame", "thorny", "tidy", "tough", "twisted", "vast",
    "vivid", "warm", "wild", "windy", "wispy", "witty", "young", "zesty",
];

const COLORS: &[&str] = &[
    "amber", "aqua", "azure", "beige", "black", "blue", "brass", "bronze", "brown", "cedar",
    "charcoal", "cherry", "cobalt", "copper", "coral", "cream", "crimson", "cyan", "ebony",
    "ember", "garnet", "gold", "granite", "green", "grey", "hazel", "indigo", "ivory", "jade",
    "khaki", "lemon", "lilac", "lime", "maple", "maroon", "mauve", "mint", "mocha", "navy",
    "ochre", "olive", "onyx", "orange", "orchid", "peach", "pearl", "pine", "plum", "quartz",
    "rose", "ruby", "rust", "sage", "sand", "scarlet", "silver", "slate", "smoke", "steel",
    "stone", "tan", "teal", "topaz", "umber", "violet", "walnut", "wheat", "white", "wine",
];

const ANIMALS: &[&str] = &[
    "badger", "bat", "bear", "beetle", "bison", "bobcat", "cobra", "condor", "crane", "crow",
    "deer", "dingo", "eagle", "elk", "falcon", "ferret", "finch", "fox", "gecko", "goat", "goblin",
    "grouse", "hare", "hawk", "heron", "horse", "ibex", "iguana", "jackal", "jay", "koala",
    "lemur", "lion", "lizard", "llama", "lynx", "marten", "moose", "moth", "newt", "otter", "owl",
    "panda", "parrot", "pelican", "pike", "puma", "quail", "rabbit", "raccoon", "raven", "robin",
    "salmon", "shark", "snail", "snake", "sparrow", "squid", "stork", "swan", "tiger", "toad",
    "toucan", "turtle", "viper", "walrus", "wasp", "whale", "wolf", "wren",
];

/// Derive a three-word codename from raw bytes.
///
/// Hashes the input with SHA-256 and uses different portions of the digest
/// to index into each word list. Deterministic: same input → same codename.
pub fn from_bytes(data: &[u8]) -> String {
    let hash = Sha256::digest(data);

    // Use separate parts of the hash for each word to avoid correlation.
    let adj_idx = u16::from_le_bytes([hash[0], hash[1]]) as usize % ADJECTIVES.len();
    let color_idx = u16::from_le_bytes([hash[2], hash[3]]) as usize % COLORS.len();
    let animal_idx = u16::from_le_bytes([hash[4], hash[5]]) as usize % ANIMALS.len();

    format!(
        "{}-{}-{}",
        ADJECTIVES[adj_idx], COLORS[color_idx], ANIMALS[animal_idx]
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn deterministic() {
        assert_eq!(from_bytes(b"hello"), from_bytes(b"hello"));
    }

    #[test]
    fn different_input_different_name() {
        assert_ne!(from_bytes(b"hello"), from_bytes(b"world"));
    }

    #[test]
    fn three_words() {
        let name = from_bytes(b"test");
        assert_eq!(name.split('-').count(), 3);
    }

    #[test]
    fn not_empty() {
        let name = from_bytes(b"");
        assert!(!name.is_empty(), "codename is empty");
        assert!(name.len() > 5);
    }
}
