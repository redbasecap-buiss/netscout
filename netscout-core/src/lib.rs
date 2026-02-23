pub mod cert;
pub mod dns;
pub mod http;
pub mod netif;
pub mod output;
pub mod ping;
pub mod port;
pub mod scan;
pub mod speed;
pub mod trace;
pub mod whois;

/// Output format for all commands.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum OutputFormat {
    Human,
    Json,
    Table,
    Csv,
}

impl OutputFormat {
    /// Return all available output formats.
    pub fn all() -> Vec<OutputFormat> {
        vec![
            OutputFormat::Human,
            OutputFormat::Json,
            OutputFormat::Table,
            OutputFormat::Csv,
        ]
    }

    /// Return the format as a string.
    pub fn as_str(&self) -> &'static str {
        match self {
            OutputFormat::Human => "human",
            OutputFormat::Json => "json",
            OutputFormat::Table => "table",
            OutputFormat::Csv => "csv",
        }
    }

    /// Parse a format from a string.
    pub fn from_str(s: &str) -> Option<OutputFormat> {
        match s.to_lowercase().as_str() {
            "human" | "h" => Some(OutputFormat::Human),
            "json" | "j" => Some(OutputFormat::Json),
            "table" | "t" => Some(OutputFormat::Table),
            "csv" | "c" => Some(OutputFormat::Csv),
            _ => None,
        }
    }

    /// Check if the format produces structured data.
    pub fn is_structured(&self) -> bool {
        matches!(self, OutputFormat::Json | OutputFormat::Csv)
    }

    /// Check if the format produces human-readable output.
    pub fn is_human_readable(&self) -> bool {
        matches!(self, OutputFormat::Human | OutputFormat::Table)
    }
}

impl std::fmt::Display for OutputFormat {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.as_str())
    }
}

impl Default for OutputFormat {
    fn default() -> Self {
        OutputFormat::Human
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_output_format_variants() {
        let _ = OutputFormat::Human;
        let _ = OutputFormat::Json;
        let _ = OutputFormat::Table;
        let _ = OutputFormat::Csv;
    }

    #[test]
    fn test_output_format_equality() {
        assert_eq!(OutputFormat::Human, OutputFormat::Human);
        assert_eq!(OutputFormat::Json, OutputFormat::Json);
        assert_eq!(OutputFormat::Table, OutputFormat::Table);
        assert_eq!(OutputFormat::Csv, OutputFormat::Csv);
    }

    #[test]
    fn test_output_format_inequality() {
        assert_ne!(OutputFormat::Human, OutputFormat::Json);
        assert_ne!(OutputFormat::Json, OutputFormat::Table);
        assert_ne!(OutputFormat::Table, OutputFormat::Csv);
        assert_ne!(OutputFormat::Csv, OutputFormat::Human);
    }

    #[test]
    fn test_output_format_clone() {
        let fmt = OutputFormat::Json;
        let cloned = fmt.clone();
        assert_eq!(fmt, cloned);
    }

    #[test]
    fn test_output_format_copy() {
        let fmt = OutputFormat::Json;
        let copied = fmt;
        assert_eq!(fmt, copied);
        // Can still use original after copy
        assert_eq!(fmt, OutputFormat::Json);
    }

    #[test]
    fn test_output_format_debug() {
        assert_eq!(format!("{:?}", OutputFormat::Human), "Human");
        assert_eq!(format!("{:?}", OutputFormat::Json), "Json");
        assert_eq!(format!("{:?}", OutputFormat::Table), "Table");
        assert_eq!(format!("{:?}", OutputFormat::Csv), "Csv");
    }

    #[test]
    fn test_output_format_display() {
        assert_eq!(format!("{}", OutputFormat::Human), "human");
        assert_eq!(format!("{}", OutputFormat::Json), "json");
        assert_eq!(format!("{}", OutputFormat::Table), "table");
        assert_eq!(format!("{}", OutputFormat::Csv), "csv");
    }

    #[test]
    fn test_output_format_as_str() {
        assert_eq!(OutputFormat::Human.as_str(), "human");
        assert_eq!(OutputFormat::Json.as_str(), "json");
        assert_eq!(OutputFormat::Table.as_str(), "table");
        assert_eq!(OutputFormat::Csv.as_str(), "csv");
    }

    #[test]
    fn test_output_format_from_str() {
        assert_eq!(OutputFormat::from_str("human"), Some(OutputFormat::Human));
        assert_eq!(OutputFormat::from_str("json"), Some(OutputFormat::Json));
        assert_eq!(OutputFormat::from_str("table"), Some(OutputFormat::Table));
        assert_eq!(OutputFormat::from_str("csv"), Some(OutputFormat::Csv));
    }

    #[test]
    fn test_output_format_from_str_case_insensitive() {
        assert_eq!(OutputFormat::from_str("HUMAN"), Some(OutputFormat::Human));
        assert_eq!(OutputFormat::from_str("JSON"), Some(OutputFormat::Json));
        assert_eq!(OutputFormat::from_str("Table"), Some(OutputFormat::Table));
        assert_eq!(OutputFormat::from_str("CSV"), Some(OutputFormat::Csv));
    }

    #[test]
    fn test_output_format_from_str_short_forms() {
        assert_eq!(OutputFormat::from_str("h"), Some(OutputFormat::Human));
        assert_eq!(OutputFormat::from_str("j"), Some(OutputFormat::Json));
        assert_eq!(OutputFormat::from_str("t"), Some(OutputFormat::Table));
        assert_eq!(OutputFormat::from_str("c"), Some(OutputFormat::Csv));
    }

    #[test]
    fn test_output_format_from_str_invalid() {
        assert_eq!(OutputFormat::from_str("invalid"), None);
        assert_eq!(OutputFormat::from_str("xml"), None);
        assert_eq!(OutputFormat::from_str(""), None);
        assert_eq!(OutputFormat::from_str("yaml"), None);
    }

    #[test]
    fn test_output_format_all() {
        let all = OutputFormat::all();
        assert_eq!(all.len(), 4);
        assert!(all.contains(&OutputFormat::Human));
        assert!(all.contains(&OutputFormat::Json));
        assert!(all.contains(&OutputFormat::Table));
        assert!(all.contains(&OutputFormat::Csv));
    }

    #[test]
    fn test_output_format_all_unique() {
        let all = OutputFormat::all();
        let mut unique = all.clone();
        unique.sort_by_key(|f| f.as_str());
        unique.dedup();
        assert_eq!(all.len(), unique.len());
    }

    #[test]
    fn test_output_format_is_structured() {
        assert!(!OutputFormat::Human.is_structured());
        assert!(OutputFormat::Json.is_structured());
        assert!(!OutputFormat::Table.is_structured());
        assert!(OutputFormat::Csv.is_structured());
    }

    #[test]
    fn test_output_format_is_human_readable() {
        assert!(OutputFormat::Human.is_human_readable());
        assert!(!OutputFormat::Json.is_human_readable());
        assert!(OutputFormat::Table.is_human_readable());
        assert!(!OutputFormat::Csv.is_human_readable());
    }

    #[test]
    fn test_output_format_default() {
        assert_eq!(OutputFormat::default(), OutputFormat::Human);
    }

    #[test]
    fn test_output_format_pattern_matching() {
        let format = OutputFormat::Json;
        match format {
            OutputFormat::Human => panic!("Should not match Human"),
            OutputFormat::Json => {}, // Expected
            OutputFormat::Table => panic!("Should not match Table"),
            OutputFormat::Csv => panic!("Should not match Csv"),
        }
    }

    #[test]
    fn test_output_format_round_trip() {
        let formats = OutputFormat::all();
        for format in formats {
            let str_repr = format.as_str();
            let parsed = OutputFormat::from_str(str_repr);
            assert_eq!(parsed, Some(format));
        }
    }

    #[test]
    fn test_output_format_hash() {
        use std::collections::HashSet;
        let mut set = HashSet::new();
        set.insert(OutputFormat::Human);
        set.insert(OutputFormat::Json);
        set.insert(OutputFormat::Table);
        set.insert(OutputFormat::Csv);
        assert_eq!(set.len(), 4);
        
        // Test that inserting the same format doesn't increase size
        set.insert(OutputFormat::Human);
        assert_eq!(set.len(), 4);
    }

    #[test]
    fn test_output_format_comprehensive_conversion() {
        let test_cases = vec![
            ("human", Some(OutputFormat::Human)),
            ("h", Some(OutputFormat::Human)),
            ("HUMAN", Some(OutputFormat::Human)),
            ("H", Some(OutputFormat::Human)),
            ("json", Some(OutputFormat::Json)),
            ("j", Some(OutputFormat::Json)),
            ("JSON", Some(OutputFormat::Json)),
            ("J", Some(OutputFormat::Json)),
            ("table", Some(OutputFormat::Table)),
            ("t", Some(OutputFormat::Table)),
            ("TABLE", Some(OutputFormat::Table)),
            ("T", Some(OutputFormat::Table)),
            ("csv", Some(OutputFormat::Csv)),
            ("c", Some(OutputFormat::Csv)),
            ("CSV", Some(OutputFormat::Csv)),
            ("C", Some(OutputFormat::Csv)),
            ("invalid", None),
            ("xml", None),
            ("yaml", None),
            ("", None),
            (" ", None),
            ("unknown", None),
        ];

        for (input, expected) in test_cases {
            assert_eq!(OutputFormat::from_str(input), expected, "Failed for input: '{}'", input);
        }
    }

    #[test]
    fn test_output_format_structured_vs_readable() {
        let all = OutputFormat::all();
        let structured_count = all.iter().filter(|f| f.is_structured()).count();
        let human_readable_count = all.iter().filter(|f| f.is_human_readable()).count();
        
        assert_eq!(structured_count, 2); // Json and Csv
        assert_eq!(human_readable_count, 2); // Human and Table
        
        // Each format should be either structured or human-readable (but not necessarily both)
        for format in all {
            // This is not a requirement, just documenting current behavior
            let _ = format.is_structured() || format.is_human_readable();
        }
    }

    #[test]
    fn test_output_format_string_consistency() {
        // Test that Display and as_str return the same value
        let formats = OutputFormat::all();
        for format in formats {
            assert_eq!(format.to_string(), format.as_str());
        }
    }
}