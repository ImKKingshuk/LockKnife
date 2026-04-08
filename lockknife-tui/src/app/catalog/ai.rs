use super::super::ModuleEntry;
use super::fields::{action, case_dir_field, module, number_field, text_field};

pub(super) fn build_module() -> ModuleEntry {
    module(
        "ai",
        "AI",
        vec![
            action(
                "ai.anomaly_score",
                "Anomaly score",
                vec![
                    text_field("input", "Input JSON path", ""),
                    text_field("features", "Feature keys (comma, optional)", ""),
                    text_field("output", "Output path (optional)", ""),
                    case_dir_field(),
                ],
                false,
                false,
            ),
            action(
                "ai.train_malware",
                "Train malware classifier",
                vec![
                    text_field("input", "Training data JSON path", ""),
                    text_field("features", "Feature keys (comma)", ""),
                    text_field("label", "Label key", "label"),
                    text_field("model", "Model output path (optional)", ""),
                    case_dir_field(),
                ],
                false,
                false,
            ),
            action(
                "ai.classify_malware",
                "Classify malware",
                vec![
                    text_field("input", "Input JSON path", ""),
                    text_field("model", "Model path", ""),
                    text_field("output", "Output path (optional)", ""),
                    case_dir_field(),
                ],
                false,
                false,
            ),
            action(
                "ai.predict_passwords",
                "Password predictor",
                vec![
                    text_field("wordlist", "Wordlist path", ""),
                    text_field(
                        "personal_data",
                        "Personal/device data JSON path (optional)",
                        "",
                    ),
                    number_field("count", "Count", "50"),
                    number_field("min_len", "Min length", "6"),
                    number_field("max_len", "Max length", "12"),
                    number_field("seed", "Seed", ""),
                    number_field("markov_order", "Markov order", "2"),
                    text_field("output", "Output path (optional)", ""),
                    case_dir_field(),
                ],
                false,
                false,
            ),
        ],
    )
}
