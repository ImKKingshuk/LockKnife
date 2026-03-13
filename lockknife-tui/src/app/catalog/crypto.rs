use super::super::ModuleEntry;
use super::fields::{
    action, bool_field, case_dir_field, choice_field, module, number_field, text_field,
};

pub(super) fn build_module() -> ModuleEntry {
    module(
        "crypto",
        "Crypto Wallet",
        vec![
            action(
                "crypto.wallets",
                "Wallet extraction",
                vec![
                    text_field("path", "SQLite path", ""),
                    number_field("limit", "Limit", "5000"),
                    bool_field("lookup", "Enrich addresses", true),
                    text_field("output", "Output path (optional)", ""),
                    case_dir_field(),
                ],
                false,
                false,
            ),
            action(
                "crypto.transactions",
                "Wallet transactions",
                vec![
                    text_field("address", "Address", ""),
                    choice_field("kind", "Kind (btc/eth)", "btc", &["btc", "eth"]),
                    number_field("limit", "Limit", "50"),
                ],
                false,
                false,
            ),
        ],
    )
}
