//! The cloud instance this host runs on.

use super::inventory_text;

pub(super) fn cloud_metadata() -> (String, String, String) {
    (
        std::env::var("MERLIN_CLOUD_PROVIDER")
            .ok()
            .map(|value| inventory_text(&value, 128))
            .unwrap_or_default(),
        std::env::var("MERLIN_CLOUD_INSTANCE_ID")
            .ok()
            .map(|value| inventory_text(&value, 128))
            .unwrap_or_default(),
        std::env::var("MERLIN_CLOUD_REGION")
            .ok()
            .map(|value| inventory_text(&value, 128))
            .unwrap_or_default(),
    )
}
