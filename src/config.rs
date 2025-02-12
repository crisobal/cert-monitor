
use serde::{Deserialize, Serialize};


fn default_target_port() -> u32 {
    443
}

fn default_log_target () -> String {
    "cert-monitor".to_owned()
}

#[derive(Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SiteConfig {
    phones: Vec<Site>,

    #[serde(default = "default_log_target")]
    log_target: String
}
#[derive(Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct Site {
    target_fqn: String,
    service : String,

    #[serde(default = "default_target_port")]
    port : u32,
    min_valid_days : u32
}
