use serde::{Deserialize, Serialize};
use std::fs::File;
use std::io::BufReader;
use std::path::PathBuf;


fn default_target_port() -> u32 {
    443
}

fn default_log_target () -> String {
    "cert-monitor".to_owned()
}

fn default_min_valid_days() -> i64 { 15 }

pub fn load_config_file( file : PathBuf) -> Option<SiteConfig>{
    if file.exists() {
        if let Ok(file) = File::open(file) {
            let reader = BufReader::new(file);
            let config: Result<SiteConfig, serde_json::Error>   = serde_json::from_reader(reader);
            if let Ok(config) = config {
                return Some(config);
            }
        }
    }
    None
}

#[derive(Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SiteConfig {
    sites: Vec<Site>,

    #[serde(default = "default_log_target")]
    pub log_target: String
}



impl SiteConfig {
    pub fn site_iter(&self) -> impl Iterator<Item=&Site> {
        self.sites.iter()
    }

    pub fn simple(target_fqn: &String, target_port: u32, min_valid_days : i64) -> SiteConfig {
        SiteConfig {
            sites: vec![ Site {
                target_fqn: target_fqn.to_owned(),
                service: "query".to_string(),
                port: target_port,
                min_valid_days,
            }
            ],
            log_target: "".to_string(),
        }
        
    }
}

#[derive(Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
#[derive(Debug)]
pub struct Site {
    pub target_fqn: String,
    pub service : String,

    #[serde(default = "default_target_port")]
    pub port : u32,
    
    #[serde(default = "default_min_valid_days")]
    pub min_valid_days : i64
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn serialize_test() {
        let s1 = Site {
            target_fqn: "www.tschirky.ch".to_string(),
            service: "flup".to_string(),
            port: 4444,
            min_valid_days: 15,
        };
        let s2 = Site {
            target_fqn: "gitea.tschirky.ch".to_string(),
            service: "other".to_string(),
            port: 443,
            min_valid_days: 15,
        };
        let cfg = SiteConfig {
            sites: vec![s1,s2],
            log_target: "monitor".to_string(),
        };
        let serialized = serde_json::to_string(&cfg).unwrap();
        println!("{:?}", serialized);
    }
}
