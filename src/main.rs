mod cert_retriever;

use std::io::Write;

use crate::cert_retriever::{CertError, CertRetriever};

fn main() {
    let retriever = CertRetriever::new();
    match retriever.get_target_cert_from_endpoint("gatekeeper.tschirky.ch", 443) {
        Ok(cert) => {
            if cert.get_remaining_days() < 10 {
                println!("Target Cert for {} has less than 10 days. ({})", cert.get_common_name(), cert.get_remaining_days());
            }
        }
        Err(e) => {
            match e {
                CertError::InvalidFormat(e) => {}
                CertError::TargetNotReachable(e) => {}
                CertError::TargetHasNoCertMatch(e) => {}
            }
        }
    }
}