mod cert_retriever;
mod config;

use std::path::{PathBuf};
use std::process::ExitCode;
use clap::{Parser, Subcommand};
use crate::cert_retriever::{CertError, CertRetriever};


#[derive(Parser)]
#[command(version, about, long_about = None, version = "0.1.0")]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// does testing things
    InstallService {},
    Monitor {
        /// config file
        #[arg(short = 'c', long, value_name = "FILE")]
        config_file: PathBuf,

        /// monitor interval
        #[arg(short = 'i', long, value_name = "interval")]
        interval_hours: Option<u32>
    },
    Check {
        #[arg(short = 't', long, value_name = "target_host")]
        target_host: String,

        #[arg(short = 'p', long, value_name = "target_port", default_value = "443")]
        target_port: u32
    }

}


fn main() -> ExitCode {
    let cli = Cli::parse();
    match cli.command {
        Commands::InstallService { .. } => {
            ExitCode::SUCCESS
        }
        Commands::Monitor { .. } => {
            ExitCode::SUCCESS
        }
        Commands::Check { target_host, target_port, .. } => {
            let retriever = CertRetriever::new();
            match retriever.get_target_cert_from_endpoint(&target_host, target_port) {
                Ok(cert) => {
                    println!("{}", cert.get_remaining_days());
                    if cert.get_remaining_days() < 10 {
                        println!("Target Cert for {} has less than 10 days. ({})", cert.get_common_name(), cert.get_remaining_days());
                    }
                    ExitCode::SUCCESS
                }
                Err(e) => {
                    match e {
                        CertError::InvalidFormat(e) => {
                            println!("InvalidCertFormat: {}", e);
                        }
                        CertError::TargetNotReachable(e) => {
                            println!("TargetNotReachable: {}", e);
                        }
                        CertError::TargetHasNoCertMatch(e) => {
                            println!("TargetHasNoCertMatch: {}", e);
                        }
                    }
                    ExitCode::FAILURE
                }
            }
        }
    }
} 
       
    
