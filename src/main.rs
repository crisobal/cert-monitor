mod cert_retriever;
mod config;
use crate::cert_retriever::{CertError, CertRetriever};
use crate::config::{load_config_file, Site, SiteConfig};
use clap::{Parser, Subcommand};
use std::path::PathBuf;
use std::process::ExitCode;
use console::{style, Style};

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
        interval_hours: Option<u32>,

        /// Daemon mode without verbose console output but log entries instead
        #[arg(short = 'd', long, value_name = "daemon", default_value = "false")]
        daemon: bool
    },
    Check {
        /// Full qualified target host to query
        #[arg(short = 't', long, value_name = "target_host")]
        target_host: String,

        /// Port of the service at target host
        #[arg(short = 'p', long, value_name = "target_port", default_value = "443")]
        target_port: u32,

        /// Output the certificate instead of the table
        #[arg(short = 'c', long, value_name = "cert", default_value = "false")]
        cert_output: bool


    }
}


fn main() -> ExitCode {
    let cli = Cli::parse();
    match cli.command {
        Commands::InstallService { .. } => {
            ExitCode::SUCCESS
        }
        Commands::Monitor { config_file,interval_hours, daemon } => {
            if let Some(site_config) = load_config_file(config_file) {
                monitor_cert_list(site_config, daemon, !daemon, true, false);
            }
            ExitCode::SUCCESS
        }
        Commands::Check { target_host, target_port, cert_output } => {
            let config = SiteConfig::simple(&target_host, target_port, 10);

            monitor_cert_list(config, false, true, true, cert_output);

            ExitCode::SUCCESS
        }
    }
}

fn monitor_cert_list(site_config: SiteConfig, do_log_out : bool, do_console_out: bool, print_table_header : bool, cert_output: bool) {


    if do_console_out && print_table_header &&  !cert_output {
        println!(" ! | {: <35} | {: <5} | {: <7} | {: <40} | {: <50}",
            style("Target").white().bold(),
            style("Port").white().bold(),
            style("RemDays").white().bold(),
            style("Serial").white().bold(),
            style("CN").white().bold());
        println!("---+ {:-<35}-+-{:-<5}-+-{:-<7}-+-{:-<40}-+-{:-<50}","","","","","");
    }

    site_config.site_iter().for_each(|site| {
        let y = Style::new().yellow().bold();
        let retriever = CertRetriever::new();
        match retriever.get_target_cert_from_endpoint(&site.target_fqn, site.port) {
            Ok(cert) => {
                let expires = cert.get_remaining_days() < site.min_valid_days;

                if do_console_out && !cert_output {
                    if expires {
                        println!(" {:<1} | {: <35} | {: >5} | {: >7} | {: <40} | {: <50}",
                                 y.apply_to("!"),
                                 y.apply_to(site.target_fqn.clone()),
                                 y.apply_to(site.port),
                                 y.apply_to(cert.get_remaining_days()),
                                 y.apply_to(cert.get_serial_number()),
                                 y.apply_to(cert.get_common_name()));
                    } else {
                        println!(" {:<1} | {: <35} | {: >5} | {: >7} | {: <40} | {: <50}", "",
                                 site.target_fqn,
                                 site.port as i64,
                                 cert.get_remaining_days(),
                                 cert.get_serial_number(),
                                 cert.get_common_name());
                    }
                } else if cert_output {
                    println!("{}", cert.get_pem());
                }
            }
            Err(e) => {
                if do_console_out {
                    match e {
                        CertError::InvalidFormat(e) => {
                            print_err("InvalidCertFormat", &e, site);
                        }
                        CertError::TargetNotReachable(e) => {
                            print_err("TargetNotReachable", &e, site);
                        }
                        CertError::TargetHasNoCertMatch(e) => {
                            print_err("TargetHasNoCertMatch", &e, site);
                        }
                    }
                }
            }
        }
    })
}




fn print_err(kind: &str, e: &str, site : &Site) {
    let r = Style::new().red().bold();
    println!(" {:<1} | {: <35} | {: >5} | {: >7} | {: <40} | {: <50}",
             r.apply_to("!"),
             r.apply_to(site.target_fqn.clone()),
             r.apply_to(site.port),
             r.apply_to("???"),
             r.apply_to("<No Serial>"),
             r.apply_to(format!("<{} : {}>", kind , e)));
}

