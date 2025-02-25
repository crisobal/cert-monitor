use rustls::pki_types::ServerName;
use rustls::{ClientConfig, RootCertStore};
use std::io::{BufRead, Write};
use std::net::TcpStream;
use std::sync::Arc;
use time::OffsetDateTime;
use x509_parser::error::PEMError;
use x509_parser::extensions::GeneralName;
use x509_parser::prelude::{FromDer, X509Certificate};


pub struct CertRetriever {
    config : Arc<ClientConfig>
}



impl CertRetriever {
    pub fn new() -> CertRetriever {
        let root_store = RootCertStore {
            roots: webpki_roots::TLS_SERVER_ROOTS.into(),
        };
        let mut config = ClientConfig::builder()
            .with_root_certificates(root_store)
            .with_no_client_auth();
        config.enable_sni = true;
        config.enable_early_data = true;        
        config.key_log = Arc::new(rustls::KeyLogFile::new());
        
        //TODO: future approach to also include expired certificates
        //config.dangerous().set_certificate_verifier()
        CertRetriever {
            config : Arc::new(config)
        }
    }

    pub fn get_target_cert_from_endpoint(&self, target_name: &str, target_port: u32) -> Result<SimpleCertificate, CertError> {
        let full_target = format!("{}:{}", target_name, target_port);
        let server_name : ServerName = String::from(target_name).try_into().unwrap();


        match TcpStream::connect(&full_target) {
            Ok(sock) => {
                let mut sock = sock;
                let mut conn = rustls::ClientConnection::new(self.config.clone(), server_name).unwrap();
                
                let mut tls = rustls::Stream::new(&mut conn, &mut sock);
                if let Err(e) = tls.write(b"\n") {
                    //TODO change to proper debug logging
                    //println!("Error during connect to {}: {}", full_target, e.kind().to_string());
                }

                match SimpleCertificate::find_matching_certificate(target_name, tls.conn.peer_certificates()){
                    None => {
                        Err(CertError::TargetHasNoCertMatch(target_name.to_owned()))
                    }
                    Some(peer_cert) => {
                        Ok(peer_cert.clone())
                    }
                }
            }
            Err(_) => {
                Err(CertError::TargetNotReachable(format!("Target {} is unreachable", &full_target).to_string()))
            }
        }
    }
}

#[derive(Debug)]
pub enum CertError {
    InvalidFormat(String),
    TargetNotReachable(String),
    TargetHasNoCertMatch(String)
}


pub fn get_serial_number(cert : &X509Certificate) -> String {
    cert.raw_serial_as_string().replace(':',"")
}

pub fn get_common_name(cert : &X509Certificate) -> String {
    let mut name = String::new();
    cert.subject.iter_common_name().for_each(| cn | {
        if let Ok(n) = cn.as_str() {
            name.push_str(n);
        }
    });
    name
}

pub fn get_san_dns_names(cert : &X509Certificate) -> Vec<String> {
    let mut dns_names = Vec::new();
    if let Ok( Some(san)) = cert.subject_alternative_name() {
        san.value.general_names.iter().for_each(| gn | {
            if let GeneralName::DNSName(n) = gn {
                dns_names.push(n.to_string());
            }
        })
    }
    dns_names
}


#[derive(Clone)]
pub struct SimpleCertificate{
    common_name : String,
    serial_number : String,
    expiration_date : OffsetDateTime,
    san_list : Vec<String>,
    is_ca : bool,
    pem : String
}


impl SimpleCertificate {

    fn build(cert : &X509Certificate, pem : String) -> SimpleCertificate {

        //let cert = Arc::new(c.to_owned());
        SimpleCertificate {
            common_name : get_common_name(cert),
            serial_number : get_serial_number(cert),
            expiration_date : cert.validity().not_after.to_datetime(),
            san_list : get_san_dns_names(cert),
            is_ca : cert.is_ca(),
            pem
        }
    }



    fn to_pem(der : &[u8]) -> String {

        let mut pem = "-----BEGIN CERTIFICATE-----\n".to_string();

        let mut b64 = data_encoding::BASE64.encode(&der);
        while let Some((line, remaining)) = b64.split_at_checked(65) {
            pem.push_str(line);
            if !remaining.is_empty() {
                b64 = remaining.to_string();
                pem.push('\n');
            } else {
                b64 = "".to_owned();
            }
        }
        if !b64.is_empty() {
            pem.push_str(&b64);
        }

        pem.push_str("\n-----END CERTIFICATE-----\n");
        pem
    }


    pub fn from_certificate_der(der_cert : &rustls::pki_types::CertificateDer) -> Result<SimpleCertificate, CertError>{
        let pem = Self::to_pem(der_cert.as_ref());
        match X509Certificate::from_der(der_cert.as_ref()) {
            Ok((_,cert)) => {
                Ok(SimpleCertificate::build(&cert, pem))
            }
            Err(e) => {
                Err(CertError::InvalidFormat(e.to_string()))
            },
        }
    }

    pub fn find_matching_certificate(peer_name : &str, certs : std::option::Option<&[rustls::pki_types::CertificateDer]>) -> Option<SimpleCertificate>{
        let mut found_matching_cert = None;
        if let Some(cert) = certs {
            cert.iter().for_each(|cert| {
                if let Ok(c) = Self::from_certificate_der(cert) {
                    if c.get_common_name() == peer_name ||
                        c.get_san_dns_names().iter().any(|name| name == peer_name){
                        found_matching_cert = Some(c);
                    }
                };
            });
        };
        found_matching_cert
    }

    pub fn get_serial_number(&self) -> &str {
        &self.serial_number
    }

    pub fn get_common_name(&self) -> &str {
        &self.common_name
    }

    pub fn get_san_dns_names(&self) -> &Vec<String> {
        &self.san_list
    }

    pub fn get_pem(&self) -> String {
        self.pem.clone()
    }

    pub fn get_remaining_days(&self) -> i64 {
        let now = OffsetDateTime::now_utc();
        let end = self.expiration_date;
        let remain =  end - now;
        let days = remain.whole_days();
        days
    }
}


#[cfg(test)]
mod tests {
    use super::*;
    use rustls::pki_types::CertificateDer;
    use time::macros::format_description;
    const GITEA_CERT: &[u8] = include_bytes!("../testdata/gitea.tschirky.ch.crt");
    const GATEKEEPER_CERT: &[u8] = include_bytes!("../testdata/gatekeeper.tschirky.ch.crt");
    const WWW_CERT: &[u8] = include_bytes!("../testdata/www.tschirky.ch.crt");


    fn test_day_offset() -> i64 {
        let now = OffsetDateTime::now_utc();
        let format = format_description!("[year]-[month]-[day] [hour]:[minute]:[second] [offset_hour sign:mandatory]:[offset_minute]:[offset_second]");
        let date_zero = OffsetDateTime::parse("2025-02-10 05:30:00 +01:00:00", &format).unwrap();
        ((now - date_zero).as_seconds_f64()/(3600.0*24.0)).round() as i64
    }

    #[test]
    fn test_cert_load(){
        let der_cert = CertificateDer::from(GITEA_CERT);
        let cert = SimpleCertificate::from_certificate_der(&der_cert);
        if let Ok(c) = cert {
            assert_eq!(c.get_common_name(), "gitea.tschirky.ch");
            assert_eq!(c.get_serial_number(), "04ba66ac8f777d7daa73e89ceab53b47f5ae");
            assert_eq!(c.get_san_dns_names(), &["gitea.tschirky.ch"]);

            assert_eq!(c.get_remaining_days(), (38 - test_day_offset()));
        } else {
            assert!(false);
        }
    }

    #[test]
    fn test_get_common_name_ok_1(){
        let certs = [ CertificateDer::from(GITEA_CERT), CertificateDer::from(GATEKEEPER_CERT), CertificateDer::from(WWW_CERT)];
        let cert = SimpleCertificate::find_matching_certificate("owncloud.tschirky.ch", Some(&certs));
        assert!(cert.is_some());
        let cert = cert.unwrap();
        assert_eq!(cert.get_common_name(), "gatekeeper.tschirky.ch");
        assert_eq!(cert.get_san_dns_names(), &["gatekeeper.tschirky.ch", "owncloud.tschirky.ch"]);
    }

    #[test]
    fn test_get_common_name_ok_2(){
        let certs = [ CertificateDer::from(GITEA_CERT), CertificateDer::from(GATEKEEPER_CERT), CertificateDer::from(WWW_CERT)];
        let cert = SimpleCertificate::find_matching_certificate("gitea.tschirky.ch", Some(&certs));
        assert!(cert.is_some());
        let cert = cert.unwrap();
        assert_eq!(cert.get_common_name(), "gitea.tschirky.ch");
        assert_eq!(cert.get_san_dns_names(), &["gitea.tschirky.ch"]);
    }

    #[test]
    fn test_get_common_name_nok_1(){
        let certs = [ CertificateDer::from(GITEA_CERT), CertificateDer::from(GATEKEEPER_CERT), CertificateDer::from(WWW_CERT)];
        let cert = SimpleCertificate::find_matching_certificate("mirko.tschirky.ch", Some(&certs));
        assert!(cert.is_none());
    }

    #[test]
    fn test_cert_retriever() {
        let retr = CertRetriever::new();
        let cert = retr.get_target_cert_from_endpoint("www.ibm.com", 443);
        assert!(cert.is_ok());
        assert_eq!(cert.unwrap().get_common_name(), "www.ibm.com")

    }

    #[test]
    fn test_cert_retriever_unreachable_target_1() {
        let retr = CertRetriever::new();
        let cert = retr.get_target_cert_from_endpoint("www.tschirky.ch", 998);

        match cert {
            Err(e) => {
                match e {
                    CertError::TargetNotReachable(e) => {
                        assert_eq!(e, "Target www.tschirky.ch:998 is unreachable");
                    }
                    _ => {
                        assert!(false);
                    }
                }
            },
            Ok(_) => {
                assert!(false)
            }
        }
    }

    #[test]
    fn test_cert_retriever_unreachable_target_2() {
        let retr = CertRetriever::new();
        let cert = retr.get_target_cert_from_endpoint("schludri.e3ag.ch", 443);

        match cert {
            Err(e) => {
                match e {
                    CertError::TargetNotReachable(e) => {
                        assert_eq!(e, "Target schludri.e3ag.ch:443 is unreachable");
                    }
                    _ => {
                        panic!("Unexpected CertError");
                    }
                }
            },
            Ok(_) => {
                panic!("We expect CertError");
            }
        }
    }


    #[test]
    fn test_write_to_pem(){
        let gitea = SimpleCertificate::from_certificate_der( &CertificateDer::from(GITEA_CERT)).unwrap();
        println!("{}", gitea.get_pem());
    }

    #[test]
    fn compare_pem(){
        let mut pem = "-----BEGIN CERTIFICATE-----\n".to_string();
        let lines : Vec<&str> = vec![];
        let mut b64 = data_encoding::BASE64.encode(&GITEA_CERT);
        while let Some((line, remaining)) = b64.split_at_checked(65) {
            pem.push_str(line);
            if !remaining.is_empty() {
                b64 = remaining.to_string();
                pem.push('\n');
            }
        }
        if !b64.is_empty() {
            pem.push_str(&b64);
        }
        pem.push_str("\n-----END CERTIFICATE-----\n");
        println!("{}",pem)
    }
}