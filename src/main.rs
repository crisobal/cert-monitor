
use std::io::{Write};
use std::net::TcpStream;
use std::sync::Arc;
use rustls::pki_types::{CertificateDer, ServerName};
use rustls::RootCertStore;
use x509_parser::parse_x509_certificate;
use x509_parser::prelude::{FromDer, GeneralName, X509Certificate};


fn get_peer_certificate<'a>(peer_name : &str, certs : std::option::Option<&'a [rustls::pki_types::CertificateDer<'a>]>) -> Option<X509Certificate<'a>>{
    let mut certificate = None;
    if let Some(cert) = certs {
        cert.iter().for_each(|cert| {
            if let Ok((_,c)) = X509Certificate::from_der(cert.as_ref()) {
                let cn_match = c.subject().iter_common_name().any(|name| {
                    if let Ok(cn) = name.as_str(){
                        cn == peer_name
                    } else {
                        false
                    }
                });
                let san_match = c.subject_alternative_name().unwrap().is_some_and(|c| {
                    c.value.general_names.iter().any(|name| {                        
                        match name{
                            GeneralName::DNSName(n) => {
                                *n == peer_name
                            }
                            _ => false
                        }
                    })                    
                });
                
                if cn_match || san_match {
                    certificate = Some(c);
                }
            }
        })
    }
    certificate
}

fn main() {
    let root_store = RootCertStore {
        roots: webpki_roots::TLS_SERVER_ROOTS.into(),
    };
    let mut config = rustls::ClientConfig::builder()
        .with_root_certificates(root_store)
        .with_no_client_auth();
    config.enable_sni = true;
    config.enable_early_data = true;




    // Allow using SSLKEYLOGFILE.
    config.key_log = Arc::new(rustls::KeyLogFile::new());

    let server_name_str = "owncloud.tschirky.ch";
    let server_name : ServerName = server_name_str.try_into().unwrap();

    let mut sock = TcpStream::connect(format!("{}:443", server_name_str)).unwrap();

    let mut conn = rustls::ClientConnection::new(Arc::new(config), server_name).unwrap();


    let mut tls = rustls::Stream::new(&mut conn, &mut sock);

    let res = tls.write(b"\n").unwrap();

    let ciphersuite = tls
        .conn
        .negotiated_cipher_suite()
        .unwrap();

    writeln!(
        &mut std::io::stderr(),
        "Current ciphersuite: {:?}",
        ciphersuite.suite()
    ).unwrap();

    if let Some(peer_cert) = get_peer_certificate(server_name_str, tls.conn.peer_certificates()){
        println!("Cert {:?}", peer_cert);
        println!("Cert Serial {:?}", peer_cert.raw_serial_as_string());
        println!("Cert CN {:?}", peer_cert.subject);
        println!("Cert Expiry {:?}", peer_cert.validity().not_after.to_datetime());
    }
}