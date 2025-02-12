mod target_cert;

use std::io::{Write};
use std::net::TcpStream;
use std::sync::Arc;
use rustls::pki_types::{ServerName};
use rustls::RootCertStore;
use x509_parser::prelude::{FromDer, GeneralName, X509Certificate};


fn dump_peer_certificates<'a>(certs : Option<&'a [rustls::pki_types::CertificateDer<'a>]>){
    if let Some(cert) = certs {

        cert.iter().for_each(|cert| {
            if let Ok((_,c)) = X509Certificate::from_der(cert.as_ref()) {
                c.subject().iter_common_name().for_each(|name| {
                    if let Ok(cn) = name.as_str(){
                        let out_file_name = format!("./testdata/{}.cer", cn);
                        std::fs::write(&out_file_name, cert.as_ref()).unwrap();
                    }
                });
            }
        })
    }
}

fn get_peer_certificate<'a>(peer_name : &str, certs : Option<&'a [rustls::pki_types::CertificateDer<'a>]>) -> Option<X509Certificate<'a>>{
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
    config.key_log = Arc::new(rustls::KeyLogFile::new());

    let server_name_str = "www.tschirky.ch";
    let server_name : ServerName = server_name_str.try_into().unwrap();

    let mut sock = TcpStream::connect(format!("{}:443", server_name_str)).unwrap();
    let mut conn = rustls::ClientConnection::new(Arc::new(config), server_name).unwrap();
    let mut tls = rustls::Stream::new(&mut conn, &mut sock);

    let _res = tls.write(b"\n").unwrap();

    dump_peer_certificates(tls.conn.peer_certificates());
    if let Some(peer_cert) = get_peer_certificate(server_name_str, tls.conn.peer_certificates()){
        //println!("Cert {:?}", peer_cert);
        println!("Cert Serial {:?}", peer_cert.raw_serial_as_string().replace(":",""));
        peer_cert.subject.iter_common_name().for_each(|s| {
            if let Ok(name_str) = s.as_str(){
                println!("Cert CommonName {:?}", name_str);
            }
        });
        println!("Cert Expiry {:?}", peer_cert.validity().not_after.to_datetime());
    }
}