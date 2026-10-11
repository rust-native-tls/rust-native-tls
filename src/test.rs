use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::process::{Command, Stdio};
use std::string::String;
use std::{fs, thread};

use super::*;

macro_rules! p {
    ($e:expr) => {
        match $e {
            Ok(r) => r,
            Err(e) => panic!("{:?}", e),
        }
    };
}

#[test]
#[cfg_attr(target_vendor = "apple", should_panic = "-9830", allow(deprecated))]
fn connect_google_tls13_only() {
    let builder = p!(TlsConnector::builder()
        .min_protocol_version(Some(Protocol::Tlsv13))
        .max_protocol_version(Some(Protocol::Tlsv13))
        .build());
    let s = p!(TcpStream::connect("google.com:443"));
    let mut socket = p!(builder.connect("google.com", s));

    p!(socket.write_all(b"GET / HTTP/1.0\r\n\r\n"));
    let mut result = vec![];
    p!(socket.read_to_end(&mut result));

    println!("{}", String::from_utf8_lossy(&result));
    assert!(result.starts_with(b"HTTP/1.0"));
    assert!(result.ends_with(b"</HTML>\r\n") || result.ends_with(b"</html>"));
}

#[test]
#[cfg_attr(target_vendor = "apple", allow(deprecated))]
fn connect_google_tls12_13() {
    let builder = p!(TlsConnector::builder()
        .min_protocol_version(Some(Protocol::Tlsv12))
        .max_protocol_version(Some(Protocol::Tlsv13))
        .build());
    let s = p!(TcpStream::connect("www.google.com:443"));
    let mut socket = p!(builder.connect("www.google.com", s));

    p!(socket.write_all(b"GET / HTTP/1.0\r\n\r\n"));
    let mut result = vec![];
    p!(socket.read_to_end(&mut result));

    println!("{}", String::from_utf8_lossy(&result));
    assert!(result.starts_with(b"HTTP/1.0"));
    assert!(result.ends_with(b"</HTML>\r\n") || result.ends_with(b"</html>"));
}

#[test]
fn connect_google() {
    let builder = p!(TlsConnector::new());
    let s = p!(TcpStream::connect("google.com:443"));
    let mut socket = p!(builder.connect("google.com", s));

    p!(socket.write_all(b"GET / HTTP/1.0\r\n\r\n"));
    let mut result = vec![];
    p!(socket.read_to_end(&mut result));

    println!("{}", String::from_utf8_lossy(&result));
    assert!(result.starts_with(b"HTTP/1.0"));
    assert!(result.ends_with(b"</HTML>\r\n") || result.ends_with(b"</html>"));
}

#[test]
fn connect_bad_hostname() {
    let builder = p!(TlsConnector::new());
    let s = p!(TcpStream::connect("google.com:443"));
    builder.connect("goggle.com", s).unwrap_err();
}

#[test]
fn connect_bad_hostname_ignored() {
    let builder = p!(TlsConnector::builder()
        .danger_accept_invalid_hostnames(true)
        .build());
    let s = p!(TcpStream::connect("google.com:443"));
    builder.connect("goggle.com", s).unwrap();
}

#[test]
fn connect_no_root_certs() {
    let builder = p!(TlsConnector::builder().disable_built_in_roots(true).build());
    let s = p!(TcpStream::connect("google.com:443"));
    assert!(builder.connect("google.com", s).is_err());
}

#[test]
fn server_no_root_certs() {
    let keys = test_cert_gen::keys();

    let identity = p!(Identity::from_pkcs12(
        &keys.server.cert_and_key_pkcs12.pkcs12.0,
        &keys.server.cert_and_key_pkcs12.password
    ));
    let builder = p!(TlsAcceptor::new(identity));

    let listener = p!(TcpListener::bind("0.0.0.0:0"));
    let port = p!(listener.local_addr()).port();

    let j = thread::spawn(move || {
        let socket = p!(listener.accept()).0;
        let mut socket = p!(builder.accept(socket));

        let mut buf = [0; 5];
        p!(socket.read_exact(&mut buf));
        assert_eq!(&buf, b"hello");

        p!(socket.write_all(b"world"));
    });

    let root_ca = Certificate::from_der(keys.client.ca.get_der()).unwrap();

    let socket = p!(TcpStream::connect(("localhost", port)));
    let builder = p!(TlsConnector::builder()
        .disable_built_in_roots(true)
        .add_root_certificate(root_ca)
        .build());
    let mut socket = p!(builder.connect("localhost", socket));

    p!(socket.write_all(b"hello"));
    let mut buf = vec![];
    p!(socket.read_to_end(&mut buf));
    assert_eq!(buf, b"world");

    p!(j.join());
}

#[test]
fn server() {
    let keys = test_cert_gen::keys();

    let identity = p!(Identity::from_pkcs12(
        &keys.server.cert_and_key_pkcs12.pkcs12.0,
        &keys.server.cert_and_key_pkcs12.password
    ));
    let builder = p!(TlsAcceptor::new(identity));

    let listener = p!(TcpListener::bind("0.0.0.0:0"));
    let port = p!(listener.local_addr()).port();

    let j = thread::spawn(move || {
        let socket = p!(listener.accept()).0;
        let mut socket = p!(builder.accept(socket));

        let mut buf = [0; 5];
        p!(socket.read_exact(&mut buf));
        assert_eq!(&buf, b"hello");

        p!(socket.write_all(b"world"));
    });

    let root_ca = Certificate::from_der(keys.client.ca.get_der()).unwrap();

    let socket = p!(TcpStream::connect(("localhost", port)));
    let builder = p!(TlsConnector::builder()
        .add_root_certificate(root_ca)
        .build());
    let mut socket = p!(builder.connect("localhost", socket));

    p!(socket.write_all(b"hello"));
    let mut buf = vec![];
    p!(socket.read_to_end(&mut buf));
    assert_eq!(buf, b"world");

    p!(j.join());
}

#[test]
fn certificate_from_pem() {
    let dir = tempfile::tempdir().unwrap();
    let keys = test_cert_gen::keys();

    let der_path = dir.path().join("cert.der");
    fs::write(&der_path, keys.client.ca.get_der()).unwrap();
    let output = Command::new("openssl")
        .arg("x509")
        .arg("-in")
        .arg(der_path)
        .arg("-inform")
        .arg("der")
        .stderr(Stdio::piped())
        .output()
        .unwrap();

    assert!(output.status.success());

    let cert = Certificate::from_pem(&output.stdout).unwrap();
    assert_eq!(cert.to_der().unwrap(), keys.client.ca.get_der());
}

#[test]
fn peer_certificate() {
    let keys = test_cert_gen::keys();

    let identity = p!(Identity::from_pkcs12(
        &keys.server.cert_and_key_pkcs12.pkcs12.0,
        &keys.server.cert_and_key_pkcs12.password
    ));
    let builder = p!(TlsAcceptor::new(identity));

    let listener = p!(TcpListener::bind("0.0.0.0:0"));
    let port = p!(listener.local_addr()).port();

    let j = thread::spawn(move || {
        let socket = p!(listener.accept()).0;
        let socket = p!(builder.accept(socket));
        assert!(socket.peer_certificate().unwrap().is_none());
    });

    let root_ca = Certificate::from_der(keys.client.ca.get_der()).unwrap();

    let socket = p!(TcpStream::connect(("localhost", port)));
    let builder = p!(TlsConnector::builder()
        .add_root_certificate(root_ca)
        .build());
    let socket = p!(builder.connect("localhost", socket));

    let cert = socket.peer_certificate().unwrap().unwrap();
    assert_eq!(
        cert.to_der().unwrap(),
        keys.server.cert_and_key.cert.get_der()
    );

    p!(j.join());
}

#[test]
fn server_tls11_only() {
    let keys = test_cert_gen::keys();

    let identity = p!(Identity::from_pkcs12(
        &keys.server.cert_and_key_pkcs12.pkcs12.0,
        &keys.server.cert_and_key_pkcs12.password
    ));
    let builder = p!(TlsAcceptor::builder(identity)
        .min_protocol_version(Some(Protocol::Tlsv12))
        .max_protocol_version(Some(Protocol::Tlsv12))
        .build());

    let listener = p!(TcpListener::bind("0.0.0.0:0"));
    let port = p!(listener.local_addr()).port();

    let j = thread::spawn(move || {
        let socket = p!(listener.accept()).0;
        let mut socket = p!(builder.accept(socket));

        let mut buf = [0; 5];
        p!(socket.read_exact(&mut buf));
        assert_eq!(&buf, b"hello");

        p!(socket.write_all(b"world"));
    });

    let root_ca = Certificate::from_der(keys.client.ca.get_der()).unwrap();

    let socket = p!(TcpStream::connect(("localhost", port)));
    let builder = p!(TlsConnector::builder()
        .add_root_certificate(root_ca)
        .min_protocol_version(Some(Protocol::Tlsv12))
        .max_protocol_version(Some(Protocol::Tlsv12))
        .build());
    let mut socket = p!(builder.connect("localhost", socket));

    p!(socket.write_all(b"hello"));
    let mut buf = vec![];
    p!(socket.read_to_end(&mut buf));
    assert_eq!(buf, b"world");

    p!(j.join());
}

#[test]
fn server_no_shared_protocol() {
    let keys = test_cert_gen::keys();

    let identity = p!(Identity::from_pkcs12(
        &keys.server.cert_and_key_pkcs12.pkcs12.0,
        &keys.server.cert_and_key_pkcs12.password
    ));
    let builder = p!(TlsAcceptor::builder(identity)
        .min_protocol_version(Some(Protocol::Tlsv12))
        .build());

    let listener = p!(TcpListener::bind("0.0.0.0:0"));
    let port = p!(listener.local_addr()).port();

    let j = thread::spawn(move || {
        let socket = p!(listener.accept()).0;
        assert!(builder.accept(socket).is_err());
    });

    let root_ca = Certificate::from_der(keys.client.ca.get_der()).unwrap();

    let socket = p!(TcpStream::connect(("localhost", port)));
    let builder = p!(TlsConnector::builder()
        .add_root_certificate(root_ca)
        .min_protocol_version(Some(Protocol::Tlsv11))
        .max_protocol_version(Some(Protocol::Tlsv11))
        .build());
    assert!(builder.connect("localhost", socket).is_err());

    p!(j.join());
}

#[test]
fn server_untrusted() {
    let keys = test_cert_gen::keys();

    let identity = p!(Identity::from_pkcs12(
        &keys.server.cert_and_key_pkcs12.pkcs12.0,
        &keys.server.cert_and_key_pkcs12.password
    ));
    let builder = p!(TlsAcceptor::new(identity));

    let listener = p!(TcpListener::bind("0.0.0.0:0"));
    let port = p!(listener.local_addr()).port();

    let j = thread::spawn(move || {
        let socket = p!(listener.accept()).0;
        // FIXME should assert error
        // https://github.com/steffengy/schannel-rs/issues/20
        let _ = builder.accept(socket);
    });

    let socket = p!(TcpStream::connect(("localhost", port)));
    let builder = p!(TlsConnector::new());
    builder.connect("localhost", socket).unwrap_err();

    p!(j.join());
}

#[test]
fn server_untrusted_unverified() {
    let keys = test_cert_gen::keys();

    let identity = p!(Identity::from_pkcs12(
        &keys.server.cert_and_key_pkcs12.pkcs12.0,
        &keys.server.cert_and_key_pkcs12.password
    ));
    let builder = p!(TlsAcceptor::new(identity));

    let listener = p!(TcpListener::bind("0.0.0.0:0"));
    let port = p!(listener.local_addr()).port();

    let j = thread::spawn(move || {
        let socket = p!(listener.accept()).0;
        let mut socket = p!(builder.accept(socket));

        let mut buf = [0; 5];
        p!(socket.read_exact(&mut buf));
        assert_eq!(&buf, b"hello");

        p!(socket.write_all(b"world"));
    });

    let socket = p!(TcpStream::connect(("localhost", port)));
    let builder = p!(TlsConnector::builder()
        .danger_accept_invalid_certs(true)
        .build());
    let mut socket = p!(builder.connect("localhost", socket));

    p!(socket.write_all(b"hello"));
    let mut buf = vec![];
    p!(socket.read_to_end(&mut buf));
    assert_eq!(buf, b"world");

    p!(j.join());
}

#[test]
fn import_same_identity_multiple_times() {
    let keys = test_cert_gen::keys();

    let _ = p!(Identity::from_pkcs12(
        &keys.server.cert_and_key_pkcs12.pkcs12.0,
        &keys.server.cert_and_key_pkcs12.password
    ));
    let _ = p!(Identity::from_pkcs12(
        &keys.server.cert_and_key_pkcs12.pkcs12.0,
        &keys.server.cert_and_key_pkcs12.password
    ));

    let cert = keys.server.cert_and_key.cert.to_pem().into_bytes();
    let key = rsa_to_pkcs8(&keys.server.cert_and_key.key.to_pem_incorrect()).into_bytes();
    let _ = p!(Identity::from_pkcs8(&cert, &key));
    let _ = p!(Identity::from_pkcs8(&cert, &key));
}

#[test]
fn from_pkcs8_rejects_rsa_key() {
    let keys = test_cert_gen::keys();
    let cert = keys.server.cert_and_key.cert.to_pem().into_bytes();
    let rsa_key = keys.server.cert_and_key.key.to_pem_incorrect();
    assert!(Identity::from_pkcs8(&cert, rsa_key.as_bytes()).is_err());
    let pkcs8_key = rsa_to_pkcs8(&rsa_key);
    assert!(Identity::from_pkcs8(&cert, pkcs8_key.as_bytes()).is_ok());
}

#[test]
fn shutdown() {
    let keys = test_cert_gen::keys();

    let identity = p!(Identity::from_pkcs12(
        &keys.server.cert_and_key_pkcs12.pkcs12.0,
        &keys.server.cert_and_key_pkcs12.password
    ));
    let builder = p!(TlsAcceptor::new(identity));

    let listener = p!(TcpListener::bind("0.0.0.0:0"));
    let port = p!(listener.local_addr()).port();

    let j = thread::spawn(move || {
        let socket = p!(listener.accept()).0;
        let mut socket = p!(builder.accept(socket));

        let mut buf = [0; 5];
        p!(socket.read_exact(&mut buf));
        assert_eq!(&buf, b"hello");

        assert_eq!(p!(socket.read(&mut buf)), 0);
        p!(socket.shutdown());
    });

    let root_ca = Certificate::from_der(keys.client.ca.get_der()).unwrap();

    let socket = p!(TcpStream::connect(("localhost", port)));
    let builder = p!(TlsConnector::builder()
        .add_root_certificate(root_ca)
        .build());
    let mut socket = p!(builder.connect("localhost", socket));

    p!(socket.write_all(b"hello"));
    p!(socket.shutdown());

    p!(j.join());
}

#[test]
#[cfg(feature = "alpn")]
fn alpn_google_h2() {
    let builder = p!(TlsConnector::builder().request_alpns(&["h2"]).build());
    let s = p!(TcpStream::connect("google.com:443"));
    let socket = p!(builder.connect("google.com", s));
    let alpn = p!(socket.negotiated_alpn());
    assert_eq!(alpn, Some(b"h2".to_vec()));
}

#[test]
#[cfg(feature = "alpn")]
fn alpn_google_invalid() {
    let builder = p!(TlsConnector::builder().request_alpns(&["h2c"]).build());
    let s = p!(TcpStream::connect("google.com:443"));
    let socket = p!(builder.connect("google.com", s));
    let alpn = p!(socket.negotiated_alpn());
    assert_eq!(alpn, None);
}

#[test]
#[cfg(feature = "alpn")]
fn alpn_google_none() {
    let builder = p!(TlsConnector::new());
    let s = p!(TcpStream::connect("google.com:443"));
    let socket = p!(builder.connect("google.com", s));
    let alpn = p!(socket.negotiated_alpn());
    assert_eq!(alpn, None);
}

#[test]
#[cfg(feature = "alpn-accept")]
#[cfg(not(any(target_os = "macos", target_os = "ios")))]
fn alpn_server_side() {
    let keys = test_cert_gen::keys();
    let cert = keys.server.cert_and_key.cert.to_pem().into_bytes();
    let key = rsa_to_pkcs8(&keys.server.cert_and_key.key.to_pem_incorrect()).into_bytes();

    let ident = Identity::from_pkcs8(&cert, &key).unwrap();
    let ident2 = ident.clone();
    let mut builder = TlsAcceptor::builder(ident);
    builder.accept_alpn(&["h2"]);
    let builder = p!(builder.build());

    let listener = p!(TcpListener::bind("0.0.0.0:0"));
    let port = p!(listener.local_addr()).port();

    let j = thread::spawn(move || {
        let socket = p!(listener.accept()).0;
        let mut socket = p!(builder.accept(socket));

        let alpn = p!(socket.negotiated_alpn());
        assert_eq!(alpn, Some(b"h2".to_vec()));

        let mut buf = [0; 5];
        p!(socket.read_exact(&mut buf));
        assert_eq!(&buf, b"hello");

        p!(socket.write_all(b"world"));
    });

    let root_ca = Certificate::from_der(keys.client.ca.get_der()).unwrap();

    let socket = p!(TcpStream::connect(("localhost", port)));
    let mut builder = TlsConnector::builder();

    builder.request_alpns(&["h2"]);

    builder.identity(ident2);

    builder.add_root_certificate(root_ca);
    let builder = p!(builder.build());
    let mut socket = p!(builder.connect("localhost", socket));

    p!(socket.write_all(b"hello"));
    let mut buf = vec![];
    p!(socket.read_to_end(&mut buf));
    assert_eq!(buf, b"world");

    p!(j.join());
}

#[test]
fn server_pkcs8() {
    let keys = test_cert_gen::keys();
    let cert = keys.server.cert_and_key.cert.to_pem().into_bytes();
    let key = rsa_to_pkcs8(&keys.server.cert_and_key.key.to_pem_incorrect()).into_bytes();

    let ident = Identity::from_pkcs8(&cert, &key).unwrap();
    let ident2 = ident.clone();
    let builder = p!(TlsAcceptor::new(ident));

    let listener = p!(TcpListener::bind("0.0.0.0:0"));
    let port = p!(listener.local_addr()).port();

    let j = thread::spawn(move || {
        let socket = p!(listener.accept()).0;
        let mut socket = p!(builder.accept(socket));

        let mut buf = [0; 5];
        p!(socket.read_exact(&mut buf));
        assert_eq!(&buf, b"hello");

        p!(socket.write_all(b"world"));
    });

    let root_ca = Certificate::from_der(keys.client.ca.get_der()).unwrap();

    let socket = p!(TcpStream::connect(("localhost", port)));
    let mut builder = TlsConnector::builder();
    // FIXME
    // This checks that we can successfully add a certificate on the client side.
    // Unfortunately, we can not request client certificates through the API of this library,
    // otherwise we could check in the server thread that
    // socket.peer_certificate().unwrap().is_some()
    builder.identity(ident2);

    builder.add_root_certificate(root_ca);
    let builder = p!(builder.build());
    let mut socket = p!(builder.connect("localhost", socket));

    p!(socket.write_all(b"hello"));
    let mut buf = vec![];
    p!(socket.read_to_end(&mut buf));
    assert_eq!(buf, b"world");

    p!(j.join());
}

#[test]
fn two_servers() {
    let keys1 = test_cert_gen::gen_keys();
    let cert = keys1.server.cert_and_key.cert.to_pem().into_bytes();
    let key = rsa_to_pkcs8(&keys1.server.cert_and_key.key.to_pem_incorrect()).into_bytes();
    let identity = p!(Identity::from_pkcs8(&cert, &key));
    let builder = TlsAcceptor::builder(identity);
    let builder = p!(builder.build());

    let listener = p!(TcpListener::bind("0.0.0.0:0"));
    let port = p!(listener.local_addr()).port();

    let j = thread::spawn(move || {
        let socket = p!(listener.accept()).0;
        let mut socket = p!(builder.accept(socket));

        let mut buf = [0; 5];
        p!(socket.read_exact(&mut buf));
        assert_eq!(&buf, b"hello");

        p!(socket.write_all(b"world"));
    });

    let keys2 = test_cert_gen::gen_keys();
    let cert = keys2.server.cert_and_key.cert.to_pem().into_bytes();
    let key = rsa_to_pkcs8(&keys2.server.cert_and_key.key.to_pem_incorrect()).into_bytes();
    let identity = p!(Identity::from_pkcs8(&cert, &key));
    let builder = TlsAcceptor::builder(identity);
    let builder = p!(builder.build());

    let listener = p!(TcpListener::bind("0.0.0.0:0"));
    let port2 = p!(listener.local_addr()).port();

    let j2 = thread::spawn(move || {
        let socket = p!(listener.accept()).0;
        let mut socket = p!(builder.accept(socket));

        let mut buf = [0; 5];
        p!(socket.read_exact(&mut buf));
        assert_eq!(&buf, b"hello");

        p!(socket.write_all(b"world"));
    });

    let root_ca = Certificate::from_der(keys1.client.ca.get_der()).unwrap();

    let socket = p!(TcpStream::connect(("localhost", port)));
    let mut builder = TlsConnector::builder();
    builder.add_root_certificate(root_ca);
    let builder = p!(builder.build());
    let mut socket = p!(builder.connect("localhost", socket));

    p!(socket.write_all(b"hello"));
    let mut buf = vec![];
    p!(socket.read_to_end(&mut buf));
    assert_eq!(buf, b"world");

    let root_ca = Certificate::from_der(keys2.client.ca.get_der()).unwrap();

    let socket = p!(TcpStream::connect(("localhost", port2)));
    let mut builder = TlsConnector::builder();
    builder.add_root_certificate(root_ca);
    let builder = p!(builder.build());
    let mut socket = p!(builder.connect("localhost", socket));

    p!(socket.write_all(b"hello"));
    let mut buf = vec![];
    p!(socket.read_to_end(&mut buf));
    assert_eq!(buf, b"world");

    p!(j.join());
    p!(j2.join());
}

fn rsa_to_pkcs8(pem: &str) -> String {
    let mut child = Command::new("openssl")
        .arg("pkcs8")
        .arg("-topk8")
        .arg("-nocrypt")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .spawn()
        .unwrap();
    {
        let child_stdin = child.stdin.as_mut().unwrap();
        child_stdin.write_all(pem.as_bytes()).unwrap();
    }
    String::from_utf8(child.wait_with_output().unwrap().stdout).unwrap()
}

/// Tests for the order in which the certificate chain of a PKCS #12 identity is sent
/// to the peer. These use the `openssl` crate directly to inspect the raw chain and so
/// only run with the OpenSSL backend.
#[cfg(not(any(target_os = "windows", target_vendor = "apple")))]
mod pkcs12_chain_order {
    use openssl::asn1::Asn1Time;
    use openssl::bn::BigNum;
    use openssl::hash::MessageDigest;
    use openssl::nid::Nid;
    use openssl::pkcs12::Pkcs12;
    use openssl::pkey::{PKey, Private};
    use openssl::rsa::Rsa;
    use openssl::ssl::{SslConnector, SslMethod, SslVerifyMode};
    use openssl::stack::Stack;
    use openssl::x509::extension::{BasicConstraints, SubjectAlternativeName};
    use openssl::x509::{X509Builder, X509NameBuilder, X509Ref, X509};
    use std::io::{Read, Write};
    use std::net::{TcpListener, TcpStream};
    use std::thread;

    use crate::{Identity, TlsAcceptor};

    fn make_cert(
        cn: &str,
        serial: u32,
        ca: bool,
        issuer: Option<(&X509, &PKey<Private>)>,
    ) -> (X509, PKey<Private>) {
        let key = PKey::from_rsa(Rsa::generate(2048).unwrap()).unwrap();

        let mut name = X509NameBuilder::new().unwrap();
        name.append_entry_by_text("CN", cn).unwrap();
        let name = name.build();

        let mut builder = X509Builder::new().unwrap();
        builder.set_version(2).unwrap();
        builder
            .set_serial_number(&BigNum::from_u32(serial).unwrap().to_asn1_integer().unwrap())
            .unwrap();
        builder.set_subject_name(&name).unwrap();
        builder.set_pubkey(&key).unwrap();
        builder
            .set_not_before(&Asn1Time::days_from_now(0).unwrap())
            .unwrap();
        builder
            .set_not_after(&Asn1Time::days_from_now(365).unwrap())
            .unwrap();
        let issuer_cert = issuer.map(|(cert, _)| cert);
        builder
            .set_issuer_name(issuer_cert.map_or(&name, |cert| cert.subject_name()))
            .unwrap();
        if ca {
            builder
                .append_extension(BasicConstraints::new().critical().ca().build().unwrap())
                .unwrap();
        } else {
            let san = SubjectAlternativeName::new()
                .dns("localhost")
                .build(&builder.x509v3_context(issuer_cert.map(X509::as_ref), None))
                .unwrap();
            builder.append_extension(san).unwrap();
        }
        let signing_key = issuer.map_or(&key, |(_, key)| key);
        builder.sign(signing_key, MessageDigest::sha256()).unwrap();
        (builder.build(), key)
    }

    struct Chain {
        root: X509,
        intermediate: X509,
        leaf: X509,
        leaf_key: PKey<Private>,
        unrelated: X509,
    }

    fn make_chain() -> Chain {
        let (root, root_key) = make_cert("native-tls test root", 1, true, None);
        let (intermediate, intermediate_key) = make_cert(
            "native-tls test intermediate",
            2,
            true,
            Some((&root, &root_key)),
        );
        let (leaf, leaf_key) = make_cert(
            "localhost",
            3,
            false,
            Some((&intermediate, &intermediate_key)),
        );
        let (unrelated, _) = make_cert("native-tls unrelated", 4, true, None);
        Chain {
            root,
            intermediate,
            leaf,
            leaf_key,
            unrelated,
        }
    }

    /// Builds a PKCS #12 archive whose CA bag contains `ca` in exactly that order,
    /// like `openssl pkcs12 -export -inkey leaf.key -in leaf.pem -certfile chain.pem`
    /// does for the certificates in `chain.pem`.
    fn pkcs12(chain: &Chain, ca: &[&X509]) -> Vec<u8> {
        let mut stack = Stack::new().unwrap();
        for cert in ca {
            stack.push((*cert).clone()).unwrap();
        }
        Pkcs12::builder()
            .name("native-tls test")
            .pkey(&chain.leaf_key)
            .cert(&chain.leaf)
            .ca(stack)
            .build2("hunter2")
            .unwrap()
            .to_der()
            .unwrap()
    }

    fn common_name(cert: &X509Ref) -> String {
        let cn = cert
            .subject_name()
            .entries_by_nid(Nid::COMMONNAME)
            .next()
            .unwrap();
        String::from_utf8_lossy(cn.data().as_slice()).into_owned()
    }

    /// Runs a server with `identity` and returns the common names of the certificates
    /// the server sent, in the order the client received them.
    fn served_chain(identity: Identity, root: &X509) -> Vec<String> {
        let acceptor = p!(TlsAcceptor::new(identity));
        let listener = p!(TcpListener::bind("127.0.0.1:0"));
        let port = p!(listener.local_addr()).port();

        let j = thread::spawn(move || {
            let socket = p!(listener.accept()).0;
            let mut socket = p!(acceptor.accept(socket));
            let mut buf = [0; 5];
            p!(socket.read_exact(&mut buf));
            assert_eq!(&buf, b"hello");
            p!(socket.write_all(b"world"));
        });

        let mut connector = p!(SslConnector::builder(SslMethod::tls_client()));
        p!(connector.cert_store_mut().add_cert(root.clone()));
        connector.set_verify(SslVerifyMode::PEER);
        let connector = connector.build();

        let socket = p!(TcpStream::connect(("127.0.0.1", port)));
        let mut socket = p!(connector.connect("localhost", socket));
        let chain = socket
            .ssl()
            .peer_cert_chain()
            .expect("server sent no certificates")
            .iter()
            .map(common_name)
            .collect();

        p!(socket.write_all(b"hello"));
        let mut buf = vec![];
        p!(socket.read_to_end(&mut buf));
        assert_eq!(buf, b"world");
        p!(j.join());

        chain
    }

    fn names(certs: &[&X509]) -> Vec<String> {
        certs.iter().map(|cert| common_name(cert)).collect()
    }

    /// The order `openssl pkcs12 -export ... -certfile chain.pem` stores for a
    /// `chain.pem` holding the intermediate followed by the root. OpenSSL >= 3.0 hands
    /// this order back from `PKCS12_parse` unchanged, so blindly reversing it makes the
    /// server send the root before the intermediate.
    #[test]
    fn leaf_to_root_order() {
        let chain = make_chain();
        let der = pkcs12(&chain, &[&chain.intermediate, &chain.root]);
        let identity = p!(Identity::from_pkcs12(&der, "hunter2"));
        assert_eq!(
            served_chain(identity, &chain.root),
            names(&[&chain.leaf, &chain.intermediate, &chain.root])
        );
    }

    /// An archive storing the root before the intermediate, as other tools may write
    /// it, must also be sent leaf first.
    #[test]
    fn root_to_leaf_order() {
        let chain = make_chain();
        let der = pkcs12(&chain, &[&chain.root, &chain.intermediate]);
        let identity = p!(Identity::from_pkcs12(&der, "hunter2"));
        assert_eq!(
            served_chain(identity, &chain.root),
            names(&[&chain.leaf, &chain.intermediate, &chain.root])
        );
    }

    /// Certificates that are not part of the chain are kept, after the chain, in their
    /// original order.
    #[test]
    fn unrelated_certificates_are_kept() {
        let chain = make_chain();
        let der = pkcs12(
            &chain,
            &[&chain.unrelated, &chain.root, &chain.intermediate],
        );
        let identity = p!(Identity::from_pkcs12(&der, "hunter2"));
        assert_eq!(
            served_chain(identity, &chain.root),
            names(&[
                &chain.leaf,
                &chain.intermediate,
                &chain.root,
                &chain.unrelated
            ])
        );
    }
}
