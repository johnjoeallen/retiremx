use std::{
    io::{BufRead, BufReader, Write},
    net::{TcpListener, TcpStream},
    process::{Child, Command, Stdio},
    thread,
    time::Duration,
};

struct Server(Child);

impl Server {
    fn start(port: u16) -> Self {
        Self::start_with_config(
            port,
            concat!(env!("CARGO_MANIFEST_DIR"), "/tests/fixtures/reject.md"),
        )
    }

    fn start_with_config(port: u16, config: &str) -> Self {
        let child = Command::new(env!("CARGO_BIN_EXE_retiremx"))
            .args([
                "--config",
                config,
                "smtp",
                "--bind",
                &format!("127.0.0.1:{port}"),
            ])
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .expect("start SMTP server");
        Self(child)
    }

    fn connect(port: u16) -> TcpStream {
        for _ in 0..100 {
            if let Ok(stream) = TcpStream::connect(("127.0.0.1", port)) {
                stream
                    .set_read_timeout(Some(Duration::from_secs(2)))
                    .unwrap();
                return stream;
            }
            thread::sleep(Duration::from_millis(20));
        }
        panic!("SMTP server did not start");
    }
}

impl Drop for Server {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

fn response(reader: &mut BufReader<TcpStream>) -> String {
    let mut line = String::new();
    reader.read_line(&mut line).unwrap();
    line
}

fn command(stream: &mut TcpStream, reader: &mut BufReader<TcpStream>, command: &str) -> String {
    write!(stream, "{command}\r\n").unwrap();
    stream.flush().unwrap();
    response(reader)
}

#[test]
fn retired_recipient_is_rejected_at_rcpt() {
    let _server = Server::start(2531);
    let mut stream = Server::connect(2531);
    let mut reader = BufReader::new(stream.try_clone().unwrap());
    assert!(response(&mut reader).starts_with("220"));
    assert!(command(&mut stream, &mut reader, "EHLO test").starts_with("250-"));
    let _ = response(&mut reader);
    let _ = response(&mut reader);
    assert!(command(&mut stream, &mut reader, "MAIL FROM:<sender@example.org>").starts_with("250"));
    assert!(command(&mut stream, &mut reader, "RCPT TO:<oldjohn@moyville.net>").starts_with("550"));
    assert!(command(&mut stream, &mut reader, "QUIT").starts_with("221"));
}

#[test]
fn non_local_recipient_is_rejected_without_backend_connection() {
    let backend = TcpListener::bind("127.0.0.1:2525").unwrap();
    backend.set_nonblocking(true).unwrap();
    let _server = Server::start(2540);
    let mut stream = Server::connect(2540);
    let mut reader = BufReader::new(stream.try_clone().unwrap());
    assert!(response(&mut reader).starts_with("220"));
    assert!(command(&mut stream, &mut reader, "EHLO test").starts_with("250-"));
    let _ = response(&mut reader);
    let _ = response(&mut reader);
    assert!(
        command(&mut stream, &mut reader, "MAIL FROM:<general@moyville.net>").starts_with("250")
    );
    let relay_response = command(
        &mut stream,
        &mut reader,
        "RCPT TO:<michielle7591@hotmail.com>",
    );
    assert!(relay_response.starts_with("550 5.7.1 Relay access denied"));
    assert!(
        matches!(backend.accept(), Err(error) if error.kind() == std::io::ErrorKind::WouldBlock)
    );
}

#[test]
fn unknown_local_recipient_uses_local_policy() {
    let _server = Server::start(2541);
    let mut stream = Server::connect(2541);
    let mut reader = BufReader::new(stream.try_clone().unwrap());
    assert!(response(&mut reader).starts_with("220"));
    assert!(command(&mut stream, &mut reader, "EHLO test").starts_with("250-"));
    let _ = response(&mut reader);
    let _ = response(&mut reader);
    assert!(
        command(&mut stream, &mut reader, "MAIL FROM:<anything@example.net>").starts_with("250")
    );
    let response = command(&mut stream, &mut reader, "RCPT TO:<unknown@moyville.net>");
    assert!(response.starts_with("550 5.1.1"));
    assert!(response.contains("No such address"));
}

#[test]
fn configured_sender_is_accepted_for_pass_through() {
    let _server = Server::start(2532);
    let mut stream = Server::connect(2532);
    let mut reader = BufReader::new(stream.try_clone().unwrap());
    assert!(response(&mut reader).starts_with("220"));
    assert!(command(&mut stream, &mut reader, "EHLO trusted.example").starts_with("250-"));
    let _ = response(&mut reader);
    let _ = response(&mut reader);
    assert!(
        command(
            &mut stream,
            &mut reader,
            "MAIL FROM:<trusted@trusted.example>"
        )
        .starts_with("250")
    );
    assert!(command(&mut stream, &mut reader, "RCPT TO:<oldjohn@moyville.net>").starts_with("250"));
    assert!(command(&mut stream, &mut reader, "DATA").starts_with("451"));
    assert!(command(&mut stream, &mut reader, "QUIT").starts_with("221"));
}

#[test]
fn per_address_pass_through_accepts_retired_recipient() {
    let _server = Server::start(2537);
    let mut stream = Server::connect(2537);
    let mut reader = BufReader::new(stream.try_clone().unwrap());
    assert!(response(&mut reader).starts_with("220"));
    assert!(command(&mut stream, &mut reader, "EHLO test").starts_with("250-"));
    let _ = response(&mut reader);
    let _ = response(&mut reader);
    assert!(command(&mut stream, &mut reader, "MAIL FROM:<sender@example.org>").starts_with("250"));
    assert!(
        command(&mut stream, &mut reader, "RCPT TO:<monitored@moyville.net>").starts_with("250")
    );
    assert!(command(&mut stream, &mut reader, "DATA").starts_with("451"));
}

#[test]
fn unknown_pass_through_accepts_unknown_recipient() {
    let _server = Server::start_with_config(
        2538,
        concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/tests/fixtures/unknown-pass-through.md"
        ),
    );
    let mut stream = Server::connect(2538);
    let mut reader = BufReader::new(stream.try_clone().unwrap());
    assert!(response(&mut reader).starts_with("220"));
    assert!(command(&mut stream, &mut reader, "EHLO test").starts_with("250-"));
    let _ = response(&mut reader);
    let _ = response(&mut reader);
    assert!(command(&mut stream, &mut reader, "MAIL FROM:<sender@example.org>").starts_with("250"));
    assert!(command(&mut stream, &mut reader, "RCPT TO:<unknown@example.test>").starts_with("250"));
    assert!(command(&mut stream, &mut reader, "DATA").starts_with("451"));
}

#[test]
fn mail_size_parameter_is_checked_against_limit() {
    let _server = Server::start_with_config(
        2539,
        concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/tests/fixtures/small-limits.md"
        ),
    );
    let mut stream = Server::connect(2539);
    let mut reader = BufReader::new(stream.try_clone().unwrap());
    assert!(response(&mut reader).starts_with("220"));
    assert!(command(&mut stream, &mut reader, "EHLO test").starts_with("250-"));
    let _ = response(&mut reader);
    let _ = response(&mut reader);
    assert!(
        command(
            &mut stream,
            &mut reader,
            "MAIL FROM:<sender@example.org> SIZE=11"
        )
        .starts_with("552")
    );
}

#[test]
fn pass_through_proxies_message_to_postfix() {
    let listener = TcpListener::bind("127.0.0.1:2533").unwrap();
    let postfix = std::thread::spawn(move || {
        let (mut stream, _) = listener.accept().unwrap();
        stream
            .set_read_timeout(Some(Duration::from_secs(2)))
            .unwrap();
        let mut reader = BufReader::new(stream.try_clone().unwrap());
        stream.write_all(b"220 postfix.test ESMTP\r\n").unwrap();
        assert!(response(&mut reader).starts_with("EHLO"));
        stream.write_all(b"250-postfix.test\r\n250 OK\r\n").unwrap();
        assert!(response(&mut reader).starts_with("MAIL FROM"));
        stream.write_all(b"250 2.1.0 OK\r\n").unwrap();
        assert!(response(&mut reader).starts_with("RCPT TO"));
        stream.write_all(b"250 2.1.5 OK\r\n").unwrap();
        assert!(response(&mut reader).starts_with("DATA"));
        stream.write_all(b"354 End data\r\n").unwrap();
        assert!(response(&mut reader).starts_with("Subject: test"));
        assert_eq!(response(&mut reader), "\r\n");
        assert_eq!(response(&mut reader), ".escaped\r\n");
        while response(&mut reader) != ".\r\n" {}
        stream.write_all(b"250 2.0.0 Accepted\r\n").unwrap();
    });

    let _server = Server::start_with_config(
        2534,
        concat!(env!("CARGO_MANIFEST_DIR"), "/tests/fixtures/proxy.md"),
    );
    let mut stream = Server::connect(2534);
    let mut reader = BufReader::new(stream.try_clone().unwrap());
    assert!(response(&mut reader).starts_with("220"));
    assert!(command(&mut stream, &mut reader, "EHLO trusted.example").starts_with("250-"));
    let _ = response(&mut reader);
    let _ = response(&mut reader);
    assert!(
        command(
            &mut stream,
            &mut reader,
            "MAIL FROM:<trusted@trusted.example>"
        )
        .starts_with("250")
    );
    assert!(command(&mut stream, &mut reader, "RCPT TO:<old@example.test>").starts_with("250"));
    assert!(command(&mut stream, &mut reader, "DATA").starts_with("354"));
    stream
        .write_all(b"Subject: test\r\n\r\n..escaped\r\n.\r\n")
        .unwrap();
    stream.flush().unwrap();
    assert!(response(&mut reader).starts_with("250"));
    assert!(command(&mut stream, &mut reader, "QUIT").starts_with("221"));
    postfix.join().unwrap();
}

#[test]
fn postfix_temporary_failure_is_returned_to_client() {
    let listener = TcpListener::bind("127.0.0.1:2535").unwrap();
    let postfix = std::thread::spawn(move || {
        let (mut stream, _) = listener.accept().unwrap();
        stream
            .set_read_timeout(Some(Duration::from_secs(2)))
            .unwrap();
        let mut reader = BufReader::new(stream.try_clone().unwrap());
        stream.write_all(b"220 postfix.test ESMTP\r\n").unwrap();
        assert!(response(&mut reader).starts_with("EHLO"));
        stream.write_all(b"250-postfix.test\r\n250 OK\r\n").unwrap();
        assert!(response(&mut reader).starts_with("MAIL FROM"));
        stream.write_all(b"250 2.1.0 OK\r\n").unwrap();
        assert!(response(&mut reader).starts_with("RCPT TO"));
        stream
            .write_all(b"451 4.3.0 Temporary failure\r\n")
            .unwrap();
    });

    let _server = Server::start_with_config(
        2536,
        concat!(env!("CARGO_MANIFEST_DIR"), "/tests/fixtures/proxy-4xx.md"),
    );
    let mut stream = Server::connect(2536);
    let mut reader = BufReader::new(stream.try_clone().unwrap());
    assert!(response(&mut reader).starts_with("220"));
    assert!(command(&mut stream, &mut reader, "EHLO trusted.example").starts_with("250-"));
    let _ = response(&mut reader);
    let _ = response(&mut reader);
    assert!(
        command(
            &mut stream,
            &mut reader,
            "MAIL FROM:<trusted@trusted.example>"
        )
        .starts_with("250")
    );
    assert!(command(&mut stream, &mut reader, "RCPT TO:<old@example.test>").starts_with("250"));
    assert!(command(&mut stream, &mut reader, "DATA").starts_with("451"));
    postfix.join().unwrap();
}
