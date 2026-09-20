//! Standalone consumer of the extracted published crate; no test dependencies.
use std::io::{Read, Write};
use std::net::TcpListener;
use std::time::{Duration, Instant};
use trusted_router::{BlockingClient, Client, ModelFilters, ModelList};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let listener = TcpListener::bind("127.0.0.1:0")?;
    listener.set_nonblocking(true)?;
    let address = listener.local_addr()?;
    let server = std::thread::spawn(move || -> std::io::Result<()> {
        let deadline = Instant::now() + Duration::from_secs(10);
        let mut socket = loop {
            match listener.accept() {
                Ok((socket, _)) => break socket,
                Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                    if Instant::now() >= deadline {
                        return Err(std::io::Error::new(std::io::ErrorKind::TimedOut, "no SDK call"));
                    }
                    std::thread::sleep(Duration::from_millis(10));
                }
                Err(error) => return Err(error),
            }
        };
        socket.set_read_timeout(Some(Duration::from_secs(5)))?;
        socket.set_write_timeout(Some(Duration::from_secs(5)))?;
        let mut request = Vec::new();
        while !request.ends_with(b"\r\n\r\n") {
            let mut byte = [0];
            socket.read_exact(&mut byte)?;
            request.push(byte[0]);
            assert!(request.len() < 16384, "oversized request headers");
        }
        let request = String::from_utf8_lossy(&request).to_ascii_lowercase();
        assert!(request.starts_with("get /v1/models http/1.1\r\n"));
        assert!(request.contains("\r\nauthorization: bearer consumer-key\r\n"));
        let body = r#"{"data":[{"id":"fake-model","name":"Fake"}]}"#;
        write!(socket, "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}", body.len(), body)?;
        Ok(())
    });
    let client = BlockingClient::from_builder(
        Client::builder()
            .api_key("consumer-key")
            .api_base_url(format!("http://{address}/v1"))
            .control_base_url(format!("http://{address}/v1"))
            .telemetry(false),
    )?;
    let models: ModelList = client.models(ModelFilters::default())?;
    let model = models.by_id("fake-model").ok_or("missing fake model")?;
    let name: &str = &model.name;
    assert_eq!(name, "Fake");
    server.join().map_err(|_| "fake server panicked")??;
    println!("packaged consumer: GET /v1/models -> Fake");
    Ok(())
}
