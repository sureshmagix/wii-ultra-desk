// Phase 1 probe only: no listener, no command execution, no background install.
fn main() {
    let argument = std::env::args().nth(1);
    match argument.as_deref() {
        Some("status") => println!(
            "{{\"phase\":\"foundation\",\"os\":\"{}\",\"arch\":\"{}\",\"remote_access\":false,\"unattended\":false}}",
            std::env::consts::OS, std::env::consts::ARCH
        ),
        _ => {
            eprintln!("Usage: wii-ultra-desk-agent status\nRemote sessions are not implemented.");
            std::process::exit(2);
        }
    }
}
