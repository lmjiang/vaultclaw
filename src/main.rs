use clap::Parser;
use vaultclaw::cli::commands::{Cli, execute};

fn main() {
    // Chrome native messaging host detection: Chrome spawns the host binary
    // with the extension origin (chrome-extension://...) as the first argument.
    let args: Vec<String> = std::env::args().collect();
    if args.len() >= 2 && args[1].starts_with("chrome-extension://") {
        if let Err(e) = vaultclaw::browser::host::run_native_host() {
            eprintln!("Native host error: {}", e);
            std::process::exit(1);
        }
        return;
    }

    let cli = Cli::parse();
    if let Err(e) = execute(cli) {
        eprintln!("Error: {}", e);
        std::process::exit(1);
    }
}
