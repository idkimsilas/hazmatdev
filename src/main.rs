use std::io::Write;

use clap::Parser;
use signal_hook::consts::{SIGINT, SIGTERM};
use signal_hook::iterator::Signals;

pub mod cipher;
pub mod cmd;
pub mod constants;
pub mod hazmat;
pub mod io;
pub mod ll;
pub mod msfat32;
pub mod utils;

#[derive(clap::Subcommand)]
enum AppSubcommand {
    Format,
    Open,
    Sanitize,
}

#[derive(clap::Parser)]
struct AppArg {
    #[clap(subcommand)]
    command: AppSubcommand,

    #[arg(short, long)]
    device: String,
}

// Install a signal handler thread that exits cleanly on SIGINT/SIGTERM.
fn start_exit_handler() {
    std::thread::spawn(|| {
        let Ok(mut signals) = Signals::new(vec![SIGTERM, SIGINT]) else {
            eprintln!("failed to init the signal capturer; future ctrl+c will not be caught");
            return;
        };

        if let Some(v) = signals.forever().next() {
            let signal = match v {
                SIGTERM => "SIGTERM".to_owned(),
                SIGINT => "SIGINT".to_owned(),
                _ => v.to_string(),
            };

            println!("signal {signal} caught");
            std::process::exit(0);
        }
    });
}

// Require an explicit destructive-action confirmation before format/sanitize.
fn confirm_danger(device: &str) {
    println!("you're about to perform a action that will destroy the data on '{device}'");
    print!("to confirm this action write yes in capital letters: ");
    std::io::stdout().flush().ok();

    let mut line = String::new();
    std::io::stdin()
        .read_line(&mut line)
        .expect("stdin reading failed");

    if line.trim() == "YES" {
        return;
    }

    println!("operation aborted");

    std::process::exit(0);
}

// Parse CLI arguments, guard destructive commands, and dispatch subcommands.
fn main() -> anyhow::Result<()> {
    let args = AppArg::parse();

    start_exit_handler();

    if matches!(args.command, AppSubcommand::Format)
        || matches!(args.command, AppSubcommand::Sanitize)
    {
        confirm_danger(&args.device);
    }

    match args.command {
        AppSubcommand::Format => {
            cmd::format(&args.device)?;
        }
        AppSubcommand::Sanitize => cmd::sanitize(&args.device)?,
        AppSubcommand::Open => cmd::open(&args.device)?,
    }

    Ok(())
}
