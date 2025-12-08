mod cli;
mod types;
mod yubikey_handler;
use crate::cli::Cli;
use crate::yubikey_handler::device::RealSmartCard;
use clap::Parser;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let device = Box::new(RealSmartCard::new()?);
    let cli = Cli::parse();
    cli::execute(cli, device)
}
