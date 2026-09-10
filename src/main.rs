mod address;
mod config;
mod dashboard;
mod dns;
mod logging;
mod policy;
mod smtp;

use std::{
    fs,
    io::{self, BufRead, Write},
    net::SocketAddr,
    path::{Path, PathBuf},
};

use anyhow::{Context, Result, bail};
use clap::{Parser, Subcommand, ValueEnum};

use crate::{address::Resolution, config::Config};

#[derive(Parser, Debug)]
#[command(
    name = "retiremx",
    version,
    about = "SMTP address migration and routing front end"
)]
struct Cli {
    #[arg(
        short,
        long,
        default_value = "/etc/retiremx/retiremx.md",
        global = true
    )]
    config: PathBuf,
    #[command(subcommand)]
    command: Option<Command>,
}

#[derive(Subcommand, Debug)]
enum Command {
    /// Resolve addresses without opening an SMTP listener.
    Query {
        #[arg(long, value_enum, default_value_t = Output::Plain)]
        output: Output,
        addresses: Vec<String>,
    },
    /// Start the SMTP service.
    Smtp {
        #[arg(long)]
        bind: Option<String>,
        #[arg(long)]
        port: Option<u16>,
        #[arg(long)]
        event_log: Option<PathBuf>,
    },
    /// Aggregate recipient decisions from structured logs.
    Dashboard {
        #[arg(short, long)]
        input: Option<PathBuf>,
    },
}

#[derive(Clone, Copy, Debug, ValueEnum)]
enum Output {
    Plain,
    Json,
}

fn main() -> Result<()> {
    let cli = Cli::parse();
    let command = cli.command.unwrap_or(Command::Query {
        output: Output::Plain,
        addresses: Vec::new(),
    });
    match command {
        Command::Query { output, addresses } => query(&cli.config, output, addresses),
        Command::Smtp {
            bind,
            port,
            event_log,
        } => {
            let config = load_config(&cli.config, "smtp")?;
            let listen = listen_address(config.bind, bind.as_deref(), port)?;
            smtp::serve(config, listen, cli.config, event_log)
        }
        Command::Dashboard { input } => dashboard::run(input),
    }
}

fn listen_address(
    configured: SocketAddr,
    bind: Option<&str>,
    port: Option<u16>,
) -> Result<SocketAddr> {
    let mut listen = configured;
    if let Some(bind) = bind {
        listen = if let Ok(address) = bind.parse::<SocketAddr>() {
            address
        } else if let Ok(address) = bind.parse::<std::net::IpAddr>() {
            SocketAddr::new(address, listen.port())
        } else {
            bail!("invalid bind address {bind}");
        };
    }
    if let Some(port) = port {
        listen.set_port(port);
    }
    Ok(listen)
}

fn query(path: &Path, output: Output, addresses: Vec<String>) -> Result<()> {
    let config = load_config(path, "query")?;
    if addresses.is_empty() {
        let stdin = io::stdin();
        for line in stdin.lock().lines() {
            let address = line.context("reading address from stdin")?;
            if !address.trim().is_empty() {
                print_resolution(&config, output, address.trim())?;
            }
        }
    } else {
        for address in addresses {
            print_resolution(&config, output, &address)?;
        }
    }
    Ok(())
}

fn load_config(path: &Path, mode: &str) -> Result<Config> {
    let source = match fs::read_to_string(path) {
        Ok(source) => source,
        Err(error) => {
            logging::event(
                "configuration_error",
                [
                    ("path", serde_json::json!(path.display().to_string())),
                    ("mode", serde_json::json!(mode)),
                    ("error", serde_json::json!(error.to_string())),
                ],
            );
            return Err(error).with_context(|| format!("reading configuration {}", path.display()));
        }
    };
    match Config::from_markdown(&source) {
        Ok(config) => {
            logging::event(
                "configuration_loaded",
                [
                    ("path", serde_json::json!(path.display().to_string())),
                    ("mode", serde_json::json!(mode)),
                ],
            );
            Ok(config)
        }
        Err(error) => {
            logging::event(
                "configuration_error",
                [
                    ("path", serde_json::json!(path.display().to_string())),
                    ("mode", serde_json::json!(mode)),
                    ("error", serde_json::json!(error.to_string())),
                ],
            );
            Err(error).context("loading configuration")
        }
    }
}

fn print_resolution(config: &Config, output: Output, address: &str) -> Result<()> {
    let resolution = config.resolver.resolve(address);
    match output {
        Output::Plain => print_plain(&resolution),
        Output::Json => println!("{}", serde_json::to_string_pretty(&resolution)?),
    }
    io::stdout().flush().context("flushing query output")?;
    Ok(())
}

fn print_plain(resolution: &Resolution) {
    match resolution {
        Resolution::Retired { replacements, .. } => {
            replacements.iter().for_each(|r| println!("{r}"))
        }
        Resolution::Unknown {
            message, action, ..
        } => println!("{message} ({action:?})"),
    }
}

#[cfg(test)]
mod tests {
    use super::listen_address;
    use std::net::SocketAddr;

    #[test]
    fn listener_options_override_configuration() {
        let configured: SocketAddr = "0.0.0.0:25".parse().unwrap();
        assert_eq!(
            listen_address(configured, Some("127.0.0.1"), Some(2525)).unwrap(),
            "127.0.0.1:2525".parse().unwrap()
        );
        assert_eq!(
            listen_address(configured, Some("127.0.0.1:2600"), Some(2525)).unwrap(),
            "127.0.0.1:2525".parse().unwrap()
        );
    }

    #[test]
    fn listener_options_fall_back_to_configuration() {
        let configured: SocketAddr = "127.0.0.1:2525".parse().unwrap();
        assert_eq!(listen_address(configured, None, None).unwrap(), configured);
    }
}
