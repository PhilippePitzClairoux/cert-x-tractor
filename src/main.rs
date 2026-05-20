use goblin::pe::PE;
use std::{fs};
use std::fs::File;
use std::io::Write;
use std::process::exit;
use goblin::pe::options::{ParseMode, ParseOptions};
use x509_parser::prelude::*;
use clap::Parser as ClapParser;
use log::{debug, error, info};
use cert_x_tractor::{as_pem, find_certificates, init_logger, try_from_certificate_table, Error};
use cert_x_tractor::Error::RuntimeError;

#[derive(ClapParser)]
#[command(name = "cert-x-tractor")]
#[command(version = "1.0")]
#[command(about = "Extract x509 certs from PE files (using simple bruteforce)")]
struct Args {

    #[arg(help = "File to extract certs from")]
    file: String,

    #[arg(short, long, default_value = "false", help = "output certs as pem")]
    pem: bool,

    #[arg(short, long, default_value = "false", help = "show subject/serial of every cert found ")]
    show_cert_info: bool,

    #[arg(short, long, default_value = None, help = "save certificates to specified file")]
    output: Option<String>,

    #[arg(short, long, default_value = "false", help = "show verbose output")]
    verbose: bool,
}

fn _main() -> Result<(), Error> {
    let args = Args::parse();
    init_logger(args.verbose);

    info!("Checking: {}", args.file);
    let buffer = fs::read(args.file)?;

    let mut opts = ParseOptions::default();
    opts.parse_attribute_certificates = false;
    opts.parse_mode = ParseMode::Permissive;

    let pe = PE::parse_with_opts(
        &buffer,
        &opts,
    ).map_err(|e| RuntimeError(e.to_string()))?;

    let (file_offset, size) = try_from_certificate_table(pe)
        .unwrap_or((0, buffer.len()));
    let end = std::cmp::min(file_offset+size, buffer.len());

    debug!("offset=0x{:X}, size={}, end=0x{:X}", file_offset, size, end);
    let certs = find_certificates(&buffer, file_offset, end);
    if certs.len() == 0 {
        error!("No certificates were found...");
        exit(-1);
    }

    let mut handlers: Vec<Box<dyn FnMut(&X509Certificate) -> Result<(), std::io::Error>>> = Vec::new();
    if args.show_cert_info {
        handlers.push(Box::new(
            move |cert: &X509Certificate| -> Result<(), std::io::Error> {
                info!("Certificate found: \nsubject: {}\nserial: {}",
                    cert.subject(), cert.raw_serial_as_string());
                Ok(())
            }
        ));
    }

    if args.pem {
        handlers.push(Box::new(
            move |cert: &X509Certificate| -> Result<(), std::io::Error> {
                info!("\n{}\n", as_pem(&cert));
                Ok(())
            }
        ));
    }

    if let Some(f) = args.output {
        let mut file = File::create(f)?;
        handlers.push(Box::new(
            move |cert: &X509Certificate| -> Result<(), std::io::Error> {
                file.write_all(as_pem(cert).as_bytes())?;
                file.flush()?;
                Ok(())
            }
        ));
    }

    for cert in  certs.iter() {
        for handler in handlers.iter_mut() {
            handler(cert)?;
        }
    }

    Ok(())
}

fn main() {
  match _main() {
      Ok(()) => exit(0),
      Err(e) => {
          error!("unexpected error during runtime: {}", e);
          exit(-1);
      }
  }
}