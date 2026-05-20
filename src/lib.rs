use base64::Engine;
use base64::engine::general_purpose;
use env_logger::Target;
use goblin::elf::Elf;
use goblin::mach::{Mach, MachO};
use goblin::mach::load_command::CommandVariant::CodeSignature;
use goblin::pe::data_directories::DataDirectoryType;
use goblin::pe::PE;
use log::{debug, warn, LevelFilter};
use thiserror::Error as ThisError;
use x509_parser::certificate::{X509Certificate, X509CertificateParser};
use x509_parser::nom::{AsBytes, Offset, Parser};

#[derive(ThisError, Debug)]
pub enum Error {
    #[error(transparent)]
    IoError(#[from] std::io::Error),

    #[error("{0}")]
    RuntimeError(String)
}

pub fn parse_x509(data: &[u8], start: usize, end: usize) -> Option<(X509Certificate<'_>, usize)> {
    let mut s = start;
    let mut parser = X509CertificateParser::new()
        .with_deep_parse_extensions(true);

    while s < end {
        // since this parses only the first certificate it finds,
        // we can then jump to the end of the certificate
        match parser.parse(&data[s..end]) {
            Ok((remain, x509)) => {
                let x509_end = data.offset(remain);
                return Some((x509.to_owned(), x509_end));
            },
            Err(_) => (),
        };
        s += 1;
    }
    None
}

pub fn find_certificates(data: &[u8], start: usize, end: usize) -> Vec<X509Certificate<'_>> {
    let mut result: Vec<X509Certificate> = Vec::new();

    let mut offset: usize = start;
    loop {
        match parse_x509(data, offset, end) {
            Some((cert, _offset)) => {
                result.push(cert);
                debug!("jumping: from=0x{:X}, to=0x{:X}", offset, _offset);
                offset = _offset;
            }
            None => break,
        }
    }

    result
}

pub fn try_from_certificate_table(pe: PE) -> Option<(usize, usize)> {

    match pe.header.optional_header {
        Some(header) => {

            for (dt, d) in header.data_directories.dirs() {
                match dt {
                    DataDirectoryType::CertificateTable => {
                        return Some((d.virtual_address as usize, d.size as usize));
                    }
                    _ => (),
                }
            }

            warn!("No CertificateTable found");
        }
        None => warn!("No optional header found"),
    }
    None
}

const LINKEDIT_SEGNAME: &str = "__LINKEDIT";
pub fn try_from_load_commands(mach: MachO) -> Option<(usize, usize)> {
    for cmd in mach.load_commands.iter() {
        match cmd.command {
            CodeSignature(cs) => {
                let linkedit_segment = mach.segments.iter()
                    .find(|seg| LINKEDIT_SEGNAME.as_bytes() == seg.segname.as_bytes());

                if let Some(segment) = linkedit_segment {
                    let file_offset = segment.fileoff as usize + cs.dataoff as usize;
                    return Some(( file_offset, cs.datasize as usize));
                }

                warn!("could not find {} segment", LINKEDIT_SEGNAME);
                return None
            },
            _ => (),
        }
    }

    None
}


pub fn as_pem(cert: &X509Certificate) -> String {
    let mut b64 = general_purpose::STANDARD.encode(cert.as_raw());

    let new_lines = (b64.len() as f64 / 64f64).ceil() as usize;
    debug!("pem line breaks: buffer_len={}, new_lines={}", b64.len(), new_lines);

    for i in 1..new_lines {
        b64.insert((i*64)+(i-1), '\n');
    }

    format!("-----BEGIN CERTIFICATE-----\n{}\n-----END CERTIFICATE-----", b64)
}

pub fn init_logger(verbose: bool) {
    let log_level = if verbose {
        LevelFilter::Debug
    } else {
        LevelFilter::Info
    };

    let mut l = env_logger::Builder::from_default_env();
    l.target(Target::Stdout);
    l.filter_level(log_level);
    l.init();
}
