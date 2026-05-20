# cert-x-tractor
Extract certificates from executables. We bruteforce extraction if
executable headers aren't reliable (ex.: if CertificateTable size exceeds
total file length). This is usefull when attackers tamper
with executable structure in order to hinder automatic extraction of
certificates.

Only supports PE files (for now)

## How to use
```bash
cert-x-tractor -s -p /path/to/pe/file.exe # this will outpout cert subject/serial and pem
```
### help :
```bash
cert-x-tractor -h
Extract x509 certs from PE files (using bruteforce for badly formed headers)

Usage: cert-x-tractor [OPTIONS] <FILE>

Arguments:
  <FILE>  File to extract certs from

Options:
  -p, --pem              output certs as pem
  -s, --show-cert-info   show subject/serial of every cert found 
  -o, --output <OUTPUT>  save certificates to specified file
  -v, --verbose          show verbose output
  -h, --help             Print help
  -V, --version          Print version
```

## How to build
### Natively
```bash
cargo build --release
```
### For windows from linux
Note: Might need to install additional packages from package manager (i.e: MinGW)
```bash
rustup target add x86_64-pc-windows-gnu
cargo build --release --target x86_64-pc-windows-gnu
```