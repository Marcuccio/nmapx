# nmapx
Fast and reliable rust implementation of xml to json parser for nmap scans.

```bash
nmap serializer & deserializer

Usage: nmapx [OPTIONS] <NMAP>...

Arguments:
  <NMAP>...  The XML files to use

Options:
  -c, --csv              Outputs in CSV format
  -j, --json             Outputs in JSON format
  -o, --output <OUTPUT>  Specifies the base name of the output file. The correct extension will be appended based on the selected format
  -h, --help             Print help
  -V, --version          Print version
```

## Installation

You can easily install this package using Cargo, Rust's package manager and build tool. Before proceeding, ensure you have Rust and Cargo installed on your system. If you do not have Rust installed, you can download it from [the official Rust website](https://www.rust-lang.org/tools/install).

```sh
cargo install nmapx
```

## How to use it

```bash
nmapx nmap_report.xml
[WRN] Use with caution. You are responsible for your actions.

```

### ... or use nmapx in your projects as lib

```rust
use nmapx::from_str;

fn main() {

    let file: String = std::fs::read_to_string(xml).unwrap();
    let scan: nmapx::Scan = nmapx::from_str(&file).unwrap();
    let j = serde_json::to_string(&scan).unwrap();
    
    println!("{}", j);
}
````
# Contribute

Contributions are always welcome! Please create a PR to add Github Profile.

## :pencil: License

This project is licensed under [GPL-3.0](https://opensource.org/license/gpl-3-0/) license.

## :man_astronaut: Show your support

Give a ⭐️ if this project helped you!
