# nmapx
A fast and reliable Rust tool for converting Nmap scan results from XML to JSON or CSV formats.

```bash
>$ nmapx --help
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

#### ... or use nmapx in your projects as lib

```sh
cargo add nmapx
```

# Contribute

Contributions are always welcome! Please create a PR to add Github Profile.

## :pencil: License

This project is licensed under [GPL-3.0](https://opensource.org/license/gpl-3-0/) license.

## :man_astronaut: Show your support

Give a ⭐️ if this project helped you!
