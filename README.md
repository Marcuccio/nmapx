# nmapx
Fast and reliable rust implementation of xml to json parser for nmap scans.

```bash
nmapx -h
nmapx 1.0.0 (c) 2023 by abut0n


Usage: nmapx [options]
Options:
  -h, --help                    Print this help
  -v, --version                 Print version information
  -x, --xml                     Nmap xml to parse
```

## How to use it

```bash
nmapx -x nmap_report.xml > out.json
[WRN] Use with caution. You are responsible for your actions.
[WRN] Developers assume no liability and are not responsible for any misuse or damage.
```

## ... or use nmapx in your projects

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
