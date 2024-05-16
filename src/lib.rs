use std::{io, path::PathBuf};

use serde::{Deserialize, Serialize};
use csv:: Writer;

use serde_xml_rs;

mod util;

pub fn as_json<W: io::Write>(list_of_nmaps: Vec<PathBuf>, mut w: W) -> Result<(), serde_json::Error> {
    let mut collector: Vec<Host> = vec![];

    for nmap in list_of_nmaps {
        util::debug(format!("[+] Found nmap file: {:?}", nmap));
        
        match from_file(&nmap) {
            Some(scan) => collector.extend_from_slice(&scan.host),
            None => {
                util::error(format!("Failed to read nmap file: {:?}", nmap));
            }
        }
    }

    if let Err(e) = serde_json::to_writer(&mut w, &collector) {
        util::error(format!("Failed to write JSON: {}", e));
        return Err(e);
    }

    Ok(())
}

pub fn as_csv<W: io::Write>(list_of_nmaps: Vec<PathBuf>, mut w: W) -> Result<(), csv::Error> {
    let mut writer = csv::WriterBuilder::new()
        .has_headers(false)
        .terminator(csv::Terminator::CRLF)
        .from_writer(&mut w);

    let header = vec!["addr", "addrtype", "protocol", "portid", "state", "reason", "reason_ttl","name", "product", "tunnel", "method", "conf"];
    
    if let Err(e) = writer.write_record(&header) {
        util::error(format!("Failed to write CSV header: {}", e));
        return Err(e);
    }

    for nmap in list_of_nmaps {
        if let Some(scan) = from_file(&nmap) {
            if let Err(e) = to(&scan, &mut writer) {
                util::error(format!("Failed to convert {:?} to CSV: {}", nmap, e));
            }
        } else {
            util::error(format!("Failed to read Nessus file: {:?}", nmap));
        }
    }
    
    if let Err(e) = writer.flush() {
        util::error(format!("Failed to flush CSV data: {}", e));
        return Err(e.into());
    }
    
    Ok(())
}


fn to<W: io::Write>(scan: &Scan, wtr: &mut Writer<W>) -> Result<(), csv::Error> {
    for host in &scan.host {
        let address = &host.address;
        
        for ports in &host.ports {
            if let Some(port) = &ports.port {
                for p in port {
                    let row = Row {
                        address: address.clone(),
                        port: p.clone(),
                    };
                    wtr.serialize(&row)?
                }
            } else {
                util::info(format!("No port information available for host: {:?}", address));
            }
        }
    }
    Ok(())
}

/// Reads a file and parses it into a Scan struct
pub fn from_file(xml: &PathBuf) -> Option<Scan> {
    let scan = match std::fs::read_to_string(xml) {
        Ok(file_content) => match from_str(&file_content) {
            Ok(scan) => Some(scan),
            Err(e) => {
                util::error(format!("Failed to parse XML: {}", e));
                None
            }
        },
        Err(e) => {
            util::error(format!("Failed to read file: {}", e));
            None
        }
    };
    scan
}

/// Parses an Nmap report from a string
pub fn from_str<I: Into<String>>(buffer: I) -> Result<Scan, serde_xml_rs::Error> {
    let nmaprun: Scan = serde_xml_rs::from_reader(buffer.into().as_bytes())?;
    Ok(nmaprun)
}

#[derive(Debug, Deserialize, Serialize)]
struct Row {
    pub address: Address,
    pub port: Port

}

#[derive(Debug, Clone, PartialEq, Deserialize, Serialize)]
pub struct Scan {
    pub scaninfo: Scaninfo,
    pub verbose: Verbose,
    pub debugging: Debugging,
    pub host: Vec<Host>
}


#[derive(Debug, Clone, PartialEq, Deserialize, Serialize)]
pub struct Scaninfo { 
    pub r#type: String, 
    pub protocol: Option<String>,
    pub numservices: String,
    pub services: String
}

#[derive(Debug, Clone, PartialEq, Deserialize, Serialize)]
pub struct Verbose { pub level: String}

#[derive(Debug, Clone, PartialEq, Deserialize, Serialize)]
pub struct Debugging { pub level: String}


#[derive(Debug, Clone, PartialEq, Deserialize, Serialize)]
pub struct Host {
    pub address: Address,
    pub hostnames: Hostnames,
    pub ports: Vec<Ports>,
    pub os: Option<Os>,
    pub uptime: Option<Uptime>,
    pub tcpsequence: Option<Tcpsequence>,
    pub ipidsequence: Option<Ipidsequence>,
    pub tcptssequence: Option<Tcptssequence>,
    pub times: Option<Times>
}

#[derive(Debug, Clone, PartialEq, Deserialize, Serialize)]
pub struct Address { pub addr: String, pub addrtype: String}

#[derive(Debug, Clone, PartialEq, Deserialize, Serialize)]
pub struct Hostnames {
    pub hostname: Option<Hostname>
} 

#[derive(Debug, Clone, PartialEq, Deserialize, Serialize)]
pub struct Ports {
    pub extraports: Option<Vec<Extraports>>,
    pub port: Option<Vec<Port>>,
}

#[derive(Debug, Clone, PartialEq, Deserialize, Serialize)]
pub struct Extraports {
    pub state: String,
    pub count: String,
    pub extrareasons: Option<Vec<Extrareasons>>, 
}

#[derive(Debug, Clone, PartialEq, Deserialize, Serialize)]
pub struct Hostname {
    pub name: Option<String>,
    pub r#type: String,
}

#[derive(Debug, Clone, PartialEq, Deserialize, Serialize)]
pub struct Port {
    pub protocol: Option<String>,
    pub portid: Option<String>,
    pub state: Option<State>,
    pub service: Option<Service>,
}

#[derive(Debug, Clone, PartialEq, Deserialize, Serialize)]
pub struct State { pub state: String, pub reason: String, pub reason_ttl: String}

#[derive(Debug, Clone, PartialEq, Deserialize, Serialize)]
pub struct Service { 
    pub name: Option<String>, 
    pub product: Option<String>, 
    #[serde(skip_serializing)]
    pub servicefp: Option<String>, 
    pub tunnel: Option<String>, 
    pub method: Option<String>, 
    pub conf: Option<String>,
    #[serde(skip_serializing)]
    pub cpe: Option<Vec<CPE>>
}

#[derive(Debug, Clone, PartialEq, Deserialize, Serialize)]
pub struct Status { pub state: String, pub reason: String, pub reason_ttl: String}

#[derive(Debug, Clone, PartialEq, Deserialize, Serialize)]
pub struct Extrareasons { 
    pub reason: Option<String>, 
    pub count: Option<String>,
    pub proto: Option<String>, 
    pub ports: Option<String>
}

#[derive(Debug, Clone, PartialEq, Deserialize, Serialize)]
pub struct Portused { pub state: String, pub proto: String, 
    pub portid: Option<String>
}

#[derive(Debug, Clone, PartialEq, Deserialize, Serialize)]
pub struct Uptime { pub seconds: String, pub lastboot: String}

#[derive(Debug, Clone, PartialEq, Deserialize, Serialize)]
pub struct Tcpsequence { 
    pub index: String, pub difficulty: String,
    pub values: Option<String>
}

#[derive(Debug, Clone, PartialEq, Deserialize, Serialize)]
pub struct Ipidsequence { pub class: String, 
    pub values: Option<String>
}

#[derive(Debug, Clone, PartialEq, Deserialize, Serialize)]
pub struct Tcptssequence { pub class: String, 
    pub values: Option<String>
}

#[derive(Debug, Clone, PartialEq, Deserialize, Serialize)]
pub struct Times { pub srtt: String, pub rttvar: String, pub to: String}

#[derive(Debug, Clone, PartialEq, Deserialize, Serialize)]
pub struct Finished { pub time: String, pub timestr: String, pub summary: String, pub elapsed: String, pub exit: String}

#[derive(Debug, Clone, PartialEq, Deserialize, Serialize)]
pub struct Hosts { pub up: String, pub down: String, pub total: String}

#[derive(Debug, Clone, PartialEq, Deserialize, Serialize)]
pub struct Os { 
    pub portused: Option<Vec<Portused>>,
    pub osmatch: Option<Vec<Osmatch>>
}

#[derive(Debug, Clone, PartialEq, Deserialize, Serialize)]
pub struct Osmatch { 
    pub name:String,
    pub accuracy:String,
    pub line:String,
    pub osclass: Option<Vec<Osclass>>,
}


#[derive(Debug, Clone, PartialEq, Deserialize, Serialize)]
pub struct Osclass {
    pub r#type: String,
    pub vendor: Option<String>,
    pub osfamily: Option<String>,
    pub osgen: Option<String>,
    pub accuracy: Option<String>,
    pub cpe: Option<Vec<String>>
}

#[derive(Debug, Clone, PartialEq, Deserialize, Serialize)]
pub struct CPE {
    name: Option<String>
}