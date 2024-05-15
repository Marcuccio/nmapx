use std::{error::Error, io, path::PathBuf};

use serde::{Deserialize, Serialize};
use csv::{Terminator, Writer};

use serde_xml_rs;

mod util;

pub fn as_json<W: io::Write>(list_of_nmaps: Vec<PathBuf>, w: W) -> Result<(), Box<dyn Error>> {

    let mut collector: Vec<Host> = vec![];

    for nmap in list_of_nmaps {
        util::debug(format!("[+] Found nmap file"));

        let scan = from_file(&nmap)?;

        collector.extend_from_slice(&scan.host);
    }

    util::debug(format!("[+] Collector length: {}", collector.len()));

    // Serialize the collector vector into JSON and write it using the writer provided
    serde_json::to_writer(w, &collector);

    Ok(())
}

pub fn as_csv<W: io::Write>(list_of_nmaps: Vec<PathBuf>, w: W) -> Result<(), Box<dyn Error>>  {
    
    let mut wtr = csv::WriterBuilder::new()
        .has_headers(false)
        .terminator(Terminator::CRLF)
        .from_writer(w);

    let header = vec![
        "addr", "addrtype", "port", "protocol", "state", "service"
    ];
    
    wtr.write_record(header)?;

    for nessus in list_of_nmaps {
        let scan = from_file(&nessus)?;
        to(&scan, &mut wtr)?;
    }
    
    wtr.flush()?;
    Ok(())
}

fn to<W: io::Write>(scan: &Scan, wtr: &mut Writer<W>) -> Result<(), Box<dyn Error>> {
    
    for host in scan.host.iter() {
        let address = &host.address;
        
        for ports in host.ports.iter() {
                match &ports.port {
                    Some(port) => {
                        for p in port.iter() {
                            let row: Row = Row { address: address.clone(), port: p.clone() };

                            if let Err(e) = wtr.serialize(&row) {
                                util::error(format!("[Error] Failed to serialize row {:?}: {}", address, e));
                            }
                        }
                    },
                    
                    None => unimplemented!()
                }
        }
    }

    Ok(())
}


pub fn from_file(xml: &PathBuf) -> Result<Scan, serde_xml_rs::Error> {
    
    let file = std::fs::read_to_string(xml)?;

    from_str(file)
}
#[derive(Deserialize, Serialize)]

struct Row {
    pub address: Address,
    pub port: Port

}


/// from_str Nmap Reports
pub fn from_str<I: Into<String>>(buffer: I) -> Result<Scan, serde_xml_rs::Error> {
    let nmaprun: Scan = serde_xml_rs::from_reader(buffer.into().as_bytes())?;
    Ok(nmaprun)
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
    #[serde(skip_serializing_if = "Option::is_none")]
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
    #[serde(skip_serializing_if = "Option::is_none")]
    pub uptime: Option<Uptime>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tcpsequence: Option<Tcpsequence>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ipidsequence: Option<Ipidsequence>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tcptssequence: Option<Tcptssequence>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub times: Option<Times>
}

#[derive(Debug, Clone, PartialEq, Deserialize, Serialize)]
pub struct Address { pub addr: String, pub addrtype: String}

#[derive(Debug, Clone, PartialEq, Deserialize, Serialize)]
pub struct Hostnames {
    #[serde(skip_serializing_if = "Option::is_none")]
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
    #[serde(skip_serializing_if = "Option::is_none")]
    pub protocol: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub portid: Option<String>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub state: Option<State>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub service: Option<Service>,
}

#[derive(Debug, Clone, PartialEq, Deserialize, Serialize)]
pub struct State { pub state: String, pub reason: String, pub reason_ttl: String}

#[derive(Debug, Clone, PartialEq, Deserialize, Serialize)]
pub struct Service { 
    #[serde(skip_serializing_if = "Option::is_none")]
    pub name: Option<String>, 
    #[serde(skip_serializing_if = "Option::is_none")]
    pub product: Option<String>, 
    #[serde(skip_serializing_if = "Option::is_none")]
    pub servicefp: Option<String>, 
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tunnel: Option<String>, 
    #[serde(skip_serializing_if = "Option::is_none")]
    pub method: Option<String>, 
    #[serde(skip_serializing_if = "Option::is_none")]
    pub conf: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
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
    #[serde(skip_serializing_if = "Option::is_none")]
    pub portid: Option<String>
}

#[derive(Debug, Clone, PartialEq, Deserialize, Serialize)]
pub struct Uptime { pub seconds: String, pub lastboot: String}

#[derive(Debug, Clone, PartialEq, Deserialize, Serialize)]
pub struct Tcpsequence { 
    pub index: String, pub difficulty: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub values: Option<String>
}

#[derive(Debug, Clone, PartialEq, Deserialize, Serialize)]
pub struct Ipidsequence { pub class: String, 
    #[serde(skip_serializing_if = "Option::is_none")]
    pub values: Option<String>
}

#[derive(Debug, Clone, PartialEq, Deserialize, Serialize)]
pub struct Tcptssequence { pub class: String, 
    #[serde(skip_serializing_if = "Option::is_none")]
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
    #[serde(skip_serializing_if = "Option::is_none")]
    pub portused: Option<Vec<Portused>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub osmatch: Option<Vec<Osmatch>>
}

#[derive(Debug, Clone, PartialEq, Deserialize, Serialize)]
pub struct Osmatch { 
    pub name:String,
    pub accuracy:String,
    pub line:String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub osclass: Option<Vec<Osclass>>,
}


#[derive(Debug, Clone, PartialEq, Deserialize, Serialize)]
pub struct Osclass {
    pub r#type: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub vendor: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub osfamily: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub osgen: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub accuracy: Option<String>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub cpe: Option<Vec<String>>
}

#[derive(Debug, Clone, PartialEq, Deserialize, Serialize)]
pub struct CPE {
    name: Option<String>
}