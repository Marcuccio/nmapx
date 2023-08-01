use serde_xml_rs::Error;
use serde_xml_rs;
use serde::{Deserialize, Serialize};



/// from_str Qualys Reports
pub fn from_str<I: Into<String>>(buffer: I) -> Result<Scan, Error> {
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
    pub os: Os,
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
pub struct Extrareasons { pub reason: String, pub count: String, pub proto: String, pub ports: String}

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