// Copyright (c) 2022 - 2026 Fraunhofer AISEC
// Fraunhofer-Gesellschaft zur Foerderung der angewandten Forschung e.V.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

use std::collections::{HashMap, HashSet};
use std::fmt::Display;
use std::fs::File;
use std::hash::Hash;
use std::io::{BufRead, BufReader};
use std::path::PathBuf;

include!(concat!(env!("OUT_DIR"), "/c_config.caps.rs"));
include!(concat!(env!("OUT_DIR"), "/c_config.caps.serde.rs"));

impl Display for Capability {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let cap = match self {
            Self::CapChown => "CAP_CHOWN",
            Self::CapDacOverride => "CAP_DAC_OVERRIDE",
            Self::CapDacReadSearch => "CAP_DAC_READ_SEARCH",
            Self::CapFowner => "CAP_FOWNER",
            Self::CapFsetid => "CAP_FSETID",
            Self::CapKill => "CAP_KILL",
            Self::CapSetgid => "CAP_SETGID",
            Self::CapSetuid => "CAP_SETUID",
            Self::CapSetpcap => "CAP_SETPCAP",
            Self::CapLinuxImmutable => "CAP_LINUX_IMMUTABLE",
            Self::CapNetBindService => "CAP_NET_BIND_SERVICE",
            Self::CapNetBroadcast => "CAP_NET_BROADCAST",
            Self::CapNetAdmin => "CAP_NET_ADMIN",
            Self::CapNetRaw => "CAP_NET_RAW",
            Self::CapIpcLock => "CAP_IPC_LOCK",
            Self::CapIpcOwner => "CAP_IPC_OWNER",
            Self::CapSysModule => "CAP_SYS_MODULE",
            Self::CapSysRawio => "CAP_SYS_RAWIO",
            Self::CapSysChroot => "CAP_SYS_CHROOT",
            Self::CapSysPtrace => "CAP_SYS_PTRACE",
            Self::CapSysPacct => "CAP_SYS_PACCT",
            Self::CapSysAdmin => "CAP_SYS_ADMIN",
            Self::CapSysBoot => "CAP_SYS_BOOT",
            Self::CapSysNice => "CAP_SYS_NICE",
            Self::CapSysResource => "CAP_SYS_RESOURCE",
            Self::CapSysTime => "CAP_SYS_TIME",
            Self::CapSysTtyConfig => "CAP_SYS_TTY_CONFIG",
            Self::CapMknod => "CAP_MKNOD",
            Self::CapLease => "CAP_LEASE",
            Self::CapAuditWrite => "CAP_AUDIT_WRITE",
            Self::CapAuditControl => "CAP_AUDIT_CONTROL",
            Self::CapSetfcap => "CAP_SETFCAP",
            Self::CapMacOverride => "CAP_MAC_OVERRIDE",
            Self::CapMacAdmin => "CAP_MAC_ADMIN",
            Self::CapSyslog => "CAP_SYSLOG",
            Self::CapWakeAlarm => "CAP_WAKE_ALARM",
            Self::CapBlockSuspend => "CAP_BLOCK_SUSPEND",
            Self::CapAuditRead => "CAP_AUDIT_READ",
            Self::CapPerfmon => "CAP_PERFMON",
            Self::CapBpf => "CAP_BPF",
            Self::CapCheckpointRestore => "CAP_CHECKPOINT_RESTORE",
            Self::Unspecified => "UNSPECIFIED",
        };

        f.write_str(cap)
    }
}

#[derive(Debug, Clone, Copy, Hash, PartialEq, Eq)]
pub enum CapSet {
    CapInh,
    CapPrm,
    CapEff,
    CapBnd,
    CapAmb,
}

impl Display for CapSet {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_fmt(format_args!("{self:#?}"))
    }
}

impl Capability {
    // index of first capability
    pub fn first() -> u64 {
        (Self::CapChown as i32 - 1) as u64
    }

    // index of last capability
    pub fn last() -> u64 {
        (Self::CapCheckpointRestore as i32 - 1) as u64
    }
}

impl CapSet {
    fn list() -> Vec<CapSet> {
        vec![
            Self::CapInh,
            Self::CapPrm,
            Self::CapEff,
            Self::CapBnd,
            Self::CapAmb,
        ]
    }

    pub fn parse_proc_status(
        pid: libc::pid_t,
    ) -> crate::Result<HashMap<CapSet, HashSet<Capability>>> {
        let path = PathBuf::from(format!("/proc/{pid}/status"));
        let f_status = File::open(path)?;
        let status_reader = BufReader::new(f_status);
        let status_content: Vec<_> = status_reader
            .lines()
            .filter(std::result::Result::is_ok)
            .map(std::result::Result::unwrap)
            .collect();

        let mut set_map = HashMap::new();

        for set in Self::list() {
            let caps_encoded = status_content
                .iter()
                .find(|line| line.contains(&set.to_string()))
                .unwrap();
            let caps_encoded =
                u64::from_str_radix(&caps_encoded.split_ascii_whitespace().last().unwrap(), 16)
                    .map_err(|err| crate::Error::ConversionFailed(format!("{err}")))?;

            let mut caps = HashSet::new();

            // decode caps
            for i in Capability::first()..=Capability::last() {
                if (caps_encoded & (1u64 << i)) > 0 {
                    let cap = Capability::from_i32((i + 1) as i32).ok_or(
                        crate::Error::ConversionFailed(format!("Could not convert capability")),
                    )?;
                    caps.insert(cap);
                }
            }

            set_map.insert(set, caps);
        }

        Ok(set_map)
    }
}

pub fn caps_config(pid: libc::pid_t) -> crate::Result<Config> {
    let cap_sets = CapSet::parse_proc_status(pid)?;
    let mut proto_config = Config::default();

    log::info!("Collecting capabilitiy sets for pid {pid}");

    for (k, v) in cap_sets {
        match k {
            CapSet::CapAmb => proto_config.cap_amb = v.iter().map(|cap| *cap as i32).collect(),
            CapSet::CapBnd => proto_config.cap_bnd = v.iter().map(|cap| *cap as i32).collect(),
            CapSet::CapEff => proto_config.cap_eff = v.iter().map(|cap| *cap as i32).collect(),
            CapSet::CapInh => proto_config.cap_inh = v.iter().map(|cap| *cap as i32).collect(),
            CapSet::CapPrm => proto_config.cap_prm = v.iter().map(|cap| *cap as i32).collect(),
        }
    }
    Ok(proto_config)
}
