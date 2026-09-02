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

use std::{
    fs::File,
    io::{BufRead, BufReader},
    path::PathBuf,
};

use super::ns;
use crate::{get_pid_list, map_io_error, Error, Result};

include!(concat!(env!("OUT_DIR"), "/c_config.user_ns.rs"));
include!(concat!(env!("OUT_DIR"), "/c_config.user_ns.serde.rs"));

impl TryFrom<&str> for IdMapping {
    type Error = Error;
    fn try_from(value: &str) -> std::result::Result<Self, Self::Error> {
        // handle potential tabs
        let value = value.replace("\t", " ");
        let elems: Vec<_> = value.split_ascii_whitespace().collect();
        if elems.len() != 3 {
            return Err(Error::ConversionFailed(format!("invalid id_map content")));
        }

        let current = elems[0]
            .parse()
            .map_err(|err| Error::ConversionFailed(format!("parse error: {}", err)))?;
        let parent = elems[1]
            .parse()
            .map_err(|err| Error::ConversionFailed(format!("parse error: {}", err)))?;
        let range = elems[2]
            .parse()
            .map_err(|err| Error::ConversionFailed(format!("parse error: {}", err)))?;

        Ok(Self {
            current,
            parent,
            range,
        })
    }
}

impl TryFrom<String> for IdMapping {
    type Error = Error;
    fn try_from(value: String) -> std::result::Result<Self, Self::Error> {
        IdMapping::try_from(value.as_str())
    }
}

impl IdMapping {
    // (uid_map, gid_map)
    pub fn from_pid(pid: libc::pid_t) -> Result<(Vec<IdMapping>, Vec<IdMapping>)> {
        let path = PathBuf::from(format!("/proc/{pid}"));
        let uid_path = path.join("uid_map");
        let gid_path = path.join("gid_map");

        let f_uid_map = File::open(&uid_path).map_err(|e| map_io_error(&uid_path, e))?;
        let f_gid_map = File::open(&gid_path).map_err(|e| map_io_error(&gid_path, e))?;

        let reader = BufReader::new(f_uid_map);
        let uid_mapping = reader
            .lines()
            .filter_map(|r_line| {
                if let Ok(line) = r_line {
                    Some(line)
                } else {
                    log::error!("Error parsing uid_map");
                    None
                }
            })
            .map(|line| IdMapping::try_from(line).unwrap())
            .collect();

        let reader = BufReader::new(f_gid_map);
        let gid_mapping = reader
            .lines()
            .filter_map(|r_line| {
                if let Ok(line) = r_line {
                    Some(line)
                } else {
                    log::error!("Error parsing gid_map");
                    None
                }
            })
            .map(|line| IdMapping::try_from(line).unwrap())
            .collect();

        Ok((uid_mapping, gid_mapping))
    }
}

// check whether identical mapping is used in other user namespaces
fn unique_mapping(pid: libc::pid_t) -> Result<bool> {
    let user_ns = ns::Info::info_by_ns_type(pid, ns::Type::User)?;
    let (uid_mapping, _) = IdMapping::from_pid(pid)?;
    let init_user_ns = ns::Info::info_by_ns_type(1, ns::Type::User)?;

    log::debug!("Searching unique mapping for PID {pid} with uid mapping '{uid_mapping:?}'");

    log::debug!("User namespace of PID '{pid}' is '{user_ns:?}'");
    log::debug!("Initial user namespace is '{init_user_ns:?}'");

    if user_ns.owner != init_user_ns.id {
        log::warn!("user-ns is not a direct child of init-user-ns");
    }

    let pids: Vec<libc::pid_t> = get_pid_list()
        .unwrap()
        .into_iter()
        .filter(|entry| *entry != pid)
        .collect(); // remove own pid from list

    for process in pids {
        let process_user_ns = match ns::Info::info_by_ns_type(process, ns::Type::User) {
            Ok(ns_type) => ns_type,
            Err(e) => {
                log::warn!("Failed to retrieve namespace identifier for PID {process}: {e}, did process stop?");
                continue;
            }
        };

        log::trace!("Processing PID '{process}' with user namespace '{process_user_ns:?}'");

        // exclude init_user_ns mapping
        if process_user_ns.id != user_ns.id
            && process_user_ns.owner == init_user_ns.id
            && process_user_ns.id != init_user_ns.id
        {
            let (process_uid_map, _) = IdMapping::from_pid(process)?;
            log::debug!("Evaluating mapping {process_uid_map:?}");

            for process_entry in process_uid_map {
                for entry in &uid_mapping {
                    if !((process_entry.parent + process_entry.range) <= entry.parent
                        || (entry.parent + entry.range) <= process_entry.parent)
                    {
                        log::warn!("PID '{process}' has same mapping ('{process_entry:?}') as container init PID '{pid}' ({uid_mapping:?})");
                        return Ok(false);
                    }
                }
            }
        }
    }
    Ok(true)
}

pub fn user_ns_config(pid: libc::pid_t) -> Result<Config> {
    log::info!("Collecting user namespace config for PID {pid}");
    let (uid_map, gid_map) = IdMapping::from_pid(pid)?;

    let mut proto_dac_config = Config::default();
    proto_dac_config.uid_map = uid_map.into_iter().map(|line| line.into()).collect();
    proto_dac_config.gid_map = gid_map.into_iter().map(|line| line.into()).collect();
    proto_dac_config.unique_mapping = unique_mapping(pid)?;

    Ok(proto_dac_config)
}
