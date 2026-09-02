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
    collections::HashSet,
    fs::File,
    io::{BufRead, BufReader},
    path::Path,
    path::PathBuf,
};

use log;

include!(concat!(env!("OUT_DIR"), "/c_config.cgroup.rs"));
include!(concat!(env!("OUT_DIR"), "/c_config.cgroup.serde.rs"));

// set of active controllers
type Controllers = HashSet<Controller>;

impl TryFrom<&str> for Controller {
    type Error = crate::Error;
    fn try_from(value: &str) -> std::result::Result<Self, Self::Error> {
        match value {
            "cpu" => Ok(Controller::Cpu),
            "cpuset" => Ok(Controller::Cpuset),
            "freezer" => Ok(Controller::Freezer),
            "hugetlb" => Ok(Controller::Hugetlb),
            "io" => Ok(Controller::Io),
            "memory" => Ok(Controller::Memory),
            "perf_event" => Ok(Controller::PerfEvent),
            "pids" => Ok(Controller::Pids),
            "rdma" => Ok(Controller::Rdma),
            "misc" => Ok(Controller::Misc),
            unspecified => Err(crate::Error::ConversionFailed(format!(
                "unknown cgroup controller: {unspecified}"
            ))),
        }
    }
}

impl TryFrom<String> for Controller {
    type Error = crate::Error;
    fn try_from(value: String) -> std::result::Result<Self, Self::Error> {
        Controller::try_from(value.as_str())
    }
}

pub fn get_cgroup_controllers(pid: libc::pid_t) -> crate::Result<Controllers> {
    // Step 1: get cgroup of pid
    let pid_cgroup = get_cgroup(pid)?;
    let path_cgroup = PathBuf::from("/sys/fs/cgroup")
        .join(&pid_cgroup)
        .join("cgroup.controllers");

    let f_cgroup_controller = File::open(&path_cgroup).unwrap_or_else(|e| {
        panic!(
            "Failed to open cgroup controllers file for PID '{}' at '{}': {}",
            pid,
            path_cgroup.to_string_lossy(),
            e
        );
    });

    log::debug!("Reading {}", path_cgroup.display());

    let reader = BufReader::new(f_cgroup_controller);
    let cgroup_controllers = reader
        .lines()
        .filter(std::result::Result::is_ok)
        .map(std::result::Result::unwrap)
        .map(|line| {
            let elements: Vec<_> = line
                .split_ascii_whitespace()
                .map(|elem| elem.to_string())
                .collect();

            elements.into_iter()
        })
        .flatten()
        .filter_map(|entry| {
            if let Ok(controller) = Controller::try_from(entry.as_str()) {
                Some(controller)
            } else {
                log::error!("Unknown controller entry encountered: {entry}");
                None
            }
        })
        .collect();

    Ok(cgroup_controllers)
}

pub fn get_cpu_max(pid: libc::pid_t) -> crate::Result<String> {
    let pid_cgroup = get_cgroup(pid)?;
    let pathbuf_cgroup = PathBuf::from("/sys/fs/cgroup").join(&pid_cgroup);
    let mut path_cgroup = pathbuf_cgroup.as_path();

    while path_cgroup != Path::new("/sys/fs/cgroup") {
        let f_cgroup_controller = File::open(path_cgroup.join("cpu.max"));
        if let Ok(f_cgroup_controller) = f_cgroup_controller {
            let mut reader = BufReader::new(f_cgroup_controller);
            let mut content = String::new();
            reader.read_line(&mut content)?;

            return Ok(content);
        }

        path_cgroup = path_cgroup.parent().unwrap();
        log::debug!("Did not detect cgroup limit, evaluating parent cgroup");
    }

    log::debug!("Did not detect cgroup limit for PID {pid_cgroup}''");
    Ok(String::new())
}

pub fn get_memory_max(pid: libc::pid_t) -> crate::Result<String> {
    let pid_cgroup = get_cgroup(pid)?;
    let pathbuf_cgroup = PathBuf::from("/sys/fs/cgroup").join(&pid_cgroup);
    let mut path_cgroup = pathbuf_cgroup.as_path();

    while path_cgroup != Path::new("/sys/fs/cgroup") {
        log::debug!("Attempting to access {}", path_cgroup.display());

        let f_cgroup_controller = File::open(path_cgroup.join("memory.max"));

        if !f_cgroup_controller.is_ok() {
            path_cgroup = path_cgroup.parent().unwrap();
            log::debug!("No limit configured at this level, continuing...");
            continue;
        }

        let mut reader = BufReader::new(f_cgroup_controller.unwrap());
        let mut content = String::new();
        reader.read_line(&mut content)?;

        let limit = content.trim();

        log::debug!("Found limit {limit}, checking...");

        if limit != "max" {
            log::debug!(
                "Found cgroup limit: '{limit}' at  '{}'",
                path_cgroup.display()
            );
            return Ok(content);
        }

        path_cgroup = path_cgroup.parent().unwrap();
        log::debug!("Cgroup limit is 'max', continuing...");
    }

    log::debug!("Did not detect cgroup limit at '{}'", path_cgroup.display());
    Ok(String::new())
}

pub fn get_cgroup(pid: libc::pid_t) -> crate::Result<String> {
    let path = PathBuf::from(format!("/proc/{pid}/cgroup"));
    let f_cgroup = File::open(path)?;
    let reader = BufReader::new(f_cgroup);
    let mut cgroups: Vec<_> = reader
        .lines()
        .filter(std::result::Result::is_ok)
        .map(std::result::Result::unwrap)
        .collect();
    // cgroup v2 -> only one entry
    if cgroups.len() != 1 {
        return Err(crate::Error::CgroupError);
    }

    let cgroup = cgroups.pop().unwrap();
    // remove "0::" prefix
    let cgroup = cgroup.strip_prefix("0::/").unwrap().to_string();

    Ok(cgroup)
}

pub fn cgroup_config(pid: libc::pid_t) -> crate::Result<Config> {
    log::info!("Collecting cgroup config for PID {}", pid);
    let mut proto_cgroup_conf = Config::default();
    proto_cgroup_conf.cgroup = get_cgroup(pid)?;

    let controllers = get_cgroup_controllers(pid)?;
    proto_cgroup_conf.controllers = controllers
        .iter()
        .map(|controller| *controller as i32)
        .collect();

    log::debug!("Active cgroup controllers: {controllers:?}");

    let cpu_max = get_cpu_max(pid)?;
    let memory_max = get_memory_max(pid)?;

    if !cpu_max.is_empty() {
        proto_cgroup_conf
            .interface_files
            .insert(format!("cpu.max"), cpu_max);
    }

    if !memory_max.is_empty() {
        proto_cgroup_conf
            .interface_files
            .insert(format!("memory.max"), memory_max);
    }

    Ok(proto_cgroup_conf)
}
