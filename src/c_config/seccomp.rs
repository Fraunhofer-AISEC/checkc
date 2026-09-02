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
    ffi::OsStr,
    fmt::Display,
    fs::File,
    io::{BufRead, BufReader},
    path::{Path, PathBuf},
};

use crate::{Error, Result};
use libc;
use nix;
use regex::Regex;

include!(concat!(env!("OUT_DIR"), "/c_config.seccomp.rs"));
include!(concat!(env!("OUT_DIR"), "/c_config.seccomp.serde.rs"));

impl Display for Mode {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::SeccompModeDisabled => f.write_str("SECCOMP_MODE_DISABLED"),
            Self::SeccompModeStrict => f.write_str("SECCOMP_MODE_STRICT"),
            Self::SeccompModeFilter => f.write_str("SECCOMP_MODE_FILTER"),
            Self::Unspecified => f.write_str("UNSPECIFIED"),
        }
    }
}

impl TryFrom<libc::c_uint> for Mode {
    type Error = Error;

    fn try_from(value: libc::c_uint) -> std::result::Result<Self, Self::Error> {
        match value {
            libc::SECCOMP_MODE_DISABLED => Ok(Self::SeccompModeDisabled),
            libc::SECCOMP_MODE_STRICT => Ok(Self::SeccompModeStrict),
            libc::SECCOMP_MODE_FILTER => Ok(Self::SeccompModeFilter),
            _ => return Err(Error::ConversionFailed(format!("unknown seccomp mode"))),
        }
    }
}

// syscall tests

fn test_remount_sysfs() -> SyscallResult {
    let mut result = SyscallResult::default();
    if let Err(errno) = nix::mount::mount(
        None::<&OsStr>,
        Path::new("/sys"),
        None::<&OsStr>,
        nix::mount::MsFlags::empty(),
        None::<&OsStr>,
    ) {
        result.success = false;
        result.info = format!("{errno}");
    } else {
        result.success = true;
    }

    result
}

pub fn seccomp_config(pid: libc::pid_t) -> Result<Config> {
    log::info!("Collecting seccomp config for PID {pid}");
    let path = PathBuf::from(format!("/proc/{pid}/status"));
    let f_status = File::open(path)?;

    let seccomp_mode = BufReader::new(f_status)
        .lines()
        .filter_map(|r_line| r_line.ok())
        .find_map(|line| {
            if line.starts_with("Seccomp:") {
                // get value
                let seccomp_mode = Regex::new("[^[:digit:]]").unwrap().replace_all(&line, "");
                let seccomp_mode: libc::c_uint = seccomp_mode
                    .parse()
                    .expect("Could not parse seccomp field in proc/pid/status");
                Some(Mode::try_from(seccomp_mode).unwrap())
            } else {
                None
            }
        })
        .unwrap();

    let mut proto_seccomp_config = Config::default();
    proto_seccomp_config.mode = seccomp_mode.into();

    proto_seccomp_config
        .syscall_map
        .insert(format!("mount: remount sysfs"), test_remount_sysfs());
    Ok(proto_seccomp_config)
}
