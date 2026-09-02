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

use crate::Result;
use log;
use std::{os::linux::fs::MetadataExt, path::PathBuf};

include!(concat!(env!("OUT_DIR"), "/c_config.chroot.rs"));
include!(concat!(env!("OUT_DIR"), "/c_config.chroot.serde.rs"));

impl Root {
    fn from_pid(pid: libc::pid_t) -> Result<Self> {
        let path = PathBuf::from(format!("/proc/{pid}/root"));
        log::trace!("root path: {:#?}", &path);
        let m_root = path.metadata()?;

        Ok(Self {
            path: path.read_link()?.to_string_lossy().to_string(),
            st_ino: m_root.st_ino(),
            st_dev: m_root.st_dev(),
        })
    }
}

pub fn chroot_config(pid_host: libc::pid_t, pid_container: libc::pid_t) -> Result<Config> {
    log::debug!("Gathering chroot_config");
    let mut chroot_config = Config::default();
    let host_root = Root::from_pid(pid_host)?;
    let container_root = Root::from_pid(pid_container)?;

    chroot_config.host = Some(host_root);
    chroot_config.container = Some(container_root);
    Ok(chroot_config)
}
