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

use walkdir::WalkDir;

use crate::{map_device_error, Error, Error::DeviceError, Error::ValueError, Result};
use std::{
    backtrace::Backtrace,
    collections::HashSet,
    hash::Hash,
    os::linux::fs::MetadataExt,
    os::unix::fs::PermissionsExt,
    path::{Path, PathBuf},
};

use tempfile::tempdir_in;

include!(concat!(env!("OUT_DIR"), "/c_config.device.rs"));
include!(concat!(env!("OUT_DIR"), "/c_config.device.serde.rs"));

const MKNOD_TMPDIR: &str = "/dev/";

impl Eq for Id {}
impl Hash for Id {
    fn hash<H: std::hash::Hasher>(&self, state: &mut H) {
        self.major.hash(state);
        self.minor.hash(state);
        self.r#type().hash(state);
    }
}

impl TryFrom<u32> for Type {
    type Error = Error;

    fn try_from(value: u32) -> std::result::Result<Self, Self::Error> {
        match value & libc::S_IFMT {
            libc::S_IFBLK => Ok(Self::Block),
            libc::S_IFCHR => Ok(Self::Char),
            libc::S_IFSOCK => Ok(Self::Socket),
            libc::S_IFIFO => Ok(Self::Fifo),
            _ => Err(Error::ConversionFailed(format!("unknown device type"))),
        }
    }
}

impl Eq for Device {}

impl Hash for Device {
    fn hash<H: std::hash::Hasher>(&self, state: &mut H) {
        self.file.hash(state);
        self.id.hash(state);
    }
}

impl Device {
    pub fn from_dev_file(p: &Path) -> Result<Device> {
        let path = match p.canonicalize() {
            Ok(c) => c,
            Err(e) => {
                log::trace!(
                    "Failed to process {}, error: {e:?}, attempting to process as link",
                    p.display()
                );
                let link = p.read_link();
                if link.is_err() {
                    return Err(DeviceError {
                        path: p.to_string_lossy().to_string(),
                        source: Some(e),
                        backtrace: Backtrace::capture(),
                    });
                }
                let c = link.unwrap();
                log::trace!("Resolved path to {}", c.display());
                c
            }
        };

        // metadata information
        let dev_metadata =
            std::fs::metadata(&path).map_err(|e| map_device_error(path.clone(), Some(e)))?;
        let file_type = dev_metadata.st_mode() & libc::S_IFMT;
        if file_type == libc::S_IFREG || file_type == libc::S_IFDIR {
            log::warn!(
                "File {} is a regular file or directory, skipping",
                path.display()
            );
            return Err(DeviceError {
                path: path.to_string_lossy().to_string(),
                source: None,
                backtrace: Backtrace::capture(),
            });
        }
        let mut dev_id = Id::default();
        let st_rdev = dev_metadata.st_rdev();
        dev_id.major = libc::major(st_rdev);
        dev_id.minor = libc::minor(st_rdev);

        if let Ok(t) = Type::try_from(dev_metadata.st_mode()) {
            dev_id.set_type(t)
        } else {
            return Err(ValueError {
                msg: "Unkown st_mode".to_string(),
                val: dev_metadata.st_mode().to_string(),
                path: path.to_string_lossy().to_string(),
            });
        }
        let permissions = dev_metadata.st_mode() & (libc::S_IRWXU | libc::S_IRWXG | libc::S_IRWXO);
        let user = dev_metadata.st_uid();
        let group = dev_metadata.st_gid();

        // test direct access
        let mut read_access = Self::read_access(&path);
        let mut write_access = Self::write_access(&path);

        // if direct access not possible, attempt to chown + chmod and retry
        if !read_access || !write_access {
            let result = nix::unistd::chown(
                &path,
                Some(nix::unistd::Uid::current()),
                Some(nix::unistd::Gid::current()),
            );

            if result.is_ok() {
                log::trace!(
                    "Successfully executed chown({}, {}, {})",
                    path.display(),
                    nix::unistd::Uid::current(),
                    nix::unistd::Gid::current()
                );
            } else {
                log::trace!("Failed to chmod {}", path.display())
            }

            if !read_access {
                let mut read_perm = dev_metadata.permissions();
                read_perm.set_mode(0o444);
                if let Ok(_) = std::fs::set_permissions(&path, read_perm) {
                    log::trace!("Successfully executed chmod({}, 0444)", path.display());
                }
            }

            if !write_access {
                let mut write_perm = dev_metadata.permissions();
                write_perm.set_mode(0o666);
                if let Ok(_) = std::fs::set_permissions(&path, write_perm) {
                    log::trace!("Successfully executed chmod({}, 0o666)", path.display());
                }
            }

            let read_after = Self::read_access(&path);
            let write_after = Self::write_access(&path);

            read_access = read_access || read_after;
            write_access = write_access || write_after;

            if (read_after != read_access) || write_after != write_access {
                log::debug!("Results of open({}) changed after chmod/chown: read: {read_after}, write: {write_after}, final result: read: {read_access}, write: {write_access}", path.display());
            } else {
                log::trace!(
                    "Results of open({}) did not change after chmod",
                    path.display()
                );
            }
        }

        let f = path.to_str();

        if f.is_none() {
            return Err(DeviceError {
                path: path.display().to_string(),
                source: None,
                backtrace: Backtrace::capture(),
            });
        };

        Ok(Self {
            file: String::from(f.unwrap()),
            id: Some(dev_id),
            permissions,
            user,
            group,
            read_access,
            write_access,
        })
    }

    pub fn parse_dev() -> Result<Vec<Device>> {
        let devices: HashSet<Device> = WalkDir::new("/dev")
            .follow_links(true)
            .into_iter()
            .filter_map(|entry| {
                if let Ok(dev_entry) = entry {
                    Some(dev_entry)
                } else {
                    log::warn!("error while walkdir /dev: {}", entry.err().unwrap());
                    None
                }
            })
            .filter(|entry| !entry.file_type().is_dir())
            .map(|entry| Device::from_dev_file(entry.path()))
            .filter_map(|device_result| match device_result {
                Ok(device) => Some(device),
                Err(Error::DeviceError {
                    path: p,
                    source: s,
                    backtrace: b,
                }) => {
                    log::warn!(
                        "Failed to retrieve device info for {p}, error: {}",
                        if s.is_none() {
                            String::from("None")
                        } else {
                            s.unwrap().to_string()
                        }
                    );
                    log::trace!("Backtrace is: {}", b);
                    None
                }
                Err(e) => {
                    log::error!("An unexpected error occurred: {:?}", e);
                    None
                }
            })
            .collect();

        Ok(Vec::from_iter(devices.into_iter()))
    }

    fn write_access(path: &PathBuf) -> bool {
        match nix::fcntl::open(
            path,
            nix::fcntl::OFlag::O_WRONLY,
            nix::sys::stat::Mode::empty(),
        ) {
            Ok(fd) => {
                // success
                nix::unistd::close(fd).unwrap_or_else(|err| log::warn!("Error closing fd: {err}"));
                return true;
            }
            Err(errno) => match errno {
                nix::errno::Errno::EPERM
                | nix::errno::Errno::EACCES
                | nix::errno::Errno::ENXIO
                | nix::errno::Errno::ENODEV => {
                    return false;
                }
                errno => {
                    log::warn!(
                        "open({}, O_WRONLY, NULL) returned errno: {errno}",
                        path.display().to_string()
                    );
                    return false;
                }
            },
        }
    }

    fn read_access(path: &PathBuf) -> bool {
        match nix::fcntl::open(
            path,
            nix::fcntl::OFlag::O_RDONLY,
            nix::sys::stat::Mode::empty(),
        ) {
            Ok(fd) => {
                // success
                nix::unistd::close(fd).unwrap_or_else(|err| log::warn!("Error closing fd: {err}"));
                return true;
            }
            Err(errno) => match errno {
                nix::errno::Errno::EPERM
                | nix::errno::Errno::EACCES
                | nix::errno::Errno::ENXIO
                | nix::errno::Errno::ENODEV => {
                    return false;
                }
                errno => {
                    log::warn!(
                        "open({}, O_RDONLY, NULL) returned errno: {errno}",
                        path.display().to_string()
                    );
                    return false;
                }
            },
        }
    }

    // cycle through possible number range and mknod
    fn mknod_brute_force() -> Result<Vec<Device>> {
        // create temp dir for test
        let dir = tempdir_in(MKNOD_TMPDIR)?;
        let mut result = Vec::new();

        let major_max = 2_u64.checked_pow(12).unwrap();
        let minor_max = 256;

        log::debug!(
            "Testing mknod up to major {major_max} / minor {minor_max} at {}",
            dir.path().display()
        );

        // major
        for i in 0..=major_max {
            // minor
            for j in 0..=minor_max {
                let path = dir.path().join(format!("char_{i}_{j}"));
                // char devices
                match nix::sys::stat::mknod(
                    &path,
                    nix::sys::stat::SFlag::S_IFCHR,
                    nix::sys::stat::Mode::S_IRWXU,
                    nix::sys::stat::makedev(i, j),
                ) {
                    Ok(_) => {
                        let mut device = Device::default();
                        let id = Id {
                            r#type: Type::Char as i32,
                            major: i as u32,
                            minor: j as u32,
                        };
                        device.file = path.to_string_lossy().to_string();
                        device.id = Some(id);
                        device.user = unsafe { libc::getuid() };
                        device.group = unsafe { libc::getgid() };
                        device.permissions = libc::S_IRWXU;
                        device.read_access = Self::read_access(&path);
                        device.write_access = Self::write_access(&path);
                        if device.read_access || device.write_access {
                            result.push(device);
                        }
                    }

                    Err(errno) => {
                        log::trace!("mknod {:#?} resulted in {errno}", &path);
                    }
                }

                // block devices
                let path = dir.path().join(format!("block_{i}_{j}"));
                match nix::sys::stat::mknod(
                    &path,
                    nix::sys::stat::SFlag::S_IFBLK,
                    nix::sys::stat::Mode::S_IRWXU,
                    nix::sys::stat::makedev(i, j),
                ) {
                    Ok(_) => {
                        let mut device = Device::default();
                        let id = Id {
                            r#type: Type::Block as i32,
                            major: i as u32,
                            minor: j as u32,
                        };
                        device.file = path.to_string_lossy().to_string();
                        device.id = Some(id);
                        device.user = unsafe { libc::getuid() };
                        device.group = unsafe { libc::getgid() };
                        device.permissions = libc::S_IRWXU;
                        device.read_access = Self::read_access(&path);
                        device.write_access = Self::write_access(&path);
                        if device.read_access || device.write_access {
                            result.push(device);
                        }
                    }

                    Err(errno) => {
                        log::trace!("mknod {:#?} resulted in {errno}", &path);
                    }
                }
            }
        }

        // delete dir
        dir.close()?;

        Ok(result)
    }

    // try mknod on all devices listed in /sys/dev
    fn _mknod_sys_dev() -> Result<Vec<Device>> {
        let path = PathBuf::from("/sys/dev");
        let block_devices: Vec<_> = std::fs::read_dir(path.join("block"))?
            .filter_map(|r_dir_entry| {
                if let Ok(entry) = r_dir_entry {
                    let file_name = entry.file_name().to_string_lossy().to_string();
                    log::debug!("found device {}", &file_name);
                    let dev_id: Vec<&str> = file_name.split(":").collect();
                    let major = dev_id[0].parse().unwrap();
                    let minor = dev_id[1].parse().unwrap();
                    Some(Id {
                        r#type: Type::Block as i32,
                        major,
                        minor,
                    })
                } else {
                    None
                }
            })
            .collect();
        let char_devices: Vec<_> = std::fs::read_dir(path.join("char"))?
            .filter_map(|r_dir_entry| {
                if let Ok(entry) = r_dir_entry {
                    let file_name = entry.file_name().to_string_lossy().to_string();
                    log::debug!("found device {}", &file_name);
                    let dev_id: Vec<&str> = file_name.split(":").collect();
                    let major = dev_id[0].parse().unwrap();
                    let minor = dev_id[1].parse().unwrap();
                    Some(Id {
                        r#type: Type::Char as i32,
                        major,
                        minor,
                    })
                } else {
                    None
                }
            })
            .collect();

        // create temp dir for test
        let dir = tempdir_in(MKNOD_TMPDIR)?;
        let mut result = Vec::new();

        // block devices
        for id in block_devices {
            let path = dir.path().join(format!("block_{}_{}", id.major, id.minor));
            match nix::sys::stat::mknod(
                &path,
                nix::sys::stat::SFlag::S_IFBLK,
                nix::sys::stat::Mode::S_IRWXU,
                libc::makedev(id.major, id.minor),
            ) {
                Ok(_) => {
                    let mut device = Device::default();
                    device.file = path.to_string_lossy().to_string();
                    device.id = Some(id);
                    device.user = unsafe { libc::getuid() };
                    device.group = unsafe { libc::getgid() };
                    device.permissions = libc::S_IRWXU;
                    device.read_access = Self::read_access(&path);
                    device.write_access = Self::write_access(&path);
                    if device.read_access || device.write_access {
                        result.push(device);
                    }
                }

                Err(errno) => {
                    log::warn!("mknod {:#?} resulted in {errno}", &path);
                }
            }
        }

        // char devices
        for id in char_devices {
            let path = dir.path().join(format!("char_{}_{}", id.major, id.minor));

            match nix::sys::stat::mknod(
                &path,
                nix::sys::stat::SFlag::S_IFCHR,
                nix::sys::stat::Mode::S_IRWXU,
                libc::makedev(id.major, id.minor),
            ) {
                Ok(_) => {
                    let mut device = Device::default();
                    device.file = path.to_string_lossy().to_string();
                    device.id = Some(id);
                    device.user = unsafe { libc::getuid() };
                    device.group = unsafe { libc::getgid() };
                    device.permissions = libc::S_IRWXU;
                    device.read_access = Self::read_access(&path);
                    device.write_access = Self::write_access(&path);
                    if device.read_access || device.write_access {
                        result.push(device);
                    }
                }

                Err(errno) => {
                    log::warn!("mknod {:#?} resulted in {errno}", &path);
                }
            }
        }

        // delete dir
        dir.close()?;

        Ok(result)
    }
}

pub fn device_config() -> Result<Config> {
    log::info!("Retrieving dev_config from proto");
    let mut proto_dev_config = Config::default();
    log::info!("Parsing devices");
    proto_dev_config.dev_devices = Device::parse_dev()?;
    log::info!("Testing mknod");
    proto_dev_config.mknod_devices = Device::mknod_brute_force()?;

    Ok(proto_dev_config)
}
