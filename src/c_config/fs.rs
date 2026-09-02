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

use log;

use std::env::{current_dir, set_current_dir};
use std::ffi::{c_int, CStr, CString};
use std::fs::File;
use std::io::{prelude::*, BufRead, BufReader};
use std::path::Path;

use std::backtrace::Backtrace;
use std::fmt::Debug;
use std::path::PathBuf;

use serde::{Deserialize, Serialize};

use crate::config::{FLAG_SEARCH_PATH_SKIPS, MOUNTPOINT_FS_SKIPS, MOUNTPOINT_PATH_SKIPS};
use crate::{
    get_pid_list, join_ns_by_path, map_io_error_str, ns, Error::SyscallError, Error::ValueError,
    Result, REGEX_MOUNTINFO, REGEX_MOUNTS,
};

use uuid::Uuid;

use libc::{__errno_location, setns, strerror, CLONE_NEWNS, O_RDONLY};

use rust_search::{FilterExt, SearchBuilder};

include!(concat!(env!("OUT_DIR"), "/c_config.fs.rs"));
include!(concat!(env!("OUT_DIR"), "/c_config.fs.serde.rs"));

static FLAG_BASE_NAME: &'static str = "xyz_checkc_flag";
static FLAG_SKIP_FS: &'static [&str] =
    &["devtmpfs", "proc", "sysfs", "devpts", "cgroup", "cgroup2"];

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Info {
    ns_id: ns::Id,
    mounts: Vec<String>,
    mountinfo: Vec<String>,
    mountstats: Vec<String>,
}

impl Default for Info {
    fn default() -> Self {
        Self {
            ns_id: ns::Id::default(),
            mounts: Vec::new(),
            mountinfo: Vec::new(),
            mountstats: Vec::new(),
        }
    }
}

impl Info {
    pub fn info_by_pid(pid: libc::pid_t) -> Result<Info> {
        let path = PathBuf::from(format!("/proc/{pid}"));

        let f_mounts = File::open(path.join("mounts"))?;
        let f_mountinfo = File::open(path.join("mountinfo"))?;
        //let f_mounstats = File::open(path.join("mountstats"))?;

        let mut info = Info::default();
        info.ns_id = ns::Id::from_type(pid, ns::Type::Mount)?;

        // read content of /proc/pid/mounts
        let reader = BufReader::new(f_mounts);
        log::trace!("Collecting  /proc/pid/mounts");
        info.mounts.extend(reader.lines().filter_map(|line| {
            if let Ok(entry) = line {
                let Some(matches) = REGEX_MOUNTS.captures(&entry) else {
                    log::error!("Failed to parse mounts from entry {entry}");
                    return None;
                };

                if MOUNTPOINT_FS_SKIPS.contains(&&matches["fs_type"]) {
                    log::trace!(
                        "Skipping mount point {entry} with fs type {}",
                        &matches["fs_type"]
                    );
                    None
                } else if MOUNTPOINT_PATH_SKIPS.contains(&&matches["mountpoint"]) {
                    log::trace!(
                        "Skipping mount point {entry} with dst path {}",
                        &matches["mountpoint"]
                    );
                    None
                } else {
                    Some(entry)
                }
            } else {
                log::error!("error reading from /proc/pid/mounts");
                None
            }
        }));

        // parse /proc/pid/mountinfo
        log::trace!("Collecting  /proc/pid/mountinfo");
        let reader = BufReader::new(f_mountinfo);
        info.mountinfo.extend(reader.lines().filter_map(|line| {
            if let Ok(entry) = line {
                let Some(matches) = REGEX_MOUNTINFO.captures(&entry) else {
                    log::error!("Failed to parse mountinfo entry {}", entry);
                    return None;
                };

                if MOUNTPOINT_FS_SKIPS.contains(&&matches["fs_type"]) {
                    log::trace!("Skipping mount point {entry} with fs type {}", &matches["fs_type"]);
                    return None;
                } else if MOUNTPOINT_PATH_SKIPS.iter().any(|skip| matches["mountpoint"].starts_with(skip)) {
                    log::trace!("Skipping mount point '{entry}' with dst path {} due to match in MOUNTPOINT_PATH_SKIPS", &matches["mountpoint"]);
                    return None;
                } else {
                    log::trace!{"Adding mount point '{entry}' to list for mountns {}:{}",   info.ns_id.st_dev, info.ns_id.st_ino};
                    return Some(entry);
                }
            } else {
                log::error!("error reading from /proc/pid/mountinfo");
                return None;
            }
        }));

        Ok(info)
    }
}

pub fn get_mountinfos(pid_cfg: Option<(&Vec<libc::pid_t>, bool)>) -> Vec<MountNamespace> {
    let mut mount_namespaces: Vec<MountNamespace> = vec![];

    // Aggregate mountinfo for all PIDs
    // This is needed as the view on mountpoints may differs for each process due to mount namespaces
    let pids: Vec<libc::pid_t> = get_pid_list().unwrap();

    for p in pids {
        if let Some((pid_list, include_mode)) = pid_cfg {
            if include_mode && (!pid_list.contains(&p)) {
                log::trace!("Skipping PID {p} not contained in include list");
                continue;
            }

            if (!include_mode) && pid_list.contains(&p) {
                log::trace!("Skipping PID {p} contained in exclude list");
                continue;
            }
        }

        log::trace!("Collecting mount namespace / mountpoint info for PID {p}");
        let Ok(ns_id) = ns::Id::from_type(p, ns::Type::Mount) else {
            log::trace!("Failed to retrieve mountns ID for PID {p}, did it exit?");
            continue;
        };

        log::trace!("Mountns ID is {}:{}", ns_id.st_dev, ns_id.st_ino);

        let mut mountns_filter: Vec<&mut MountNamespace> = mount_namespaces
            .iter_mut()
            .filter(|n| ns_id == n.ns_id.unwrap())
            .collect();

        if 1 < mountns_filter.len() {
            // workaround compiler error uninitialized (but panicing here)
            panic!("Error: mountns_handle.len() > 1");
        } else if 1 == mountns_filter.len() {
            log::trace!(
                "Not processing mount namespace {}:{} again, adding {p} to PID list of namespace",
                ns_id.st_dev,
                ns_id.st_ino
            );

            let mountns_handle: &mut MountNamespace = mountns_filter.last_mut().unwrap();
            mountns_handle.ns_pids.push(p);
            continue;
        }

        let Ok(info) = Info::info_by_pid(p) else {
            log::warn!("Failed to retrieve fs info for PID {p}, did it exit?");
            continue;
        };

        log::trace!(
            "Mount namespace {}:{} not yet contained in mount namespace list, adding new entry",
            info.ns_id.st_dev,
            info.ns_id.st_ino
        );
        let mut mountns = MountNamespace::default();
        mountns.ns_id = Some(info.ns_id);
        mountns.ns_pids.push(p);

        for mp_add in info.mounts.into_iter() {
            if !mountns.mounts.contains(&mp_add) {
                mountns.mounts.push(mp_add);
            }
        }

        for mp_add in info.mountinfo.into_iter() {
            if !mountns.mountinfo.contains(&mp_add) {
                mountns.mountinfo.push(mp_add);
            }
        }

        mount_namespaces.push(mountns);
    }

    mount_namespaces
}

// this process mountpoints when running inside the container
// that is, it writes a flag file to each mount point
pub fn process_mountpoints_container(
    _checkc_mountns_fd: i32,
    _pid_cfg: Option<(&Vec<libc::pid_t>, bool)>,
) -> Result<Vec<MountNamespace>> {
    let mut mount_namespaces = get_mountinfos(None);
    let flag_file: String = format!("{FLAG_BASE_NAME}_{}", Uuid::new_v4());
    log::debug!("Flag file name is {flag_file}");

    for mountns in mount_namespaces.iter_mut() {
        for mp in mountns.mountinfo.iter() {
            // create flag file on each mount point
            let Some(matches) = REGEX_MOUNTINFO.captures(&mp) else {
                return Err(ValueError {
                    msg: format!("Failed to parse mountinfo from mount point {mp}"),
                    val: mp.clone(),
                    path: "".to_string(),
                });
            };

            if FLAG_SKIP_FS.contains(&&matches["fs_type"]) {
                log::trace!(
                    "Skipping flag file for file system {} at {} in namespace {}:{}",
                    &matches["fs_type"],
                    mp,
                    mountns.ns_id.unwrap().st_dev,
                    mountns.ns_id.unwrap().st_ino
                );
            } else {
                let flag_path = format!("{}/{flag_file}", &matches["mountpoint"]);
                let meta = Path::new(&flag_path).metadata();

                if meta.is_ok() {
                    if meta.unwrap().is_file() {
                        continue;
                    }
                }

                log::debug!("Writing flag file {flag_path}");
                let f = File::create(&flag_path);

                if let Err(e) = f {
                    if !File::open(&flag_path).is_ok() {
                        log::error!("Error 'ConversionFailed' while creating flag file at '{flag_path}': {e}");
                    } else {
                        log::debug!("File was already created processing other mount namespace");
                    }
                } else {
                    if let Err(e) = f.unwrap().sync_all() {
                        log::error!("Failed to sync flag file '{flag_path}' to disk: {e}");
                    }

                    mountns.flag_files.push(flag_path);
                }
            }
        }
    }

    Ok(mount_namespaces)
}

// this function retrieves the fs config when running in container mode
pub fn fs_config_container() -> Result<Vec<MountNamespace>> {
    log::debug!("Collecting fs config in container mode");
    let proto_fs_config = fs_config_generic(process_mountpoints_container, None)?;

    Ok(proto_fs_config)
}

fn process_mountpoints_host(
    checkc_mountns_fd: i32,
    pid_cfg: Option<(&Vec<libc::pid_t>, bool)>,
) -> Result<Vec<MountNamespace>> {
    log::debug!("Collecting host mount namespace / mount point information (host view), this may take some time");
    // when running in host mode, search for flag files in mount points
    // to this end, join mountns where the respective mount point was recorded

    let mut proto_fs_config = get_mountinfos(pid_cfg);
    let n_mountns = proto_fs_config.len();

    log::trace!("Finished mount point collection, searching flag files");

    for (i, mountns) in proto_fs_config.iter_mut().enumerate() {
        log::trace!(
            "Searching flag files in mount namespace {}/{}: {}:{}",
            i + 1,
            n_mountns,
            mountns.ns_id.unwrap().st_dev,
            mountns.ns_id.unwrap().st_ino
        );
        let mut mountns_success = false;

        for mountns_pid in mountns.ns_pids.iter() {
            log::trace!(
                "Attempt to process mount namespace {}:{} using PID {mountns_pid}",
                mountns.ns_id.unwrap().st_dev,
                mountns.ns_id.unwrap().st_ino
            );

            // depending on PID namespace represented by procfs mounted in current namespace,
            // PIDs collected from checkc's PID namespace (root PID namespace) may not be valid
            // in /proc of other mount namespaces
            // Thus, temporarily join checkc's PID namespace before accessing /proc
            unsafe {
                if -1 == setns(checkc_mountns_fd, CLONE_NEWNS) {
                    let errno = *__errno_location();
                    let strerr: &CStr = CStr::from_ptr(strerror(errno));

                    log::warn!("Failed to join checkc fd by path, ret == -1, errno: {errno} ({}), continue in current mountns", strerr.to_string_lossy());
                }
            }

            let cmdline_path = format!("/proc/{}/cmdline", mountns_pid);
            let Ok(mut f_cmdline) =
                File::open(&cmdline_path).map_err(|e| map_io_error_str(&cmdline_path, e))
            else {
                log::warn!(
                    "Failed to read /proc/{}/cmdline, did process vanish?",
                    mountns_pid
                );
                continue;
            };

            let mut cmdline = String::new();
            f_cmdline
                .read_to_string(&mut cmdline)
                .map_err(|e| map_io_error_str(&cmdline_path, e))?;

            log::trace!("/proc/{mountns_pid}/cmdline is {cmdline}");

            if cmdline.is_empty() {
                log::debug!("Skipping kernel thread with PID {}", mountns_pid);
                continue;
            }

            // join mount name space to process mount point
            unsafe {
                let mountns_path = CString::new(format!("/proc/{}/ns/mnt", mountns_pid)).unwrap();

                if let Err(e) = join_ns_by_path(&mountns_path, CLONE_NEWNS) {
                    log::warn!("Warn '{e}' attempting to join mount namespace {}:{} with PID {}, did process vanish? Re-trying with next PID", mountns.ns_id.unwrap().st_dev, mountns.ns_id.unwrap().st_ino, mountns_pid);
                    continue;
                }
            }

            for (i2, mp) in mountns.mountinfo.iter().enumerate() {
                log::trace!(
                    "Searching flag files at mountpoint {}/{}: {}",
                    i2 + 1,
                    mountns.mountinfo.len(),
                    mp
                );

                let Some(matches) = REGEX_MOUNTINFO.captures(&mp) else {
                    return Err(ValueError {
                        msg: format!("Failed to parse mountinfo from entry"),
                        val: mp.clone(),
                        path: "".to_string(),
                    });
                };

                let mut entries: Vec<String> = SearchBuilder::default()
                    .location(&matches["mountpoint"])
                    .hidden()
                    .search_input(FLAG_BASE_NAME)
                    .custom_filter(|entry| {
                        let path = entry.path();
                        let meta = match path.metadata() {
                            Ok(m) => m,
                            Err(e) => {
                                log::trace!("Failed to get metadata for {}: '{e}'", path.display());
                                return false;
                            }
                        };

                        if meta.is_dir() {
                            log::trace!("Entering directory '{}'", path.display());
                            return true;
                        }

                        // skip paths matching an entry in FLAG_SEARCH_PATH_SKIPS
                        if FLAG_SEARCH_PATH_SKIPS.iter().any(|skip| {
                            let res = path.starts_with(skip);
                            log::trace!("Processing skip {}, returning {}", skip, res);
                            return res;
                        }) {
                            log::trace!(
                                "Skipping file {} contained in FLAG_SEARCH_PATH_SKIPS",
                                path.display()
                            );
                            return false;
                        } else {
                            log::trace!(
                                "File {} not contained in FLAG_SEARCH_PATH_SKIPS",
                                path.display()
                            );
                        }

                        // only process regular files
                        if !(meta.is_file() || meta.is_dir()) {
                            log::trace!(
                                "Skipping '{}' (not a directory nor regular file)",
                                path.display()
                            );
                            return false;
                        }

                        // only return files starting with FLAG_BASE_NAME
                        let path = entry.path();
                        log::trace!("Searching flag file at path {}", path.display());
                        let f = path.file_name();

                        if f.is_none() || f.unwrap().to_str().is_none() {
                            log::error!("Failed to parse file name from path {}", path.display());
                            return false;
                        }

                        let fs = f.unwrap().to_str().unwrap();

                        if !fs.starts_with(FLAG_BASE_NAME) {
                            log::trace!(
                                "Skipping file {} not matching FLAG_BASE_NAME '{FLAG_BASE_NAME}'",
                                path.display()
                            );
                            return false;
                        } else {
                            log::trace!("{fs} matches {FLAG_BASE_NAME}, returning it");
                        }

                        log::trace!("Found flag file at {}", path.display());

                        return true;
                    }) // end filter
                    .build()
                    .collect();

                entries.retain(|entry| entry != &matches["mountpoint"]);

                for entry in entries {
                    if !mountns.flag_files.contains(&entry) {
                        log::trace!(
                            "Entry {entry} not yet contained in flag files for mountns, adding"
                        );
                        mountns.flag_files.push(entry);
                    } else {
                        log::trace!(
                            "Entry {entry} already contained in flag files for mountns, skipping"
                        );
                    }
                }

                // successfully processed mount point continue with next one
                log::trace!("Successfully processed mount point {mp}, continuing");
            }

            // successfully processed mount namespace using current PID, continue with next mount namespace
            log::trace!(
                "Successfully processed mount namespace {}:{} using PID {mountns_pid}, continuing",
                mountns.ns_id.unwrap().st_dev,
                mountns.ns_id.unwrap().st_ino
            );
            mountns_success = true;
            break;
        }

        if !mountns_success {
            log::warn!(
                "Failed to process mount namespace {}:{} using any PID",
                mountns.ns_id.unwrap().st_dev,
                mountns.ns_id.unwrap().st_ino
            );
        }

        // processed all mount points of mount namespace, continuing with next one
        log::trace!(
            "Processed all mount points in mount namespace {}:{}, continuing",
            mountns.ns_id.unwrap().st_dev,
            mountns.ns_id.unwrap().st_ino
        );
    }

    Ok(proto_fs_config)
}

// this function implements the sourrounding logic needed to restore the original mount namespace
// after fs config retrieval
pub fn fs_config_generic(
    f_mp: fn(i32, Option<(&Vec<libc::pid_t>, bool)>) -> Result<Vec<MountNamespace>>,
    pid_cfg: Option<(&Vec<libc::pid_t>, bool)>,
) -> Result<Vec<MountNamespace>> {
    let checkc_mountns_path: &CStr =
        &CString::new(format!("/proc/{}/ns/mnt", std::process::id())).unwrap();
    let checkc_mountns_fd;
    let checkc_cwd = current_dir()?;

    log::trace!("Current working directory is {}", checkc_cwd.display());

    unsafe {
        let own_pid = libc::getpid();
        log::trace!("libc::getpid() returned {own_pid}");

        checkc_mountns_fd = libc::open(checkc_mountns_path.as_ptr(), O_RDONLY);

        if -1 == checkc_mountns_fd {
            let errno: c_int = (*__errno_location()).clone();

            let raw_msg = strerror(errno);
            let errno_string =
                String::from_utf8_lossy(CStr::from_ptr(raw_msg).to_bytes()).to_string();

            log::error!(
                "Failed to open path {}, ret == -1, errno: {:x} ({})",
                checkc_mountns_path.to_string_lossy(),
                errno,
                errno_string
            );
            return Err(SyscallError {
                name: "open".to_string(),
                retval: -1,
                errno: errno,
                errno_msg: errno_string,
                backtrace: Backtrace::capture(),
            });
        }

        log::trace!("checkc mountns fd is {checkc_mountns_fd}");
    }

    // execute provided mountpoint processing function
    let r_fs_config = f_mp(checkc_mountns_fd, pid_cfg);

    // re-join original mount namespace
    unsafe {
        log::trace!("Re-joining checkc mountns fd {checkc_mountns_fd}");

        if -1 == setns(checkc_mountns_fd, CLONE_NEWNS) {
            let errno = *__errno_location();
            let strerr: &CStr = CStr::from_ptr(strerror(errno));

            log::error!("Failed to join fd by path, ret == -1, errno: {errno} ({}), continue in current mountns", strerr.to_string_lossy());
        }

        if -1 == libc::close(checkc_mountns_fd) {
            let errno: c_int = (*__errno_location()).to_owned().clone();

            let raw_msg = strerror(errno);
            let errno_string =
                String::from_utf8_lossy(CStr::from_ptr(raw_msg).to_bytes()).to_string();

            log::error!(
                "Failed to close fd {checkc_mountns_fd}, ret == -1, errno: {:x} ({})",
                errno,
                errno_string
            );
        }
    }

    match current_dir() {
        Ok(cwd) => log::trace!(
            "Current working directory is {}, attempting to restoring original path {}",
            cwd.display(),
            checkc_cwd.display()
        ),
        Err(e) => log::warn!("Failed to determine current working directory: {e}"),
    }

    if let Err(e) = set_current_dir(&checkc_cwd) {
        log::error!(
            "Failed to restore original working directory {}: {e}",
            checkc_cwd.display()
        );
    }

    r_fs_config
}

// collect fs _config in when running in host mode
pub fn fs_config_hostview(
    pid_list: &Vec<libc::pid_t>,
    include_mode: bool,
) -> Result<Vec<MountNamespace>> {
    log::trace!("Collecting fs config (host mode), this may take some time");
    log::trace!("PID list is {:?}, include_mode is {include_mode}", pid_list);

    let fs_config_proto =
        fs_config_generic(process_mountpoints_host, Some((pid_list, include_mode)));

    fs_config_proto
}
