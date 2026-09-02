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

#![feature(error_generic_member_access)]
pub mod assessment;
pub mod c_config;
pub mod config;
pub mod evaluation;
use std::backtrace::Backtrace;

use thiserror::Error;

use std::ffi::CStr;
use std::fs::{read_dir, File};
use std::io::Read;
use std::os::fd::BorrowedFd;
use std::os::linux::fs::MetadataExt;
use std::path::PathBuf;

use regex::Regex;

use libc::{__errno_location, c_int, setns, strerror, O_RDONLY};

use crate::Error::{DeviceError, MyIoError, SyscallError, ValueError};

use crate::c_config::device;
use crate::c_config::fs::MountNamespace;
use crate::c_config::ns;

use once_cell::sync::Lazy;

//regex
static REGEX_PROC_STAT: Lazy<Regex> =
    Lazy::new(|| Regex::new(r"[0-9]+\s\(.*\) [[:alpha:]] (?<ppid>[0-9]+)").unwrap());
static REGEX_MOUNTS: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r"[^\s\s]*(?<mountpoint>[^\s]+) (?<fs_type>[^\s]+) (?<mountopts>[^\s]+) [0-9] [0-9]")
        .unwrap()
});
static REGEX_MOUNTINFO: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r"[0-9]+ [0-9]+ [0-9]+:[0-9]+ [^\s]+ (?<mountpoint>[^\s]+) [^\s]+ ([[:alpha:]]+:[0-9]+ )*- (?<fs_type>[^\s]+)").unwrap()
});

static REGEX_UUID: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r"[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}").unwrap()
});

static PROC_PID_STAT_PPID_INDEX: usize = 3;

// error handling

pub type Result<T> = std::result::Result<T, Error>;

#[derive(Error, Debug)]
pub enum Error {
    #[error("{msg}: '{val}' at '{path}'")]
    ValueError {
        msg: String,
        val: String,
        path: String,
    },
    #[error("ConversionFailed: {0}")]
    ConversionFailed(String),
    #[error("Failed to access file at '{path}': {source}")]
    MyIoError {
        path: String,
        source: std::io::Error,
        backtrace: Backtrace,
    },
    #[error("Syscall through libc failed: '{name}', ret: {retval}, errno: {errno:x}")]
    SyscallError {
        name: String,
        retval: i32,
        errno: c_int,
        errno_msg: String,
        backtrace: Backtrace,
    },

    #[error("IoError: {source}")]
    IoError {
        #[from]
        source: std::io::Error,
        backtrace: Backtrace,
    },
    #[error("Ioctl failed: {0:?}")]
    IoctlFailed(nix::errno::Errno),
    #[error("NixError: {source}")]
    NixError {
        #[from]
        source: nix::Error,
        backtrace: Backtrace,
    },
    #[error("Cgroup v1 is not supported")]
    CgroupError,
    #[error("'{path}' does not point to a device node")]
    DeviceError {
        path: String,
        source: Option<std::io::Error>,
        backtrace: Backtrace,
    },
    #[error(" {msg} : {inner}")]
    BacktraceError {
        msg: String,
        inner: std::io::Error,
        bt: Backtrace,
    },
}

pub fn map_io_error(path: &PathBuf, e: std::io::Error) -> crate::Error {
    MyIoError {
        path: path.display().to_string(),
        source: e,
        backtrace: Backtrace::capture(),
    }
}

pub fn map_io_error_str(path: &str, e: std::io::Error) -> crate::Error {
    MyIoError {
        path: path.to_string(),
        source: e,
        backtrace: Backtrace::capture(),
    }
}

pub fn map_device_error(path: PathBuf, e: Option<std::io::Error>) -> crate::Error {
    DeviceError {
        path: path.display().to_string(),
        source: e,
        backtrace: Backtrace::capture(),
    }
}

// impls for protobuf-generated structs
impl PartialEq<ns::Id> for MountNamespace {
    fn eq(&self, other: &ns::Id) -> bool {
        if self.ns_id.is_none() {
            return false;
        } else {
            return self.ns_id.unwrap() == *other;
        }
    }
}

impl std::fmt::Display for device::Type {
    fn fmt(&self, fmt: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            device::Type::Block => fmt.write_str("block"),
            device::Type::Char => fmt.write_str("char"),
            device::Type::Socket => fmt.write_str("socket"),
            device::Type::Fifo => fmt.write_str("fifo"),
        }
    }
}

// process handling
pub fn get_pid_list() -> Result<Vec<libc::pid_t>> {
    let proc_dir = std::fs::read_dir("/proc")?;

    // read proc and filter for PID-directories
    let pids: Vec<PathBuf> = proc_dir
        .filter(std::result::Result::is_ok)
        .map(|entry| {
            let entry = entry.unwrap();
            entry.path()
        })
        .filter(|entry| entry.is_dir())
        .filter(|entry| {
            entry
                .to_str()
                .unwrap()
                .contains(|char: char| char.is_ascii_digit())
        })
        .collect();

    let pids: Vec<libc::pid_t> = pids
        .iter()
        .map(|entry| {
            entry
                .file_name()
                .unwrap()
                .to_str()
                .unwrap()
                .parse::<libc::pid_t>()
                .unwrap()
        })
        .collect();

    Ok(pids)
}

pub fn get_container_pids(cinit_pid: libc::pid_t) -> Result<Vec<libc::pid_t>> {
    let mut container_pids: Vec<libc::pid_t> = Vec::new();
    container_pids.push(cinit_pid);

    let all_pids: Vec<libc::pid_t> = get_pid_list()?;

    for p in all_pids.into_iter() {
        log::trace!("Checking whether {p} is a child of {cinit_pid}");

        let mut current: libc::pid_t = p;

        // while not reached init
        while current > 1 {
            let proc_stat_path = format!("/proc/{}/stat", current);

            let Ok(mut f_proc_stat) =
                File::open(&proc_stat_path).map_err(|e| map_io_error_str(&proc_stat_path, e))
            else {
                log::trace!("Could not read {proc_stat_path} as process vanished, continuing");
                break;
            };

            let mut proc_stat = String::new();
            f_proc_stat
                .read_to_string(&mut proc_stat)
                .map_err(|e| map_io_error_str(&proc_stat_path, e))?;

            let tokens: Vec<&str> = proc_stat.split(" ").collect();

            let Some(matches) = REGEX_PROC_STAT.captures(&proc_stat) else {
                return Err(ValueError {
                    msg: format!("Failed to parse PPID from /proc/<pid>/stat"),
                    val: proc_stat,
                    path: proc_stat_path,
                });
            };

            let parse_ppid = &matches["ppid"].parse::<i32>();

            if parse_ppid.as_ref().is_err() {
                log::error!(
                    "Failed to parse PPID from value {}",
                    tokens[PROC_PID_STAT_PPID_INDEX]
                );
                return Err(ValueError {
                    msg: format!("Failed to parse PPID from value"),
                    val: tokens[PROC_PID_STAT_PPID_INDEX].to_string(),
                    path: proc_stat_path,
                });
            }

            let ppid: libc::pid_t = *parse_ppid.as_ref().unwrap();

            if ppid == cinit_pid {
                log::trace!("Reached container init pid {cinit_pid}");
                container_pids.push(p);
                break;
            } else {
                log::trace!("Got PPID {ppid} for PID {current}, continuing");
                current = ppid;
            }
        }
    }

    Ok(container_pids)
}

// namespace handling

impl Copy for ns::Id {}

impl ns::Id {
    // returns the ns ID for a given ns type for a given process
    pub fn from_type(pid: libc::pid_t, ns_type: ns::Type) -> Result<ns::Id> {
        let path = PathBuf::from(format!("/proc/{pid}/ns/{}", ns_type.to_string()));

        let file = File::open(&path).map_err(|e| map_io_error(&path, e))?;

        let metadata = file.metadata()?;

        Ok(ns::Id {
            st_dev: metadata.st_dev(),
            st_ino: metadata.st_ino(),
        })
    }

    fn from_fd(ns_fd: std::os::fd::RawFd) -> Result<ns::Id> {
        let fstat = unsafe { nix::sys::stat::fstat(BorrowedFd::borrow_raw(ns_fd)) }?;

        Ok(Self {
            st_dev: fstat.st_dev,
            st_ino: fstat.st_ino,
        })
    }
}

pub unsafe fn join_ns_by_path(path: &CStr, ns_type: libc::c_int) -> Result<()> {
    log::trace!("Joining namespace by path '{}'", path.to_string_lossy());

    let fd = libc::open(path.as_ptr(), O_RDONLY);

    if -1 == fd {
        let path_string_after = path.to_string_lossy();
        let errno: c_int = (*__errno_location()).clone();

        let raw_msg = strerror(errno);
        let errno_string = String::from_utf8_lossy(CStr::from_ptr(raw_msg).to_bytes()).to_string();

        log::error!(
            "Failed to open path {}, ret == -1, errno: {:x} ({})",
            path_string_after,
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

    if -1 == setns(fd, ns_type) {
        let errno = *__errno_location();

        let raw_msg = strerror(errno);
        let errno_msg = String::from_utf8_lossy(CStr::from_ptr(raw_msg).to_bytes()).to_string();

        if -1 == libc::close(fd) {
            log::error!("Additionally failed to close fd {fd} after setns error");
        }

        log::error!("Failed to join fd by path, ret == -1, errno: {errno} ({errno_msg})");
        return Err(SyscallError {
            name: "setns".to_string(),
            retval: -1,
            errno: errno,
            errno_msg: errno_msg,
            backtrace: Backtrace::capture(),
        });
    }

    if -1 == libc::close(fd) {
        let errno: c_int = (*__errno_location()).to_owned().clone();

        let raw_msg = strerror(errno);
        let errno_string = String::from_utf8_lossy(CStr::from_ptr(raw_msg).to_bytes()).to_string();

        log::error!(
            "Failed to close fd {fd}, ret == -1, errno: {:x} ({})",
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

    Ok(())
}

// misc
fn _log_open_fds() -> Result<()> {
    let fd_count;

    {
        fd_count = read_dir("/proc/self/fd")
            .map_err(|e| map_io_error_str("/proc/self/fd", e))?
            .collect::<Vec<_>>()
            .len();
    }
    log::trace!("Currently open fds: {fd_count}");

    Ok(())
}
