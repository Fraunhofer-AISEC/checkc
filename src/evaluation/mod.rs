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

use crate::c_config;
use crate::evaluation::cgroup::Controller;
use crate::{c_config::*, config::*, evaluation::fs::MountNamespace, REGEX_UUID};
use log;
use std::collections::*;
use std::path::PathBuf;

include!(concat!(env!("OUT_DIR"), "/evaluation.rs"));
include!(concat!(env!("OUT_DIR"), "/evaluation.serde.rs"));

impl EvalResult {
    pub fn from_config(config: &Config, container_root_host: &PathBuf) -> crate::Result<Self> {
        let mut unprivileged = false;

        let info = Some(EvalInfo {
            pids_container: config.info.as_ref().unwrap().pids_container.clone(),
            pids_ref_container: config.info.as_ref().unwrap().pids_ref_container.clone(),
            pid_host: config.info.as_ref().unwrap().pid_host.clone(),
            container_root_host: container_root_host.display().to_string(),
        });

        let unshared_ns: HashMap<_, _> = config
            .ns_config
            .as_ref()
            .unwrap()
            .unshared
            .iter()
            .map(|ns| (ns.r#type(), ns.clone()))
            .collect();

        let mut ns_set = HashSet::new();
        let user_ns = unshared_ns.get(&ns::Type::User);

        if user_ns.is_some() {
            unprivileged = true;
            ns_set.insert(ns::Type::User);
            // verify namespaces relative to user ns
            for (ns_type, ns_info) in &unshared_ns {
                if ns_info.owner.unwrap() == user_ns.unwrap().id.unwrap() {
                    ns_set.insert(ns_type.to_owned());
                }
            }
        } else {
            // check against host user
            let user_ns = config
                .ns_config
                .as_ref()
                .unwrap()
                .shared_host
                .iter()
                .find(|ns| ns.r#type() == ns::Type::User)
                .unwrap();
            for (ns_type, ns_info) in &unshared_ns {
                if ns_info.owner.unwrap() == user_ns.id.unwrap() {
                    ns_set.insert(ns_type.to_owned());
                } else {
                    log::warn!("Namespace neither owned by initital user namespace nor by own user namespace");
                }
            }
        }

        let capabilities: HashSet<caps::Capability> =
            config.caps_config.as_ref().unwrap().cap_prm().collect();

        let mut categories = HashMap::new();
        categories.insert(
            format!("network"),
            category_network(config, &ns_set, &capabilities),
        );
        categories.insert(
            format!("filesystem"),
            category_filesystem(config, &ns_set, &capabilities, container_root_host),
        );
        categories.insert(
            format!("devices"),
            category_devices(config, &ns_set, &capabilities),
        );
        categories.insert(
            format!("resource_control"),
            category_resource_control(config, &ns_set, &capabilities),
        );
        categories.insert(
            format!("process_control"),
            category_process_control(config, &ns_set, &capabilities),
        );
        categories.insert(
            format!("access_control"),
            category_access_control(config, &ns_set, &capabilities),
        );
        categories.insert(
            format!("time"),
            category_time(config, &ns_set, &capabilities),
        );
        categories.insert(
            format!("global"),
            category_global(config, &ns_set, &capabilities),
        );

        Ok(Self {
            unprivileged,
            categories,
            info,
        })
    }
}

// categories

fn category_network(
    config: &Config,
    ns_set: &HashSet<ns::Type>,
    capabilities: &HashSet<caps::Capability>,
) -> Category {
    let caps = HashSet::from([
        caps::Capability::CapNetAdmin,
        caps::Capability::CapNetBindService,
        caps::Capability::CapNetRaw,
    ]);

    let namespaces = HashSet::from([ns::Type::Network, ns::Type::Uts]);

    let mut isolation = IsolationMechanisms::default();
    isolation.namespaces = Some(Namespaces {
        active: namespaces
            .intersection(&ns_set)
            .map(|ns| *ns as i32)
            .collect(),
        desired: namespaces.into_iter().map(|ns| ns as i32).collect(),
    });

    // test
    let mut tests = HashMap::new();

    let container_specific_hostname = config.uts_config_host.as_ref().unwrap().hostname
        != config.uts_config_container.as_ref().unwrap().hostname;
    tests.insert(
        "container_specific_hostname".to_string(),
        TestResult {
            passed: container_specific_hostname,
            valid: true,
            info: vec![],
        },
    );
    let container_specific_domainname = config.uts_config_host.as_ref().unwrap().domainname
        != config.uts_config_container.as_ref().unwrap().domainname;
    tests.insert(
        "container_specific_domainname".to_string(),
        TestResult {
            passed: container_specific_domainname,
            valid: true,
            info: vec![],
        },
    );
    Category {
        isolation: Some(isolation),
        capabilities: caps
            .intersection(&capabilities)
            .map(|cap| *cap as i32)
            .collect(),
        tests,
        description: format!(
            "Network namespace and UTS namespace status, networking-related capabilities"
        ),
    }
}

fn do_check_flags_host(namespaces: &Vec<MountNamespace>, root_dir: &PathBuf) -> Vec<String> {
    let mut flag_matches = HashMap::<String, Vec<ns::Id>>::new();
    let mut uuids = HashSet::<&str>::new();

    for mountns in namespaces.iter() {
        log::trace!(
            "Checking flags found in mountns {}:{} {:?}",
            mountns.ns_id.unwrap().st_dev,
            mountns.ns_id.unwrap().st_ino,
            mountns.flag_files
        );

        for flag in mountns.flag_files.iter() {
            log::trace!("Processing flag file at {flag}");

            if let Some(captures) = REGEX_UUID.captures(&flag) {
                if captures.len() != 1 {
                    log::error!("Found {} uuid matches in flag path {flag}", captures.len())
                }

                let match_str: &str = captures.get(0).unwrap().as_str();
                log::trace!("Processing uuid UUID {match_str}");

                uuids.insert(match_str);
            } else {
                log::error!("Failed to parse UUID from '{flag}'");
                continue;
            }

            let flag_path = PathBuf::from(flag);

            if flag_path.starts_with(root_dir) {
                log::trace!("Flag {flag} is located at given root directoy (host view) at {}, continuing...", root_dir.display());
                continue;
            }

            for allow in FLAG_LOCATION_ALLOW {
                if flag_path.starts_with(allow) {
                    log::debug!(
                        "Flag {flag} is located at allowed directory {allow}, continuing..."
                    );
                    continue;
                }
            }

            if flag_matches.contains_key(flag) {
                log::trace!("Flag already contained in matches, appending ns id to existing entry");
                flag_matches
                    .get_mut(flag)
                    .unwrap()
                    .push(mountns.ns_id.unwrap());
            } else {
                log::debug!("Adding flag match {flag}");
                flag_matches.insert(flag.clone(), vec![mountns.ns_id.unwrap()]);
            }
        }
    }

    if 1 != uuids.len() {
        log::error!("Found flag files with multiple UUIDs: '{uuids:?}' => pollution from previous checkc run?");
    }

    let mut flag_matches_str: Vec<String> = vec![];

    for (flag, ids) in flag_matches.iter() {
        let ids_str = ids
            .iter()
            .map(|ns_id| format!("{}:{}", ns_id.st_dev, ns_id.st_ino))
            .collect::<Vec<String>>()
            .join(", ");

        flag_matches_str.push(format!("{flag}: {ids_str}"));
    }

    flag_matches_str
}

fn do_check_flags_refcontainer(namespaces: &Vec<MountNamespace>) -> Vec<String> {
    let mut flag_matches = HashMap::<String, Vec<ns::Id>>::new();

    for mountns in namespaces.iter() {
        log::debug!(
            "Checking flags found in mountns {}:{} {:?}",
            mountns.ns_id.unwrap().st_dev,
            mountns.ns_id.unwrap().st_ino,
            mountns.flag_files
        );

        for flag in mountns.flag_files.iter() {
            log::debug!("Processing flag file at {flag}");

            if flag_matches.contains_key(flag) {
                log::debug!("Flag already contained in matches, appending ns id to existing entry");
                flag_matches
                    .get_mut(flag)
                    .unwrap()
                    .push(mountns.ns_id.unwrap());
            } else {
                flag_matches.insert(flag.clone(), vec![mountns.ns_id.unwrap()]);
            }
        }
    }

    let mut flag_matches_str: Vec<String> = vec![];

    for (flag, ids) in flag_matches.iter() {
        let ids_str = ids
            .iter()
            .map(|ns_id| format!("{}:{}", ns_id.st_dev, ns_id.st_ino))
            .collect::<Vec<String>>()
            .join(", ");

        flag_matches_str.push(format!("{flag}: {ids_str}"));
    }

    flag_matches_str
}

fn category_filesystem(
    config: &Config,
    ns_set: &HashSet<ns::Type>,
    capabilities: &HashSet<caps::Capability>,
    container_root_host: &PathBuf,
) -> Category {
    let caps = HashSet::from([
        caps::Capability::CapSysChroot,
        caps::Capability::CapLinuxImmutable,
        caps::Capability::CapLease,
    ]);

    let namespaces = HashSet::from([ns::Type::Mount]);

    let mut isolation = IsolationMechanisms::default();
    isolation.namespaces = Some(Namespaces {
        active: namespaces
            .intersection(&ns_set)
            .map(|ns| *ns as i32)
            .collect(),
        desired: namespaces.into_iter().map(|ns| ns as i32).collect(),
    });
    let host_root = config
        .chroot_config
        .as_ref()
        .unwrap()
        .host
        .as_ref()
        .unwrap();
    let container_root = config
        .chroot_config
        .as_ref()
        .unwrap()
        .container
        .as_ref()
        .unwrap();

    let chroot =
        (host_root.st_dev != container_root.st_dev) || (host_root.st_ino != container_root.st_ino);
    let pivot_root = chroot && container_root.path == "/";
    isolation.chroot = Some(Chroot { chroot, pivot_root });

    // tests
    let mut tests = HashMap::new();

    let flag_matches_host = do_check_flags_host(
        &config.fs_config.as_ref().unwrap().host_namespaces,
        container_root_host,
    );
    tests.insert(
        format!("flag_matches_host"),
        TestResult {
            passed: flag_matches_host.is_empty(),
            valid: true,
            info: flag_matches_host,
        },
    );

    let flag_matches_ref_container =
        do_check_flags_refcontainer(&config.fs_config.as_ref().unwrap().ref_container_namespaces);
    tests.insert(
        format!("flag_matches_refcontainer"),
        TestResult {
            passed: flag_matches_ref_container.is_empty(),
            valid: true,
            info: flag_matches_ref_container,
        },
    );

    Category {
        isolation: Some(isolation),
        capabilities: caps
            .intersection(&capabilities)
            .map(|cap| *cap as i32)
            .collect(),
        tests,
        description: format!(
            "Container filesystem isolation (Mount namespace, Chroot), filesystem-related capabilities, filesystem configuration"
        ),
    }
}

fn category_devices(
    config: &Config,
    ns_set: &HashSet<ns::Type>,
    capabilities: &HashSet<caps::Capability>,
) -> Category {
    let caps = HashSet::from([
        caps::Capability::CapMknod,
        caps::Capability::CapSysRawio,
        caps::Capability::CapSysTtyConfig,
    ]);

    // tests
    let mut tests = HashMap::new();

    log::debug!("Evaluating device whitelist compliance");
    tests.insert(
        format!("dev_whitelist_compliance"),
        dev_whitelist_compliance(
            config
                .device_config
                .as_ref()
                .unwrap()
                .dev_devices
                .as_slice(),
            ns_set.contains(&c_config::ns::Type::User),
        ),
    );

    log::debug!("Evaluating mknod device whitelist compliance");
    tests.insert(
        format!("mknod_whitelist_compliance"),
        dev_whitelist_compliance(
            config
                .device_config
                .as_ref()
                .unwrap()
                .mknod_devices
                .as_slice(),
            ns_set.contains(&c_config::ns::Type::User),
        ),
    );

    Category {
        isolation: None,
        capabilities: caps
            .intersection(&capabilities)
            .map(|cap| *cap as i32)
            .collect(),
        tests,
        description: format!(
            "Capabilities related to device handling, device whitelist compliance"
        ),
    }
}

fn category_resource_control(
    config: &Config,
    ns_set: &HashSet<ns::Type>,
    capabilities: &HashSet<caps::Capability>,
) -> Category {
    let caps = HashSet::from([
        caps::Capability::CapSysNice,
        caps::Capability::CapSysResource,
    ]);

    let namespaces = HashSet::from([ns::Type::Cgroup]);

    // Isolation
    let mut isolation = IsolationMechanisms::default();
    isolation.namespaces = Some(Namespaces {
        active: namespaces
            .intersection(&ns_set)
            .map(|ns| *ns as i32)
            .collect(),
        desired: namespaces.into_iter().map(|ns| ns as i32).collect(),
    });
    isolation.cgroup = Some(isolation_mechanisms::Cgroup {
        cgroup: !config
            .cgroup_config
            .as_ref()
            .unwrap()
            .controllers
            .is_empty(),
    });

    // tests
    let mut tests = HashMap::new();

    let cpu_max_limit = config
        .cgroup_config
        .as_ref()
        .unwrap()
        .interface_files
        .get("cpu.max");
    let mut cpu_max_limited = TestResult::default();
    if let Some(cpu_max_limit) = cpu_max_limit {
        cpu_max_limited.passed = !cpu_max_limit.contains("max");
        cpu_max_limited.valid = true;
        cpu_max_limited.info.push(format!("{cpu_max_limit}"));
    } else {
        cpu_max_limited.passed = false;
        cpu_max_limited.valid = true;
        cpu_max_limited.info.push(format!("cpu.max not available"));
    }
    tests.insert("cpu_max_limited".to_string(), cpu_max_limited);

    let memory_max_limit = config
        .cgroup_config
        .as_ref()
        .unwrap()
        .interface_files
        .get("memory.max");
    let mut memory_max_limited = TestResult::default();
    if let Some(memory_max_limit) = memory_max_limit {
        memory_max_limited.passed = !memory_max_limit.contains("max");
        memory_max_limited.valid = true;
        memory_max_limited.info.push(format!("{memory_max_limit}"));
    } else {
        memory_max_limited.passed = false;
        memory_max_limited.valid = true;
        memory_max_limited
            .info
            .push(format!("memory.max not available"));
    }
    tests.insert("memory_max_limited".to_string(), memory_max_limited.clone());

    let mut required_cgroups_controllers_active = TestResult::default();
    let controllers = config.cgroup_config.as_ref().unwrap().controllers.clone();

    let mut missing_controllers: String = String::from("");
    for c in CGROUPS_CONTROLLERS_REQUIRED.iter() {
        if !controllers.contains(c) {
            log::debug!("Required cgroups controller {c} not active");
            missing_controllers.push_str(&format!("{:?}, ", Controller::from_i32(*c)));
        }
    }
    required_cgroups_controllers_active.valid = true;
    required_cgroups_controllers_active.passed = missing_controllers.is_empty();
    tests.insert("".to_string(), required_cgroups_controllers_active);

    Category {
        isolation: Some(isolation),
        capabilities: caps
            .intersection(&capabilities)
            .map(|cap| *cap as i32)
            .collect(),
        tests,
        description: format!("Cgroup namespace, Cgroup status, capabilities related to resource managment, tests on Cgroup limits"),
    }
}

fn category_process_control(
    _config: &Config,
    ns_set: &HashSet<ns::Type>,
    capabilities: &HashSet<caps::Capability>,
) -> Category {
    let caps = HashSet::from([
        caps::Capability::CapSysPtrace,
        caps::Capability::CapSysPacct,
        caps::Capability::CapCheckpointRestore,
        caps::Capability::CapKill,
        caps::Capability::CapSysBoot,
    ]);

    let namespaces = HashSet::from([ns::Type::Pid, ns::Type::Ipc]);

    // Isolation
    let mut isolation = IsolationMechanisms::default();
    isolation.namespaces = Some(Namespaces {
        active: namespaces
            .intersection(&ns_set)
            .map(|ns| *ns as i32)
            .collect(),
        desired: namespaces.into_iter().map(|ns| ns as i32).collect(),
    });

    // tests
    let tests = HashMap::new();

    Category {
        isolation: Some(isolation),
        capabilities: caps
            .intersection(&capabilities)
            .map(|cap| *cap as i32)
            .collect(),
        tests,
        description: format!(
            "PID namespace and IPC namespace state, capabilities related to process handling/management"
        ),
    }
}

fn category_access_control(
    config: &Config,
    ns_set: &HashSet<ns::Type>,
    capabilities: &HashSet<caps::Capability>,
) -> Category {
    let caps = HashSet::from([
        caps::Capability::CapChown,
        caps::Capability::CapDacOverride,
        caps::Capability::CapDacReadSearch,
        caps::Capability::CapFowner,
        caps::Capability::CapFsetid,
        caps::Capability::CapSetuid,
        caps::Capability::CapSetgid,
        caps::Capability::CapSetpcap,
        caps::Capability::CapSetfcap,
        caps::Capability::CapIpcOwner,
        caps::Capability::CapMacOverride,
        caps::Capability::CapMacAdmin,
    ]);

    let namespaces = HashSet::from([ns::Type::User]);

    // Isolation
    let mut isolation = IsolationMechanisms::default();
    isolation.namespaces = Some(Namespaces {
        active: namespaces
            .intersection(&ns_set)
            .map(|ns| *ns as i32)
            .collect(),
        desired: namespaces.into_iter().map(|ns| ns as i32).collect(),
    });

    // tests
    let mut tests = HashMap::new();

    let uid_maps_to_root = config
        .user_ns_config
        .as_ref()
        .unwrap()
        .uid_map
        .iter()
        .find(|mapping| mapping.parent == 0);

    tests.insert(
        format!("user_ns_maps_to_non_root_user"),
        TestResult {
            passed: uid_maps_to_root.is_none(),
            valid: true,
            info: vec![format!("")],
        },
    );

    tests.insert(
        format!("user_ns_mapping_unique"),
        TestResult {
            passed: config.user_ns_config.as_ref().unwrap().unique_mapping,
            valid: true,
            info: vec![format!("")],
        },
    );

    let seccomp_mode = config.seccomp_config.as_ref().unwrap().mode();
    tests.insert(
        format!("seccomp_enabled"),
        TestResult {
            passed: seccomp_mode == c_config::seccomp::Mode::SeccompModeFilter
                || seccomp_mode == c_config::seccomp::Mode::SeccompModeStrict,
            valid: true,
            info: vec![format!("")],
        },
    );

    Category {
        isolation: Some(isolation),
        capabilities: caps
            .intersection(&capabilities)
            .map(|cap| *cap as i32)
            .collect(),
        tests,
        description: format!("User namespace status, capabilities related to access control management, tests on User namespace mapping")
    }
}

fn category_time(
    _config: &Config,
    ns_set: &HashSet<ns::Type>,
    capabilities: &HashSet<caps::Capability>,
) -> Category {
    let caps = HashSet::from([caps::Capability::CapSysTime]);

    let namespaces = HashSet::from([ns::Type::Time]);

    // Isolation
    let mut isolation = IsolationMechanisms::default();
    isolation.namespaces = Some(Namespaces {
        active: namespaces
            .intersection(&ns_set)
            .map(|ns| *ns as i32)
            .collect(),
        desired: namespaces.into_iter().map(|ns| ns as i32).collect(),
    });

    // tests
    let tests = HashMap::new();

    Category {
        isolation: Some(isolation),
        capabilities: caps
            .intersection(&capabilities)
            .map(|cap| *cap as i32)
            .collect(),
        tests,
        description: format!(
            "Time namespace status, capabilities related to system clock interaction"
        ),
    }
}

fn category_global(
    _config: &Config,
    _ns_set: &HashSet<ns::Type>,
    capabilities: &HashSet<caps::Capability>,
) -> Category {
    let caps = HashSet::from([
        caps::Capability::CapSysAdmin,
        caps::Capability::CapAuditControl,
        caps::Capability::CapAuditRead,
        caps::Capability::CapAuditWrite,
        caps::Capability::CapSysModule,
        caps::Capability::CapSyslog,
        caps::Capability::CapWakeAlarm,
        caps::Capability::CapPerfmon,
        caps::Capability::CapBpf,
        caps::Capability::CapNetBroadcast,
        caps::Capability::CapIpcLock,
        caps::Capability::CapBlockSuspend,
    ]);

    // tests
    let tests = HashMap::new();

    Category {
        isolation: None,
        capabilities: caps
            .intersection(&capabilities)
            .map(|cap| *cap as i32)
            .collect(),
        tests,
        description: format!(
            "Default category for capabilities and tests not matching other categories"
        ),
    }
}

// tests
fn dev_whitelist_compliance(
    devices: &[c_config::device::Device],
    unprivileged: bool,
) -> TestResult {
    let mut not_allowed_dev = Vec::new();

    log::trace!("Evaluating {} devices", devices.len());

    for dev in devices {
        log::trace!("Processing device {}", dev.file);
        // skip non-char and non-block devices
        if dev.id.as_ref().unwrap().r#type() != device::Type::Char
            && dev.id.as_ref().unwrap().r#type() != device::Type::Block
        {
            log::trace!("Skipping device {}", dev.file);
            continue;
        }
        if !DEV_MAJOR_WHITELIST.contains(&(
            dev.id.as_ref().unwrap().r#type(),
            dev.id.as_ref().unwrap().major,
        )) {
            if !DEV_WHITELIST_GENERAL.contains_key(dev.id.as_ref().unwrap()) {
                if !(unprivileged
                    && DEV_WHITELIST_UNPRIVILEGED.contains_key(dev.id.as_ref().unwrap()))
                {
                    let id = dev.id.as_ref().unwrap();
                    let dev_type = c_config::device::Type::from_i32(id.r#type).unwrap();
                    let dev_str = format!(
                        "{} {}:{} at {}",
                        dev_type,
                        dev.id.as_ref().unwrap().major,
                        dev.id.as_ref().unwrap().minor,
                        dev.file
                    );
                    log::trace!("Processing device {dev_str}");
                    not_allowed_dev.push(format!("{dev_str}"));
                } else {
                    log::trace!("Skipping device {}", dev.file);
                }
            } else {
                log::trace!(
                    "Skipping device {} matching DEV_WHITELIST_GENERAL",
                    dev.file
                );
            }
        } else {
            log::trace!("Skipping device {} matching DEV_MAJOR_WHITELIST", dev.file);
        }
    }

    TestResult {
        passed: not_allowed_dev.is_empty(),
        valid: true,
        info: not_allowed_dev,
    }
}

// helper functions
pub fn contains_ns_type(ns_vec: &[ns::Info], ns_type: ns::Type) -> bool {
    ns_vec
        .iter()
        .find(|info| info.r#type() == ns_type)
        .is_some()
}

pub fn capability_is_set(cap_set: &[caps::Capability], cap: caps::Capability) -> bool {
    cap_set.iter().find(|elem| **elem == cap).is_some()
}
