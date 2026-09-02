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

use crate::assessment::Criticality;
use crate::c_config::*;
use once_cell::sync::Lazy;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::collections::HashSet;

// descriptions adapted from https://man7.org/linux/man-pages/man7/capabilities.7.html
pub static CAP_MAP: Lazy<HashMap<caps::Capability, CapabilityRecord>> = Lazy::new(|| {
    let mut map = HashMap::new();
    map.insert(
        caps::Capability::CapAuditControl,
        CapabilityRecord {
            ok: HashSet::from([ns::Type::User]),
            warn: HashSet::new(),
            default: Criticality::Error,
            notes: format!("Manage kernel auditing (activation, rules, etc.)"),
        },
    );

    map.insert(
        caps::Capability::CapAuditRead,
        CapabilityRecord {
            ok: HashSet::from([ns::Type::User]),
            warn: HashSet::new(),
            default: Criticality::Warn,
            notes: format!("Allows reading audit log via netlink"),
        },
    );

    map.insert(
        caps::Capability::CapAuditWrite,
        CapabilityRecord {
            ok: HashSet::from([ns::Type::User]),
            warn: HashSet::new(),
            default: Criticality::Error,
            notes: format!("Allows writing to audit log"),
        },
    );

    map.insert(
        caps::Capability::CapBlockSuspend,
        CapabilityRecord {
            ok: HashSet::from([ns::Type::User]),
            warn: HashSet::new(),
            default: Criticality::Warn,
            notes: format!("Allows blocking system suspend"),
        },
    );

    map.insert(
        caps::Capability::CapBpf,
        CapabilityRecord {
            ok: HashSet::from([ns::Type::User]),
            warn: HashSet::new(),
            default: Criticality::Error,
            notes: format!("Allows privileged BPF operations"),
        },
    );

    map.insert(
        caps::Capability::CapCheckpointRestore,
        CapabilityRecord {
            ok: HashSet::from([ns::Type::User, ns::Type::Pid]),
            warn: HashSet::new(),
            default: Criticality::Error,
            notes: format!("Allows writing to /proc/sys/kernel/ns_last_pid, clonse set_tid-feature, read /proc/pid/map_files"),
        },
    );

    map.insert(
        caps::Capability::CapChown,
        CapabilityRecord {
            ok: HashSet::from([ns::Type::User]),
            warn: HashSet::new(),
            default: Criticality::Error,
            notes: format!("Arbitrary changes to file uids / gids"),
        },
    );

    map.insert(
        caps::Capability::CapDacOverride,
        CapabilityRecord {
            ok: HashSet::from([ns::Type::User]),
            warn: HashSet::new(),
            default: Criticality::Warn,
            notes: format!("Allows bypassing DAC"),
        },
    );

    map.insert(
        caps::Capability::CapDacReadSearch,
        CapabilityRecord {
            ok: HashSet::from([ns::Type::User]),
            warn: HashSet::new(),
            default: Criticality::Error,
            notes: format!(
                "Bypass permissions of files/directories, create link to file by fd, allows open_by_handle_at (https://www.exploit-db.com/exploits/33808)"
            ),
        },
    );
    map.insert(
        caps::Capability::CapFowner,
        CapabilityRecord {
            ok: HashSet::from([ns::Type::User]),
            warn: HashSet::new(),
            default: Criticality::Error,
            notes: format!("Bypass file owner permission checks"),
        },
    );

    map.insert(
        caps::Capability::CapFsetid,
        CapabilityRecord {
            ok: HashSet::from([ns::Type::User]),
            warn: HashSet::new(),
            default: Criticality::Error,
            notes: format!("Functionality related to the set UID and set GID bits, e.g. not clearing them when modifying a file"),
        },
    );

    map.insert(
        caps::Capability::CapIpcLock,
        CapabilityRecord {
            ok: HashSet::from([ns::Type::User]),
            warn: HashSet::from([]),
            default: Criticality::Error,
            notes: format!("Lock memory, allocate memory via huge pages"),
        },
    );

    map.insert(
        caps::Capability::CapIpcOwner,
        CapabilityRecord {
            ok: HashSet::from([ns::Type::User, ns::Type::Ipc]),
            warn: HashSet::new(),
            default: Criticality::Error,
            notes: format!("Bypass permission checks on System V IPC objects"),
        },
    );

    map.insert(
        caps::Capability::CapKill,
        CapabilityRecord {
            ok: HashSet::from([ns::Type::User]),
            warn: HashSet::from([ns::Type::Pid]),
            default: Criticality::Error,
            notes: format!("Bypass permission checks for sending signals"),
        },
    );

    map.insert(
        caps::Capability::CapLease,
        CapabilityRecord {
            ok: HashSet::from([ns::Type::User]),
            warn: HashSet::new(),
            default: Criticality::Error,
            notes: format!("Leases on arbitrary files"),
        },
    );

    map.insert(
        caps::Capability::CapLinuxImmutable,
        CapabilityRecord {
            ok: HashSet::from([ns::Type::User]),
            warn: HashSet::new(),
            default: Criticality::Error,
            notes: format!("Set FS_APPEND_FL and FS_IMMUTABLE_FL inode flags"),
        },
    );

    map.insert(
        caps::Capability::CapMacAdmin,
        CapabilityRecord {
            ok: HashSet::from([ns::Type::User]),
            warn: HashSet::new(),
            default: Criticality::Error,
            notes: format!("Allow MAC configuration or state changes"),
        },
    );

    map.insert(
        caps::Capability::CapMacOverride,
        CapabilityRecord {
            ok: HashSet::from([ns::Type::User]),
            warn: HashSet::new(),
            default: Criticality::Error,
            notes: format!("Smack LSM: Allow Mandatory Access Control override"),
        },
    );

    map.insert(
        caps::Capability::CapMknod,
        CapabilityRecord {
            ok: HashSet::from([ns::Type::User]),
            warn: HashSet::new(),
            default: Criticality::Info,
            notes: format!("Use of  the mknod system call to create device nodes"),
        },
    );

    map.insert(
        caps::Capability::CapNetAdmin,
        CapabilityRecord {
            ok: HashSet::from([ns::Type::User]),
            warn: HashSet::from([]),
            default: Criticality::Error,
            notes: format!("Allows various network-related operations"),
        },
    );

    map.insert(
        caps::Capability::CapNetBindService,
        CapabilityRecord {
            ok: HashSet::from([ns::Type::User]),
            warn: HashSet::from([ns::Type::Network]),
            default: Criticality::Error,
            notes: format!("Bind socket to privileged ports"),
        },
    );

    map.insert(
        caps::Capability::CapNetBroadcast,
        CapabilityRecord {
            ok: HashSet::from([ns::Type::User, ns::Type::Network]),
            warn: HashSet::new(),
            default: Criticality::Error,
            notes: format!("Unused capability, related to socket broadcasts / listening to multicast transmissions"),
        },
    );

    map.insert(
        caps::Capability::CapNetRaw,
        CapabilityRecord {
            ok: HashSet::from([ns::Type::User]),
            warn: HashSet::from([ns::Type::Network]),
            default: Criticality::Error,
            notes: format!("Use RAW and PACKET sockets"),
        },
    );

    map.insert(
        caps::Capability::CapPerfmon,
        CapabilityRecord {
            ok: HashSet::from([ns::Type::User]),
            warn: HashSet::new(),
            default: Criticality::Warn,
            notes: format!("Allows performance monitoring related functionality"),
        },
    );

    map.insert(
        caps::Capability::CapSetgid,
        CapabilityRecord {
            ok: HashSet::from([ns::Type::User]),
            warn: HashSet::new(),
            default: Criticality::Error,
            notes: format!("Allows arbitrary manipulation of process GID"),
        },
    );

    map.insert(
        caps::Capability::CapSetfcap,
        CapabilityRecord {
            ok: HashSet::from([ns::Type::User]),
            warn: HashSet::from([]),
            default: Criticality::Error,
            notes: format!("Allows setting arbitrary capabilities on a file"),
        },
    );

    map.insert(
        caps::Capability::CapSetpcap,
        CapabilityRecord {
            ok: HashSet::from([ns::Type::User]),
            warn: HashSet::from([]),
            default: Criticality::Error,
            notes: format!(
                "Depending on whether file caps are supported: allows manipulation of cap perm set"
            ),
        },
    );

    map.insert(
        caps::Capability::CapSetuid,
        CapabilityRecord {
            ok: HashSet::from([ns::Type::User]),
            warn: HashSet::new(),
            default: Criticality::Error,
            notes: format!("Allows arbitrary manipulations of process UID"),
        },
    );

    map.insert(
        caps::Capability::CapSysAdmin,
        CapabilityRecord {
            ok: HashSet::from([ns::Type::User]),
            warn: HashSet::from([]),
            default: Criticality::Error,
            notes: format!("Overloaded Capability, defacto root"),
        },
    );

    map.insert(
        caps::Capability::CapSysBoot,
        CapabilityRecord {
            ok: HashSet::from([ns::Type::User, ns::Type::Pid]),
            warn: HashSet::from([]),
            default: Criticality::Error,
            notes: format!("System reboot; allows to load new kernel"),
        },
    );

    // special case CAP_SYS_CHROOT, checked separately
    map.insert(
        caps::Capability::CapSysChroot,
        CapabilityRecord {
            ok: HashSet::new(),
            warn: HashSet::new(),
            default: Criticality::Error,
            notes: format!("Perform chroot; join mount namespaces"),
        },
    );

    map.insert(
        caps::Capability::CapSysModule,
        CapabilityRecord {
            ok: HashSet::from([ns::Type::User]),
            warn: HashSet::from([]),
            default: Criticality::Error,
            notes: format!("Allows loading/unloading of kernel modules"),
        },
    );

    map.insert(
        caps::Capability::CapSysNice,
        CapabilityRecord {
            ok: HashSet::from([ns::Type::User]),
            warn: HashSet::new(),
            default: Criticality::Warn,
            notes: format!("Allows various operations regarding process scheduling"),
        },
    );

    map.insert(
        caps::Capability::CapSysPacct,
        CapabilityRecord {
            ok: HashSet::from([ns::Type::User]),
            warn: HashSet::new(),
            default: Criticality::Warn,
            notes: format!("Switch process accounting on or off"),
        },
    );

    map.insert(
        caps::Capability::CapSysPtrace,
        CapabilityRecord {
            ok: HashSet::from([ns::Type::User]),
            warn: HashSet::from([ns::Type::Pid]),
            default: Criticality::Error,
            notes: format!("Allow tracing processes via ptrace"),
        },
    );

    map.insert(
        caps::Capability::CapSysRawio,
        CapabilityRecord {
            ok: HashSet::from([ns::Type::User]),
            warn: HashSet::new(),
            default: Criticality::Error,
            notes: format!("Grants access to /dev/mem, /dev/kmem and others"),
        },
    );

    map.insert(
        caps::Capability::CapSysResource,
        CapabilityRecord {
            ok: HashSet::from([ns::Type::User]),
            warn: HashSet::new(),
            default: Criticality::Error,
            notes: format!("Allows various resource-related operations"),
        },
    );

    map.insert(
        caps::Capability::CapSysTime,
        CapabilityRecord {
            ok: HashSet::from([ns::Type::User]),
            warn: HashSet::from([]),
            default: Criticality::Error,
            notes: format!("Set system clock and realtime clock"),
        },
    );

    map.insert(
        caps::Capability::CapSysTtyConfig,
        CapabilityRecord {
            ok: HashSet::from([ns::Type::User]),
            warn: HashSet::from([]),
            default: Criticality::Error,
            notes: format!("vhangup system call, various privileged ioctl operations"),
        },
    );

    map.insert(
        caps::Capability::CapSyslog,
        CapabilityRecord {
            ok: HashSet::from([ns::Type::User]),
            warn: HashSet::new(),
            default: Criticality::Error,
            notes: format!("Privileged operations on the system log; view kernel addresses via procfs and others"),
        },
    );

    map.insert(
        caps::Capability::CapWakeAlarm,
        CapabilityRecord {
            ok: HashSet::from([ns::Type::User]),
            warn: HashSet::new(),
            default: Criticality::Error,
            notes: format!("Set CLOCK_REALTIME_ALARM, CLOCK_BOOTTIME_ALARM"),
        },
    );

    assert_eq!(map.len(), caps::Capability::last() as usize + 1);
    map
});

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CapabilityRecord {
    ok: HashSet<ns::Type>,
    warn: HashSet<ns::Type>,
    default: Criticality,
    notes: String,
}

impl CapabilityRecord {
    pub fn ok(&self) -> &HashSet<ns::Type> {
        &self.ok
    }

    pub fn warn(&self) -> &HashSet<ns::Type> {
        &self.warn
    }

    pub fn default(&self) -> Criticality {
        self.default
    }

    pub fn notes(&self) -> &str {
        self.notes.as_str()
    }
}
