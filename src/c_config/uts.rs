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

use nix::unistd;

include!(concat!(env!("OUT_DIR"), "/c_config.uts.rs"));
include!(concat!(env!("OUT_DIR"), "/c_config.uts.serde.rs"));

pub fn uts_config() -> Result<Config> {
    log::info!("Collecting UTS config");
    let mut proto_uts_config = Config::default();

    proto_uts_config.hostname = unistd::gethostname()?.to_string_lossy().to_string();
    proto_uts_config.domainname = nix::sys::utsname::uname()?
        .domainname()
        .to_string_lossy()
        .to_string();

    Ok(proto_uts_config)
}
