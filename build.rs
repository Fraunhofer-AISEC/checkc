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

use prost_build;
use std::env;
use std::{io::Result, path::PathBuf};
use walkdir::WalkDir;

fn main() -> Result<()> {
    let root = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("protos");
    let proto_files: Vec<PathBuf> = WalkDir::new(&root)
        .into_iter()
        .map(|r_entry| r_entry.unwrap())
        .filter(|entry| entry.file_type().is_file())
        .map(|entry| entry.into_path())
        .collect();

    for proto_file in &proto_files {
        println!("cargo:rerun-if-changed={}", proto_file.display());
    }

    let descriptor_path = PathBuf::from(env::var("OUT_DIR").unwrap()).join("proto_descriptor.bin");

    let mut prost_conf = prost_build::Config::new();

    prost_conf
        .file_descriptor_set_path(&descriptor_path)
        .compile_well_known_types()
        .extern_path(".google.protobuf", "::pbjson_types");

    prost_conf.type_attribute("c_config.ns.Id", " #[derive(Eq, Hash)]");
    prost_conf.type_attribute("evaluation.Namespaces", " #[derive(Eq, Hash)]");

    prost_conf.compile_protos(&proto_files, &[root])?;

    let descriptor_set = std::fs::read(descriptor_path)?;
    pbjson_build::Builder::new()
        .emit_fields()
        .register_descriptors(&descriptor_set)?
        .build(&[".c_config", ".evaluation", ".assessment"])?;
    Ok(())
}
