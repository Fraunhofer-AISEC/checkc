#!/bin/bash

# Copyright (c) 2022 - 2026 Fraunhofer AISEC
# Fraunhofer-Gesellschaft zur Foerderung der angewandten Forschung e.V.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

mkdir /checkc/checkc_data

echo "Executing checkc binary with md5sum $(md5sum /checkc/checkc)"

RUST_BACKTRACE="1" RUST_LOG="debug,globset=info,ignore=info" RUST_LOG_STYLE="always" /checkc/checkc container -o /checkc/checkc_data/container_data_raw.json 2>&1 | tee /checkc/checkc_data/checkc_container.log || true

echo "Keep checkc test container running" && sleep 1000000000000000000000000000
