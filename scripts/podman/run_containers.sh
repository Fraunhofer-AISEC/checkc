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

############## 1. Clean up previous container instances ##############
echo "Attempting to stop container instances from previous runs"
podman container kill checkctest
podman container rm checkctest

podman container kill checkcref
podman container rm checkcref

set -e

############## 2. Start example container ##############
echo "Starting example container"
podman build -f Containerfile -t checkctest_img ../../

podman run -d --name checkctest checkctest_img



############## 2. Start reference container ##############
echo "Starting reference container"
podman build -f Containerfile_ref -t checkcref_img ../..

podman run -d --name checkcref checkcref_img
