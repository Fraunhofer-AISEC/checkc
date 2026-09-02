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

IMGPATH=""

if [ -f "$1" ];then
	IMGPATH="$1"
else
	echo "ERROR: No regular file found at '$1'"
	exit 1
fi

echo "Running image at '$IMGPATH'"

kvm -cpu host -smp 4 -m 8192 -nographic \
   -net nic -net user,hostfwd=tcp::2222-:22 \
   -drive file=${IMGPATH},format=raw \
