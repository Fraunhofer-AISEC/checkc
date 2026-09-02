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
GPARTED_PATH="gparted-live-1.8.0-2-amd64.iso"

if [ -f "$1" ];then
	IMGPATH="$1"
else
	echo "ERROR: No regular file found at '$1', exiting..."
	exit 1
fi

if ! [ -f "$GPARTED_PATH" ];then
	echo "ERROR: Did not find gparted image at '$1', exiting..."
	exit 1
fi

echo "Running image at '$IMGPATH' with gparted at '$GPARTED_PATH'"

kvm -cpu host -smp 4 -m 8192 \
   -net nic -net user,hostfwd=tcp::2222-:22 \
   -drive file=${IMGPATH},format=raw \
   -boot menu=on -drive file=gparted-live-1.8.0-2-amd64.iso,media=cdrom,readonly=on \
