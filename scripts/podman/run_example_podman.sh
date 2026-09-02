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

set -e

info () {
	echo -e "$CYAN$1$CLEAR"
}

CYAN="\e[36m"
CLEAR="\e[0m"

BASE_PATH="$(dirname ${BASH_SOURCE[0]})"

CHECKC_PATH="$(readlink --canonicalize "$BASE_PATH/../../target/x86_64-unknown-linux-gnu/release/checkc" || true)"

CONTAINER_NAME="checkctest"
REF_CONTAINER_NAME="checkcref"

ID_CONTAINER="$(podman ps -qf 'name=checkctest')"
ID_REF_CONTAINER="$(podman ps -qf 'name=checkcref')"

if [ -z "$ID_CONTAINER" ] || [ -z "$ID_REF_CONTAINER" ];then
	info "Failed to retrieve container IDs:"
	info "ID_CONTAINER='$ID_CONTAINER'"
	info "ID_REF_CONTAINER='$ID_REF_CONTAINER'"
	exit 1
fi

info "Retrieving container IDs, PIDs and directories"
PID_CONTAINER="$(podman inspect -f '{{.State.Pid}}' "$ID_CONTAINER")"
PID_REF_CONTAINER="$(podman inspect -f '{{.State.Pid}}' "$ID_REF_CONTAINER")"
PID_HOST="1"

CONTAINER_ROOT_HOST="$(podman inspect -f '{{.GraphDriver.Data.MergedDir}}' $ID_CONTAINER)"
CONTAINER_ROOT_HOST="$(dirname $CONTAINER_ROOT_HOST)"

HOST_DATA_RAW="$BASE_PATH/reports/host_data_raw.json"
CONTAINER_DATA_RAW="$BASE_PATH/reports/container_data_raw.json"
EVALUATION_REPORT="$BASE_PATH/reports/evaluation_report.json"
ASSESSMENT_REPORT="$BASE_PATH/reports/assessment_report.json"
mkdir -p "$BASE_PATH/reports"

DEFAULT_RUST_BACKTRACE="1"
DEFAULT_RUST_LOG="info,globset=info,ignore=info"
DEFAULT_RUST_LOG_STYLE="always"

echo "ID_CONTAINER: '$ID_CONTAINER'"
echo "ID_REF_CONTAINER: '$ID_REF_CONTAINER'"

echo "PID_CONTAINER: '$PID_CONTAINER'"
echo "PID_REF_CONTAINER: '$PID_REF_CONTAINER'"
echo "PID_HOST: '$PID_HOST'"

echo "CONTAINER_ROOT_HOST: '$CONTAINER_ROOT_HOST'"

if [ -z "$PID_CONTAINER" ] || [ -z "$PID_REF_CONTAINER" ] || [ -z "$PID_HOST" ];then
    info "Failed to determine PID_CONTAINER or PID_REF_CONTAINER, exiting..."
    exit 1
fi

# 1. Wait for checkc to create container report
info "Retrieving checkc report from test container"
while true;do
    res="$(podman cp $ID_CONTAINER:/checkc/checkc_data/container_data_raw.json "$CONTAINER_DATA_RAW" 2>&1 || true)" || true
    match="$(info "$res" | grep "could not be found on container" || true)" || true

    if ! [ -z "$match" ];then
        info "Waiting for checkc to finish run inside container"
        sleep 2
        continue
    fi  

    sleep 2

    info "Storing to ./reports/container_data_raw.json"
    podman cp $ID_CONTAINER:/checkc/checkc_data/container_data_raw.json ./reports/container_data_raw.json
    podman cp $ID_CONTAINER:/checkc/checkc_data/checkc_container.log ./reports/checkc_container.log
    break
done

# 2. Run checkc in host mode
info "Executing checkc in host mode"
time sudo RUST_BACKTRACE="$DEFAULT_RUST_BACKTRACE" RUST_LOG="$DEFAULT_RUST_LOG" RUST_LOG_STYLE="$DEFAULT_RUST_LOG_STYLE" "$CHECKC_PATH" host --pid-host="$PID_HOST" --pid-container="$PID_CONTAINER" --pid-ref-container="$PID_REF_CONTAINER" -o "$HOST_DATA_RAW" 2>&1 | tee reports/checkc_host.log

info "Executed checkc in host mode, return code: $?"

# 3. Run checkc in evaluation mode
info "Executing checkc in evaluation mode"
time RUST_BACKTRACE="$DEFAULT_RUST_BACKTRACE" RUST_LOG="$DEFAULT_RUST_LOG" RUST_LOG_STYLE="$DEFAULT_RUST_LOG_STYLE" "$CHECKC_PATH" evaluation --c-config-host="$HOST_DATA_RAW" --c-config-container="$CONTAINER_DATA_RAW" --container-root-host="$CONTAINER_ROOT_HOST" -o "$EVALUATION_REPORT" 2>&1 | tee ./reports/checkc_evaluation.log
info "Executed checkc in evaluation mode, return code: $?"

# 4. Run checkc in assessment mode
info "Executing checkc in assessment mode"
time RUST_BACKTRACE="$DEFAULT_RUST_BACKTRACE" RUST_LOG="$DEFAULT_RUST_LOG" RUST_LOG_STYLE="$DEFAULT_RUST_LOG_STYLE" "$CHECKC_PATH" assessment --evaluation-report "$EVALUATION_REPORT" -o "$ASSESSMENT_REPORT" 2>&1 | tee ./reports/checkc_assessment.log
info "Executed checkc in assessment mode, return code: $?"

info "Done, reports stored at"
info "CONTAINER_DATA_RAW: $CONTAINER_DATA_RAW"
info "HOST_DATA_RAW: $HOST_DATA_RAW"
info "EVALUATION_REPORT: $EVALUATION_REPORT"
info "ASSESSMENT_REPORT: $ASSESSMENT_REPORT"
