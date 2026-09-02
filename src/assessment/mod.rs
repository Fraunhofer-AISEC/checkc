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

use std::collections::HashSet;

use crate::c_config::caps::Capability;
use crate::c_config::ns::Type;
use crate::config::cap_sec::CAP_MAP;
use crate::evaluation::Chroot;
use crate::evaluation::{EvalResult, Namespaces, TestResult};

include!(concat!(env!("OUT_DIR"), "/assessment.rs"));
include!(concat!(env!("OUT_DIR"), "/assessment.serde.rs"));

impl SecResult {
    fn append(&mut self, c: Criticality, info: &Vec<String>) -> () {
        self.state = std::cmp::max(self.state, c.into());
        self.info.extend(info.clone());
    }
}

pub fn assess_eval_result(eval_result: &EvalResult) -> AssessmentReport {
    let mut sec_report: AssessmentReport = AssessmentReport::default();

    if !eval_result.unprivileged {
        log::info!("Processing privileged container");
    }

    sec_report.unprivileged = eval_result.unprivileged;

    // assess security goal S2
    sec_report.goal_s2 = assess_goal_s2(eval_result.unprivileged, eval_result);

    let result_goal_s2 = if sec_report.goal_s2.is_some() {
        Criticality::from_i32(
            sec_report
                .goal_s2
                .as_ref()
                .unwrap()
                .result
                .as_ref()
                .unwrap()
                .state,
        )
        .unwrap()
    } else {
        Criticality::Error
    };

    // assess security goal S1
    sec_report.goal_s1 = assess_goal_s1(eval_result.unprivileged, eval_result, result_goal_s2);

    if sec_report.goal_s1.is_none() {
        panic!("Failed to assess security goal S-1");
    }

    // assess security goal S3
    sec_report.goal_s3 = assess_goal_s3(eval_result.unprivileged, eval_result);

    // assess security goal S4
    sec_report.goal_s4 = assess_goal_s4(eval_result.unprivileged, eval_result);

    return sec_report;
}

fn assess_goal_s4(
    _unprivileged: bool,
    eval_result: &EvalResult,
) -> Option<GoalS4NoAvaiabilityImpact> {
    let mut report_s4 = GoalS4NoAvaiabilityImpact::default();
    let mut sec_result = SecResult::default();
    sec_result.state = Criticality::Ok.into();

    report_s4.description = "No availability impact".to_string();

    let cgroups_result = &eval_result.categories.get("resource_control").unwrap();

    if cgroups_result
        .isolation
        .as_ref()
        .unwrap()
        .namespaces
        .as_ref()
        .unwrap()
        .desired
        != cgroups_result
            .isolation
            .as_ref()
            .unwrap()
            .namespaces
            .as_ref()
            .unwrap()
            .active
    {
        let active = cgroups_result
            .isolation
            .clone()
            .unwrap()
            .namespaces
            .unwrap()
            .active
            .into_iter()
            .map(|t| Type::from_i32(t).unwrap().as_str_name())
            .collect::<Vec<_>>()
            .join(", ");
        let desired = cgroups_result
            .isolation
            .clone()
            .unwrap()
            .namespaces
            .unwrap()
            .desired
            .into_iter()
            .map(|t| Type::from_i32(t).unwrap().as_str_name())
            .collect::<Vec<_>>()
            .join(", ");
        let info = format!("Active namespaces ({active}) did not match desired ones ({desired}) for category 'resource_control', assessment result for goal S4 is ERROR");

        log::debug!("{}", info);
        sec_result.append(Criticality::Error, &vec![info]);
        report_s4.cgroups_namespace_used = false;
    } else {
        report_s4.cgroups_namespace_used = true;
    }

    //test: cpu_max_limited
    let test_uid_mapping = &eval_result
        .categories
        .get("resource_control")
        .unwrap()
        .tests
        .get("cpu_max_limited")
        .unwrap();
    assess_test("cpu_max_limited", test_uid_mapping, &mut sec_result);

    //test: memory_max_limited
    let test_uid_mapping = &eval_result
        .categories
        .get("resource_control")
        .unwrap()
        .tests
        .get("memory_max_limited")
        .unwrap();
    assess_test("memory_max_limited", test_uid_mapping, &mut sec_result);

    report_s4.result = Some(sec_result);

    return Some(report_s4);
}

fn assess_goal_s3(
    _unprivileged: bool,
    eval_result: &EvalResult,
) -> Option<GoalS3NoContainerDataLeak> {
    let mut report_s3 = GoalS3NoContainerDataLeak::default();
    let mut sec_result = SecResult::default();
    sec_result.state = Criticality::Ok.into();

    report_s3.description = "No container data leak".to_string();

    //test: uid mapping unique
    let test_uid_mapping = &eval_result
        .categories
        .get("access_control")
        .unwrap()
        .tests
        .get("user_ns_mapping_unique")
        .unwrap();
    assess_test("user_ns_mapping_unique", test_uid_mapping, &mut sec_result);

    //test: flag_matches_refcontainer
    let test_flag_matches_refcontainer = &eval_result
        .categories
        .get("filesystem")
        .unwrap()
        .tests
        .get("flag_matches_refcontainer")
        .unwrap();
    assess_test(
        "flag_matches_refcontainer",
        test_flag_matches_refcontainer,
        &mut sec_result,
    );

    //test: flag_matches_host
    let test_flag_matches_host = &eval_result
        .categories
        .get("filesystem")
        .unwrap()
        .tests
        .get("flag_matches_host")
        .unwrap();
    assess_test("flag_matches_host", test_flag_matches_host, &mut sec_result);

    report_s3.result = Some(sec_result);

    return Some(report_s3);
}

fn assess_goal_s2(
    _unprivileged: bool,
    eval_result: &EvalResult,
) -> Option<GoalS2RestrictedDeviceAccess> {
    let mut report_s2 = GoalS2RestrictedDeviceAccess::default();
    let mut sec_result = SecResult::default();
    sec_result.state = Criticality::Ok.into();

    report_s2.description = "Restriction of device access".to_string();

    let test_uid_mapping = &eval_result
        .categories
        .get("devices")
        .unwrap()
        .tests
        .get("dev_whitelist_compliance")
        .unwrap();
    assess_test(
        "dev_whitelist_compliance",
        test_uid_mapping,
        &mut sec_result,
    );

    //test: mknod_whitelist_compliance
    let test_uid_mapping = &eval_result
        .categories
        .get("devices")
        .unwrap()
        .tests
        .get("mknod_whitelist_compliance")
        .unwrap();
    assess_test(
        "mknod_whitelist_compliance",
        test_uid_mapping,
        &mut sec_result,
    );

    report_s2.result = Some(sec_result);

    return Some(report_s2);
}

fn assess_goal_s1(
    _unprivileged: bool,
    eval_result: &EvalResult,
    result_goal_s2: Criticality,
) -> Option<GoalS1GlobalResourceModification> {
    let mut report_s1 = GoalS1GlobalResourceModification::default();
    let mut sec_result = SecResult::default();
    sec_result.state = Criticality::Ok.into();

    report_s1.description = "Restriction of global resource modification".to_string();

    // collect namespace configuration
    let mut active_ns = HashSet::<Type>::new();
    let mut desired_ns = HashSet::<Type>::new();
    for (l, c) in &eval_result.categories {
        log::debug!("Collecting namespace information from category '{l}'");

        if c.isolation.as_ref().is_none() {
            log::debug!("No isolation information collected for category {l}");
        } else if c.isolation.as_ref()?.namespaces.is_none() {
            log::warn!("No namespace information collected for category {l}");
        } else {
            active_ns.extend(
                &mut c
                    .isolation
                    .as_ref()
                    .unwrap()
                    .namespaces
                    .as_ref()
                    .unwrap()
                    .active
                    .iter()
                    .copied()
                    .map(|n| Type::from_i32(n).unwrap()),
            );
            desired_ns.extend(
                &mut c
                    .isolation
                    .as_ref()
                    .unwrap()
                    .namespaces
                    .as_ref()
                    .unwrap()
                    .desired
                    .iter()
                    .copied()
                    .map(|n| Type::from_i32(n).unwrap()),
            );
        }
    }

    // collect capability configuration
    // enum is represented by i32 values internally,
    // conversion to string is performed implicitly during JSON serialization
    let mut capabilities = Vec::<Capability>::default();
    for (_, c) in &eval_result.categories {
        let mut c: Vec<Capability> = c
            .capabilities
            .clone()
            .into_iter()
            .map(|c| Capability::from_i32(c).unwrap())
            .collect();
        capabilities.append(&mut c);
    }

    // collect chroot configuration
    let chroot_conf: Chroot = eval_result
        .categories
        .get("filesystem")
        .unwrap()
        .isolation
        .as_ref()
        .unwrap()
        .chroot
        .clone()?;

    // assess chroot / pivot_root
    if (!chroot_conf.chroot) || (!chroot_conf.pivot_root) {
        log::debug!("issue in chroot config, setting sec_result to error");
        sec_result.append(
            Criticality::Error,
            &vec![format!(
                "goal_s1: Unexpected chroot config: chroot {}, pivot_root: {}",
                chroot_conf.chroot, chroot_conf.pivot_root
            )],
        );
    } else {
        log::debug!("chroot config ok, not modifying result for goal S1");
    }

    // assess namespaces
    let diff: Vec<&Type> = desired_ns.difference(&active_ns).collect();
    let info = diff
        .into_iter()
        .map(|t| Type::as_str_name(t))
        .collect::<Vec<_>>()
        .join(", ");

    //ensure all namespaces active
    if !(desired_ns
        .difference(&active_ns)
        .collect::<Vec<_>>()
        .is_empty())
    {
        sec_result.append(
            Criticality::Error,
            &vec![format!(
                "Active namespaces do not match desired namespaces: {info}"
            )],
        );
    }

    // assess capabilities
    let sec_result_caps =
        assess_capabilities(&active_ns, &capabilities, result_goal_s2, &chroot_conf);
    sec_result.append(
        Criticality::from_i32(sec_result_caps.state).unwrap(),
        &sec_result_caps.info,
    );

    let mut namespaces = Namespaces::default();
    namespaces.active = active_ns.iter().copied().map(|n| n.into()).collect();
    namespaces.desired = desired_ns.iter().copied().map(|n| n.into()).collect();

    //test: user_ns_maps_to_non_root_user
    let test_uid_mapping = &eval_result
        .categories
        .get("access_control")
        .unwrap()
        .tests
        .get("user_ns_maps_to_non_root_user")
        .unwrap();
    assess_test(
        "user_ns_maps_to_non_root_user",
        test_uid_mapping,
        &mut sec_result,
    );

    report_s1.result = Some(sec_result);
    report_s1.namespace_conf = Some(namespaces);
    report_s1.capabilities = capabilities.into_iter().map(|c| c.into()).collect();
    report_s1.chroot_conf = Some(chroot_conf);

    return Some(report_s1);
}

fn assess_test(name: &str, test: &TestResult, sec_result: &mut SecResult) -> () {
    log::debug!("Assessing result of container-side test {name}");

    if !test.valid {
        log::debug!("test {name} was not valid, assessment result for goal S3 is ERROR");
        sec_result.append(
            Criticality::Error,
            &vec![format!(
                "test {name} was not valid, assessment result is ERROR"
            )],
        );
    }

    if !test.passed {
        log::debug!("test {name} did not pass, assessment result for goal S3 is ERROR");
        sec_result.append(
            Criticality::Error,
            &vec![format!(
                "test {name} did not pass, assessment result is ERROR"
            )],
        );
    }
}

// Evaluate collected capabilities against CAP_MAP as configured in src/config/cap_sec.rs
fn assess_capabilities(
    ns_set: &HashSet<Type>,
    cap_set: &Vec<Capability>,
    result_goal_s2: Criticality,
    chroot_conf: &Chroot,
) -> SecResult {
    // perform lookup
    let mut sec_result = SecResult::default();

    for cap in cap_set {
        let cap_record = CAP_MAP.get(&cap).unwrap();

        // special case CAP_SYS_CHROOT --> handle separately
        if cap == &Capability::CapSysChroot {
            log::debug!("Assessing CAP_SYS_CHROOT");

            if (!ns_set.contains(&Type::User)) || (!ns_set.contains(&Type::Mount)) {
                sec_result.append(Criticality::Error,
                                   & vec![format!("CAP_SYS_CHROOT: active namespaces '{ns_set:?}' do not match required namespaces 'TYPE_USER, TYPE_MOUNT'")]);
                log::debug!("Result after assessing CAP_SYS_CHROOT is '{sec_result:?}' because active namespaces '{ns_set:?}' do not match required namespaces 'TYPE_USER, TYPE_MOUNT', ");
            } else if (!chroot_conf.chroot) || (!chroot_conf.pivot_root) {
                sec_result.append(Criticality::Error, &vec![format!("Result for CAP_SYS_CHROOT is Criticality::Error because of result for chroot tests (chroot: '{}',  pivot_root: '{}')", chroot_conf.chroot, chroot_conf.pivot_root)]);
                log::debug!("Result after assessing CAP_SYS_CHROOT is '{sec_result:?}' bacause of result for chroot tests (chroot: '{}',  pivot_root: '{}')", chroot_conf.chroot, chroot_conf.pivot_root);
            } else if Criticality::Ok != result_goal_s2 {
                sec_result.append(result_goal_s2, &vec![format!("CAP_SYS_CHROOT: Criticality::Error because of result '{result_goal_s2:?}' for Goal S2")]);
                log::debug!("Result after assessing CAP_SYS_CHROOT is '{sec_result:?}' because of result for Goal S2: '{result_goal_s2:?}'");
            } else {
                sec_result.append(Criticality::Ok, &vec![]);
                log::debug!("Result after assessing CAP_SYS_CHROOT is '{sec_result:?}'");
            }

            continue;
        }

        if (!cap_record.ok().is_empty()) && cap_record.ok().is_subset(ns_set) {
            let n = ns_set
                .intersection(cap_record.ok())
                .map(|n| n.to_string())
                .collect::<Vec<String>>()
                .join(", ");
            log::debug!("cap '{cap}' has 'Criticality::ok' as namespace(s) '{n}' are active");
        } else if (!cap_record.warn().is_empty()) && cap_record.warn().is_subset(ns_set) {
            let n = ns_set
                .intersection(cap_record.warn())
                .map(|n| n.to_string())
                .collect::<Vec<String>>()
                .join(", ");
            log::debug!("cap '{cap}' has 'Criticality::Warn' as namespace(s) '{n}' are active");

            sec_result.append(
                Criticality::Warn,
                &vec![format!(
                    "{}: {}, description: {}",
                    cap.to_string(),
                    Criticality::Warn.as_str_name(),
                    cap_record.notes()
                )],
            );
        } else {
            log::debug!(
                "No namespace match for cap '{}' in config, returning default criticality '{}'",
                cap.as_str_name(),
                cap_record.default().as_str_name()
            );

            sec_result.append(
                cap_record.default(),
                &vec![format!(
                    "{}: {} (default), description: {}",
                    cap.to_string(),
                    cap_record.default().as_str_name(),
                    cap_record.notes()
                )],
            );
        }
    }

    sec_result
}
