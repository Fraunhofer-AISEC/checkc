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

use anyhow::{Ok, Result};
use clap::{Args, Parser, Subcommand};
use env_logger::{self, fmt::style, Env};
use libc;
use std::env;

use checkc::*;
use std::io::Write;
use std::{fs::File, io::BufReader, path::*};

use crate::{c_config::HostInfo, get_container_pids};

#[derive(Parser)]
#[command(name = env!("CARGO_PKG_NAME"))]
#[command(author, version, about, long_about = None, after_help = "
Example usage

1. Gather host view of container config:

   user@host# checkc host --pid-host=1 --pid-container=<container init PID> --pid-ref-container=<container init PID>

2. Gather container view of container config. The checkc must be executed
   as regular container process to ensure a correct analysis.
   (e.g. not injected by nsenter or similar tools)

   user@container# checkc container -o </path/to/container_data_raw.json>

3. Evaluate container configuration:
   user@host checkc evaluation --c-config-container </path/to/container_data_raw.json>  --c-config-host </path/to/host_data_raw.json> --container-root-host </path/to/container/root>

4. Assess isolation characteristics of container:
   user@host checkc assessment --evaluation-report </path/to/evaluation_report.json>



")] // Read from `Cargo.toml`
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    // run in host-mode
    Host(HostArgs),
    // run in container-mode
    Container(ContainerArgs),
    // run in evaluation mode
    Evaluation(EvalArgs),
    // run in assessment mode
    Assessment(AssArgs),
}

#[derive(Args)]
struct HostArgs {
    // PID of a host process. Defaults to init process
    #[arg(long, default_value_t = 1)]
    pid_host: libc::pid_t,
    // PID of container manager (Optional)
    // PID of container process
    #[arg(long)]
    pid_container: libc::pid_t,
    #[arg(long)]
    pid_ref_container: libc::pid_t,
    #[arg(short,long,default_value_t = String::from("host_data_raw.json"))]
    output: String,
}

#[derive(Args)]
struct ContainerArgs {
    #[arg(short,long,default_value_t = String::from("container_data_raw.json"))]
    output: String,
}

#[derive(Args)]
struct EvalArgs {
    // mount point of container root (host view)
    #[arg(long, short = 'm', long)]
    container_root_host: PathBuf,
    // container config gathered inside container
    #[arg(long)]
    c_config_container: PathBuf,
    // container config gathered outside container
    #[arg(long)]
    c_config_host: PathBuf,
    // path to output file
    #[arg(short,long,default_value_t = String::from("evaluation_report.json"))]
    output: String,
}

#[derive(Args)]
struct AssArgs {
    // Container evaluation report
    #[arg(short = 'r', long)]
    evaluation_report: PathBuf,
    #[arg(short, long,default_value_t = String::from("assessment_report.json"))]
    output: String,
}

fn store_report(out: &String, data: &String, default_file: &str) -> Result<()> {
    let out_path = Path::new(out);

    if out_path.is_file() {
        panic!(
            "Refusing to overwrite file at {}",
            out_path.to_string_lossy()
        )
    }

    let p = if out_path.is_dir() {
        out_path.join(default_file)
    } else {
        out_path.to_path_buf()
    };

    log::debug!("Storing report to {}", p.to_string_lossy());

    let mut f = File::create(p)?;

    f.write_all(data.as_bytes())?;
    f.flush()?;

    Ok(())
}

fn main() -> Result<()> {
    // init logging
    env_logger::Builder::from_env(Env::default().default_filter_or("debug"))
        .format(|buf, record| {
            let mut style = env_logger::fmt::style::Style::new();
            style = style.bold();
            style = match record.level() {
                log::Level::Error => {
                    style.fg_color(Some(style::Color::Ansi(style::AnsiColor::Red)))
                }
                log::Level::Warn => {
                    style.fg_color(Some(style::Color::Ansi(style::AnsiColor::Yellow)))
                }
                log::Level::Debug => {
                    style.fg_color(Some(style::Color::Ansi(style::AnsiColor::Magenta)))
                }

                _ => style.fg_color(Some(style::Color::Ansi(style::AnsiColor::Blue))),
            };
            writeln!(
                buf,
                "{} {}:{}\t[{style}{}{style:#}] - {}",
                buf.timestamp(),
                record.file().unwrap_or("unknown"),
                record.line().unwrap_or(0),
                record.level(),
                record.args()
            )
        })
        .init();
    let cli = Cli::parse();

    match &cli.command {
        // collect host view of container configuration
        Commands::Host(args) => {
            log::info!("{} running in host mode\n\thost PID: {}\n\tcontainer PID: {}\n\tref container PID: {}", env!("CARGO_PKG_NAME"), args.pid_host, args.pid_container, args.pid_ref_container);

            let ns_config = c_config::ns::ns_config(args.pid_host, args.pid_container)?;
            let caps_config = c_config::caps::caps_config(args.pid_container)?;
            let cgroup_config = c_config::cgroup::cgroup_config(args.pid_container)?;
            let uts_config = c_config::uts::uts_config()?;
            let user_ns_config = c_config::user_ns::user_ns_config(args.pid_container)?;
            let fs_root_config =
                c_config::chroot::chroot_config(args.pid_host, args.pid_container)?;

            // parse mount points of test and reference containers (host view)
            let includes_test_container = get_container_pids(args.pid_container).unwrap();
            let includes_ref_container = get_container_pids(args.pid_ref_container).unwrap();

            log::debug!("Collecting fs config of test container (host view)");
            log::trace!("Using PID include list '{includes_test_container:?}'");
            let test_container_namespaces =
                c_config::fs::fs_config_hostview(&includes_test_container, true)?;

            log::debug!("Collecting fs config of reference container (host view)");
            log::trace!("Using PID include list '{includes_ref_container:?}'");
            let ref_container_namespaces =
                c_config::fs::fs_config_hostview(&includes_ref_container, true)?;

            // parse mount points of host (excluding test and reference containers)
            let mut excludes_host = get_container_pids(args.pid_container)?;
            excludes_host.append(&mut get_container_pids(args.pid_ref_container)?);

            log::debug!("Collecting fs config of host (excluding test and reference containers)");
            log::trace!("Using PID exclude list '{excludes_host:?}'");
            let host_namespaces = c_config::fs::fs_config_hostview(&excludes_host, false)?;

            let mut fs_config = c_config::fs::Config::default();
            fs_config.host_namespaces = host_namespaces;
            fs_config.container_namespaces = test_container_namespaces;
            fs_config.ref_container_namespaces = ref_container_namespaces;

            // create report
            log::debug!("Creating report");
            let mut c_config = c_config::Config::default();

            let mut info = HostInfo::default();
            info.pids_container = get_container_pids(args.pid_container)?;
            info.pids_ref_container = get_container_pids(args.pid_ref_container)?;

            c_config.info = Some(info);
            c_config.info.as_mut().unwrap().pid_host = args.pid_host;

            c_config.fs_config = Some(fs_config);
            c_config.ns_config = Some(ns_config);
            c_config.caps_config = Some(caps_config);
            c_config.cgroup_config = Some(cgroup_config);
            c_config.uts_config_host = Some(uts_config);
            c_config.user_ns_config = Some(user_ns_config);
            c_config.chroot_config = Some(fs_root_config);

            let c_config_json = serde_json::to_string_pretty(&c_config)?;

            store_report(&args.output, &c_config_json, "host_data_raw.json")?
        }
        // collect container view of container configuration
        Commands::Container(args) => {
            log::info!("{} running in container mode", env!("CARGO_PKG_NAME"));
            // use own pid
            log::info!("Collecting fs configuration");
            let pid = std::process::id() as libc::pid_t;
            log::info!("Running with PID '{pid}' inside container");

            let uid = unsafe { libc::geteuid() };
            assert_eq!(uid, 0); // abort if not root

            log::info!("Collecting uts configuration");
            let uts_config = c_config::uts::uts_config()?;

            log::info!("Collecting device information");
            let device_conf = c_config::device::device_config()?;

            log::info!("Collecting seccomp configuration");
            let seccomp_config = c_config::seccomp::seccomp_config(pid)?;

            log::info!("Collecting namespace configuration");
            let container_namespaces = c_config::fs::fs_config_container()?;

            log::info!("Collecting container view of fs configuration");
            let mut fs_config = c_config::fs::Config::default();
            fs_config.container_namespaces = container_namespaces;

            // create report
            log::info!("Creating report");
            let mut c_config = c_config::Config::default();
            c_config.fs_config = Some(fs_config);
            c_config.uts_config_container = Some(uts_config);
            c_config.device_config = Some(device_conf);
            c_config.seccomp_config = Some(seccomp_config);

            let c_config_json = serde_json::to_string_pretty(&c_config)?;

            store_report(&args.output, &c_config_json, "container_data_raw.json")?
        }

        Commands::Evaluation(args) => {
            log::info!("{} running in evaluation mode", env!("CARGO_PKG_NAME"));

            // load container configuration reports
            log::info!(
                "Loading container's configuration view from file {}",
                args.c_config_container.display()
            );
            let c_config_container: c_config::Config = serde_json::from_reader(BufReader::new(
                File::open(&args.c_config_container)
                    .map_err(|e| map_io_error(&args.c_config_container, e))?,
            ))
            .expect("Failed to parse raw container config report");

            log::info!(
                "Loading host's configuration view from file {}",
                args.c_config_host.display()
            );
            let c_config_host: c_config::Config = serde_json::from_reader(BufReader::new(
                File::open(&args.c_config_host)
                    .map_err(|e| map_io_error(&args.c_config_host, e))?,
            ))
            .expect("Failed to parse raw host config report");

            // combine reports
            let fs_config_combined = c_config::fs::Config {
                container_namespaces: c_config_container
                    .fs_config
                    .as_ref()
                    .expect("host part does not contain ns_config")
                    .container_namespaces
                    .clone(),
                ref_container_namespaces: c_config_host
                    .fs_config
                    .as_ref()
                    .expect("host part does not contain ns_config")
                    .ref_container_namespaces
                    .clone(),
                host_namespaces: c_config_host
                    .fs_config
                    .as_ref()
                    .expect("host part does not contain ns_config")
                    .host_namespaces
                    .clone(),
            };

            let config = c_config::Config {
                ns_config: Some(
                    c_config_host
                        .ns_config
                        .expect("host part does not contain ns_config"),
                ),
                caps_config: Some(
                    c_config_host
                        .caps_config
                        .expect("host part does not contain caps_config"),
                ),
                cgroup_config: Some(
                    c_config_host
                        .cgroup_config
                        .expect("host part does not contain cgroup_config"),
                ),
                fs_config: Some(fs_config_combined),
                user_ns_config: Some(
                    c_config_host
                        .user_ns_config
                        .expect("host part does not contain user_ns_config"),
                ),
                seccomp_config: Some(
                    c_config_container
                        .seccomp_config
                        .expect("container part does not contain seccomp_config"),
                ),
                uts_config_host: Some(
                    c_config_host
                        .uts_config_host
                        .expect("host part does not contain uts_config"),
                ),
                uts_config_container: Some(
                    c_config_container
                        .uts_config_container
                        .expect("container part does not contain uts_config"),
                ),
                chroot_config: Some(
                    c_config_host
                        .chroot_config
                        .expect("host part does not contain fs_root_config"),
                ),
                device_config: Some(
                    c_config_container
                        .device_config
                        .expect("container part does not contain device_config"),
                ),
                info: Some(
                    c_config_host
                        .info
                        .expect("host part does not contain field info"),
                ),
            };

            // perform evaluation
            let eval = evaluation::EvalResult::from_config(&config, &args.container_root_host)?;

            let eval_json = serde_json::to_string_pretty(&eval)?;

            store_report(&args.output, &eval_json, "evaluation_report.json")?
        }

        Commands::Assessment(args) => {
            log::info!("{} running in assessment mode", env!("CARGO_PKG_NAME"));

            if args.evaluation_report.is_file() {
                let eval_result: evaluation::EvalResult =
                    serde_json::from_reader(BufReader::new(File::open(&args.evaluation_report)?))?;

                // perform assessment
                let assessment_result = assessment::assess_eval_result(&eval_result);

                let assessment_report_json = serde_json::to_string_pretty(&assessment_result)?;

                store_report(
                    &args.output,
                    &assessment_report_json,
                    "assessment_report.json",
                )?;
            } else {
                panic!(
                    "Failed to load evaluation report from '{}'",
                    args.evaluation_report.as_path().display()
                );
            }
        }
    }

    Ok(())
}
