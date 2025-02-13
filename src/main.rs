use nix::sys::reboot::{reboot, RebootMode};
use nix::unistd::{fork, sync, ForkResult};

use std::panic;

mod check_supported;
mod container_toolkit;
mod coreutils;
mod cpu_vendor;
mod daemons;
mod get_devices;
mod kata_agent;
mod mount;
mod ndev;
mod proc_cmdline;
mod query_cc_mode;
mod start_stop_daemon;
mod user_group;

#[macro_use]
extern crate log;
extern crate kernlog;

//use cgroup::set_cgroup_subtree_control;
use container_toolkit::{nvidia_ctk_cdi, nvidia_ctk_system};
use kata_agent::kata_agent;
use ndev::udev;
use proc_cmdline::NVRC;

fn main() {
    panic::set_hook(Box::new(|panic_info| {
        error!("{}", panic_info);
        sync();
        reboot(RebootMode::RB_POWER_OFF).unwrap();
    }));

    let mut init = NVRC::init();

    init.mount_setup();

    kernlog::init().unwrap();
    log::set_max_level(log::LevelFilter::Off);

    init.mount_readonly("/");
    init.process_kernel_params(None).unwrap();
    init.query_cpu_vendor().unwrap();
    init.get_gpu_devices(None).unwrap();
    //set_cgroup_subtree_control().unwrap();
    // At this this point we either have GPUs (cold-plug) or we do not have
    // any GPUs (hot-plug) depending on the mode of operation execute cold|hot-plug
    init.hot_or_cold_plug.get(&init.cold_plug).unwrap()(&mut init);
}

impl NVRC {
    fn cold_plug(&mut self) {
        debug!("cold-plug mode detected, starting GPU setup");
        self.setup_gpu();
        kata_agent().unwrap();
    }

    fn hot_plug(&mut self) {
        debug!("hot-plug mode detected, starting udev and GPU setup");
        match unsafe { fork() } {
            Ok(ForkResult::Parent { child: _ }) => {
                kata_agent().unwrap();
            }
            Ok(ForkResult::Child) => loop {
                udev();
                self.get_gpu_devices(None).unwrap();
                self.setup_gpu();
            },
            Err(e) => {
                panic!("Fork failed: {}", e);
            }
        }
    }

    fn setup_gpu(&mut self) {
        self.query_gpu_cc_mode().unwrap();
        self.check_gpu_supported(None).unwrap();
        // If we're running in a confidential environment we may need to set
        // specific kernel module parameters. Check those first and then load
        // the modules.
        nvidia_ctk_system().unwrap();
        // Once we have loaded the driver we can start persistenced
        // CDI will not pick up the daemon if it is not created
        self.nvidia_persistenced().unwrap();
        // Create the CDI spec for the GPUs including persistenced
        nvidia_ctk_cdi().unwrap();
        // If user has enabled nvrc.dcgm=on in the kernel command line
        // we're starting the DCGM exporter
        self.nv_hostengine().unwrap();
        self.dcgm_exporter().unwrap();
        // If user has enabled nvidia_smi_srs in the kernel command line
        // we can optionally set the GPU to Ready
        self.nvidia_smi_srs().unwrap();
    }
}
