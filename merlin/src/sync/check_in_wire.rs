//! Typed device check-in wire payload, shared with the authenticated server contract.
use super::{DeviceHealth, DeviceInventory, DeviceOSInfo};
use crate::{linux_hardening, linux_posture};
use serde::Serialize;

#[derive(Serialize)]
pub(super) struct DeviceCheckInRequest<'a> {
    pub(super) host: &'a str,
    pub(super) platform: &'static str,
    pub(super) agent_version: &'static str,
    pub(super) os_version: &'a str,
    pub(super) kernel_version: &'a str,
    pub(super) sensor_mode: &'a str,
    pub(super) current_rules_sha256: &'a str,
    pub(super) status: &'static str,
    pub(super) capabilities: Vec<&'static str>,
    pub(super) health: DeviceHealth,
    pub(super) posture: linux_posture::DevicePosture,
    pub(super) hardening: linux_hardening::HardeningSnapshot,
    pub(super) os_info: DeviceOSInfo,
    pub(super) inventory: DeviceInventory,
}
