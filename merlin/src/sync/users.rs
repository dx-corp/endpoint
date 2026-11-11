//! Local users and groups.

use super::{DeviceUser, bounded_read, inventory_text};

pub(super) fn collect_users_groups() -> (Vec<DeviceUser>, Vec<String>) {
    let mut users = Vec::new();
    if let Some(body) = bounded_read("/etc/passwd", 256 << 10) {
        for line in String::from_utf8_lossy(&body).lines().take(256) {
            let fields = line.split(':').collect::<Vec<_>>();
            if fields.len() < 7 {
                continue;
            }
            let Some(uid) = fields[2].parse::<u64>().ok() else {
                continue;
            };
            let name = inventory_text(fields[0], 128);
            if name.is_empty() {
                continue;
            }
            users.push(DeviceUser {
                admin: uid == 0,
                name,
                uid,
                shell: inventory_text(fields[6], 256),
                source: "passwd".into(),
            });
        }
    }
    let mut groups = Vec::new();
    if let Some(body) = bounded_read("/etc/group", 256 << 10) {
        for line in String::from_utf8_lossy(&body).lines().take(256) {
            if let Some(name) = line
                .split(':')
                .next()
                .map(|value| inventory_text(value, 128))
            {
                if !name.is_empty() {
                    groups.push(name);
                }
            }
        }
    }
    users.sort_by(|left, right| left.uid.cmp(&right.uid).then(left.name.cmp(&right.name)));
    groups.sort();
    groups.dedup();
    (users, groups)
}
