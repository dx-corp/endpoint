use super::*;

#[test]
fn manifest_covers_200_distinct_rule_targets_with_typed_fact_requirements() {
    let manifest = manifest().unwrap();
    assert_eq!(manifest.targets.len(), 161);
    let mut covered = BTreeSet::new();
    for target in &manifest.targets {
        let fields: &[&str] = match target.kind.as_str() {
            "package" => &["state"],
            "file" => &["uid", "gid", "mode"],
            "systemd_unit" => &[
                "active_state",
                "unit_file_state",
                "socket_active_state",
                "socket_unit_file_state",
            ],
            "sshd_setting" => &["context", "effective_value"],
            "sudo_setting" => &["context", "effective_state"],
            "kernel_module" => &["load_state", "effective_install_command", "blacklist_state"],
            "mount" => &["runtime_options", "persistent_options"],
            "sysctl" | "boot_argument" => &["runtime_value", "persistent_value"],
            "audit_watch" => &["runtime_permissions", "persistent_permissions"],
            kind => panic!("unknown collector kind {kind}"),
        };
        assert!(!target.target.is_empty() && target.target.len() <= 1024);
        assert!(!target.target.chars().any(char::is_control));
        assert!(!target.fields.is_empty());
        if matches!(target.kind.as_str(), "sshd_setting" | "sudo_setting") {
            assert!(target.fields.iter().any(|field| field == "context"));
        }
        for field in &target.fields {
            assert!(
                fields.contains(&field.as_str()),
                "{} unsupported {field}",
                target.kind
            );
        }
        for rule in &target.rules {
            assert!(rule.starts_with("dx-linux-"));
            assert!(covered.insert(rule));
        }
    }
    assert_eq!(covered.len(), 200);
    assert_eq!(
        manifest
            .targets
            .iter()
            .map(|t| (&t.kind, &t.target))
            .collect::<BTreeSet<_>>()
            .len(),
        manifest.targets.len()
    );
}

#[test]
fn complete_package_enumeration_rejects_truncation_and_malformed_records() {
    assert_eq!(parse_dpkg("Package: sudo\nStatus: install ok installed\n\nPackage: old\nStatus: deinstall ok config-files\n\n").unwrap(), BTreeSet::from(["sudo".into()]));
    assert!(parse_dpkg("Package: sudo\nStatus: install ok installed").is_none());
    assert!(parse_dpkg("Package: sudo\n\n").is_none());
    assert!(parse_apk("P:sudo\nV:1.0\n\n").unwrap().contains("sudo"));
    assert!(parse_apk("P:sudo\nV:1.0").is_none());
    assert!(parse_package_lines("sudo\ninvalid package\n").is_none());
}

#[test]
fn mount_parsing_preserves_exact_options_and_rejects_duplicate_mounts() {
    assert_eq!(
        mount_options(
            "1 0 0:1 / /tmp rw,nosuid,nodev - tmpfs tmpfs rw,noexec\n",
            "/tmp"
        ),
        Some("rw,nosuid,nodev,noexec".into())
    );
    assert!(
        mount_options(
            "1 0 0:1 / /tmp rw - tmpfs tmpfs rw\n2 0 0:2 / /tmp rw - tmpfs tmpfs rw\n",
            "/tmp"
        )
        .is_none()
    );
    assert_eq!(
        fstab_options("tmpfs /tmp tmpfs defaults,nodev,nosuid 0 0\n", "/tmp"),
        Some("defaults,nodev,nosuid".into())
    );
    assert!(
        fstab_options(
            "tmpfs /tmp tmpfs defaults 0 0\ntmpfs /tmp tmpfs noexec 0 0\n",
            "/tmp"
        )
        .is_none()
    );
}

#[test]
fn sysctl_last_assignment_wins_and_unsupported_globs_stay_unknown() {
    assert_eq!(
        sysctl_value(
            "net.ipv4.ip_forward = 0\nnet/ipv4/ip_forward = 1\n",
            "net.ipv4.ip_forward"
        ),
        Some(1)
    );
    assert!(
        sysctl_value(
            "net.ipv4.ip_forward=0\nnet.ipv4.*=1\n",
            "net.ipv4.ip_forward"
        )
        .is_none()
    );
}

#[test]
fn audit_requires_both_abis_and_respects_deletes_and_exclusions() {
    let both = "-a always,exit -F arch=b64 -F path=/etc/passwd -F perm=wa\n-a always,exit -F arch=b32 -F path=/etc/passwd -F perm=wa\n";
    assert_eq!(
        audit_permissions(both, "/etc/passwd", &["b64", "b32"]),
        Some("wa".into())
    );
    assert_eq!(
        audit_permissions(both.lines().next().unwrap(), "/etc/passwd", &["b64", "b32"]),
        Some("".into())
    );
    assert_eq!(
        audit_permissions("-w /etc/passwd -p wa\n-D\n", "/etc/passwd", &["b64", "b32"]),
        Some("".into())
    );
    assert!(
        audit_permissions(
            "-a never,exit -F path=/etc/passwd\n-w /etc/passwd -p wa\n",
            "/etc/passwd",
            &["b64"]
        )
        .is_none()
    );
}

#[test]
fn effective_settings_do_not_accept_duplicate_or_partial_output() {
    assert_eq!(
        sshd_value("permitrootlogin no\nloglevel VERBOSE\n", "LogLevel"),
        Some("VERBOSE".into())
    );
    assert!(
        sshd_value(
            "permitrootlogin no\npermitrootlogin yes\n",
            "PermitRootLogin"
        )
        .is_none()
    );
    assert_eq!(
        boot_value("quiet audit=1 ipv6.disable=1", "audit"),
        Some("1".into())
    );
    assert!(boot_value("audit=0 audit=1", "audit").is_none());
    assert_eq!(boot_value("quiet", "audit"), Some(String::new()));
}

#[test]
fn nofollow_reads_reject_symlinks_fifos_and_oversized_files() {
    let dir = std::env::temp_dir().join(format!("merlin-hardening-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    std::fs::write(dir.join("file"), b"12345").unwrap();
    std::os::unix::fs::symlink("file", dir.join("link")).unwrap();
    assert!(read_text(&dir.join("link"), 10).is_none());
    assert!(read_text(&dir.join("file"), 4).is_none());
    assert_eq!(read_text(&dir.join("file"), 5), Some("12345".into()));
    std::fs::remove_dir_all(dir).unwrap();
}

#[test]
fn systemd_aliases_share_native_facts_without_invalidating_other_units() {
    let raw = "Id=ssh.service\nNames=ssh.service sshd.service\nLoadState=loaded\nUnitFileState=enabled\nActiveState=active\n\nId=ssh.service\nNames=ssh.service sshd.service\nLoadState=loaded\nUnitFileState=enabled\nActiveState=active\n\n";
    let units = parse_systemd(raw).unwrap();
    assert_eq!(units["sshd.service"]["ActiveState"], "active");
    assert_eq!(units["ssh.service"], units["sshd.service"]);
    assert!(
        parse_systemd(&raw.replace(
            "ActiveState=active",
            "ActiveState=active\nActiveState=inactive"
        ))
        .is_none()
    );
}

#[test]
fn sudo_and_nextboot_only_report_explicit_unambiguous_context_values() {
    assert_eq!(
        sudo_pty(
            "Matching Defaults entries for root on example:\n    env_reset, !use_pty\n\nUser root may run the following commands:\n"
        ),
        Some("disabled".into())
    );
    assert_eq!(
        sudo_pty(
            "Matching Defaults entries for root on example:\n    env_reset, use_pty\n\nUser root may run the following commands:\n"
        ),
        Some("enabled".into())
    );
    assert!(
        sudo_pty(
            "Matching Defaults entries for root on example:\n    use_pty\n\nOptions: !use_pty\n"
        )
        .is_none()
    );
    assert!(
        sudo_pty("Matching Defaults entries for root on example:\n    env_reset\n\n").is_none()
    );
    assert!(parse_dpkg("Package: sudo\nStatus: install ok unpacked\n\n").is_none());
}

#[test]
fn bounded_native_commands_reject_stdout_stderr_overflow_and_timeout() {
    if !Path::new("/usr/bin/python3").exists() {
        return;
    }
    let start = Instant::now();
    assert!(
        probe(
            &["/usr/bin/python3"],
            &[
                "-c",
                "import sys; sys.stdout.write('x' * 5000000); sys.stderr.write('y' * 5000000)"
            ],
            start + Duration::from_secs(3)
        )
        .is_none()
    );
    assert!(start.elapsed() < Duration::from_secs(3));
    let start = Instant::now();
    assert!(
        probe(
            &["/usr/bin/python3"],
            &["-c", "import time; time.sleep(10)"],
            start + Duration::from_millis(150)
        )
        .is_none()
    );
    assert!(start.elapsed() < Duration::from_secs(1));
}

#[test]
fn audit_suppression_order_and_insertions_cannot_produce_passes() {
    for action in [
        "never,exit",
        "exit,never",
        "never,task",
        "task,never",
        "always,exclude",
        "exclude,always",
    ] {
        for flag in ["-a", "-A"] {
            let raw = format!("{flag} {action} -F uid=0\n-w /etc/passwd -p wa\n");
            assert!(
                audit_permissions(&raw, "/etc/passwd", &["b64", "b32"]).is_none(),
                "{raw}"
            );
        }
    }
}

#[test]
fn custom_sshd_configuration_and_overrides_are_preserved_for_native_probe() {
    let (binary, args) =
        sshd_probe_args(b"/usr/sbin/sshd\0-D\0-f\0/etc/ssh/custom.conf\0-o\0PermitRootLogin=yes\0")
            .unwrap();
    assert_eq!(binary, "/usr/sbin/sshd");
    assert_eq!(
        args,
        ["-f", "/etc/ssh/custom.conf", "-o", "PermitRootLogin=yes"]
    );
    let (_, args) = sshd_probe_args(b"sshd: /usr/sbin/sshd -D -f /etc/ssh/custom.conf -o PermitRootLogin=yes [listener] 0 of 10 startups\0").unwrap();
    assert_eq!(
        args,
        ["-f", "/etc/ssh/custom.conf", "-o", "PermitRootLogin=yes"]
    );
    assert!(sshd_probe_args(b"sshd: root [priv]\0").is_none());
    assert!(sshd_probe_args(b"/usr/sbin/sshd\0-f\0/etc/ssh/custom config\0").is_none());
}

#[test]
fn differently_named_socket_is_accounted_for_by_native_triggers() {
    let raw = "Id=unexpected.socket\nNames=unexpected.socket\nLoadState=loaded\nUnitFileState=enabled\nActiveState=active\nTriggers=blocked.service\n";
    let sockets = parse_systemd(raw).unwrap();
    assert_eq!(
        socket_aggregate(&sockets, &BTreeSet::from(["blocked.service".into()])),
        Some(("enabled".into(), "active".into()))
    );
    assert_eq!(
        socket_aggregate(&sockets, &BTreeSet::from(["other.service".into()])),
        Some(("not-found".into(), "not-found".into()))
    );
}

#[test]
fn sysctl_loader_chain_rejects_custom_and_later_unit_overrides() {
    let mut unit = BTreeMap::from([("ExecStart".into(), "{ path=/usr/lib/systemd/systemd-sysctl ; argv[]=/usr/lib/systemd/systemd-sysctl ; ignore_errors=no }".into()), ("FragmentPath".into(), "/usr/lib/systemd/system/systemd-sysctl.service".into())]);
    assert_eq!(sysctl_loader(&unit), Some("systemd"));
    unit.insert(
        "ExecStartPost".into(),
        "{ argv[]=/usr/sbin/sysctl -w fs.suid_dumpable=1 ; }".into(),
    );
    assert_eq!(sysctl_loader(&unit), None);
    unit.remove("ExecStartPost");
    unit.insert(
        "DropInPaths".into(),
        "/etc/systemd/system/systemd-sysctl.service.d/override.conf".into(),
    );
    assert_eq!(sysctl_loader(&unit), None);
}

#[test]
fn grub_saved_nextboot_and_kernel_branches_resolve_without_grubby() {
    let cfg = "set default=\"0\"\nmenuentry 'Ubuntu' --id ubuntu {\nlinux /vmlinuz root=x audit=1 ipv6.disable=1\nlinux /vmlinuz root=x audit=1 ipv6.disable=1 panic=-1\n}\nmenuentry 'Other' --id other {\nlinux /vmlinuz-old audit=0 ipv6.disable=0\n}\n";
    assert_eq!(
        boot_value(
            &grub_arguments(cfg, "# GRUB Environment Block\n").unwrap(),
            "audit"
        ),
        Some("1".into())
    );
    assert!(grub_arguments(cfg, "# GRUB Environment Block\nnext_entry=other\n").is_none());
    assert!(grub_arguments(cfg, "# GRUB Environment Block\ninitrdfail=1\n").is_none());
    assert!(
        grub_arguments(
            &cfg.replace("root=x", "root=$kernelopts"),
            "# GRUB Environment Block\n"
        )
        .is_none()
    );
}

#[test]
fn native_file_stat_preserves_special_mode_bits_and_owner_ids() {
    use std::os::unix::fs::PermissionsExt;
    let path = std::env::temp_dir().join(format!("merlin-stat-{}", std::process::id()));
    std::fs::write(&path, b"").unwrap();
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o4750)).unwrap();
    let mut host = Host::new(Instant::now() + Duration::from_secs(1));
    let target = Target {
        kind: "file".into(),
        target: path.to_str().unwrap().into(),
        fields: vec!["mode".into(), "uid".into(), "gid".into()],
        rules: vec![],
    };
    let mut row = Map::new();
    host.collect(&target, &mut row);
    assert_eq!(row["mode"], "4750");
    assert_eq!(row["uid"].as_u64(), Some(unsafe { libc::geteuid() } as u64));
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o0644)).unwrap();
    host.collect(&target, &mut row);
    assert_eq!(row["mode"], "0644");
    std::fs::remove_file(path).unwrap();
}

#[test]
fn module_native_config_and_loaded_state_have_independent_positive_facts() {
    let mut host = Host::new(Instant::now() + Duration::from_secs(1));
    host.modules = Some("cramfs 12288 0 - Live 0x0\n".into());
    host.modprobe = Some(Some("install cramfs /bin/false\nblacklist cramfs\n".into()));
    let target = Target {
        kind: "kernel_module".into(),
        target: "cramfs".into(),
        fields: vec![
            "load_state".into(),
            "effective_install_command".into(),
            "blacklist_state".into(),
        ],
        rules: vec![],
    };
    let mut row = Map::new();
    host.collect(&target, &mut row);
    assert_eq!(row["load_state"], "loaded");
    assert_eq!(row["blacklist_state"], "blacklisted");
    assert_eq!(row["effective_install_command"], "/bin/false");
    host.modprobe = Some(Some("blacklist other\n".into()));
    let mut row = Map::new();
    host.collect(&target, &mut row);
    assert_eq!(row["effective_install_command"], "");
    assert_eq!(row["blacklist_state"], "not-blacklisted");
    host.modprobe = Some(Some(
        "install cramfs /bin/false\ninstall cramfs /bin/true\nblacklist cramfs\n".into(),
    ));
    let mut row = Map::new();
    host.collect(&target, &mut row);
    assert!(row.get("effective_install_command").is_none());
    assert_eq!(row["blacklist_state"], "blacklisted");
}

#[test]
fn audit_applicable_abis_come_from_running_kernel_configuration() {
    assert_eq!(
        abis_for_config("x86_64", "CONFIG_IA32_EMULATION=y\n"),
        Some(vec!["b64", "b32"])
    );
    assert_eq!(
        abis_for_config("x86_64", "# CONFIG_IA32_EMULATION is not set\n"),
        Some(vec!["b64"])
    );
    assert_eq!(
        abis_for_config("aarch64", "# CONFIG_COMPAT is not set\n"),
        Some(vec!["b64"])
    );
    assert!(abis_for_config("x86_64", "").is_none());
    assert!(
        abis_for_config(
            "x86_64",
            "CONFIG_IA32_EMULATION=y\n# CONFIG_IA32_EMULATION is not set\n"
        )
        .is_none()
    );
}

#[test]
fn unused_or_dynamic_one_shot_environment_never_overrides_static_default() {
    let cfg = "set default=\"0\"\nmenuentry 'Bad' --id bad {\nlinux /vmlinuz audit=0\n}\nmenuentry 'Good' --id good {\nlinux /vmlinuz-old audit=1\n}\n";
    assert!(grub_arguments(cfg, "# GRUB Environment Block\nnext_entry=good\n").is_none());
    let conditional =
        format!("if [ -n \"${{next_entry}}\" ]; then\nset default=\"${{next_entry}}\"\nfi\n{cfg}");
    assert!(grub_arguments(&conditional, "# GRUB Environment Block\nnext_entry=good\n").is_none());
}

#[test]
fn disagreeing_grub_kernel_branches_keep_target_uncertainty() {
    for second in ["audit=0 ipv6.disable=1", "ipv6.disable=1"] {
        let cfg = format!(
            "set default=\"0\"\nmenuentry 'Fixture' --id fixture {{\nlinux /vmlinuz audit=1 ipv6.disable=1\nlinux /vmlinuz {second}\n}}\n"
        );
        let resolved = grub_arguments(&cfg, "# GRUB Environment Block\n").unwrap();
        assert!(boot_value(&resolved, "audit").is_none());
        assert_eq!(boot_value(&resolved, "ipv6.disable"), Some("1".into()));
    }
}

#[test]
fn unknown_compat_abi_never_accepts_only_the_b64_watch() {
    let only64 = "-a always,exit -F arch=b64 -F path=/etc/passwd -F perm=wa\n";
    assert!(audit_permissions_scoped(only64, "/etc/passwd", &["b64", "b32"], false).is_none());
    assert_eq!(
        audit_permissions_scoped(
            "-w /etc/passwd -p wa\n",
            "/etc/passwd",
            &["b64", "b32"],
            false
        ),
        Some("wa".into())
    );
    assert_eq!(
        audit_permissions_scoped(only64, "/etc/passwd", &["b64"], true),
        Some("wa".into())
    );
}

#[test]
fn existing_unreadable_or_unsupported_sudo_configuration_is_never_absence() {
    use std::os::unix::fs::PermissionsExt;
    let dir = std::env::temp_dir().join(format!("merlin-sudo-config-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let file = dir.join("sudo.conf");
    assert!(sudo_plugin_configuration_supported(&file));
    std::fs::write(&file, "# standard compiled-in policy\n").unwrap();
    assert!(sudo_plugin_configuration_supported(&file));
    std::fs::write(
        &file,
        "Plugin sudoers_policy sudoers.so sudoers_file=/elsewhere\n",
    )
    .unwrap();
    std::fs::set_permissions(&file, std::fs::Permissions::from_mode(0o000)).unwrap();
    assert!(!sudo_plugin_configuration_supported(&file));
    std::fs::set_permissions(&file, std::fs::Permissions::from_mode(0o600)).unwrap();
    let link = dir.join("linked.conf");
    std::os::unix::fs::symlink(&file, &link).unwrap();
    assert!(!sudo_plugin_configuration_supported(&link));
    std::fs::write(&file, vec![b'#'; MAX_FILE as usize + 1]).unwrap();
    assert!(!sudo_plugin_configuration_supported(&file));
    std::fs::remove_dir_all(dir).unwrap();
}

#[test]
fn bls_default_selection_is_explicitly_unsupported_not_a_default_guess() {
    let cfg = "set default=\"another-entry\"\ninsmod blscfg\nblscfg\n";
    assert!(
        grub_arguments(
            cfg,
            "# GRUB Environment Block\nsaved_entry=compliant-default\n"
        )
        .is_none()
    );
}

#[test]
fn dynamic_grub_menus_cannot_shift_a_numeric_selection_into_a_false_pass() {
    for (open, close) in [
        ("if [ 1 = 0 ]; then", "fi"),
        ("for item in absent; do", "done"),
        ("while false; do", "done"),
        ("function optional_menu {", "}"),
        ("true; if [ 1 = 0 ]; then", "fi"),
        ("if [ 1 = 0 ]; then menuentry 'Inline' {", "fi"),
    ] {
        let cfg = format!(
            "set default=\"1\"\n{open}\nmenuentry 'Absent' --id absent {{\nlinux /old audit=0\n}}\n{close}\nmenuentry 'Good' --id good {{\nlinux /current audit=1\n}}\nmenuentry 'Bad' --id bad {{\nlinux /other audit=0\n}}\n"
        );
        assert!(
            grub_arguments(&cfg, "# GRUB Environment Block\n").is_none(),
            "{open}"
        );
        let direct = cfg.replace("set default=\"1\"", "set default=\"absent\"");
        assert!(grub_arguments(&direct, "# GRUB Environment Block\n").is_none());
    }
}

#[test]
fn static_grub_selection_preceding_optional_firmware_menu_remains_supported() {
    let cfg = "function load_video {\nif true; then\ninsmod video\nfi\n}\nset default=\"0\"\nmenuentry 'Linux' --id linux {\nlinux /vmlinuz audit=1 ipv6.disable=1\n}\nif [ true ]; then\nmenuentry 'Firmware' {\nfwsetup\n}\nfi\n";
    assert_eq!(
        boot_value(
            &grub_arguments(cfg, "# GRUB Environment Block\n").unwrap(),
            "audit"
        ),
        Some("1".into())
    );
}

#[test]
fn selected_grub_entry_rejects_control_flow_and_embedded_kernel_commands() {
    for command in [
        "if true; then linux /other audit=0; fi",
        "if true; then\nlinux /other audit=0\nfi",
        "for item in x; do linuxefi /other audit=0; done",
        "while true; do linux16 /other audit=0; done",
        "function alternate { linux /other audit=0; }",
        "true; linux /other audit=0",
    ] {
        let cfg = format!(
            "set default=\"0\"\nmenuentry 'Linux' {{\nlinux /vmlinuz audit=1\n{command}\n}}\n"
        );
        assert!(
            grub_arguments(&cfg, "# GRUB Environment Block\n").is_none(),
            "{command}"
        );
    }
}

#[test]
fn selected_grub_entry_never_executes_unresolved_functions() {
    for (definition, invocation) in [
        (
            "function alternate {\nif true; then linux /other audit=0; fi\n}\n",
            "alternate",
        ),
        (
            "function linux {\necho no-kernel\n}\n",
            "linux /vmlinuz audit=1",
        ),
    ] {
        let cfg = format!(
            "{definition}set default=\"0\"\nmenuentry 'Linux' {{\nlinux /vmlinuz audit=1\n{invocation}\n}}\n"
        );
        assert!(grub_arguments(&cfg, "# GRUB Environment Block\n").is_none());
    }
}

#[test]
fn grub_default_requires_unconditional_assignment_and_no_later_mutation() {
    let menus = "menuentry 'Good' {\nlinux /vmlinuz audit=1\n}\nmenuentry 'Bad' {\nlinux /other audit=0\n}\n";
    for cfg in [
        format!("function unused {{\nset default=\"0\"\n}}\n{menus}"),
        format!("if false; then\nset default=\"0\"\nfi\n{menus}"),
        format!("set default=\"0\"\n{menus}true; set default=1\n"),
        format!("set default=\"0\"\n{menus}unset default\n"),
        format!("set default=\"0\"\n{menus}load_env\n"),
    ] {
        assert!(
            grub_arguments(&cfg, "# GRUB Environment Block\n").is_none(),
            "{cfg}"
        );
    }
}

#[test]
fn grub_static_profile_never_treats_other_options_as_menu_ids() {
    let cfg = "set default=\"good\"\nmenuentry 'Bad' {\nlinux /vmlinuz audit=0\n}\nmenuentry 'Other' --users good {\nlinux /other audit=1\n}\n";
    assert!(grub_arguments(cfg, "# GRUB Environment Block\n").is_none());
    for option in [
        "--id good --unsupported nope",
        "--id good --id good",
        "--id good $extra",
    ] {
        assert!(
            grub_arguments(
                &cfg.replace("--users good", option),
                "# GRUB Environment Block\n"
            )
            .is_none()
        );
    }
    let explicit = cfg.replace("--users good", "--id=good");
    assert_eq!(
        boot_value(
            &grub_arguments(&explicit, "# GRUB Environment Block\n").unwrap(),
            "audit"
        ),
        Some("1".into())
    );
    for suffix in [
        "set 'default'=0",
        "search --set=default uuid",
        "load_env -f /other/env",
    ] {
        assert!(
            grub_arguments(
                &format!("{explicit}{suffix}\n"),
                "# GRUB Environment Block\n"
            )
            .is_none()
        );
    }
}

#[test]
fn grub_never_assumes_redirected_custom_loader_paths_are_absent() {
    let entry = "set default=\"0\"\nmenuentry 'Good' {\nlinux /vmlinuz audit=1\n}\n";
    for loader in [
        "set prefix=/other\nsource $prefix/custom.cfg",
        "set config_directory=/other\nsource ${config_directory}/custom.cfg",
        "if true; then s'ource' /other/custom.cfg; fi",
        "configfile /other/grub.cfg",
    ] {
        let cfg = format!("{entry}{loader}\n");
        assert!(
            grub_arguments(&cfg, "# GRUB Environment Block\n").is_none(),
            "{loader}"
        );
    }
}
