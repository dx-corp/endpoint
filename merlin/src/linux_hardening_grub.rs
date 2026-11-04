use super::{MAX_FILE, boot_value, read_text};
use std::{
    collections::{BTreeMap, BTreeSet},
    fs,
    path::Path,
};

pub(super) fn resolved_grub_arguments() -> Option<String> {
    let candidates = ["/boot/grub/grub.cfg", "/boot/grub2/grub.cfg"];
    let present = candidates
        .iter()
        .filter(|path| fs::symlink_metadata(path).is_ok())
        .collect::<Vec<_>>();
    if present.len() != 1 {
        return None;
    }
    let path = Path::new(present[0]);
    let dir = path.parent()?;
    if fs::symlink_metadata(dir.join("custom.cfg")).is_ok() {
        return None;
    }
    let cfg = read_text(path, MAX_FILE * 4)?;
    let env = read_text(&dir.join("grubenv"), 65536)?;
    let runtime = read_text(Path::new("/proc/cmdline"), 65536)?;
    let image = runtime
        .split_whitespace()
        .find_map(|word| word.strip_prefix("BOOT_IMAGE="))?;
    if !cfg
        .lines()
        .filter_map(|line| {
            let mut words = line.split_whitespace();
            ["linux", "linuxefi", "linux16"]
                .contains(&words.next()?)
                .then(|| words.next())
                .flatten()
        })
        .any(|path| path == image)
    {
        return None;
    }
    grub_arguments(&cfg, &env)
}
pub(super) fn grub_arguments(cfg: &str, env: &str) -> Option<String> {
    if !env.starts_with("# GRUB Environment Block\n")
        || cfg.contains("blscfg")
        || cfg.contains("configfile ")
    {
        return None;
    }
    let env = env
        .lines()
        .filter_map(|line| line.split_once('='))
        .collect::<BTreeMap<_, _>>();
    if env.get("next_entry").is_some_and(|v| !v.is_empty())
        || env.get("initrdfail").is_some_and(|v| !v.is_empty())
        || env.get("prev_saved_entry").is_some_and(|v| !v.is_empty())
    {
        return None;
    }
    let mut defaults = BTreeSet::new();
    let mut functions = BTreeSet::new();
    for line in cfg.lines().map(str::trim) {
        if line.starts_with('#') {
            continue;
        }
        // Neither prefix nor config_directory is bound to this on-disk cfg.
        // Even a conventional custom.cfg include can execute another path.
        if grub_words(line)?.iter().any(|word| {
            word.split([';', '&', '|', '(', ')'])
                .any(|part| matches!(part, "source" | "configfile"))
        }) {
            return None;
        }
        if let Some(rest) = line.strip_prefix("function ") {
            let words = grub_words(rest)?;
            let name = words.first()?;
            if !name.chars().all(|c| c.is_ascii_alphanumeric() || c == '_') {
                return None;
            }
            functions.insert(name.clone());
        }
        if let Some(value) = line.strip_prefix("set default=") {
            let value = value.trim_matches('"');
            if value == "${next_entry}" {
                continue;
            }
            let value = if value == "${saved_entry}" {
                *env.get("saved_entry")?
            } else {
                value
            };
            if value.contains(['$', '\\', '"', '\'']) {
                return None;
            }
            defaults.insert(value.to_string());
        }
    }
    if defaults.len() != 1 {
        return None;
    }
    let mut menu_seen = false;
    for line in cfg
        .lines()
        .map(str::trim)
        .filter(|line| !line.starts_with('#'))
    {
        let command = line.split_whitespace().next().unwrap_or("");
        if command == "set" {
            let (key, _) = line.strip_prefix("set ")?.split_once('=')?;
            if key.is_empty() || !key.chars().all(|c| c.is_ascii_alphanumeric() || c == '_') {
                return None;
            }
        }
        if command == "load_env" && line != "load_env"
            || command == "search"
                && (line.contains('$')
                    || grub_words(line)?.iter().any(|word| {
                        word == "--set" || word.starts_with("--set=") && word != "--set=root"
                    }))
        {
            return None;
        }
        menu_seen |= matches!(command, "menuentry" | "submenu");
        if !matches!(
            command,
            "" | "set"
                | "export"
                | "load_env"
                | "save_env"
                | "insmod"
                | "search"
                | "terminal_input"
                | "terminal_output"
                | "serial"
                | "background_image"
                | "loadfont"
                | "echo"
                | "if"
                | "elif"
                | "else"
                | "fi"
                | "then"
                | "for"
                | "while"
                | "until"
                | "do"
                | "done"
                | "function"
                | "}"
                | "menuentry"
                | "submenu"
                | "linux"
                | "linuxefi"
                | "linux16"
                | "initrd"
                | "initrdefi"
                | "initrd16"
                | "fwsetup"
                | "source"
        ) || functions.contains(command)
            || command.starts_with('$')
            || matches!(command, "eval" | "unset")
            || menu_seen && command == "load_env"
            || line.contains("set default=") && !line.starts_with("set default=")
            || line
                .strip_prefix("set ")
                .and_then(|v| v.split_once('='))
                .is_some_and(|(key, _)| key.contains('$'))
        {
            return None;
        }
    }
    // A nonempty one-shot environment value alone cannot prove that this cfg
    // applies it. Dynamic one-shot selection is outside the static profile.
    let selection = defaults.iter().next()?.clone();
    if selection.trim().is_empty() {
        return None;
    }
    let selected_numeric = selection
        .split('>')
        .map(str::parse::<usize>)
        .collect::<Result<Vec<_>, _>>()
        .ok();
    let mut counters = vec![0usize];
    let mut parents = Vec::new();
    let mut current: Option<(Vec<usize>, String, String, Vec<String>)> = None;
    let mut selected = Vec::new();
    let mut scopes = Vec::new();
    let mut static_default_seen = false;
    for line in cfg.lines().map(str::trim) {
        if current.is_none() {
            if scopes.is_empty()
                && line.starts_with("set default=")
                && !line.contains("${next_entry}")
            {
                static_default_seen = true;
            }
            let command = line.split_whitespace().next().unwrap_or("");
            if !line.starts_with('#')
                && (line.contains(['\\', '`'])
                    || (!matches!(command, "menuentry" | "submenu")
                        && (line.contains("menuentry ") || line.contains("submenu "))))
            {
                return None;
            }
            let end = match command {
                "if" => Some("fi"),
                "for" | "while" | "until" => Some("done"),
                "function" if line.ends_with('{') => Some("}"),
                "function" | "case" | "select" => return None,
                _ => None,
            };
            if let Some(end) = end {
                // Only standalone block headers are understood. Never treat an
                // inline declaration or an unevaluated function as a menu slot.
                if line.contains("menuentry ") || line.contains("submenu ") {
                    return None;
                }
                scopes.push(end);
                continue;
            }
            if scopes.last() == Some(&line) {
                scopes.pop();
                continue;
            }
            if !line.starts_with('#')
                && (line.contains(';') && command != "elif"
                    || matches!(command, "eval" | "linux" | "linuxefi" | "linux16"))
            {
                return None;
            }
        }
        if line.starts_with("menuentry ") || line.starts_with("submenu ") {
            if current.is_some() || !scopes.is_empty() || !line.ends_with('{') {
                return None;
            }
            let words = grub_words(line.trim_end_matches('{').trim())?;
            let title = words.get(1)?.clone();
            if words.iter().any(|word| word.contains('$')) {
                return None;
            }
            let mut options = words.iter().skip(2);
            while let Some(option) = options.next() {
                match option.as_str() {
                    "--id" | "--class" | "--users" | "--hotkey" => {
                        if options.next()?.starts_with('-') {
                            return None;
                        }
                    }
                    "--unrestricted" => {}
                    value if value.starts_with("--id=") => {}
                    _ => return None,
                }
            }
            let ids = words
                .iter()
                .filter_map(|word| word.strip_prefix("--id="))
                .chain(
                    words
                        .windows(2)
                        .filter(|pair| pair[0] == "--id")
                        .map(|pair| pair[1].as_str()),
                )
                .collect::<Vec<_>>();
            if ids.len() > 1 {
                return None;
            }
            let id = ids.into_iter().next().unwrap_or("").to_string();
            if id.contains('$') {
                return None;
            }
            let mut path = parents.clone();
            path.push(*counters.last()?);
            *counters.last_mut()? += 1;
            if line.starts_with("submenu ") {
                parents = path;
                counters.push(0);
            } else {
                current = Some((path, title, id, Vec::new()));
            }
        } else if line == "}" {
            if let Some((path, title, id, commands)) = current.take() {
                let matches = selected_numeric
                    .as_ref()
                    .map(|p| *p == path)
                    .unwrap_or(selection == title || !id.is_empty() && selection == id);
                if matches {
                    if !selected.is_empty() || commands.is_empty() {
                        return None;
                    }
                    selected = commands;
                    // Later optional menus cannot shift this established numeric
                    // slot. ID/title selections must still reject duplicates.
                    if selected_numeric.is_some() {
                        break;
                    }
                }
            } else if !parents.is_empty() {
                parents.pop();
                counters.pop();
            }
        } else if let Some((_, _, _, commands)) = &mut current {
            let mut words = line.split_whitespace();
            if let Some(command) = words.next() {
                if line.starts_with('#') {
                    continue;
                }
                if functions.contains(command)
                    || !matches!(
                        command,
                        "linux"
                            | "linuxefi"
                            | "linux16"
                            | "initrd"
                            | "initrdefi"
                            | "initrd16"
                            | "search"
                            | "insmod"
                            | "set"
                            | "echo"
                    )
                    || line.contains([';', '\\', '`'])
                    || matches!(
                        command,
                        "if" | "elif"
                            | "else"
                            | "fi"
                            | "for"
                            | "while"
                            | "until"
                            | "done"
                            | "function"
                            | "case"
                            | "eval"
                            | "source"
                            | "configfile"
                            | "chainloader"
                            | "multiboot"
                            | "multiboot2"
                            | "normal"
                    )
                {
                    return None;
                }
                if ["linux", "linuxefi", "linux16"].contains(&command) {
                    words.next()?;
                    let args = words.collect::<Vec<_>>().join(" ");
                    if args.contains(['$', '\\', '\'', '"', ';', '`']) {
                        return None;
                    }
                    commands.push(args);
                } else if command == "function" || line.contains('{') && !line.contains("${") {
                    return None;
                }
            }
        }
    }
    if selected.is_empty() || current.is_some() || !static_default_seen {
        return None;
    }
    // Every possible kernel command in the selected entry must agree. This
    // permits harmless initrd fallback branches without guessing their outcome.
    let keys = selected
        .iter()
        .flat_map(|args| {
            args.split_whitespace()
                .filter_map(|word| word.split_once('=').map(|pair| pair.0.to_string()))
        })
        .collect::<BTreeSet<_>>();
    let mut resolved = Vec::new();
    for key in keys {
        let values = selected
            .iter()
            .map(|args| boot_value(args, &key))
            .collect::<Option<BTreeSet<_>>>()?;
        // A differing branch is represented internally by duplicate key values;
        // boot_value rejects it as unknown. Absence is explicit only if every
        // candidate branch lacks the key, never a dropped conflicting value.
        for value in values {
            resolved.push(format!("{key}={value}"));
        }
    }
    Some(resolved.join(" "))
}
fn grub_words(raw: &str) -> Option<Vec<String>> {
    let mut result = Vec::new();
    let mut word = String::new();
    let mut quote = None;
    for ch in raw.chars() {
        match (quote, ch) {
            (None, '\'' | '"') => quote = Some(ch),
            (Some(q), c) if q == c => quote = None,
            (None, c) if c.is_whitespace() => {
                if !word.is_empty() {
                    result.push(std::mem::take(&mut word));
                }
            }
            (_, '\\' | '`') => return None,
            _ => word.push(ch),
        }
    }
    if quote.is_some() {
        return None;
    }
    if !word.is_empty() {
        result.push(word);
    }
    Some(result)
}
