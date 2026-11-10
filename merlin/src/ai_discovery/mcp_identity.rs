//! What an MCP server definition runs, reduced to an identity that is safe to
//! send: for a local (stdio) server, the package or image a known runner
//! starts (`npx`, `bunx`, `pnpm dlx`, `yarn dlx`, `npm exec`, `uvx`,
//! `pipx run`, `docker run`, `podman run`) or else the program file name;
//! for a remote server, the URL host name.
//!
//! Nothing after the package spec is read into the result, and values of
//! flags such as `--env`, `--index-url` or `--env-file` are skipped, so
//! arguments, environment, headers, paths, query strings and tokens never
//! reach it. A spec that looks like a path, a URL or an assignment is
//! refused and the runner name is reported instead.

/// Runners whose first positional argument (after their own flags) is the
/// package or image they start, with the flags that take a separate value
/// and the flag whose value names the package outright.
struct Runner {
    names: &'static [&'static str],
    /// A leading subcommand the runner needs (`pnpm dlx`, `docker run`).
    subcommand: Option<&'static str>,
    value_flags: &'static [&'static str],
    package_flags: &'static [&'static str],
    /// Package names on this registry are lowercase (npm, OCI repositories).
    lowercase_name: bool,
}

const RUNNERS: &[Runner] = &[
    Runner {
        names: &["npx", "bunx"],
        subcommand: None,
        value_flags: &[
            "-c",
            "--call",
            "--node-options",
            "--registry",
            "--cache",
            "--userconfig",
        ],
        package_flags: &["-p", "--package"],
        lowercase_name: true,
    },
    Runner {
        names: &["pnpm", "yarn"],
        subcommand: Some("dlx"),
        value_flags: &["-c", "--registry", "--cache-dir"],
        package_flags: &["-p", "--package"],
        lowercase_name: true,
    },
    Runner {
        names: &["npm"],
        subcommand: Some("exec"),
        value_flags: &[
            "-c",
            "--call",
            "--registry",
            "--cache",
            "--userconfig",
            "-w",
            "--workspace",
        ],
        package_flags: &["-p", "--package"],
        lowercase_name: true,
    },
    Runner {
        names: &["uvx"],
        subcommand: None,
        value_flags: &[
            "--with",
            "--with-requirements",
            "--python",
            "-p",
            "--index",
            "--index-url",
            "--extra-index-url",
            "--default-index",
            "--find-links",
            "-f",
            "--constraint",
            "-c",
            "--override",
            "--build-constraint",
            "--refresh-package",
            "--reinstall-package",
            "--upgrade-package",
            "--exclude-newer",
            "--cache-dir",
            "--config-file",
            "--directory",
            "--project",
            "--env-file",
            "--keyring-provider",
            "--resolution",
            "--prerelease",
            "--allow-insecure-host",
            "--index-strategy",
            "--link-mode",
            "--color",
        ],
        package_flags: &["--from"],
        lowercase_name: false,
    },
    Runner {
        names: &["pipx"],
        subcommand: Some("run"),
        value_flags: &["--python", "--pip-args", "--index-url", "-i"],
        package_flags: &["--spec"],
        lowercase_name: false,
    },
    Runner {
        names: &["docker", "podman"],
        subcommand: Some("run"),
        value_flags: &[
            "-e",
            "--env",
            "--env-file",
            "-v",
            "--volume",
            "--mount",
            "--name",
            "-p",
            "--publish",
            "--network",
            "--net",
            "-w",
            "--workdir",
            "-u",
            "--user",
            "--entrypoint",
            "-l",
            "--label",
            "--label-file",
            "--add-host",
            "--cpus",
            "-m",
            "--memory",
            "--platform",
            "--pull",
            "--restart",
            "--device",
            "--cap-add",
            "--cap-drop",
            "--security-opt",
            "--tmpfs",
            "--ulimit",
            "-h",
            "--hostname",
            "--dns",
            "--log-driver",
            "--log-opt",
            "--runtime",
            "--gpus",
            "--ipc",
            "--pid",
            "--cidfile",
            "--group-add",
            "--secret",
        ],
        package_flags: &[],
        lowercase_name: true,
    },
];

/// The file name of a program path, Unix or Windows style.
fn base_name(command: &str) -> &str {
    command.rsplit(['/', '\\']).next().unwrap_or(command)
}

/// A package spec or image reference worth reporting: bounded, from the
/// characters registries use, and not a path, URL or flag. npm and OCI names
/// are lowercase and have no `_` or `=`, which also keeps tokens such as
/// `ghp_...` from passing for one.
fn safe_spec(spec: &str, lowercase_name: bool) -> bool {
    let name = spec
        .rsplit_once('@')
        .filter(|(name, _)| !name.is_empty())
        .map_or(spec, |(name, _)| name);
    let name = name.split(':').next().unwrap_or(name);
    !spec.is_empty()
        && spec.len() <= 214
        && !spec.contains("://")
        && !spec.contains("..")
        && !spec.starts_with(['-', '.', '/', '~'])
        && spec.bytes().all(|b| {
            b.is_ascii_alphanumeric()
                || b"@/._:+~-".contains(&b)
                // Python requirement specs: `pkg==1.2`, `my_pkg>=1,<2`.
                || (!lowercase_name && b"=<>!,_".contains(&b))
        })
        && (!lowercase_name || !name.bytes().any(|b| b.is_ascii_uppercase()))
}

/// The identity of a stdio server: its package or image for a known runner,
/// else its program's file name.
pub(super) fn stdio_package(command: &str, args: &[&str]) -> String {
    // Some configs put the whole command line in `command`.
    let mut words: Vec<&str> = command.split_whitespace().collect();
    let program = match words.first() {
        Some(first) if RUNNERS.iter().any(|r| r.names.contains(&base_name(first))) => {
            words.remove(0)
        }
        _ => {
            words.clear();
            command.trim()
        }
    };
    let program = base_name(program);
    let Some(runner) = RUNNERS.iter().find(|r| r.names.contains(&program)) else {
        return safe_program(program);
    };
    words.extend_from_slice(args);
    let mut rest = words.into_iter();
    if let Some(subcommand) = runner.subcommand {
        if rest.next() != Some(subcommand) {
            return safe_program(program);
        }
    }
    let mut from_flag = None;
    while let Some(word) = rest.next() {
        if word == "--" {
            continue;
        }
        if let Some((flag, value)) = word
            .split_once('=')
            .filter(|(flag, _)| flag.starts_with('-'))
        {
            if runner.package_flags.contains(&flag) && from_flag.is_none() {
                from_flag = Some(value);
            }
            continue;
        }
        if runner.package_flags.contains(&word) {
            if let Some(value) = rest.next() {
                from_flag.get_or_insert(value);
            }
            continue;
        }
        if runner.value_flags.contains(&word) {
            rest.next();
            continue;
        }
        if word.starts_with('-') {
            continue;
        }
        let spec = from_flag.unwrap_or(word);
        return if safe_spec(spec, runner.lowercase_name) {
            spec.to_string()
        } else {
            program.to_string()
        };
    }
    match from_flag {
        Some(spec) if safe_spec(spec, runner.lowercase_name) => spec.to_string(),
        _ => program.to_string(),
    }
}

/// A program file name, when it is one: bounded and without spaces or
/// unusual characters (which would suggest a path fragment or a value).
fn safe_program(program: &str) -> String {
    let ok = !program.is_empty()
        && program.len() <= 128
        && !program.starts_with(['.', '-'])
        && program
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"._+-".contains(&b));
    if ok {
        program.to_string()
    } else {
        String::new()
    }
}

/// The host name of a remote server's URL: no scheme, user, password, port,
/// path, query or fragment. Empty when the URL is not http(s) or ws(s).
pub(super) fn remote_host(url: &str) -> String {
    let url = url.trim();
    let Some((scheme, rest)) = url.split_once("://") else {
        return String::new();
    };
    if !["http", "https", "ws", "wss"].contains(&scheme.to_ascii_lowercase().as_str()) {
        return String::new();
    }
    let authority = rest.split(['/', '?', '#']).next().unwrap_or("");
    let host_port = authority.rsplit('@').next().unwrap_or("");
    let host = if let Some(bracketed) = host_port.strip_prefix('[') {
        match bracketed.split_once(']') {
            Some((inner, _)) => format!("[{inner}]"),
            None => return String::new(),
        }
    } else {
        host_port.split(':').next().unwrap_or("").to_string()
    };
    let host = host.to_ascii_lowercase();
    let ok = !host.is_empty()
        && host.len() <= 253
        && host
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b".-:[]".contains(&b));
    if ok { host } else { String::new() }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_known_runner_reports_only_its_package_spec() {
        for (command, args, want) in [
            (
                "npx",
                vec!["-y", "@modelcontextprotocol/server-github"],
                "@modelcontextprotocol/server-github",
            ),
            (
                "npx",
                vec![
                    "--yes",
                    "@upstash/context7-mcp@1.0.14",
                    "--api-key",
                    "ctx7sk-SECRET",
                ],
                "@upstash/context7-mcp@1.0.14",
            ),
            (
                "/opt/homebrew/bin/npx",
                vec!["-p", "mcp-remote@0.1", "mcp-remote", "https://x"],
                "mcp-remote@0.1",
            ),
            (
                "npx -y figma-developer-mcp --figma-api-key=SECRET",
                vec![],
                "figma-developer-mcp",
            ),
            (
                "bunx",
                vec!["chrome-devtools-mcp@latest"],
                "chrome-devtools-mcp@latest",
            ),
            ("pnpm", vec!["dlx", "@playwright/mcp"], "@playwright/mcp"),
            ("npm", vec!["exec", "--", "tavily-mcp"], "tavily-mcp"),
            ("uvx", vec!["mcp-server-fetch"], "mcp-server-fetch"),
            (
                "uvx",
                vec![
                    "--index-url",
                    "https://user:SECRET@pypi.corp/simple",
                    "awslabs.aws-api-mcp-server@latest",
                ],
                "awslabs.aws-api-mcp-server@latest",
            ),
            (
                "uvx",
                vec!["--from", "git-mcp==1.2", "git-mcp-server"],
                "git-mcp==1.2",
            ),
            ("pipx", vec!["run", "mcp-server-time"], "mcp-server-time"),
            (
                "docker",
                vec![
                    "run",
                    "-i",
                    "--rm",
                    "-e",
                    "GITHUB_PERSONAL_ACCESS_TOKEN=SECRET",
                    "ghcr.io/github/github-mcp-server",
                ],
                "ghcr.io/github/github-mcp-server",
            ),
            (
                "docker",
                vec![
                    "run",
                    "--env-file",
                    "/home/alice/.env",
                    "--rm",
                    "-i",
                    "mcp/postgres:latest",
                    "postgresql://u:SECRET@db/x",
                ],
                "mcp/postgres:latest",
            ),
            (
                "podman",
                vec!["run", "-i", "--env=TOKEN=SECRET", "docker.io/mcp/time"],
                "docker.io/mcp/time",
            ),
        ] {
            assert_eq!(stdio_package(command, &args), want, "{command} {args:?}");
        }
    }

    #[test]
    fn anything_else_reports_the_program_name_or_nothing() {
        for (command, args, want) in [
            (
                "node",
                vec!["/Users/alice/work/server.js", "--token", "SECRET"],
                "node",
            ),
            ("/Users/alice/.local/bin/my-mcp", vec!["SECRET"], "my-mcp"),
            ("C:\\Users\\alice\\mcp\\server.exe", vec![], "server.exe"),
            ("python3", vec!["-m", "server", "--key=SECRET"], "python3"),
            // A runner with a path, URL, assignment or uppercase name as its
            // spec reports only the runner.
            ("npx", vec!["/home/alice/pkg"], "npx"),
            ("npx", vec!["./local-server"], "npx"),
            (
                "npx",
                vec!["https://user:SECRET@git.example/pkg.tgz"],
                "npx",
            ),
            ("npx", vec!["ghp_SECRETtoken"], "npx"),
            (
                "docker",
                vec!["run", "--some-new-flag", "SECRETVALUE", "img"],
                "docker",
            ),
            ("docker", vec!["compose", "up"], "docker"),
            ("pnpm", vec!["install"], "pnpm"),
            ("npx", vec!["-y"], "npx"),
            ("my server with spaces", vec![], ""),
        ] {
            assert_eq!(stdio_package(command, &args), want, "{command} {args:?}");
        }
    }

    #[test]
    fn a_remote_server_reports_only_its_host_name() {
        for (url, want) in [
            (
                "https://api.githubcopilot.com/mcp/",
                "api.githubcopilot.com",
            ),
            (
                "https://user:SECRET@mcp.example.com:8443/sse?token=SECRET#x",
                "mcp.example.com",
            ),
            ("HTTPS://MCP.Linear.app/sse", "mcp.linear.app"),
            ("http://[::1]:3000/mcp", "[::1]"),
            ("wss://ws.example.org/socket", "ws.example.org"),
            ("file:///home/alice/server", ""),
            ("not a url", ""),
            ("https://bad host/", ""),
        ] {
            assert_eq!(remote_host(url), want, "{url}");
        }
    }
}
