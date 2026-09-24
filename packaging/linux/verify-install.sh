#!/bin/sh
set -eu

# Read-only deployment check. Never source or print the EnvironmentFile: it
# contains the device token and is intentionally accessible only to root.
BIN=/usr/local/libexec/merlin/merlin
EBPF=/usr/local/libexec/merlin/merlin-ebpf.o
LAUNCHER=/usr/local/libexec/merlin/merlin-launcher
CONFIG=/etc/merlin/merlin.env
RULES=/etc/merlin/rules.yaml
UNIT=/usr/lib/systemd/system/merlin.service

fail() {
  printf 'Deixic Endpoint verification failed: %s\n' "$1" >&2
  exit 1
}

check_file() {
  path=$1
  [ -f "$path" ] && [ ! -L "$path" ] || fail "$2 is missing or is a symbolic link"
  [ "$(stat -c %u -- "$path")" = 0 ] || fail "$2 is not owned by root"
  mode=$(stat -c %a -- "$path") || fail "cannot inspect $2 permissions"
  [ $((0$mode & 022)) -eq 0 ] || fail "$2 is group or world writable"
}

for directory in /usr/local/libexec /usr/local/libexec/merlin /etc/merlin /usr/lib/systemd/system; do
  [ -d "$directory" ] && [ ! -L "$directory" ] || fail 'package or configuration directory is missing or is a symbolic link'
  [ "$(stat -c %u -- "$directory")" = 0 ] || fail 'package or configuration directory is not owned by root'
  mode=$(stat -c %a -- "$directory") || fail 'cannot inspect directory permissions'
  [ $((0$mode & 022)) -eq 0 ] || fail 'package or configuration directory is group or world writable'
done

check_file "$BIN" 'sensor binary'
[ -x "$BIN" ] || fail 'sensor binary is not executable'
check_file "$EBPF" 'eBPF object'
check_file "$LAUNCHER" 'sensor launcher'
[ -x "$LAUNCHER" ] || fail 'sensor launcher is not executable'
check_file "$CONFIG" 'device configuration'
[ "$(stat -c %a -- "$CONFIG")" = 600 ] || fail 'device configuration must have mode 0600'
check_file "$RULES" 'rules policy'
check_file "$UNIT" 'systemd unit'

systemctl is-enabled --quiet merlin.service || fail 'systemd service is not enabled'
systemctl is-active --quiet merlin.service || fail 'systemd service is not active'
fragment=$(systemctl show --property=FragmentPath --value merlin.service) || fail 'cannot inspect loaded systemd unit'
[ "$fragment" = "$UNIT" ] || fail 'systemd loaded an unexpected unit path'
dropins=$(systemctl show --property=DropInPaths --value merlin.service) || fail 'cannot inspect systemd drop-ins'
[ -z "$dropins" ] || fail 'systemd drop-ins change the packaged unit'
exec_start=$(systemctl show --property=ExecStart --value merlin.service) || fail 'cannot inspect service command'
case "$exec_start" in
  "{ path=$LAUNCHER ; argv[]=$LAUNCHER ; "*" }") ;;
  *) fail 'systemd service does not execute the packaged launcher' ;;
esac
for extra_command in ExecCondition ExecStartPre ExecStartPost; do
  extra_value=$(systemctl show --property="$extra_command" --value merlin.service) || fail 'cannot inspect additional service commands'
  [ -z "$extra_value" ] || fail 'systemd service has an additional command'
done
environment_files=$(systemctl show --property=EnvironmentFiles --value merlin.service) || fail 'cannot inspect service configuration path'
[ "$environment_files" = "$CONFIG (ignore_errors=no)" ] || fail 'systemd service does not load only the expected configuration path'
grep -Fx "EnvironmentFile=$CONFIG" "$UNIT" >/dev/null || fail 'systemd unit has an unexpected configuration path'
grep -Fx "ExecStart=$LAUNCHER" "$UNIT" >/dev/null || fail 'systemd unit has an unexpected launcher path'
printf '%s\n' 'Deixic Endpoint package, configuration, and systemd service verified.'
