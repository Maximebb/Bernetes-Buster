#!/usr/bin/env bash
# Check: container breakout / privileged foothold signals
# SPDX-License-Identifier: AGPL-3.0-or-later

section "02 — Container & node exposure"

# Privileged / capabilities
if is_privileged_caps; then
  signal_found "container.privileged_caps" "CRITICAL" \
    "CapEff suggests near-full capabilities ($(cap_eff_hex)) — likely privileged or host-exposed" \
    "Drop capabilities; avoid privileged: true; use drop ALL + add only needed caps" \
    "security-eng,red-team"
else
  signal_not_found "container.privileged_caps" "Effective capabilities do not look fully privileged ($(cap_eff_hex))"
fi

# Dangerous individual caps
for cap in CAP_SYS_ADMIN CAP_SYS_PTRACE CAP_DAC_OVERRIDE CAP_NET_ADMIN CAP_SYS_MODULE; do
  if has_cap "$cap" || grep -qi "$cap" <<<"$(capsh --print 2>/dev/null || true)"; then
    signal_found "container.cap.${cap}" "HIGH" \
      "Capability ${cap} appears present" \
      "Drop ${cap} unless strictly required" \
      "security-eng,red-team"
  else
    # Grep CapEff against known bits is hard without a table; soft-check via /proc/1 status only if capsh lists it
    :
  fi
done

# Docker / containerd / CRI socket
for sock in /var/run/docker.sock /run/docker.sock /var/run/containerd/containerd.sock /run/containerd/containerd.sock /var/run/crio/crio.sock; do
  if [[ -S "$sock" ]]; then
    signal_found "container.runtime_socket" "CRITICAL" \
      "Container runtime socket accessible: ${sock}" \
      "Never mount runtime sockets into application pods" \
      "security-eng,red-team"
  fi
done
if [[ ! -S /var/run/docker.sock && ! -S /run/docker.sock && ! -S /var/run/containerd/containerd.sock && ! -S /run/containerd/containerd.sock ]]; then
  signal_not_found "container.runtime_socket" "No docker/containerd/crio socket found in common paths"
fi

# Host mounts
HOST_MOUNTS=0
mounts="$( (mount 2>/dev/null || cat /proc/mounts 2>/dev/null || true) || true )"
while IFS= read -r line; do
  [[ -z "$line" ]] && continue
  case "$line" in
    *\ /host\ *|*\ /hostfs\ *|*\ /rootfs\ *|*\ /mnt/host\ *)
      signal_found "container.host_mount" "CRITICAL" \
        "Possible host filesystem mount: ${line}" \
        "Remove hostPath mounts to root or sensitive host dirs" \
        "security-eng,red-team"
      HOST_MOUNTS=1
      ;;
  esac
done <<< "$mounts"
if [[ "$HOST_MOUNTS" -eq 0 ]]; then
  signal_not_found "container.host_mount" "No obvious host root mounts (/host,/hostfs,/rootfs)"
fi

# hostPID: many processes visible
proc_count=0
if [[ -d /proc ]]; then
  proc_count="$(find /proc -maxdepth 1 -type d -name '[0-9]*' 2>/dev/null | wc -l | tr -d ' ' || echo 0)"
fi
proc_count="${proc_count:-0}"
if [[ "$proc_count" -gt 200 ]]; then
  signal_found "container.host_pid" "HIGH" \
    "Unusually high /proc entry count (${proc_count}) — possible hostPID" \
    "Do not set hostPID: true on untrusted workloads" \
    "security-eng,red-team"
else
  signal_not_found "container.host_pid" "Process visibility looks container-scoped (~${proc_count} PIDs)"
fi

# hostNetwork heuristic: can see docker0/cbr0/kube-ipvs0
ifaces="$(ip link show 2>/dev/null || true)"
if echo "$ifaces" | grep -Eq 'docker0|cbr0|flannel|cali|kube-ipvs0|cni0'; then
  signal_found "container.host_network" "HIGH" \
    "Host/CNI interfaces visible — possible hostNetwork: true" \
    "Avoid hostNetwork unless required; restrict with NetworkPolicy" \
    "security-eng,red-team"
else
  signal_not_found "container.host_network" "No obvious host/CNI bridges in local interfaces"
fi

# Privileged device nodes (only meaningful inside a container/pod)
if in_cluster; then
  for dev in /dev/kmem /dev/mem /dev/sda /dev/vda /dev/nvme0n1; do
    if [[ -e "$dev" ]]; then
      signal_found "container.host_device" "CRITICAL" \
        "Sensitive host device node present: ${dev}" \
        "Remove host device mounts" \
        "red-team,security-eng"
    fi
  done
else
  signal_skipped "container.host_device" "Not in-cluster — skipping host device probes"
fi

# Running as root
uid="$(id -u 2>/dev/null || echo unknown)"
if [[ "$uid" == "0" ]]; then
  signal_found "container.runs_as_root" "MEDIUM" \
    "Process UID is 0 (root)" \
    "Set runAsNonRoot: true and runAsUser to non-zero" \
    "developer,security-eng"
else
  signal_not_found "container.runs_as_root" "Running as UID ${uid}"
fi

# Seccomp / AppArmor
if [[ -r /proc/self/status ]]; then
  seccomp="$(awk '/Seccomp:/{print $2}' /proc/self/status)"
  # 0=disabled, 1=strict, 2=filter
  if [[ "$seccomp" == "0" ]]; then
    signal_found "container.seccomp_disabled" "MEDIUM" \
      "Seccomp mode is disabled (Seccomp: 0)" \
      "Enable RuntimeDefault or a custom seccompProfile" \
      "developer,security-eng"
  else
    signal_not_found "container.seccomp_disabled" "Seccomp mode=${seccomp} (non-zero)"
  fi
fi

# Writable root FS probe
if touch /bbuster_write_test 2>/dev/null; then
  rm -f /bbuster_write_test
  signal_found "container.writable_rootfs" "LOW" \
    "Root filesystem is writable" \
    "Set readOnlyRootFilesystem: true and mount emptyDir for temp paths" \
    "developer"
else
  signal_not_found "container.writable_rootfs" "Root filesystem appears read-only"
fi

true
