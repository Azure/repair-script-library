#!/bin/bash
########################################################################################################
#
# .SYNOPSIS
#   Read-only check of whether a Linux OS disk is ready for MANA (Microsoft Azure Network Adapter) hosts. v1.0.0
#
# .DESCRIPTION
#   Runs on the repair VM against the source VM's OS disk attached as a data disk. NOTE: use the option
#   --run-on-repair. Inspecting the disk offline works even when the source VM has no network connectivity.
#   Marks the attached root partition read-only at the block-device level, mounts it read-only without journal
#   replay, and reports:
#     - for every installed kernel, whether the MANA Ethernet driver (mana) and the synthetic NIC driver
#       (hv_netvsc) are built in, available as modules, missing, or could not be determined
#     - modprobe blacklist/install rules and kernel command-line options that disable mana or hv_netvsc
#     - network configuration that references Mellanox drivers (mlx4/mlx5) or virtual-function interface
#       names (enP*), which can bind networking to a virtual function instead of the synthetic interface
#     - informational only: whether the newest initramfs image contains the mana module
#     - distro identity
#
#   Makes NO changes. The block device stays write-protected while mounted, so the kernel cannot delete orphan
#   inodes or replay a log on a disk copied from a running VM; its original write state is restored and the
#   filesystem unmounted before exit. A result that could not be
#   established is reported as "unknown", never as missing.
#
#   Emits one machine-readable JSON line prefixed with [MANA-EVIDENCE-JSON].
#
# .RESOLVES
#   Nothing. Detection only. No automated MANA repair exists yet; the evidence identifies what a repair, or a
#   kernel update to a release that includes the mana driver, would need to address.
#
# .PARAMETER 1 (optional)
#   Device override for the attached OS disk, e.g. /dev/sdc or /dev/nvme1n1. Bash scripts receive
#   positional parameters, so pass it as: --parameters ++/dev/sdc
#
# .EXAMPLE
#   az vm repair run -g MyRG -n MyVM --run-id linux-detect-mana-readiness --run-on-repair --verbose
#
########################################################################################################

# Initialize script
. ./src/linux/common/setup/init.sh

DEVICE_OVERRIDE="${1:-}"
TIMESTAMP=$(date +%Y%m%d%H%M%S)
EVIDENCE_DIR="/tmp/mana-evidence-${TIMESTAMP}"
MOUNT_POINT="/tmp/mana-detect-root-${TIMESTAMP}"
STATUS=$STATUS_SUCCESS

# The run driver executes this script under `bash -e`, so every command that may legitimately return
# non-zero is guarded; an unguarded failure would abort the run before the evidence is written.
mkdir -p "$EVIDENCE_DIR" "$MOUNT_POINT" 2>/dev/null || true

Log-Output "START: Running script linux-detect-mana-readiness (read-only)"
Log-Output "Evidence directory: $EVIDENCE_DIR"

cleanup() {
    if mountpoint -q "$MOUNT_POINT" 2>/dev/null; then
        umount "$MOUNT_POINT" 2>/dev/null || umount -l "$MOUNT_POINT" 2>/dev/null || true
    fi
    restore_device_write_state
}

trap cleanup EXIT

# A read-only mount alone is not enough: ext4 still deletes orphan inodes (and XFS may replay its log) on a
# disk copied from a running VM. Marking the block device itself read-only makes the kernel skip all of that.
PROTECTED_DEVICE=""
protect_device() {
    local part="$1" was_ro
    was_ro=$(blockdev --getro "$part" 2>/dev/null || echo "unknown")
    if [ "$was_ro" = "0" ] && blockdev --setro "$part" 2>/dev/null; then
        PROTECTED_DEVICE="$part"
        return 0
    fi
    # Already read-only is fine; if it cannot be made read-only, the partition is not mounted.
    [ "$was_ro" = "1" ]
}

restore_device_write_state() {
    if [ -n "$PROTECTED_DEVICE" ]; then
        blockdev --setrw "$PROTECTED_DEVICE" 2>/dev/null || true
        PROTECTED_DEVICE=""
    fi
}

json_escape() {
    local value="$1"
    value=${value//\\/\\\\}
    value=${value//\"/\\\"}
    value=${value//$'\n'/\\n}
    value=${value//$'\r'/\\r}
    value=${value//$'\t'/\\t}
    printf '%s' "$value"
}

# Mount without replaying a journal, so inspecting a disk that was not shut down cleanly cannot modify it.
# nouuid lets XFS mount when the repair VM's own root filesystem has the same UUID.
mount_read_only() {
    local part="$1" fstype="$2" status
    if ! protect_device "$part"; then
        Log-Warning "Could not mark $part read-only at the block level; skipping it rather than risking a write."
        return 1
    fi
    case "$fstype" in
        ext3|ext4) mount -t "$fstype" -o ro,noload "$part" "$MOUNT_POINT" 2>/dev/null && status=0 || status=$? ;;
        xfs)       mount -t xfs -o ro,norecovery,nouuid "$part" "$MOUNT_POINT" 2>/dev/null && status=0 || status=$? ;;
        *)         mount -t "$fstype" -o ro "$part" "$MOUNT_POINT" 2>/dev/null && status=0 || status=$? ;;
    esac
    [ "$status" -eq 0 ] || restore_device_write_state
    return "$status"
}

# Prints present-builtin, present-module, missing, or unknown for one module in one kernel's module tree.
# "missing" requires both the built-in list and the module tree to have been read without error.
module_status() {
    local kernel_dir="$1" module="$2" builtin_status files find_status
    grep -q "/${module}\.ko" "$kernel_dir/modules.builtin" 2>/dev/null && builtin_status=0 || builtin_status=$?
    if [ "$builtin_status" -eq 0 ]; then
        echo "present-builtin"
        return
    fi
    files=$(find "$kernel_dir" -name "${module}.ko*" 2>/dev/null) && find_status=0 || find_status=$?
    if [ -n "$files" ]; then
        echo "present-module"
    elif [ "$builtin_status" -eq 1 ] && [ "$find_status" -eq 0 ]; then
        echo "missing"
    else
        echo "unknown"
    fi
}

# --- Inventory -------------------------------------------------------------------------------------
lsblk -f -o NAME,FSTYPE,LABEL,UUID,SIZE,TYPE,MOUNTPOINT > "$EVIDENCE_DIR/lsblk.txt" 2>/dev/null || true
Log-Info "Block device inventory:"
cat "$EVIDENCE_DIR/lsblk.txt" 2>/dev/null || true

ROOT_SOURCE=$(findmnt -n -o SOURCE / 2>/dev/null || echo "")
ROOT_DISK=$(lsblk -no PKNAME "$ROOT_SOURCE" 2>/dev/null | head -n1 || echo "")
Log-Info "Repair VM root device: ${ROOT_SOURCE:-unknown} (disk: ${ROOT_DISK:-unknown})"

# --- Locate the attached OS root partition ---------------------------------------------------------
CANDIDATES=""
if [ -n "$DEVICE_OVERRIDE" ]; then
    CANDIDATES=$(lsblk -ln -o NAME,TYPE "$DEVICE_OVERRIDE" 2>/dev/null | awk '$2=="part"{print "/dev/"$1}' || echo "")
    Log-Info "Using device override: $DEVICE_OVERRIDE"
else
    for d in $(lsblk -dn -o NAME,TYPE 2>/dev/null | awk '$2=="disk"{print $1}'); do
        [ "$d" = "$ROOT_DISK" ] && continue
        parts=$(lsblk -ln -o NAME,TYPE "/dev/$d" 2>/dev/null | awk '$2=="part"{print "/dev/"$1}' || echo "")
        CANDIDATES="$CANDIDATES $parts"
    done
fi

OS_PARTITION=""
for part in $CANDIDATES; do
    fstype=$(lsblk -no FSTYPE "$part" 2>/dev/null | head -n1 || echo "")
    case "$fstype" in
        ext2|ext3|ext4|xfs|btrfs) ;;
        LVM2_member)
            Log-Warning "$part is an LVM physical volume. LVM layouts are out of scope for this detector."
            continue
            ;;
        crypto_LUKS)
            Log-Warning "$part is LUKS-encrypted (ADE). Encrypted disks are out of scope for this detector."
            continue
            ;;
        *) continue ;;
    esac

    if mount_read_only "$part" "$fstype"; then
        if [ -d "$MOUNT_POINT/etc" ] && { [ -d "$MOUNT_POINT/lib/modules" ] || [ -d "$MOUNT_POINT/usr/lib/modules" ]; }; then
            OS_PARTITION="$part"
            Log-Output "Found attached root filesystem on $part (mounted read-only)"
            break
        fi
        umount "$MOUNT_POINT" 2>/dev/null || true
        restore_device_write_state
    fi
done

if [ -z "$OS_PARTITION" ]; then
    Log-Error "No attached Linux root filesystem found. Pass a device explicitly with --parameters ++/dev/sdc"
    exit $STATUS_ERROR
fi

# --- Distro identity -------------------------------------------------------------------------------
DISTRO_ID=""
DISTRO_VER=""
if [ -f "$MOUNT_POINT/etc/os-release" ]; then
    cp "$MOUNT_POINT/etc/os-release" "$EVIDENCE_DIR/os-release" 2>/dev/null || true
    DISTRO_ID=$(grep -E '^ID=' "$MOUNT_POINT/etc/os-release" | head -n1 | cut -d= -f2 | tr -d '"' || echo "")
    DISTRO_VER=$(grep -E '^VERSION_ID=' "$MOUNT_POINT/etc/os-release" | head -n1 | cut -d= -f2 | tr -d '"' || echo "")
fi
Log-Output "Attached OS: ${DISTRO_ID:-unknown} ${DISTRO_VER:-}"

# --- Kernels: mana and hv_netvsc per installed kernel -----------------------------------------------
# /lib is a symlink to /usr/lib on merged-/usr distributions; use whichever holds real kernel directories.
MODULES_ROOT="$MOUNT_POINT/lib/modules"
[ -d "$MODULES_ROOT" ] || MODULES_ROOT="$MOUNT_POINT/usr/lib/modules"
if [ -L "$MOUNT_POINT/lib" ] || [ -L "$MOUNT_POINT/lib/modules" ]; then
    MODULES_ROOT="$MOUNT_POINT/usr/lib/modules"
fi

KERNELS=$(ls -1 "$MODULES_ROOT" 2>/dev/null | sort -V || true)
NEWEST_KERNEL=$(printf '%s\n' "$KERNELS" | grep -v '^$' | tail -n1 || true)
KERNELS_JSON=""
NEWEST_MANA="unknown"
NEWEST_NETVSC="unknown"
ANY_KERNEL_MANA="false"

if [ -z "$KERNELS" ]; then
    Log-Warning "No kernel module directories found under /lib/modules on the attached disk."
fi
for kernel in $KERNELS; do
    kernel_dir="$MODULES_ROOT/$kernel"
    [ -d "$kernel_dir" ] || continue
    mana=$(module_status "$kernel_dir" mana)
    netvsc=$(module_status "$kernel_dir" hv_netvsc)
    case "$mana" in present-*) ANY_KERNEL_MANA="true" ;; esac
    if [ "$kernel" = "$NEWEST_KERNEL" ]; then
        NEWEST_MANA="$mana"
        NEWEST_NETVSC="$netvsc"
    fi
    Log-Output "Kernel $kernel: mana=$mana hv_netvsc=$netvsc"
    [ -n "$KERNELS_JSON" ] && KERNELS_JSON="${KERNELS_JSON},"
    KERNELS_JSON="${KERNELS_JSON}{\"version\":\"$(json_escape "$kernel")\",\"mana\":\"$mana\",\"hvNetvsc\":\"$netvsc\"}"
done

# --- Rules that disable the drivers ----------------------------------------------------------------
# A blacklist line stops automatic loading; an "install <module> /bin/false"-style rule stops loading entirely.
DISABLE_RULES=$(grep -hsE '^[[:space:]]*(blacklist|install)[[:space:]]+(mana|mana_ib|hv_netvsc)([[:space:]]|$)' \
    "$MOUNT_POINT"/etc/modprobe.d/*.conf "$MOUNT_POINT"/lib/modprobe.d/*.conf "$MOUNT_POINT"/usr/lib/modprobe.d/*.conf \
    2>/dev/null | sed 's/^[[:space:]]*//' | sort -u || true)
CMDLINE_RULES=$(grep -hsoE '(module_blacklist|modprobe\.blacklist)=[^" ]*' "$MOUNT_POINT/etc/default/grub" 2>/dev/null \
    | grep -E '(=|,)(mana|hv_netvsc)(,|$)' | sort -u || true)
MANA_DISABLED="false"
NETVSC_DISABLED="false"
if printf '%s\n%s\n' "$DISABLE_RULES" "$CMDLINE_RULES" | grep -qE '(^|[[:space:]=,])mana([[:space:],]|$)'; then
    MANA_DISABLED="true"
fi
if printf '%s\n%s\n' "$DISABLE_RULES" "$CMDLINE_RULES" | grep -qE '(^|[[:space:]=,])hv_netvsc([[:space:],]|$)'; then
    NETVSC_DISABLED="true"
fi
[ -n "$DISABLE_RULES" ] && Log-Warning "modprobe rules affecting MANA/synthetic networking: $(echo "$DISABLE_RULES" | tr '\n' ';')"
[ -n "$CMDLINE_RULES" ] && Log-Warning "Kernel command line disables modules: $(echo "$CMDLINE_RULES" | tr '\n' ' ')"

# --- Network configuration pinned to a virtual function (report-only) -----------------------------------
# File names only: configuration contents can include addresses.
PINNED_FILES=$(grep -lsE 'mlx4_core|mlx4_en|mlx5_core|(^|[^A-Za-z0-9])enP[0-9]+' \
    "$MOUNT_POINT"/etc/netplan/*.yaml "$MOUNT_POINT"/etc/netplan/*.yml \
    "$MOUNT_POINT"/etc/sysconfig/network-scripts/ifcfg-* "$MOUNT_POINT"/etc/sysconfig/network/ifcfg-* \
    "$MOUNT_POINT"/etc/NetworkManager/system-connections/* "$MOUNT_POINT"/etc/systemd/network/* \
    "$MOUNT_POINT"/etc/udev/rules.d/*.rules 2>/dev/null | sed "s|^$MOUNT_POINT||" | sort -u || true)
PINNED_COUNT=$(printf '%s\n' "$PINNED_FILES" | grep -c . || true)
if [ "${PINNED_COUNT:-0}" -gt 0 ]; then
    Log-Warning "Network configuration referencing Mellanox drivers or VF interface names (report-only): $(echo "$PINNED_FILES" | tr '\n' ' ')"
fi

# --- Informational: newest initramfs -------------------------------------------------------------
# The mana module does not need to be in the initramfs for boot; this is recorded to inform repair design.
INITRAMFS_HAS_MANA="not-checked"
INITRAMFS_METHOD="none"
NEWEST_IMAGE=$(ls -1t "$MOUNT_POINT"/boot/init* 2>/dev/null | head -n1 || true)
if [ -n "$NEWEST_IMAGE" ]; then
    if command -v lsinitrd >/dev/null 2>&1; then
        INITRAMFS_METHOD="lsinitrd"
        CONTENTS=$(lsinitrd "$NEWEST_IMAGE" 2>/dev/null) || CONTENTS=""
    elif command -v lsinitramfs >/dev/null 2>&1; then
        INITRAMFS_METHOD="lsinitramfs"
        CONTENTS=$(lsinitramfs "$NEWEST_IMAGE" 2>/dev/null) || CONTENTS=""
    else
        CONTENTS=""
    fi
    if [ "$INITRAMFS_METHOD" != "none" ]; then
        if [ -z "$CONTENTS" ]; then
            INITRAMFS_HAS_MANA="unknown"
        elif printf '%s\n' "$CONTENTS" | grep -qE '/mana\.ko'; then
            INITRAMFS_HAS_MANA="true"
        else
            INITRAMFS_HAS_MANA="false"
        fi
    fi
fi
Log-Info "Informational: newest initramfs contains mana: $INITRAMFS_HAS_MANA (method: $INITRAMFS_METHOD)"

# --- Verdict ---------------------------------------------------------------------------------------
PROBLEMS=""
case "$NEWEST_NETVSC" in missing) PROBLEMS="${PROBLEMS}synthetic-driver-missing;" ;; esac
[ "$NETVSC_DISABLED" = "true" ] && PROBLEMS="${PROBLEMS}synthetic-driver-disabled;"
case "$NEWEST_MANA" in missing) PROBLEMS="${PROBLEMS}mana-driver-missing;" ;; esac
[ "$MANA_DISABLED" = "true" ] && PROBLEMS="${PROBLEMS}mana-driver-disabled;"
# Report-only: a reference is a risk indicator, not proof that networking is bound to the virtual function.
RISK_INDICATORS=""
[ "${PINNED_COUNT:-0}" -gt 0 ] && RISK_INDICATORS="network-config-references-vf;"

if [ -n "$PROBLEMS" ]; then
    VERDICT="NOT_READY"
    Log-Warning "Attached OS is NOT ready for MANA hosts. Problems: $PROBLEMS"
elif [ "$NEWEST_MANA" = "unknown" ] || [ "$NEWEST_NETVSC" = "unknown" ]; then
    VERDICT="UNKNOWN"
    Log-Warning "MANA readiness could not be established for the newest kernel (${NEWEST_KERNEL:-none found})."
else
    VERDICT="READY"
    Log-Output "Attached OS appears READY for MANA hosts (newest kernel ${NEWEST_KERNEL} includes mana and hv_netvsc)."
fi
if [ "$NEWEST_MANA" = "missing" ] && [ "$ANY_KERNEL_MANA" = "true" ]; then
    Log-Info "An older installed kernel includes mana; the newest kernel does not."
fi

PINNED_JSON=""
while IFS= read -r file; do
    [ -z "$file" ] && continue
    [ -n "$PINNED_JSON" ] && PINNED_JSON="${PINNED_JSON},"
    PINNED_JSON="${PINNED_JSON}\"$(json_escape "$file")\""
done <<EOF
$PINNED_FILES
EOF

cat > "$EVIDENCE_DIR/evidence.json" <<EOF
{"schemaVersion":"1.0","scenario":"mana-readiness","producedBy":"linux-detect-mana-readiness","producedAtUtc":"$(date -u +%Y-%m-%dT%H:%M:%SZ)","verdict":"$VERDICT","problems":"$PROBLEMS","riskIndicators":"$RISK_INDICATORS","os":{"family":"linux","distro":"$(json_escape "$DISTRO_ID")","version":"$(json_escape "$DISTRO_VER")"},"guest":{"osPartition":"$(json_escape "$OS_PARTITION")","newestKernel":"$(json_escape "$NEWEST_KERNEL")","newestKernelMana":"$NEWEST_MANA","newestKernelHvNetvsc":"$NEWEST_NETVSC","anyKernelHasMana":$ANY_KERNEL_MANA,"kernels":[${KERNELS_JSON}],"manaDisabledByRule":$MANA_DISABLED,"hvNetvscDisabledByRule":$NETVSC_DISABLED,"vfPinnedConfigFiles":[${PINNED_JSON}],"initramfsHasMana":"$INITRAMFS_HAS_MANA","initramfsCheckMethod":"$INITRAMFS_METHOD"},"evidencePath":"$(json_escape "$EVIDENCE_DIR")"}
EOF

Log-Output "[MANA-EVIDENCE-JSON]$(cat "$EVIDENCE_DIR/evidence.json")"

trap - EXIT
cleanup
Log-Output "END: Detection complete. Evidence at $EVIDENCE_DIR"
exit $STATUS
