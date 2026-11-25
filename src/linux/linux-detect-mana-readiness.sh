#!/bin/bash
########################################################################################################
#
# .SYNOPSIS
#   Read-only check of whether a Linux OS disk is ready for MANA (Microsoft Azure Network Adapter) hosts. v1.0.0
#
# .DESCRIPTION
#   Runs on the repair VM against the source VM's OS disk attached as a data disk. NOTE: use the option
#   --run-on-repair. Inspecting the disk offline works even when the source VM has no network connectivity.
#   Write-protects the attached root partition at the block-device level and mounts it read-only through a
#   temporary device-mapper snapshot, then reports:
#     - for every installed kernel, whether the MANA Ethernet driver (mana) and the synthetic NIC driver
#       (hv_netvsc) are built in, available as modules, missing, or could not be determined
#     - modprobe blacklist/install rules and kernel command-line options that disable mana or hv_netvsc. modprobe
#       search-path precedence is honoured, hyphens and underscores in module names are treated alike, and the
#       command line is read from the boot entry of the newest kernel (grub.cfg, or BLS entries and grubenv on a
#       separate /boot). An install rule whose effect cannot be established is reported as unknown. Rules cannot
#       disable a built-in driver, so they are recorded but not counted as a problem for one.
#     - whether GRUB is pinned (GRUB_DEFAULT, or saved_entry with GRUB_DEFAULT=saved) to an installed kernel other
#       than the newest; the kernel that boots is then not the one assessed, so the result is unknown
#     - network configuration that references Mellanox drivers (mlx4/mlx5) or virtual-function interface
#       names (enP*), which can bind networking to a virtual function instead of the synthetic interface
#     - informational only: whether the newest initramfs image contains the mana module
#     - distro identity
#
#   Makes NO changes to the attached disk. Paths on the disk, including absolute symlinks such as /lib -> /usr/lib,
#   are resolved inside the attached filesystem and never against the repair VM. The repair VM's own disks are
#   excluded from discovery, and if they cannot be identified the script stops. Journal (ext4) or log (XFS) replay and orphan cleanup, which a disk
#   copied from a running VM needs for a current view, are written to a temporary copy-on-write file in /tmp, not
#   to the disk. If no snapshot can be created, the disk is mounted with replay disabled and the evidence reports
#   mountMode "no-replay", because recently written changes may then be missing. The disk's original write state
#   is restored and everything is unmounted before exit. A result that could not be
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
STATUS=$STATUS_SUCCESS

# The run driver executes this script under `bash -e`, so every command that may legitimately return
# non-zero is guarded; an unguarded failure would abort the run before the evidence is written.

# This runs as root in a world-writable /tmp. mktemp -d creates each directory atomically and private to root,
# so another local user cannot pre-create it or plant symlinks that redirect the evidence writes, and
# concurrent runs never share a mount point.
EVIDENCE_DIR=$(mktemp -d "/tmp/mana-evidence-${TIMESTAMP}.XXXXXX" 2>/dev/null) || EVIDENCE_DIR=""
MOUNT_POINT=$(mktemp -d "/tmp/mana-detect-root-${TIMESTAMP}.XXXXXX" 2>/dev/null) || MOUNT_POINT=""
if [ -z "$EVIDENCE_DIR" ] || [ -z "$MOUNT_POINT" ]; then
    Log-Error "Could not create private working directories under /tmp."
    [ -n "$EVIDENCE_DIR" ] && rmdir "$EVIDENCE_DIR" 2>/dev/null
    [ -n "$MOUNT_POINT" ] && rmdir "$MOUNT_POINT" 2>/dev/null
    exit "$STATUS_ERROR"
fi

Log-Output "START: Running script linux-detect-mana-readiness (read-only)"
Log-Output "Evidence directory: $EVIDENCE_DIR"

cleanup() {
    release_boot_mount
    release_mount
    rmdir "$MOUNT_POINT" 2>/dev/null || true
}

trap cleanup EXIT

# The attached disk is usually a copy of a VM that was running, so its journal (ext4) or log (XFS) holds
# changes that are not yet in place. Mounting it directly would either replay that journal onto the disk or,
# with replay disabled, show a stale view that can miss recently installed kernels. Instead the disk is
# write-protected and mounted through a non-persistent device-mapper snapshot: replay and orphan cleanup go to
# a temporary copy-on-write file, the disk is never written, and the view is current. If a snapshot cannot be
# created, the disk is mounted with replay disabled and the evidence records mountMode "no-replay".
PROTECTED_DEVICE=""
SNAPSHOT_NAME="mana-detect-${TIMESTAMP}-$$"
SNAPSHOT_DEVICE=""
COW_FILE=""
COW_LOOP=""
MOUNT_MODE="none"

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

close_snapshot() {
    if [ -n "$SNAPSHOT_DEVICE" ]; then
        dmsetup remove "$SNAPSHOT_NAME" 2>/dev/null || dmsetup remove --retry "$SNAPSHOT_NAME" 2>/dev/null || true
        SNAPSHOT_DEVICE=""
    fi
    if [ -n "$COW_LOOP" ]; then
        losetup -d "$COW_LOOP" 2>/dev/null || true
        COW_LOOP=""
    fi
    if [ -n "$COW_FILE" ]; then
        rm -f "$COW_FILE" 2>/dev/null || true
        COW_FILE=""
    fi
}

open_snapshot() {
    local part="$1" sectors
    command -v dmsetup >/dev/null 2>&1 || return 1
    modprobe dm_snapshot 2>/dev/null || true
    sectors=$(blockdev --getsz "$part" 2>/dev/null) || return 1
    # Sparse: only blocks rewritten by journal replay consume space.
    COW_FILE=$(mktemp "/tmp/mana-detect-cow-${TIMESTAMP}.XXXXXX" 2>/dev/null) || { COW_FILE=""; return 1; }
    truncate -s 1G "$COW_FILE" 2>/dev/null || { close_snapshot; return 1; }
    COW_LOOP=$(losetup -f --show "$COW_FILE" 2>/dev/null) || { COW_LOOP=""; close_snapshot; return 1; }
    if ! echo "0 $sectors snapshot $part $COW_LOOP N 8" | dmsetup create "$SNAPSHOT_NAME" 2>/dev/null; then
        close_snapshot
        return 1
    fi
    SNAPSHOT_DEVICE="/dev/mapper/$SNAPSHOT_NAME"
    udevadm settle 2>/dev/null || true
    [ -b "$SNAPSHOT_DEVICE" ] || { close_snapshot; return 1; }
}

release_mount() {
    if mountpoint -q "$MOUNT_POINT" 2>/dev/null; then
        umount "$MOUNT_POINT" 2>/dev/null || umount -l "$MOUNT_POINT" 2>/dev/null || true
    fi
    close_snapshot
    restore_device_write_state
    MOUNT_MODE="none"
}

json_escape() {
    local value="$1"
    value=${value//\\/\\\\}
    value=${value//\"/\\\"}
    value=${value//$'\n'/\\n}
    value=${value//$'\r'/\\r}
    value=${value//$'\t'/\\t}
    # Every other U+0001-U+001F control character (valid in Linux file names) as \u00XX, so the JSON stays valid.
    if [[ "$value" == *[[:cntrl:]]* ]]; then
        local code oct ch hex
        for code in {1..31}; do
            printf -v oct '%03o' "$code"
            printf -v ch '%b' "\\0$oct"
            printf -v hex '\\u%04x' "$code"
            value=${value//"$ch"/$hex}
        done
    fi
    printf '%s' "$value"
}

# nouuid lets XFS mount when the repair VM's own root filesystem has the same UUID.
mount_read_only() {
    local part="$1" fstype="$2" xfs_opts=""
    if ! protect_device "$part"; then
        Log-Warning "Could not mark $part read-only at the block level; skipping it rather than risking a write."
        return 1
    fi
    [ "$fstype" = "xfs" ] && xfs_opts=",nouuid"

    if open_snapshot "$part"; then
        if mount -t "$fstype" -o "ro${xfs_opts}" "$SNAPSHOT_DEVICE" "$MOUNT_POINT" 2>/dev/null; then
            MOUNT_MODE="snapshot-replayed"
            return 0
        fi
        close_snapshot
    fi

    case "$fstype" in
        ext3|ext4) mount -t "$fstype" -o ro,noload "$part" "$MOUNT_POINT" 2>/dev/null && MOUNT_MODE="no-replay" ;;
        xfs)       mount -t xfs -o ro,norecovery,nouuid "$part" "$MOUNT_POINT" 2>/dev/null && MOUNT_MODE="no-replay" ;;
        *)         mount -t "$fstype" -o ro "$part" "$MOUNT_POINT" 2>/dev/null && MOUNT_MODE="no-replay" ;;
    esac
    if [ "$MOUNT_MODE" = "no-replay" ]; then
        return 0
    fi
    restore_device_write_state
    return 1
}

# Prints the repair-VM path for $1, an absolute path inside the attached filesystem. Symlinks are followed within
# the attached filesystem only: an absolute link target such as /lib -> /usr/lib is re-rooted at $MOUNT_POINT
# instead of resolving against the repair VM's own /. The last component is resolved too.
# Prints the repair-VM path of a resolved guest path. Once a separate /boot partition is mounted, the guest's /boot
# lives there rather than under the root filesystem.
guest_to_host() {
    local p="${1:-/}"
    if [ -n "${BOOT_MOUNT:-}" ]; then
        case "$p" in
            /boot) printf '%s\n' "$BOOT_MOUNT"; return ;;
            /boot/*) printf '%s%s\n' "$BOOT_MOUNT" "${p#/boot}"; return ;;
        esac
    fi
    printf '%s%s\n' "$MOUNT_POINT" "$p"
}

resolve_in_root() {
    local rest="${1#/}" resolved="" part target hops=0 host
    while [ -n "$rest" ]; do
        part="${rest%%/*}"
        if [ "$part" = "$rest" ]; then rest=""; else rest="${rest#*/}"; fi
        case "$part" in
            ''|.) continue ;;
            ..) resolved="${resolved%/*}"; continue ;;
        esac
        host=$(guest_to_host "$resolved/$part")
        if [ -L "$host" ]; then
            hops=$((hops + 1))
            [ "$hops" -le 40 ] || return 1
            target=$(readlink "$host") || return 1
            case "$target" in /*) resolved="" ;; esac
            if [ -n "$rest" ]; then rest="${target#/}/$rest"; else rest="${target#/}"; fi
        else
            resolved="$resolved/$part"
        fi
    done
    guest_to_host "${resolved:-/}"
}

# A separate /boot partition holds grub.cfg or the BLS entries that carry the effective kernel command line.
# It is write-protected and mounted read-only without journal replay, which /boot rarely needs.
BOOT_MOUNT=""
BOOT_PROTECTED=""
BOOT_MOUNT_MODE="not-separate"

release_boot_mount() {
    if [ -n "$BOOT_MOUNT" ]; then
        if mountpoint -q "$BOOT_MOUNT" 2>/dev/null; then
            umount "$BOOT_MOUNT" 2>/dev/null || umount -l "$BOOT_MOUNT" 2>/dev/null || true
        fi
        rmdir "$BOOT_MOUNT" 2>/dev/null || true
        BOOT_MOUNT=""
    fi
    if [ -n "$BOOT_PROTECTED" ]; then
        blockdev --setrw "$BOOT_PROTECTED" 2>/dev/null || true
        BOOT_PROTECTED=""
    fi
}

mount_boot_read_only() {
    local part="$1" fstype opts was_ro
    fstype=$(blkid -s TYPE -o value "$part" 2>/dev/null || echo "")
    case "$fstype" in
        ext2|ext3|ext4) opts="ro,noload" ;;
        xfs) opts="ro,norecovery,nouuid" ;;
        *) return 1 ;;
    esac
    # A partition already mounted on this machine is left alone: changing its write state would disturb that mount.
    if findmnt -rn -S "$part" >/dev/null 2>&1; then
        return 1
    fi
    was_ro=$(blockdev --getro "$part" 2>/dev/null || echo "unknown")
    if [ "$was_ro" = "0" ]; then
        blockdev --setro "$part" 2>/dev/null || return 1
        BOOT_PROTECTED="$part"
    elif [ "$was_ro" != "1" ]; then
        return 1
    fi
    BOOT_MOUNT=$(mktemp -d "/tmp/mana-detect-boot-${TIMESTAMP}.XXXXXX" 2>/dev/null) || { BOOT_MOUNT=""; release_boot_mount; return 1; }
    if ! mount -t "$fstype" -o "$opts" "$part" "$BOOT_MOUNT" 2>/dev/null; then
        release_boot_mount
        return 1
    fi
    BOOT_MOUNT_MODE="no-replay"
}

# Prints the repair-VM path of $1, a path relative to the guest's /boot. Symlinks are followed inside the guest,
# with /boot mapped to the separate partition when there is one.
boot_path() {
    resolve_in_root "/boot/$1"
}

# Prints present-builtin, present-module, missing, or unknown for one module in one kernel's module tree.
# Only regular files with a loadable-module suffix count: leftovers such as mana.ko.bak or mana.ko.disabled, and
# directories, do not. A symlinked module counts only if it resolves to a regular file inside the attached disk.
# "missing" requires both the built-in list and the module tree to have been read without error.
module_status() {
    local kernel_dir="$1" module="$2" builtin_status builtin_list files find_status f real
    # An absolute symlink for modules.builtin must not resolve to the repair VM's own list.
    builtin_list=$(resolve_in_root "${kernel_dir#"$MOUNT_POINT"}/modules.builtin" || echo "")
    if [ -n "$builtin_list" ]; then
        grep -q "/${module}\.ko" "$builtin_list" 2>/dev/null && builtin_status=0 || builtin_status=$?
    else
        builtin_status=2
    fi
    if [ "$builtin_status" -eq 0 ]; then
        echo "present-builtin"
        return
    fi
    files=$(find "$kernel_dir" \( -type f -o -type l \) \( -name "${module}.ko" -o -name "${module}.ko.xz" \
        -o -name "${module}.ko.zst" -o -name "${module}.ko.gz" \) 2>/dev/null) && find_status=0 || find_status=$?
    while IFS= read -r f; do
        [ -n "$f" ] || continue
        if [ -L "$f" ]; then
            real=$(resolve_in_root "${f#"$MOUNT_POINT"}") || continue
            [ -f "$real" ] || continue
        fi
        echo "present-module"
        return
    done <<EOF
$files
EOF
    if [ "$builtin_status" -eq 1 ] && [ "$find_status" -eq 0 ]; then
        echo "missing"
    else
        echo "unknown"
    fi
}

# Prints "blocks", "loads", or "unknown" for the command of an `install <module> <command>` modprobe rule.
# /bin/false or /bin/true in place of loading stops the module from loading. "modprobe --ignore-install <module>"
# as the first command is the usual wrapper that loads the module itself (optionally followed by more commands).
# Anything else is an arbitrary command whose effect cannot be established offline.
classify_install() {
    local module="$1" first word saw_modprobe=0 saw_ignore=0 saw_module=0
    first=$(printf '%s' "$2" | sed -E 's/[[:space:]]*(;|&&|\|\||\|).*$//')
    local -a words
    read -r -a words <<< "$first"
    set -- "${words[@]}"
    case "${1:-}" in
        /bin/false|/usr/bin/false|false|/bin/true|/usr/bin/true|true|:|exit) echo "blocks"; return ;;
    esac
    for word in "$@"; do
        case "$word" in
            modprobe|*/modprobe) saw_modprobe=1 ;;
            --ignore-install|-i) saw_ignore=1 ;;
            *) [ "${word//-/_}" = "$module" ] && saw_module=1 ;;
        esac
    done
    if [ "$saw_modprobe" -eq 1 ] && [ "$saw_ignore" -eq 1 ] && [ "$saw_module" -eq 1 ]; then
        echo "loads"
    else
        echo "unknown"
    fi
}

# --- Inventory -------------------------------------------------------------------------------------
lsblk -f -o NAME,FSTYPE,LABEL,UUID,SIZE,TYPE,MOUNTPOINT > "$EVIDENCE_DIR/lsblk.txt" 2>/dev/null || true
Log-Info "Block device inventory:"
cat "$EVIDENCE_DIR/lsblk.txt" 2>/dev/null || true

# The repair VM's own disks must never be candidates: write-protecting a live root partition would break the
# repair VM. findmnt reports Btrfs subvolumes as /dev/sda2[/@] and some kernels as /dev/root, so the root device is
# resolved through its major:minor number where possible. Every disk below it (through LVM, RAID or dm layers) is
# excluded, as is every disk with a mounted partition (/boot, /boot/efi, the resource disk). If the root device
# cannot be identified, discovery stops rather than guess.
ROOT_SOURCE=$(findmnt -n -o SOURCE / 2>/dev/null || echo "")
ROOT_MAJMIN=$(findmnt -n -o MAJ:MIN / 2>/dev/null || echo "")
ROOT_DEVICE=""
if [ -n "$ROOT_MAJMIN" ] && [ -b "/dev/block/$ROOT_MAJMIN" ]; then
    ROOT_DEVICE=$(readlink -f "/dev/block/$ROOT_MAJMIN" 2>/dev/null || echo "")
fi
if [ -z "$ROOT_DEVICE" ]; then
    candidate="${ROOT_SOURCE%%\[*}"
    [ -b "$candidate" ] && ROOT_DEVICE="$candidate"
fi
ROOT_DISKS=""
if [ -n "$ROOT_DEVICE" ]; then
    ROOT_DISKS=$(lsblk -nsr -o NAME,TYPE "$ROOT_DEVICE" 2>/dev/null | awk '$2=="disk"{print $1}' | sort -u | tr '\n' ' ' || echo "")
fi
Log-Info "Repair VM root device: ${ROOT_SOURCE:-unknown} (resolved: ${ROOT_DEVICE:-unknown}; disks: ${ROOT_DISKS:-unknown})"

disk_has_mounts() {
    lsblk -nr -o MOUNTPOINT "/dev/$1" 2>/dev/null | grep -q . && return 0
    return 1
}

# --- Locate the attached OS root partition ---------------------------------------------------------
CANDIDATES=""
if [ -n "$DEVICE_OVERRIDE" ]; then
    CANDIDATES=$(lsblk -ln -o NAME,TYPE "$DEVICE_OVERRIDE" 2>/dev/null | awk '$2=="part"{print "/dev/"$1}' || echo "")
    Log-Info "Using device override: $DEVICE_OVERRIDE"
else
    if [ -z "$ROOT_DISKS" ]; then
        Log-Error "Could not identify the repair VM's own disk, so no disk can be inspected safely. Pass the attached disk explicitly with --parameters ++/dev/sdc"
        exit "$STATUS_ERROR"
    fi
    for d in $(lsblk -dn -o NAME,TYPE 2>/dev/null | awk '$2=="disk"{print $1}'); do
        case " $ROOT_DISKS " in *" $d "*) continue ;; esac
        if disk_has_mounts "$d"; then
            Log-Info "Skipping /dev/$d: it has mounted partitions, so it belongs to the repair VM."
            continue
        fi
        parts=$(lsblk -ln -o NAME,TYPE "/dev/$d" 2>/dev/null | awk '$2=="part"{print "/dev/"$1}' || echo "")
        CANDIDATES="$CANDIDATES $parts"
    done
fi

OS_PARTITION=""
for part in $CANDIDATES; do
    if findmnt -rn -S "$part" >/dev/null 2>&1; then
        Log-Warning "$part is mounted on this repair VM; skipping it."
        continue
    fi
    fstype=$(lsblk -no FSTYPE "$part" 2>/dev/null | head -n1 || echo "")
    case "$fstype" in
        ext2|ext3|ext4|xfs|btrfs) ;;
        LVM2_member)
            Log-Warning "$part is an LVM physical volume. LVM layouts are out of scope for this detector."
            SKIPPED_LVM="true"
            continue
            ;;
        crypto_LUKS)
            Log-Warning "$part is LUKS-encrypted (ADE). Encrypted disks are out of scope for this detector."
            continue
            ;;
        *) continue ;;
    esac

    if mount_read_only "$part" "$fstype"; then
        if [ -d "$MOUNT_POINT/etc" ] && { [ -d "$(resolve_in_root /lib/modules)" ] || [ -d "$(resolve_in_root /usr/lib/modules)" ]; }; then
            OS_PARTITION="$part"
            Log-Output "Found attached root filesystem on $part (mounted read-only, mode: $MOUNT_MODE)"
            if [ "$MOUNT_MODE" = "no-replay" ]; then
                Log-Warning "A device-mapper snapshot could not be created, so the journal was not replayed. Changes written shortly before the VM stopped, such as a newly installed kernel, may not be visible."
            fi
            break
        fi
        release_mount
    fi
done

if [ -z "$OS_PARTITION" ]; then
    if [ "${SKIPPED_LVM:-false}" = "true" ]; then
        Log-Error "The attached disk uses LVM for its root filesystem, which this detector does not support yet. No verdict was produced."
    else
        Log-Error "No attached Linux root filesystem found. Pass a device explicitly with --parameters ++/dev/sdc"
    fi
    exit "$STATUS_ERROR"
fi

# --- Distro identity -------------------------------------------------------------------------------
DISTRO_ID=""
DISTRO_VER=""
OS_RELEASE=$(resolve_in_root /etc/os-release || echo "")
[ -f "$OS_RELEASE" ] || OS_RELEASE=$(resolve_in_root /usr/lib/os-release || echo "")
if [ -f "$OS_RELEASE" ]; then
    cp "$OS_RELEASE" "$EVIDENCE_DIR/os-release" 2>/dev/null || true
    DISTRO_ID=$(grep -E '^ID=' "$OS_RELEASE" | head -n1 | cut -d= -f2 | tr -d '"' || echo "")
    DISTRO_VER=$(grep -E '^VERSION_ID=' "$OS_RELEASE" | head -n1 | cut -d= -f2 | tr -d '"' || echo "")
fi
Log-Output "Attached OS: ${DISTRO_ID:-unknown} ${DISTRO_VER:-}"

# --- Kernels: mana and hv_netvsc per installed kernel -----------------------------------------------
# /lib is a symlink to /usr/lib on merged-/usr distributions; resolve_in_root follows it inside the disk.
MODULES_ROOT=$(resolve_in_root /lib/modules || echo "")
[ -d "$MODULES_ROOT" ] || MODULES_ROOT=$(resolve_in_root /usr/lib/modules || echo "")

KERNELS=$(find "$MODULES_ROOT" -mindepth 1 -maxdepth 1 -printf '%f\n' 2>/dev/null | sort -V || true)
NEWEST_KERNEL=$(printf '%s\n' "$KERNELS" | grep -v '^$' | tail -n1 || true)
KERNELS_JSON=""
NEWEST_MANA="unknown"
NEWEST_NETVSC="unknown"
ANY_KERNEL_MANA="false"

if [ -z "$KERNELS" ]; then
    Log-Warning "No kernel module directories found under /lib/modules on the attached disk."
fi
for kernel in $KERNELS; do
    kernel_dir=$(resolve_in_root "${MODULES_ROOT#"$MOUNT_POINT"}/$kernel" || echo "")
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
# modprobe reads *.conf from these directories, and a file in an earlier directory replaces every later file with
# the same name (an empty or /dev/null file masks it). Module names are compared with hyphens and underscores
# treated as the same character, as modprobe does.
MANA_RULE="none"       # none | disabled | unknown
NETVSC_RULE="none"
RULE_EVIDENCE=""

note_rule() {   # $1=module (normalized) $2=effect blocks|unknown $3=evidence text
    local state="disabled"
    [ "$2" = "unknown" ] && state="unknown"
    RULE_EVIDENCE="${RULE_EVIDENCE}$3;"
    case "$1" in
        mana)
            [ "$MANA_RULE" = "disabled" ] || MANA_RULE="$state" ;;
        hv_netvsc)
            [ "$NETVSC_RULE" = "disabled" ] || NETVSC_RULE="$state" ;;
    esac
}

declare -A SEEN_CONF=()
SEEN_DIRS=""
EFFECTIVE_CONFS=""
for dir in /etc/modprobe.d /run/modprobe.d /usr/local/lib/modprobe.d /lib/modprobe.d /usr/lib/modprobe.d; do
    host_dir=$(resolve_in_root "$dir" || echo "")
    [ -d "$host_dir" ] || continue
    case " $SEEN_DIRS " in *" $host_dir "*) continue ;; esac
    SEEN_DIRS="$SEEN_DIRS $host_dir"
    for f in "$host_dir"/*.conf; do
        [ -e "$f" ] || [ -L "$f" ] || continue
        name=$(basename "$f")
        [ -n "${SEEN_CONF[$name]:-}" ] && continue
        SEEN_CONF[$name]=1
        EFFECTIVE_CONFS="${EFFECTIVE_CONFS}$dir/$name"$'\n'
    done
done

while IFS= read -r conf; do
    [ -n "$conf" ] || continue
    real=$(resolve_in_root "$conf" || echo "")
    [ -f "$real" ] || continue
    # Join backslash-continued lines, as modprobe does.
    while read -r directive module command; do
        case "$directive" in blacklist|install) ;; *) continue ;; esac
        module="${module//-/_}"
        case "$module" in mana|hv_netvsc) ;; *) continue ;; esac
        if [ "$directive" = "blacklist" ]; then
            note_rule "$module" blocks "$conf: blacklist $module"
        else
            effect=$(classify_install "$module" "$command")
            [ "$effect" = "loads" ] && continue
            note_rule "$module" "$effect" "$conf: install $module ($effect)"
        fi
    done < <(sed -e ':a' -e '/\\$/N; s/\\\n//; ta' "$real" 2>/dev/null | grep -vE '^[[:space:]]*#' || true)
done <<EOF
$EFFECTIVE_CONFS
EOF

# --- Effective kernel command line -----------------------------------------------------------------
# /etc/default/grub is only the input to grub-mkconfig; the arguments that boot the kernel are in the generated
# grub.cfg or, on RHEL-family systems, in BLS entries under /boot/loader/entries with grubenv's kernelopts. All are
# collected for the newest kernel. When no boot entry for it can be found, the command line is reported unknown.
FSTAB=$(resolve_in_root /etc/fstab || echo "")
BOOT_SPEC=""
[ -f "$FSTAB" ] && BOOT_SPEC=$(awk '$1 !~ /^#/ && $2 == "/boot" { print $1; exit }' "$FSTAB" 2>/dev/null || echo "")
if [ -n "$BOOT_SPEC" ]; then
    BOOT_MOUNT_MODE="not-mounted"
    os_disk=$(lsblk -ndo PKNAME "$OS_PARTITION" 2>/dev/null | head -n1 || echo "")
    for p in $(lsblk -ln -o NAME,TYPE "/dev/$os_disk" 2>/dev/null | awk '$2=="part"{print "/dev/"$1}'); do
        [ "$p" = "$OS_PARTITION" ] && continue
        match=0
        case "$BOOT_SPEC" in
            UUID=*|/dev/disk/by-uuid/*) [ "$(blkid -s UUID -o value "$p" 2>/dev/null)" = "${BOOT_SPEC##*[=/]}" ] && match=1 ;;
            LABEL=*|/dev/disk/by-label/*) [ "$(blkid -s LABEL -o value "$p" 2>/dev/null)" = "${BOOT_SPEC##*[=/]}" ] && match=1 ;;
            PARTUUID=*|/dev/disk/by-partuuid/*) [ "$(blkid -s PARTUUID -o value "$p" 2>/dev/null)" = "${BOOT_SPEC##*[=/]}" ] && match=1 ;;
        esac
        if [ "$match" -eq 1 ]; then
            if mount_boot_read_only "$p"; then
                Log-Output "Mounted the separate /boot partition $p read-only (no journal replay)."
            else
                Log-Warning "Could not mount the separate /boot partition $p read-only; the kernel command line is unknown."
            fi
            break
        fi
    done
fi

BOOT_ARGS=""
BOOT_ARGS_SOURCES=""
BOOT_ENTRY_FOUND="false"
BOOT_ARGS_UNRESOLVED=""

# Prints "guest-path<TAB>repair-VM-path" for each regular file matching glob $2 in guest directory $1. Every file is
# resolved inside the guest, so an absolute symlink never reads the repair VM's own file.
guest_files() {
    local dir="$1" pattern="$2" host_dir f name real
    host_dir=$(resolve_in_root "$dir" || echo "")
    [ -d "$host_dir" ] || return 0
    for f in "$host_dir"/$pattern; do
        [ -e "$f" ] || [ -L "$f" ] || continue
        name=$(basename "$f")
        real=$(resolve_in_root "$dir/$name" || echo "")
        [ -f "$real" ] || continue
        printf '%s\t%s\n' "$dir/$name" "$real"
    done
}

GRUB_CFG_FILES=""
for cfg in grub/grub.cfg grub2/grub.cfg; do
    file=$(boot_path "$cfg" || echo "")
    [ -f "$file" ] && GRUB_CFG_FILES="${GRUB_CFG_FILES}${file}"$'\n'
done
GRUBENV=""
for env in grub2/grubenv grub/grubenv; do
    file=$(boot_path "$env" || echo "")
    if [ -f "$file" ]; then GRUBENV="$file"; break; fi
done

# Prints the value GRUB gives variable $1 when it boots: grubenv first, then a "set" in the generated grub.cfg.
# Returns 1 when the variable is not defined anywhere, which is different from defined and empty.
grub_variable() {
    local name="$1" cfg
    if [ -n "$GRUBENV" ] && grep -q "^${name}=" "$GRUBENV" 2>/dev/null; then
        sed -n "s/^${name}=//p" "$GRUBENV" 2>/dev/null | head -n1
        return 0
    fi
    while IFS= read -r cfg; do
        [ -n "$cfg" ] || continue
        if grep -qE "^[[:space:]]*set[[:space:]]+${name}=" "$cfg" 2>/dev/null; then
            sed -nE "s/^[[:space:]]*set[[:space:]]+${name}=[\"']?([^\"']*).*/\1/p" "$cfg" 2>/dev/null | tail -n1
            return 0
        fi
    done <<EOF
$GRUB_CFG_FILES
EOF
    return 1
}

# Expands GRUB variable references ($kernelopts, ${extra}) in kernel arguments $2 from source $1 into RESOLVED_ARGS.
# Generated grub.cfg linux lines and BLS options can both carry them. A reference that cannot be resolved is recorded in
# BOOT_ARGS_UNRESOLVED, which makes the command line unknown rather than silently dropping what it may contain.
resolve_boot_vars() {
    local source="$1" var name value
    RESOLVED_ARGS="$2"
    # Longest names first, so $kernelopts is replaced before a shorter $kernel could match its prefix.
    for var in $(printf '%s' "$RESOLVED_ARGS" | grep -oE '\$\{?[A-Za-z_][A-Za-z0-9_]*\}?' | sort -ru || true); do
        name="${var#\$}"; name="${name#\{}"; name="${name%\}}"
        if value=$(grub_variable "$name"); then
            RESOLVED_ARGS=${RESOLVED_ARGS//"$var"/$value}
        else
            BOOT_ARGS_UNRESOLVED="${BOOT_ARGS_UNRESOLVED}${source}:${var};"
            RESOLVED_ARGS=${RESOLVED_ARGS//"$var"/}
        fi
    done
}

if [ "$BOOT_MOUNT_MODE" != "not-mounted" ] && [ -n "$NEWEST_KERNEL" ]; then
    while IFS= read -r file; do
        [ -n "$file" ] || continue
        args=$(K="vmlinuz-$NEWEST_KERNEL" awk '$1 ~ /^linux(efi|16)?$/ && index($2, ENVIRON["K"]) { $1 = ""; $2 = ""; print }' "$file" 2>/dev/null || echo "")
        if [ -n "$args" ]; then
            guest="/boot${file#"$(guest_to_host /boot)"}"
            resolve_boot_vars "$guest" "$args"
            BOOT_ARGS="$BOOT_ARGS $RESOLVED_ARGS"
            BOOT_ARGS_SOURCES="${BOOT_ARGS_SOURCES}${guest};"
            BOOT_ENTRY_FOUND="true"
        fi
    done <<EOF
$GRUB_CFG_FILES
EOF
        while IFS=$'\t' read -r guest entry; do
        [ -n "$entry" ] || continue
        K="$NEWEST_KERNEL" awk '$1 == "linux" && index($2, ENVIRON["K"]) { found = 1 } END { exit !found }' "$entry" 2>/dev/null || continue
        options=$(sed -n 's/^options[[:space:]]\{1,\}//p' "$entry" 2>/dev/null | head -n1 || echo "")
        resolve_boot_vars "$guest" "$options"
        BOOT_ARGS="$BOOT_ARGS $RESOLVED_ARGS"
        BOOT_ARGS_SOURCES="${BOOT_ARGS_SOURCES}${guest};"
        BOOT_ENTRY_FOUND="true"
    done < <(guest_files /boot/loader/entries '*.conf')
fi

# /etc/default/grub and /etc/default/grub.d/*.cfg are only inputs to grub-mkconfig. They take effect the next time it
# runs (a kernel update does), so they are evaluated the way grub-mkconfig sources them - in order, later assignments
# replacing earlier ones and $VAR references expanded - and reported as pending, never as the current boot state.
declare -A GRUB_SETTING=([GRUB_CMDLINE_LINUX_DEFAULT]="" [GRUB_CMDLINE_LINUX]="" [GRUB_DEFAULT]="")
GRUB_DEFAULT_SOURCES=""
read_grub_defaults() {
    local line name value v quoted='^"([^"]*)"' single="^'([^']*)'"
    while IFS= read -r line || [ -n "$line" ]; do
        [[ "$line" =~ ^[[:space:]]*(GRUB_CMDLINE_LINUX_DEFAULT|GRUB_CMDLINE_LINUX|GRUB_DEFAULT)=(.*)$ ]] || continue
        name="${BASH_REMATCH[1]}"
        value="${BASH_REMATCH[2]}"
        if [[ "$value" =~ $quoted ]] || [[ "$value" =~ $single ]]; then
            value="${BASH_REMATCH[1]}"
        else
            value="${value%%[[:space:]]*}"
        fi
        for v in GRUB_CMDLINE_LINUX_DEFAULT GRUB_CMDLINE_LINUX GRUB_DEFAULT; do
            value="${value//"\${$v}"/${GRUB_SETTING[$v]}}"
            value="${value//"\$$v"/${GRUB_SETTING[$v]}}"
        done
        GRUB_SETTING[$name]="$value"
    done < "$1"
}
file=$(resolve_in_root /etc/default/grub || echo "")
if [ -f "$file" ]; then
    read_grub_defaults "$file"
    GRUB_DEFAULT_SOURCES="/etc/default/grub;"
fi
while IFS=$'\t' read -r guest defaults; do
    [ -n "$defaults" ] || continue
    read_grub_defaults "$defaults"
    GRUB_DEFAULT_SOURCES="${GRUB_DEFAULT_SOURCES}${guest};"
done < <(guest_files /etc/default/grub.d '*.cfg')
PENDING_ARGS="${GRUB_SETTING[GRUB_CMDLINE_LINUX]} ${GRUB_SETTING[GRUB_CMDLINE_LINUX_DEFAULT]}"

# Prints "<module> <token>" for each kernel argument in $1 that stops mana or hv_netvsc from loading.
# module_blacklist= is matched by the kernel against the exact module name; modprobe.blacklist= is read by modprobe,
# which treats hyphens and underscores alike. Globbing is off so an argument such as * cannot expand.
cmdline_blocks() {
    local token list normalize module
    set -f
    for token in $1; do
        token="${token//\"/}"
        case "$token" in
            module_blacklist=*) list="${token#module_blacklist=}"; normalize=0 ;;
            modprobe.blacklist=*) list="${token#modprobe.blacklist=}"; normalize=1 ;;
            *) continue ;;
        esac
        for module in ${list//,/ }; do
            [ "$normalize" -eq 1 ] && module="${module//-/_}"
            case "$module" in mana|hv_netvsc) printf '%s %s\n' "$module" "$token" ;; esac
        done
    done
    set +f
}

while read -r module token; do
    [ -n "$module" ] && note_rule "$module" blocks "kernel command line: $token"
done < <(cmdline_blocks "$BOOT_ARGS")
PENDING_BLOCKS=""
while read -r module token; do
    [ -n "$module" ] || continue
    PENDING_BLOCKS="${PENDING_BLOCKS}${module};"
    RULE_EVIDENCE="${RULE_EVIDENCE}pending at next grub-mkconfig: $token;"
done < <(cmdline_blocks "$PENDING_ARGS")

BOOT_ARGS_STATUS="unknown"
if [ "$BOOT_ENTRY_FOUND" = "true" ] && [ -z "$BOOT_ARGS_UNRESOLVED" ]; then
    BOOT_ARGS_STATUS="established"
fi
if [ "$BOOT_ENTRY_FOUND" != "true" ]; then
    Log-Warning "No boot entry for kernel ${NEWEST_KERNEL:-none} was found, so the effective kernel command line could not be checked."
elif [ -n "$BOOT_ARGS_UNRESOLVED" ]; then
    Log-Warning "Boot entry variables could not be resolved (${BOOT_ARGS_UNRESOLVED}), so the effective kernel command line could not be checked."
fi

# --- Boot default ----------------------------------------------------------------------------------
# The verdict describes the newest installed kernel, which is GRUB's first menu entry. The entry GRUB actually boots
# comes from the generated grub.cfg ("set default=...") and grubenv (saved_entry, and a one-time next_entry), not from
# GRUB_DEFAULT in /etc/default/grub, which only takes effect at the next grub-mkconfig and is reported as pending.
# A default that names another installed kernel makes the result unknown and is reported. Any other default except
# the first entry (empty or 0) - a numeric submenu path such as 1>2, or a title without a version - may select an
# older kernel and cannot be resolved reliably offline, so it also makes the result unknown. When neither grub.cfg
# nor grubenv can be read, the default cannot be established and is unknown.

# Prints "<status> <kernel>" for boot target $1: newest, older <kernel>, or unknown.
classify_boot_target() {
    local target="$1" kernel
    [ -n "$NEWEST_KERNEL" ] || { echo newest; return; }
    case "$target" in
        ''|0|*"$NEWEST_KERNEL"*) echo newest; return ;;
    esac
    for kernel in $KERNELS; do
        [ "$kernel" = "$NEWEST_KERNEL" ] && continue
        case "$target" in *"$kernel"*) echo "older $kernel"; return ;; esac
    done
    echo unknown
}

# Replaces $saved_entry / ${saved_entry} style references in $1 with their grubenv or grub.cfg values.
expand_grub_target() {
    local value="$1" var name resolved
    for var in $(printf '%s' "$value" | grep -oE '\$\{?[A-Za-z_][A-Za-z0-9_]*\}?' | sort -ru || true); do
        name="${var#\$}"; name="${name#\{}"; name="${name%\}}"
        resolved=$(grub_variable "$name" 2>/dev/null || echo "")
        value=${value//"$var"/$resolved}
    done
    printf '%s' "$value"
}

BOOT_DEFAULT_SOURCE=""
BOOT_DEFAULT_TARGET=""
GENERATED_DEFAULT=""
GENERATED_DEFAULT_FOUND="false"
while IFS= read -r cfg; do
    [ -n "$cfg" ] || continue
    # 00_header writes set default="${next_entry}" for one-time boots and set default="<GRUB_DEFAULT>" otherwise.
    value=$(sed -nE 's/^[[:space:]]*set[[:space:]]+default=["'"'"']?([^"'"'"']*).*/\1/p' "$cfg" 2>/dev/null | grep -v 'next_entry' | head -n1 || true)
    if grep -qE '^[[:space:]]*set[[:space:]]+default=' "$cfg" 2>/dev/null; then
        GENERATED_DEFAULT="$value"
        GENERATED_DEFAULT_FOUND="true"
        break
    fi
done <<EOF
$GRUB_CFG_FILES
EOF
NEXT_ENTRY=""
[ -n "$GRUBENV" ] && NEXT_ENTRY=$(sed -n 's/^next_entry=//p' "$GRUBENV" 2>/dev/null | head -n1 || true)

if [ -n "$NEXT_ENTRY" ]; then
    BOOT_DEFAULT_TARGET="$NEXT_ENTRY"; BOOT_DEFAULT_SOURCE="grubenv next_entry"
elif [ "$GENERATED_DEFAULT_FOUND" = "true" ]; then
    BOOT_DEFAULT_TARGET=$(expand_grub_target "$GENERATED_DEFAULT"); BOOT_DEFAULT_SOURCE="grub.cfg"
elif [ -n "$GRUB_CFG_FILES" ]; then
    BOOT_DEFAULT_TARGET=""; BOOT_DEFAULT_SOURCE="grub.cfg"    # no "set default": GRUB boots the first entry
elif [ -n "$GRUBENV" ] && grep -q '^saved_entry=' "$GRUBENV" 2>/dev/null; then
    BOOT_DEFAULT_TARGET=$(grub_variable saved_entry 2>/dev/null || echo ""); BOOT_DEFAULT_SOURCE="grubenv saved_entry"
fi

BOOT_DEFAULT_KERNEL=""
if [ -z "$BOOT_DEFAULT_SOURCE" ]; then
    BOOT_DEFAULT_STATUS="unknown"
    [ -n "$NEWEST_KERNEL" ] || BOOT_DEFAULT_STATUS="newest"
else
    read -r BOOT_DEFAULT_STATUS BOOT_DEFAULT_KERNEL <<< "$(classify_boot_target "$BOOT_DEFAULT_TARGET")"
fi
if [ -n "$BOOT_DEFAULT_KERNEL" ]; then
    Log-Warning "GRUB is set to boot kernel $BOOT_DEFAULT_KERNEL ($BOOT_DEFAULT_SOURCE), not the newest installed kernel ${NEWEST_KERNEL}; the readiness of the kernel that boots was not assessed."
elif [ "$BOOT_DEFAULT_STATUS" = "unknown" ] && [ -z "$BOOT_DEFAULT_SOURCE" ]; then
    Log-Warning "Neither the generated grub.cfg nor grubenv could be read, so the kernel GRUB boots could not be established."
elif [ "$BOOT_DEFAULT_STATUS" = "unknown" ]; then
    Log-Warning "GRUB's default boot entry ($BOOT_DEFAULT_TARGET, from $BOOT_DEFAULT_SOURCE) could not be matched to an installed kernel, so the kernel that boots may not be the newest one."
fi

# Report-only: the default grub-mkconfig will write next time.
PENDING_BOOT_DEFAULT="${GRUB_SETTING[GRUB_DEFAULT]}"
if [ -n "$PENDING_BOOT_DEFAULT" ] && [ "$PENDING_BOOT_DEFAULT" != "saved" ]; then
    read -r pending_status _ <<< "$(classify_boot_target "$PENDING_BOOT_DEFAULT")"
    if [ "$pending_status" != "$BOOT_DEFAULT_STATUS" ]; then
        Log-Warning "GRUB_DEFAULT=$PENDING_BOOT_DEFAULT in the grub defaults takes effect at the next grub-mkconfig and would select a different entry ($pending_status) than the current one."
    fi
fi
MANA_DISABLED="false"
NETVSC_DISABLED="false"
[ "$MANA_RULE" = "disabled" ] && MANA_DISABLED="true"
[ "$NETVSC_RULE" = "disabled" ] && NETVSC_DISABLED="true"
[ -n "$RULE_EVIDENCE" ] && Log-Warning "Rules affecting MANA/synthetic networking: $RULE_EVIDENCE"

# --- Network configuration pinned to a virtual function (report-only) -----------------------------------
# File names only: configuration contents can include addresses. Each directory and file is resolved inside the
# attached filesystem, so an absolute symlink (for example a netplan file linked to /run) is never read from the
# repair VM's own configuration.
PINNED_FILES=""
for spec in '/etc/netplan|*.yaml' '/etc/netplan|*.yml' '/etc/sysconfig/network-scripts|ifcfg-*' \
    '/etc/sysconfig/network|ifcfg-*' '/etc/NetworkManager/system-connections|*' '/etc/systemd/network|*' \
    '/etc/udev/rules.d|*.rules'; do
    dir="${spec%%|*}"
    pattern="${spec#*|}"
    host_dir=$(resolve_in_root "$dir" || echo "")
    [ -d "$host_dir" ] || continue
    for f in "$host_dir"/$pattern; do
        [ -e "$f" ] || [ -L "$f" ] || continue
        guest_file="$dir/$(basename "$f")"
        real=$(resolve_in_root "$guest_file" || echo "")
        [ -f "$real" ] || continue
        if grep -qsE 'mlx4_core|mlx4_en|mlx5_core|(^|[^A-Za-z0-9])enP[0-9]+' "$real"; then
            PINNED_FILES="${PINNED_FILES}${guest_file}"$'\n'
        fi
    done
done
PINNED_FILES=$(printf '%s' "$PINNED_FILES" | sort -u || true)
PINNED_COUNT=$(printf '%s\n' "$PINNED_FILES" | grep -c . || true)
if [ "${PINNED_COUNT:-0}" -gt 0 ]; then
    Log-Warning "Network configuration referencing Mellanox drivers or VF interface names (report-only): $(echo "$PINNED_FILES" | tr '\n' ' ')"
fi

# --- Informational: newest initramfs -------------------------------------------------------------
# The mana module does not need to be in the initramfs for boot; this is recorded to inform repair design.
INITRAMFS_HAS_MANA="not-checked"
INITRAMFS_METHOD="none"
NEWEST_IMAGE=""
while IFS=$'\t' read -r _guest image; do
    [ -n "$image" ] || continue
    if [ -z "$NEWEST_IMAGE" ] || [ "$image" -nt "$NEWEST_IMAGE" ]; then NEWEST_IMAGE="$image"; fi
done < <(guest_files /boot 'init*')
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
# blacklist/install rules and the module-blacklist options only stop a module from being loaded; they cannot disable
# a driver compiled into the kernel. The rule stays in the evidence but is not a problem for a built-in driver.
PROBLEMS=""
UNKNOWNS=""
case "$NEWEST_NETVSC" in missing) PROBLEMS="${PROBLEMS}synthetic-driver-missing;" ;; esac
if [ "$NEWEST_NETVSC" != "present-builtin" ]; then
    [ "$NETVSC_RULE" = "disabled" ] && PROBLEMS="${PROBLEMS}synthetic-driver-disabled;"
    [ "$NETVSC_RULE" = "unknown" ] && UNKNOWNS="${UNKNOWNS}hv-netvsc-rule-effect-unknown;"
fi
case "$NEWEST_MANA" in missing) PROBLEMS="${PROBLEMS}mana-driver-missing;" ;; esac
if [ "$NEWEST_MANA" != "present-builtin" ]; then
    [ "$MANA_RULE" = "disabled" ] && PROBLEMS="${PROBLEMS}mana-driver-disabled;"
    [ "$MANA_RULE" = "unknown" ] && UNKNOWNS="${UNKNOWNS}mana-rule-effect-unknown;"
fi
[ "$NEWEST_MANA" = "unknown" ] && UNKNOWNS="${UNKNOWNS}mana-driver-unknown;"
[ "$NEWEST_NETVSC" = "unknown" ] && UNKNOWNS="${UNKNOWNS}hv-netvsc-driver-unknown;"
[ "$BOOT_ARGS_STATUS" = "unknown" ] && UNKNOWNS="${UNKNOWNS}kernel-command-line-unknown;"
[ -n "$BOOT_DEFAULT_KERNEL" ] && UNKNOWNS="${UNKNOWNS}boot-default-kernel-not-newest;"
[ "$BOOT_DEFAULT_STATUS" = "unknown" ] && UNKNOWNS="${UNKNOWNS}boot-default-kernel-unknown;"
# Report-only: a reference is a risk indicator, not proof that networking is bound to the virtual function.
RISK_INDICATORS=""
[ "${PINNED_COUNT:-0}" -gt 0 ] && RISK_INDICATORS="network-config-references-vf;"
# A pending grub default only matters for a driver that is a module; a built-in driver cannot be blacklisted.
case "$PENDING_BLOCKS" in *mana\;*) [ "$NEWEST_MANA" != "present-builtin" ] && RISK_INDICATORS="${RISK_INDICATORS}pending-boot-config-disables-mana;" ;; esac
case "$PENDING_BLOCKS" in *hv_netvsc\;*) [ "$NEWEST_NETVSC" != "present-builtin" ] && RISK_INDICATORS="${RISK_INDICATORS}pending-boot-config-disables-hv-netvsc;" ;; esac

if [ -n "$PROBLEMS" ]; then
    VERDICT="NOT_READY"
    Log-Warning "Attached OS is NOT ready for MANA hosts. Problems: $PROBLEMS"
elif [ -n "$UNKNOWNS" ]; then
    VERDICT="UNKNOWN"
    Log-Warning "MANA readiness could not be established for the newest kernel (${NEWEST_KERNEL:-none found}): $UNKNOWNS"
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
{"schemaVersion":"1.0","scenario":"mana-readiness","producedBy":"linux-detect-mana-readiness","producedAtUtc":"$(date -u +%Y-%m-%dT%H:%M:%SZ)","verdict":"$VERDICT","problems":"$PROBLEMS","riskIndicators":"$RISK_INDICATORS","unknowns":"$UNKNOWNS","os":{"family":"linux","distro":"$(json_escape "$DISTRO_ID")","version":"$(json_escape "$DISTRO_VER")"},"guest":{"osPartition":"$(json_escape "$OS_PARTITION")","mountMode":"$MOUNT_MODE","newestKernel":"$(json_escape "$NEWEST_KERNEL")","newestKernelMana":"$NEWEST_MANA","newestKernelHvNetvsc":"$NEWEST_NETVSC","anyKernelHasMana":$ANY_KERNEL_MANA,"kernels":[${KERNELS_JSON}],"manaDisabledByRule":$MANA_DISABLED,"hvNetvscDisabledByRule":$NETVSC_DISABLED,"manaRule":"$MANA_RULE","hvNetvscRule":"$NETVSC_RULE","ruleEvidence":"$(json_escape "$RULE_EVIDENCE")","kernelCommandLine":"$BOOT_ARGS_STATUS","kernelCommandLineSources":"$(json_escape "$BOOT_ARGS_SOURCES")","bootDefaultKernel":"$(json_escape "$BOOT_DEFAULT_KERNEL")","bootMountMode":"$BOOT_MOUNT_MODE","kernelCommandLineUnresolved":"$(json_escape "$BOOT_ARGS_UNRESOLVED")","pendingBootConfigSources":"$(json_escape "$GRUB_DEFAULT_SOURCES")","bootDefaultStatus":"$BOOT_DEFAULT_STATUS","bootDefaultSource":"$(json_escape "$BOOT_DEFAULT_SOURCE")","pendingBootDefault":"$(json_escape "$PENDING_BOOT_DEFAULT")","vfPinnedConfigFiles":[${PINNED_JSON}],"initramfsHasMana":"$INITRAMFS_HAS_MANA","initramfsCheckMethod":"$INITRAMFS_METHOD"},"evidencePath":"$(json_escape "$EVIDENCE_DIR")"}
EOF

Log-Output "[MANA-EVIDENCE-JSON]$(cat "$EVIDENCE_DIR/evidence.json")"

trap - EXIT
cleanup
Log-Output "END: Detection complete. Evidence at $EVIDENCE_DIR"
exit "$STATUS"
