#!/bin/bash
########################################################################################################
#
# .SYNOPSIS
#   Read-only detection for SCSI-to-NVMe disk controller migration boot failures on Linux. v1.0.0
#
# .DESCRIPTION
#   Runs on the repair VM against the source VM's OS disk attached as a data disk. NOTE: use the option
#   --run-on-repair. Mounts the attached root filesystem READ-ONLY and reports:
#     - unstable /dev/sd* device references in /etc/fstab (and, report-only, in GRUB cmdline and crypttab)
#     - whether the initramfs images under /boot contain an NVMe driver
#     - dracut hostonly configuration, which determines whether a plain initrd rebuild would re-include NVMe
#     - distro identity
#
#   Makes NO changes. Everything is mounted with -o ro and unmounted before exit.
#
#   Emits one machine-readable JSON line prefixed with [NVME-EVIDENCE-JSON].
#
# .RESOLVES
#   Nothing. Detection only. The repair for these findings today is:
#     az vm repair run -g RG -n VM --run-id linux-alar2 --parameters fstab,initrd --run-on-repair
#   See the review notes on whether ALAR's initrd action guarantees NVMe module inclusion.
#
# .PARAMETER 1 (optional)
#   Device override for the attached OS disk, e.g. /dev/sdc or /dev/nvme1n1. Bash scripts receive
#   positional parameters, so pass it as: --parameters ++/dev/sdc
#
# .EXAMPLE
#   az vm repair run -g MyRG -n MyVM --run-id linux-detect-nvme-readiness --run-on-repair --verbose
#
########################################################################################################

# Initialize script
. ./src/linux/common/setup/init.sh

DEVICE_OVERRIDE="${1:-}"
TIMESTAMP=$(date +%Y%m%d%H%M%S)
EVIDENCE_DIR="/tmp/nvme-evidence-${TIMESTAMP}"
MOUNT_POINT="/tmp/nvme-detect-root-${TIMESTAMP}"
STATUS=$STATUS_SUCCESS

# The run driver executes this script under `bash -e`, so every command that may legitimately return
# non-zero is guarded; an unguarded failure would abort the run before the evidence is written.
mkdir -p "$EVIDENCE_DIR" "$MOUNT_POINT" 2>/dev/null || true

Log-Output "START: Running script linux-detect-nvme-readiness (read-only)"
Log-Output "Evidence directory: $EVIDENCE_DIR"

cleanup() {
    if mountpoint -q "$MOUNT_POINT" 2>/dev/null; then
        umount "$MOUNT_POINT" 2>/dev/null || umount -l "$MOUNT_POINT" 2>/dev/null || true
    fi
}

trap cleanup EXIT

json_escape() {
    local value="$1"
    value=${value//\\/\\\\}
    value=${value//\"/\\\"}
    value=${value//$'\n'/\\n}
    value=${value//$'\r'/\\r}
    value=${value//$'\t'/\\t}
    printf '%s' "$value"
}

# --- Inventory -------------------------------------------------------------------------------------
lsblk -f -o NAME,FSTYPE,LABEL,UUID,SIZE,TYPE,MOUNTPOINT > "$EVIDENCE_DIR/lsblk.txt" 2>/dev/null || true
Log-Info "Block device inventory:"
cat "$EVIDENCE_DIR/lsblk.txt" 2>/dev/null || true

ROOT_SOURCE=$(findmnt -n -o SOURCE / 2>/dev/null || echo "")
ROOT_DISK=$(lsblk -no PKNAME "$ROOT_SOURCE" 2>/dev/null | head -n1 || echo "")
Log-Info "Repair VM root device: ${ROOT_SOURCE:-unknown} (disk: ${ROOT_DISK:-unknown})"

# Bus type of the attached disks is itself evidence about how this repair VM was created.
ATTACHED_BUSES=""
for d in $(lsblk -dn -o NAME,TYPE 2>/dev/null | awk '$2=="disk"{print $1}'); do
    case "$d" in
        nvme*) ATTACHED_BUSES="${ATTACHED_BUSES} nvme" ;;
        sd*)   ATTACHED_BUSES="${ATTACHED_BUSES} scsi" ;;
        vd*)   ATTACHED_BUSES="${ATTACHED_BUSES} virtio" ;;
    esac
done
ATTACHED_BUSES=$(echo "$ATTACHED_BUSES" | tr ' ' '\n' | sort -u | grep -v '^$' | tr '\n' ',' | sed 's/,$//' || echo "")
Log-Info "Attached disk transports: ${ATTACHED_BUSES:-unknown}"

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
            Log-Warning "$part is an LVM physical volume. LVM layouts are out of scope for this detector; use linux-alar2, which assembles LVM correctly."
            continue
            ;;
        crypto_LUKS)
            Log-Warning "$part is LUKS-encrypted (ADE). Encrypted disks are out of scope for this detector."
            continue
            ;;
        *) continue ;;
    esac

    if mount -o ro "$part" "$MOUNT_POINT" 2>/dev/null; then
        if [ -f "$MOUNT_POINT/etc/fstab" ]; then
            OS_PARTITION="$part"
            Log-Output "Found attached root filesystem on $part (mounted read-only)"
            break
        fi
        umount "$MOUNT_POINT" 2>/dev/null || true
    fi
done

if [ -z "$OS_PARTITION" ]; then
    Log-Error "No attached Linux root filesystem found. Pass a device explicitly with --parameters ++/dev/sdc"
    exit $STATUS_ERROR
fi

# --- fstab: unstable device references -------------------------------------------------------------
cp "$MOUNT_POINT/etc/fstab" "$EVIDENCE_DIR/fstab.before" 2>/dev/null || true

FSTAB_DEV_REFS=$(grep -v '^[[:space:]]*#' "$MOUNT_POINT/etc/fstab" 2>/dev/null \
                 | awk 'NF>0 {print $1}' \
                 | grep -E '^/dev/(sd|hd|vd|nvme|xvd)' || true)
FSTAB_DEV_COUNT=$(printf '%s\n' "$FSTAB_DEV_REFS" | grep -c . || true)

if [ "${FSTAB_DEV_COUNT:-0}" -gt 0 ]; then
    Log-Warning "/etc/fstab contains ${FSTAB_DEV_COUNT} unstable device reference(s):"
    printf '%s\n' "$FSTAB_DEV_REFS" | while read -r ref; do [ -n "$ref" ] && Log-Warning "  $ref"; done
else
    Log-Output "/etc/fstab uses only stable identifiers (UUID/LABEL) - good."
fi

# Report-only: these are NOT repaired by the ALAR fstab action and are out of scope for a first release.
GRUB_DEV_REFS=$(grep -rhoE '(root|resume)=/dev/[a-z0-9]+' "$MOUNT_POINT/etc/default/grub" "$MOUNT_POINT/boot/grub2/grub.cfg" "$MOUNT_POINT/boot/grub/grub.cfg" 2>/dev/null | sort -u || true)
CRYPTTAB_DEV_REFS=$(grep -v '^[[:space:]]*#' "$MOUNT_POINT/etc/crypttab" 2>/dev/null | awk 'NF>0{print $2}' | grep -E '^/dev/' || true)
[ -n "$GRUB_DEV_REFS" ] && Log-Warning "GRUB references device names (report-only, not auto-repaired): $(echo "$GRUB_DEV_REFS" | tr '\n' ' ')"
[ -n "$CRYPTTAB_DEV_REFS" ] && Log-Warning "crypttab references device names (report-only, not auto-repaired): $(echo "$CRYPTTAB_DEV_REFS" | tr '\n' ' ')"

# --- Distro identity -------------------------------------------------------------------------------
DISTRO_ID=""
DISTRO_VER=""
if [ -f "$MOUNT_POINT/etc/os-release" ]; then
    cp "$MOUNT_POINT/etc/os-release" "$EVIDENCE_DIR/os-release" 2>/dev/null || true
    DISTRO_ID=$(grep -E '^ID=' "$MOUNT_POINT/etc/os-release" | head -n1 | cut -d= -f2 | tr -d '"' || echo "")
    DISTRO_VER=$(grep -E '^VERSION_ID=' "$MOUNT_POINT/etc/os-release" | head -n1 | cut -d= -f2 | tr -d '"' || echo "")
fi
Log-Output "Attached OS: ${DISTRO_ID:-unknown} ${DISTRO_VER:-}"

# --- initramfs: does it contain an NVMe driver? ----------------------------------------------------
# Three detection methods, least to most fragile. The method actually used is reported in the JSON so the
# caller can weigh the result rather than trusting a bare boolean.
INITRAMFS_HAS_NVME="unknown"
INITRAMFS_METHOD="none"
INITRAMFS_IMAGES=$(ls -1 "$MOUNT_POINT"/boot/init* 2>/dev/null || true)

if [ -z "$INITRAMFS_IMAGES" ]; then
    Log-Warning "No initramfs image found under /boot on the attached disk."
else
    printf '%s\n' "$INITRAMFS_IMAGES" > "$EVIDENCE_DIR/initramfs-images.txt" 2>/dev/null || true
    NEWEST_IMAGE=$(ls -1t "$MOUNT_POINT"/boot/init* 2>/dev/null | head -n1 || true)
    Log-Info "Inspecting newest initramfs image: $NEWEST_IMAGE"

    if command -v lsinitrd >/dev/null 2>&1; then
        INITRAMFS_METHOD="lsinitrd"
        if lsinitrd "$NEWEST_IMAGE" 2>/dev/null | grep -qE 'nvme(_core)?\.ko'; then
            INITRAMFS_HAS_NVME="true"
        else
            INITRAMFS_HAS_NVME="false"
        fi
    elif command -v lsinitramfs >/dev/null 2>&1; then
        INITRAMFS_METHOD="lsinitramfs"
        if lsinitramfs "$NEWEST_IMAGE" 2>/dev/null | grep -qE 'nvme(_core)?\.ko'; then
            INITRAMFS_HAS_NVME="true"
        else
            INITRAMFS_HAS_NVME="false"
        fi
    else
        # Fallback: byte scan. Cheap and distro-agnostic, but a match only proves the string is present.
        INITRAMFS_METHOD="binary-scan(low-confidence)"
        if grep -a -q 'nvme' "$NEWEST_IMAGE" 2>/dev/null; then
            INITRAMFS_HAS_NVME="true"
        else
            INITRAMFS_HAS_NVME="false"
        fi
    fi
    Log-Output "initramfs NVMe driver present: $INITRAMFS_HAS_NVME (method: $INITRAMFS_METHOD)"
fi

# --- dracut hostonly -------------------------------------------------------------------------------
# hostonly=yes means a plain rebuild only re-includes drivers for hardware visible at build time, so
# rebuilding an initramfs that was generated on SCSI can legitimately produce another image with no NVMe.
DRACUT_HOSTONLY="unknown"
DRACUT_CONF=$(grep -rhE '^[[:space:]]*hostonly=' "$MOUNT_POINT/etc/dracut.conf" "$MOUNT_POINT/etc/dracut.conf.d/" 2>/dev/null | tail -n1 || true)
if [ -n "$DRACUT_CONF" ]; then
    DRACUT_HOSTONLY=$(echo "$DRACUT_CONF" | cut -d= -f2 | tr -d '"' | tr -d ' ')
elif [ -d "$MOUNT_POINT/etc/dracut.conf.d" ]; then
    DRACUT_HOSTONLY="default(yes on most dracut distros)"
fi
cp -r "$MOUNT_POINT/etc/dracut.conf.d" "$EVIDENCE_DIR/dracut.conf.d" 2>/dev/null || true
Log-Output "dracut hostonly: $DRACUT_HOSTONLY"

# --- Verdict ---------------------------------------------------------------------------------------
PROBLEMS=""
[ "${FSTAB_DEV_COUNT:-0}" -gt 0 ] && PROBLEMS="${PROBLEMS}fstab-uses-device-names;"
[ "$INITRAMFS_HAS_NVME" = "false" ] && PROBLEMS="${PROBLEMS}initramfs-missing-nvme;"

if [ -z "$PROBLEMS" ]; then
    BOOT_READY="true"
    CONFIDENCE="low"
    Log-Output "Attached OS appears READY to boot on NVMe."
else
    BOOT_READY="false"
    case "$ATTACHED_BUSES" in
        *nvme*) CONFIDENCE="high" ;;
        *)      CONFIDENCE="medium" ;;
    esac
    Log-Warning "Attached OS NOT ready to boot on NVMe. Problems: $PROBLEMS"
    Log-Output "Suggested repair: az vm repair run -g <RG> -n <VM> --run-id linux-alar2 --parameters fstab,initrd --run-on-repair"
fi

FSTAB_REFS_JSON=""
while IFS= read -r ref; do
    [ -z "$ref" ] && continue
    escaped_ref=$(json_escape "$ref")
    [ -n "$FSTAB_REFS_JSON" ] && FSTAB_REFS_JSON="${FSTAB_REFS_JSON},"
    FSTAB_REFS_JSON="${FSTAB_REFS_JSON}\"${escaped_ref}\""
done <<EOF
$FSTAB_DEV_REFS
EOF

JSON_DISTRO_ID=$(json_escape "$DISTRO_ID")
JSON_DISTRO_VER=$(json_escape "$DISTRO_VER")
JSON_ATTACHED_BUSES=$(json_escape "$ATTACHED_BUSES")
JSON_OS_PARTITION=$(json_escape "$OS_PARTITION")
JSON_DRACUT_HOSTONLY=$(json_escape "$DRACUT_HOSTONLY")
JSON_EVIDENCE_DIR=$(json_escape "$EVIDENCE_DIR")

cat > "$EVIDENCE_DIR/evidence.json" <<EOF
{"schemaVersion":"1.0","scenario":"scsi-to-nvme-migration","producedBy":"linux-detect-nvme-readiness","producedAtUtc":"$(date -u +%Y-%m-%dT%H:%M:%SZ)","confidence":"$CONFIDENCE","os":{"family":"linux","distro":"$JSON_DISTRO_ID","version":"$JSON_DISTRO_VER"},"repairVm":{"attachedDiskTransports":"$JSON_ATTACHED_BUSES"},"controlPlane":null,"guest":{"osPartition":"$JSON_OS_PARTITION","fstabDeviceRefs":[${FSTAB_REFS_JSON}],"fstabDeviceRefCount":${FSTAB_DEV_COUNT:-0},"initramfsHasNvme":"$INITRAMFS_HAS_NVME","initramfsCheckMethod":"$INITRAMFS_METHOD","dracutHostOnly":"$JSON_DRACUT_HOSTONLY","bootReadyForNvme":$BOOT_READY,"problems":"$PROBLEMS"},"recommendedRunId":"linux-alar2","recommendedParameters":"fstab,initrd","evidencePath":"$JSON_EVIDENCE_DIR"}
EOF

Log-Output "[NVME-EVIDENCE-JSON]$(cat "$EVIDENCE_DIR/evidence.json")"

trap - EXIT
cleanup
Log-Output "END: Detection complete. Evidence at $EVIDENCE_DIR"
exit $STATUS
