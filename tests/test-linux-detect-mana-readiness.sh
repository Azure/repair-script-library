#!/bin/bash
# Fixture tests for src/linux/linux-detect-mana-readiness.sh. Run as root on Linux (or WSL) from the repository root:
#   sudo bash ./tests/test-linux-detect-mana-readiness.sh .
# Builds real partitioned disk images, attaches them as loop devices, runs the unmodified detector against
# each through its device override, and checks the verdict JSON. Every image is hashed before and after the
# run to prove the detector does not write to the disk. Requires losetup, sfdisk, mkfs.ext4 (mkfs.xfs optional).
set -u
# Run from an LF copy: a Windows checkout may convert the shared helpers to CRLF, which bash cannot source,
# while Azure downloads them from GitHub with LF endings.
SOURCE_REPO=${1:-.}
WORK=$(mktemp -d /tmp/mana-detector-fixtures.XXXXXX)
mkdir -p "$WORK/repo"
cp -r "$SOURCE_REPO/src" "$WORK/repo/"
find "$WORK/repo/src/linux" -name '*.sh' -exec sed -i 's/\r$//' {} +
cd "$WORK/repo" || exit 2
DETECTOR=src/linux/linux-detect-mana-readiness.sh
pass=0
fail=0

# One case plants a blacklist in this machine's modprobe configuration. It must never outlive the run, even if the
# run is interrupted, and must never replace a file that was already there.
HOST_PLANT=/usr/lib/modprobe.d/zz-mana-detector-fixture.conf
HOST_PLANT_OWNED=0
cleanup_fixtures() {
    [ "$HOST_PLANT_OWNED" -eq 1 ] && rm -f "$HOST_PLANT"
    HOST_PLANT_OWNED=0
}
trap cleanup_fixtures EXIT
trap 'cleanup_fixtures; exit 130' INT TERM HUP

new_image() {   # $1=name $2=fstype -> prints loop device; root filesystem mounted at $WORK/$1.mnt
    local name=$1 fstype=$2 img="$WORK/$1.img" loop
    # mkfs.xfs refuses filesystems smaller than 300 MB.
    if [ "$fstype" = xfs ]; then truncate -s 400M "$img"; else truncate -s 300M "$img"; fi
    echo 'label: gpt
,,L' | sfdisk -q "$img" >/dev/null
    loop=$(losetup -fP --show "$img")
    udevadm settle 2>/dev/null || true
    if [ "$fstype" = xfs ]; then mkfs.xfs -q -f "${loop}p1"; else mkfs.ext4 -q -F "${loop}p1"; fi
    udevadm trigger "${loop}p1" 2>/dev/null; udevadm settle 2>/dev/null || true
    mkdir -p "$WORK/$name.mnt"
    mount "${loop}p1" "$WORK/$name.mnt"
    mkdir -p "$WORK/$name.mnt/etc/modprobe.d" "$WORK/$name.mnt/etc/default"
    printf 'ID=ubuntu\nVERSION_ID="22.04"\n' > "$WORK/$name.mnt/etc/os-release"
    echo "$loop"
}

kernel() {      # $1=root $2=kernel version $3=mana: module|builtin|none $4=netvsc: module|builtin|none $5=modules.builtin: yes|no
    local dir="$1/lib/modules/$2" root="${1%/usr}"
    mkdir -p "$dir/kernel/drivers/net/ethernet/microsoft/mana" "$dir/kernel/drivers/net/hyperv"
    [ "$5" = yes ] && : > "$dir/modules.builtin"
    case "$3" in
        module)  : > "$dir/kernel/drivers/net/ethernet/microsoft/mana/mana.ko.zst" ;;
        builtin) echo 'kernel/drivers/net/ethernet/microsoft/mana/mana.ko' >> "$dir/modules.builtin" ;;
    esac
    case "$4" in
        module)  : > "$dir/kernel/drivers/net/hyperv/hv_netvsc.ko.zst" ;;
        builtin) echo 'kernel/drivers/net/hyperv/hv_netvsc.ko' >> "$dir/modules.builtin" ;;
    esac
    # The generated grub.cfg entry that boots this kernel, as update-grub writes it.
    mkdir -p "$root/boot/grub"
    printf '\tlinux\t/boot/vmlinuz-%s root=UUID=0000 ro console=ttyS0 %s\n' "$2" "${GRUB_EXTRA:-}" >> "$root/boot/grub/grub.cfg"
}

run_case() {    # $1=name $2=loop $3..=jq-free expectations as key=value substrings of the evidence JSON
    local name=$1 loop=$2 before after out json status
    shift 2
    umount "$WORK/$name.mnt"; sync
    before=$(sha256sum "$WORK/$name.img" | cut -d' ' -f1)
    out=$(PATH="${RUN_PATH_PREFIX:-}$PATH" bash -e "$DETECTOR" "$loop" 2>&1); status=$?
    sync
    after=$(sha256sum "$WORK/$name.img" | cut -d' ' -f1)
    json=$(printf '%s\n' "$out" | sed -n 's/.*\[MANA-EVIDENCE-JSON\]//p')
    local ok=1 reason=""
    [ "$status" -eq 0 ] || { ok=0; reason="exit=$status"; }
    [ "$before" = "$after" ] || { ok=0; reason="$reason image-modified"; }
    [ -n "$json" ] || { ok=0; reason="$reason no-json"; }
    if [ -n "$json" ] && command -v python3 >/dev/null 2>&1; then
        printf '%s' "$json" | python3 -c 'import json,sys; json.loads(sys.stdin.read())' 2>/dev/null || { ok=0; reason="$reason invalid-json"; }
    fi
    findmnt -rn -S "${loop}p1" >/dev/null 2>&1 && { ok=0; reason="$reason left-mounted"; }
    for p in "${loop}"p*; do
        findmnt -rn -S "$p" >/dev/null 2>&1 && { ok=0; reason="$reason left-mounted:$p"; }
        [ "$(blockdev --getro "$p" 2>/dev/null)" = "0" ] || { ok=0; reason="$reason left-read-only:$p"; }
    done
    ls -d /tmp/mana-detect-root-* /tmp/mana-detect-boot-* >/dev/null 2>&1 && { ok=0; reason="$reason left-mount-dir"; }
    [ "$(blockdev --getro "${loop}p1" 2>/dev/null)" = "0" ] || { ok=0; reason="$reason left-read-only"; }
    dmsetup ls 2>/dev/null | grep -q '^mana-detect-' && { ok=0; reason="$reason left-snapshot"; }
    ls /tmp/mana-detect-cow-* >/dev/null 2>&1 && { ok=0; reason="$reason left-cow-file"; }
    losetup -a 2>/dev/null | grep -q 'mana-detect-cow-' && { ok=0; reason="$reason left-cow-loop"; }
    for expect in "$@"; do
        printf '%s' "$json" | grep -qF "$expect" || { ok=0; reason="$reason missing[$expect]"; }
    done
    if [ "$ok" -eq 1 ]; then echo "PASS $name"; pass=$((pass + 1));
    else echo "FAIL $name:$reason"; printf '%s\n' "$out" | tail -n 8 | sed 's/^/     /'; fail=$((fail + 1)); fi
    losetup -d "$loop"
}

# Simulates a VM that was running when its disk was copied: one kernel is fully on disk, and a second kernel
# installed just before the copy exists only in the filesystem journal/log.
crash_after_kernel_install() {   # $1=root $2=loop $3=fstype $4=on-disk kernel $5=journal-only kernel
    kernel "$1" "$4" module module yes
    umount "$1"
    mount -t "$3" "${2}p1" "$1"
    kernel "$1" "$5" module module yes
    sync
    xfs_io -x -c 'shutdown -f' "$1"
}

L=$(new_image ready ext4); R="$WORK/ready.mnt"
kernel "$R" 6.8.0-1073-azure module module yes
run_case ready "$L" '"verdict":"READY"' '"newestKernelMana":"present-module"' '"newestKernelHvNetvsc":"present-module"' '"problems":""' '"mountMode":"snapshot-replayed"'

L=$(new_image builtin ext4); R="$WORK/builtin.mnt"
kernel "$R" 6.8.0-1073-azure builtin builtin yes
run_case builtin "$L" '"verdict":"READY"' '"newestKernelMana":"present-builtin"'

L=$(new_image mana-missing ext4); R="$WORK/mana-missing.mnt"
kernel "$R" 5.4.0-1109-azure none module yes
run_case mana-missing "$L" '"verdict":"NOT_READY"' '"problems":"mana-driver-missing;"' '"anyKernelHasMana":false'

L=$(new_image newest-lacks-mana ext4); R="$WORK/newest-lacks-mana.mnt"
kernel "$R" 5.15.0-1020-azure module module yes
kernel "$R" 6.1.0-custom none module yes
run_case newest-lacks-mana "$L" '"verdict":"NOT_READY"' '"newestKernel":"6.1.0-custom"' '"anyKernelHasMana":true'

L=$(new_image version-sort ext4); R="$WORK/version-sort.mnt"
kernel "$R" 5.9.0-1 none module yes
kernel "$R" 5.15.0-1 module module yes
run_case version-sort "$L" '"newestKernel":"5.15.0-1"' '"verdict":"READY"'

L=$(new_image netvsc-missing ext4); R="$WORK/netvsc-missing.mnt"
kernel "$R" 6.8.0-1073-azure module none yes
run_case netvsc-missing "$L" '"verdict":"NOT_READY"' 'synthetic-driver-missing;'

L=$(new_image blacklist ext4); R="$WORK/blacklist.mnt"
kernel "$R" 6.8.0-1073-azure module module yes
echo 'blacklist mana' > "$R/etc/modprobe.d/disable-mana.conf"
echo 'blacklist mana_ib' > "$R/etc/modprobe.d/ib.conf"
run_case blacklist "$L" '"verdict":"NOT_READY"' '"problems":"mana-driver-disabled;"' '"manaDisabledByRule":true' '"hvNetvscDisabledByRule":false'

L=$(new_image only-mana-ib-blacklisted ext4); R="$WORK/only-mana-ib-blacklisted.mnt"
kernel "$R" 6.8.0-1073-azure module module yes
echo 'blacklist mana_ib' > "$R/etc/modprobe.d/ib.conf"
run_case only-mana-ib-blacklisted "$L" '"verdict":"READY"' '"manaDisabledByRule":false'

L=$(new_image install-false ext4); R="$WORK/install-false.mnt"
kernel "$R" 6.8.0-1073-azure module module yes
echo 'install hv_netvsc /bin/false' > "$R/etc/modprobe.d/x.conf"
run_case install-false "$L" '"verdict":"NOT_READY"' 'synthetic-driver-disabled;' '"hvNetvscDisabledByRule":true'

L=$(new_image grub-cmdline ext4); R="$WORK/grub-cmdline.mnt"
GRUB_EXTRA='module_blacklist=floppy,mana' kernel "$R" 6.8.0-1073-azure module module yes
echo 'GRUB_CMDLINE_LINUX="console=ttyS0 module_blacklist=floppy,mana"' > "$R/etc/default/grub"
run_case grub-cmdline "$L" '"verdict":"NOT_READY"' 'mana-driver-disabled;'

L=$(new_image builtin-list-absent ext4); R="$WORK/builtin-list-absent.mnt"
kernel "$R" 6.8.0-1073-azure none module no
run_case builtin-list-absent "$L" '"verdict":"UNKNOWN"' '"newestKernelMana":"unknown"'

L=$(new_image vf-pinned-config ext4); R="$WORK/vf-pinned-config.mnt"
kernel "$R" 6.8.0-1073-azure module module yes
mkdir -p "$R/etc/netplan"
printf 'network:\n  ethernets:\n    eth0:\n      match:\n        driver: mlx5_core\n' > "$R/etc/netplan/50-custom.yaml"
run_case vf-pinned-config "$L" '"verdict":"READY"' '"riskIndicators":"network-config-references-vf;"' '"/etc/netplan/50-custom.yaml"'

L=$(new_image merged-usr-relative ext4); R="$WORK/merged-usr-relative.mnt"
mkdir -p "$R/usr/lib/modules"; ln -s usr/lib "$R/lib"
kernel "$R/usr" 6.8.0-1073-azure module module yes
run_case merged-usr-relative "$L" '"verdict":"READY"'

# An absolute /lib -> /usr/lib link resolves against the repair VM if followed; the detector must read the disk.
L=$(new_image merged-usr-absolute ext4); R="$WORK/merged-usr-absolute.mnt"
mkdir -p "$R/usr/lib/modules"; ln -s /usr/lib "$R/lib"
kernel "$R/usr" 7.9.9-disk-only none module yes
run_case merged-usr-absolute "$L" '"newestKernel":"7.9.9-disk-only"' '"verdict":"NOT_READY"'

L=$(new_image injection-names ext4); R="$WORK/injection-names.mnt"
kernel "$R" '6.8.0-azure";x="1' module module yes
run_case injection-names "$L" '"newestKernel":"6.8.0-azure\";x=\"1"' '"verdict":"READY"'

# --- PR #182 review regressions ---------------------------------------------------------------------
# modprobe treats hv-netvsc and hv_netvsc as the same module.
L=$(new_image blacklist-hyphen ext4); R="$WORK/blacklist-hyphen.mnt"
kernel "$R" 6.8.0-1073-azure module module yes
echo 'blacklist hv-netvsc' > "$R/etc/modprobe.d/x.conf"
run_case blacklist-hyphen "$L" '"verdict":"NOT_READY"' 'synthetic-driver-disabled;'

# The usual loading wrapper is not a disable rule.
L=$(new_image install-wrapper ext4); R="$WORK/install-wrapper.mnt"
kernel "$R" 6.8.0-1073-azure module module yes
echo 'install mana /sbin/modprobe --ignore-install mana && /bin/echo loaded' > "$R/etc/modprobe.d/x.conf"
run_case install-wrapper "$L" '"verdict":"READY"' '"manaRule":"none"'

# An arbitrary install command cannot be judged offline: unknown, not disabled.
L=$(new_image install-unknown ext4); R="$WORK/install-unknown.mnt"
kernel "$R" 6.8.0-1073-azure module module yes
echo 'install mana /usr/local/sbin/net-policy mana' > "$R/etc/modprobe.d/x.conf"
run_case install-unknown "$L" '"verdict":"UNKNOWN"' '"manaRule":"unknown"' 'mana-rule-effect-unknown;'

# An /etc file replaces the vendor file with the same name, even when it is empty.
L=$(new_image modprobe-shadowed ext4); R="$WORK/modprobe-shadowed.mnt"
kernel "$R" 6.8.0-1073-azure module module yes
mkdir -p "$R/usr/lib/modprobe.d"
echo 'blacklist mana' > "$R/usr/lib/modprobe.d/vendor.conf"
: > "$R/etc/modprobe.d/vendor.conf"
run_case modprobe-shadowed "$L" '"verdict":"READY"' '"manaDisabledByRule":false'

# Leftover or renamed module files and directories are not loadable modules.
L=$(new_image module-leftovers ext4); R="$WORK/module-leftovers.mnt"
kernel "$R" 6.8.0-1073-azure none module yes
: > "$R/lib/modules/6.8.0-1073-azure/kernel/drivers/net/ethernet/microsoft/mana/mana.ko.bak"
: > "$R/lib/modules/6.8.0-1073-azure/kernel/drivers/net/ethernet/microsoft/mana/mana.ko.disabled"
mkdir -p "$R/lib/modules/6.8.0-1073-azure/kernel/drivers/net/ethernet/microsoft/mana/mana.ko"
run_case module-leftovers "$L" '"verdict":"NOT_READY"' '"newestKernelMana":"missing"'

# A module symlink counts only if it resolves to a file on the attached disk, not on the repair VM.
L=$(new_image module-symlink ext4); R="$WORK/module-symlink.mnt"
kernel "$R" 6.8.0-1073-azure none module yes
mkdir -p "$R/opt/drivers"; : > "$R/opt/drivers/mana.ko.zst"
ln -s /opt/drivers/mana.ko.zst "$R/lib/modules/6.8.0-1073-azure/kernel/drivers/net/ethernet/microsoft/mana/mana.ko.zst"
ln -s /etc/hostname "$R/lib/modules/6.8.0-1073-azure/kernel/drivers/net/hyperv/hv_netvsc.ko"
rm -f "$R/lib/modules/6.8.0-1073-azure/kernel/drivers/net/hyperv/hv_netvsc.ko.zst"
run_case module-symlink "$L" '"newestKernelMana":"present-module"' '"newestKernelHvNetvsc":"missing"' '"verdict":"NOT_READY"'

# Absolute symlinks resolve inside the disk: os-release and modprobe.d must not be read from the repair VM. A
# blacklist planted on this machine's /usr/lib/modprobe.d proves the disk's own (empty) configuration is read.
if [ -e "$HOST_PLANT" ] || [ -L "$HOST_PLANT" ]; then
    echo "FAIL absolute-links: $HOST_PLANT already exists on this machine; refusing to overwrite it"; fail=$((fail + 1))
else
mkdir -p /usr/lib/modprobe.d; HOST_PLANT_OWNED=1; echo 'blacklist mana' > "$HOST_PLANT"
L=$(new_image absolute-links ext4); R="$WORK/absolute-links.mnt"
mkdir -p "$R/usr/lib/modules"; ln -s /usr/lib "$R/lib"
kernel "$R/usr" 6.8.0-1073-azure module module yes
rm -f "$R/etc/os-release"; printf 'ID=fixtureos\nVERSION_ID="9.9"\n' > "$R/usr/lib/os-release"; ln -s /usr/lib/os-release "$R/etc/os-release"
run_case absolute-links "$L" '"distro":"fixtureos"' '"verdict":"READY"' '"manaDisabledByRule":false'
cleanup_fixtures
fi

# The generated grub.cfg carries the effective command line even when /etc/default/grub does not.
L=$(new_image grub-cfg-only ext4); R="$WORK/grub-cfg-only.mnt"
GRUB_EXTRA='module_blacklist=mana' kernel "$R" 6.8.0-1073-azure module module yes
run_case grub-cfg-only "$L" '"verdict":"NOT_READY"' 'mana-driver-disabled;' '"kernelCommandLine":"established"'

# module_blacklist= is an exact kernel match, so hv-netvsc there does nothing...
L=$(new_image module-blacklist-exact ext4); R="$WORK/module-blacklist-exact.mnt"
GRUB_EXTRA='module_blacklist=hv-netvsc' kernel "$R" 6.8.0-1073-azure module module yes
run_case module-blacklist-exact "$L" '"verdict":"READY"' '"hvNetvscDisabledByRule":false'

# ...while modprobe.blacklist= is read by modprobe, which treats hyphens and underscores alike.
L=$(new_image modprobe-blacklist-hyphen ext4); R="$WORK/modprobe-blacklist-hyphen.mnt"
GRUB_EXTRA='modprobe.blacklist=floppy,hv-netvsc' kernel "$R" 6.8.0-1073-azure module module yes
run_case modprobe-blacklist-hyphen "$L" '"verdict":"NOT_READY"' '"problems":"synthetic-driver-disabled;"'

# No boot entry for the newest kernel: the command line cannot be established, so it cannot be READY.
L=$(new_image no-boot-entry ext4); R="$WORK/no-boot-entry.mnt"
kernel "$R" 6.8.0-1073-azure module module yes
rm -f "$R/boot/grub/grub.cfg"
run_case no-boot-entry "$L" '"verdict":"UNKNOWN"' 'kernel-command-line-unknown;'

# Module rules cannot disable a driver compiled into the kernel; the rule is kept as evidence only.
L=$(new_image builtin-blacklisted ext4); R="$WORK/builtin-blacklisted.mnt"
GRUB_EXTRA='module_blacklist=hv_netvsc' kernel "$R" 6.8.0-1073-azure builtin builtin yes
echo 'blacklist mana' > "$R/etc/modprobe.d/x.conf"
run_case builtin-blacklisted "$L" '"verdict":"READY"' '"manaDisabledByRule":true' '"hvNetvscDisabledByRule":true' '"problems":""'

# RHEL layout: separate /boot partition, BLS entry whose options expand grubenv's kernelopts.
img="$WORK/separate-boot.img"; truncate -s 400M "$img"
printf 'label: gpt\n,100M,L\n,,L\n' | sfdisk -q "$img" >/dev/null
L=$(losetup -fP --show "$img"); udevadm settle 2>/dev/null || true
mkfs.ext4 -q -F "${L}p1"; mkfs.ext4 -q -F "${L}p2"; udevadm trigger "${L}p1" "${L}p2" 2>/dev/null; udevadm settle 2>/dev/null || true
R="$WORK/separate-boot.mnt"; B="$WORK/separate-boot-boot.mnt"; mkdir -p "$R" "$B"
mount "${L}p2" "$R"; mount "${L}p1" "$B"
mkdir -p "$R/etc/modprobe.d" "$R/etc/default"; printf 'ID=rhel\nVERSION_ID="9.4"\n' > "$R/etc/os-release"
kernel "$R" 5.14.0-427.el9.x86_64 module module yes; rm -rf "$R/boot/grub"
printf 'UUID=%s / ext4 defaults 0 1\nUUID=%s /boot ext4 defaults 0 2\n' "$(blkid -s UUID -o value "${L}p2")" "$(blkid -s UUID -o value "${L}p1")" > "$R/etc/fstab"
mkdir -p "$B/loader/entries" "$B/grub2"
printf 'title RHEL\nversion 5.14.0-427.el9.x86_64\nlinux /vmlinuz-5.14.0-427.el9.x86_64\noptions $kernelopts\n' > "$B/loader/entries/abc-5.14.0-427.el9.x86_64.conf"
printf '# GRUB Environment Block\nkernelopts=root=UUID=0000 ro console=ttyS0 module_blacklist=hv_netvsc\n' > "$B/grub2/grubenv"
umount "$B"
run_case separate-boot "$L" '"verdict":"NOT_READY"' 'synthetic-driver-disabled;' '"bootMountMode":"no-replay"' '"kernelCommandLineSources":"/boot/loader/entries/'

# --- PR #182 second review --------------------------------------------------------------------------
# Separate /boot whose grubenv is an absolute symlink inside that partition: it must resolve to the guest's /boot,
# not to this machine's, or $kernelopts silently expands to nothing and the blacklist is missed.
img="$WORK/boot-absolute-symlink.img"; truncate -s 400M "$img"
printf 'label: gpt\n,100M,L\n,,L\n' | sfdisk -q "$img" >/dev/null
L=$(losetup -fP --show "$img"); udevadm settle 2>/dev/null || true
mkfs.ext4 -q -F "${L}p1"; mkfs.ext4 -q -F "${L}p2"; udevadm trigger "${L}p1" "${L}p2" 2>/dev/null; udevadm settle 2>/dev/null || true
R="$WORK/boot-absolute-symlink.mnt"; B="$WORK/boot-absolute-symlink-boot.mnt"; mkdir -p "$R" "$B"
mount "${L}p2" "$R"; mount "${L}p1" "$B"
mkdir -p "$R/etc/modprobe.d" "$R/etc/default"; printf 'ID=rhel\nVERSION_ID="9.4"\n' > "$R/etc/os-release"
kernel "$R" 5.14.0-427.el9.x86_64 module module yes; rm -rf "$R/boot/grub"
printf 'UUID=%s / ext4 defaults 0 1\nUUID=%s /boot ext4 defaults 0 2\n' "$(blkid -s UUID -o value "${L}p2")" "$(blkid -s UUID -o value "${L}p1")" > "$R/etc/fstab"
mkdir -p "$B/loader/entries" "$B/grub2"
printf 'linux /vmlinuz-5.14.0-427.el9.x86_64\noptions $kernelopts\n' > "$B/loader/entries/abc-5.14.0-427.el9.x86_64.conf"
printf 'kernelopts=root=UUID=0000 ro module_blacklist=hv_netvsc\n' > "$B/grub2/grubenv.real"
ln -s /boot/grub2/grubenv.real "$B/grub2/grubenv"
umount "$B"
run_case boot-absolute-symlink "$L" '"verdict":"NOT_READY"' 'synthetic-driver-disabled;' '"kernelCommandLine":"established"'

# A BLS entry whose $kernelopts is defined nowhere has unchecked arguments: unknown, not READY.
L=$(new_image bls-unresolved ext4); R="$WORK/bls-unresolved.mnt"
kernel "$R" 5.14.0-427.el9.x86_64 module module yes; rm -f "$R/boot/grub/grub.cfg"
mkdir -p "$R/boot/loader/entries"
printf 'linux /vmlinuz-5.14.0-427.el9.x86_64\noptions $kernelopts\n' > "$R/boot/loader/entries/abc.conf"
run_case bls-unresolved "$L" '"verdict":"UNKNOWN"' 'kernel-command-line-unknown;' '"kernelCommandLineUnresolved":"/boot/loader/entries/abc.conf:$kernelopts;"'

# An absolute modules.builtin symlink must not read this machine's list (which would claim mana is built in).
printf 'kernel/drivers/net/ethernet/microsoft/mana/mana.ko\n' > "$WORK/host-modules.builtin"
L=$(new_image builtin-list-symlink ext4); R="$WORK/builtin-list-symlink.mnt"
kernel "$R" 6.8.0-1073-azure none module no
ln -s "$WORK/host-modules.builtin" "$R/lib/modules/6.8.0-1073-azure/modules.builtin"
run_case builtin-list-symlink "$L" '"verdict":"UNKNOWN"' '"newestKernelMana":"unknown"'

# /etc/default/grub is only applied at the next grub-mkconfig: a blacklist there is pending, reported as a risk,
# and does not override the generated boot entry...
L=$(new_image grub-default-pending ext4); R="$WORK/grub-default-pending.mnt"
kernel "$R" 6.8.0-1073-azure module module yes
echo 'GRUB_CMDLINE_LINUX="console=ttyS0 module_blacklist=mana"' > "$R/etc/default/grub"
run_case grub-default-pending "$L" '"verdict":"READY"' '"riskIndicators":"pending-boot-config-disables-mana;"' 'pending at next grub-mkconfig: module_blacklist=mana;'

# ...and a later grub.d assignment replaces an earlier one, as grub-mkconfig sources them.
L=$(new_image grub-default-overridden ext4); R="$WORK/grub-default-overridden.mnt"
kernel "$R" 6.8.0-1073-azure module module yes
echo 'GRUB_CMDLINE_LINUX="module_blacklist=mana"' > "$R/etc/default/grub"
mkdir -p "$R/etc/default/grub.d"; echo 'GRUB_CMDLINE_LINUX="console=ttyS0"' > "$R/etc/default/grub.d/90-override.cfg"
run_case grub-default-overridden "$L" '"verdict":"READY"' '"riskIndicators":""'

# A grub.d snippet that is an absolute symlink inside the guest must be read from the guest.
L=$(new_image grub-d-absolute-symlink ext4); R="$WORK/grub-d-absolute-symlink.mnt"
kernel "$R" 5.4.0-1109-azure none module yes
kernel "$R" 6.8.0-1073-azure module module yes
mkdir -p "$R/etc/default/grub.d" "$R/etc/pinning"
echo 'GRUB_DEFAULT="Advanced options for Ubuntu>gnulinux-5.4.0-1109-azure-advanced"' > "$R/etc/pinning/pin.cfg"
ln -s /etc/pinning/pin.cfg "$R/etc/default/grub.d/50-pin.cfg"
run_case grub-d-absolute-symlink "$L" '"verdict":"READY"' '"bootDefaultStatus":"newest"' '"pendingBootDefault":"Advanced options for Ubuntu>gnulinux-5.4.0-1109-azure-advanced"'

# A numeric submenu default such as 1>2 in the generated grub.cfg can select an older kernel; it cannot be resolved
# offline, so unknown.
L=$(new_image grub-default-submenu ext4); R="$WORK/grub-default-submenu.mnt"
kernel "$R" 5.4.0-1109-azure none module yes
kernel "$R" 6.8.0-1073-azure module module yes
printf 'set default="1>2"\n' >> "$R/boot/grub/grub.cfg"
run_case grub-default-submenu "$L" '"verdict":"UNKNOWN"' 'boot-default-kernel-unknown;' '"bootDefaultStatus":"unknown"'

# A separate /boot already mounted on this machine (device override while an operator has it open) is left alone:
# not write-protected, not remounted. The command line is then unknown.
img="$WORK/boot-in-use.img"; truncate -s 400M "$img"
printf 'label: gpt\n,100M,L\n,,L\n' | sfdisk -q "$img" >/dev/null
L=$(losetup -fP --show "$img"); udevadm settle 2>/dev/null || true
mkfs.ext4 -q -F "${L}p1"; mkfs.ext4 -q -F "${L}p2"; udevadm trigger "${L}p1" "${L}p2" 2>/dev/null; udevadm settle 2>/dev/null || true
R="$WORK/boot-in-use.mnt"; B="$WORK/boot-in-use-boot.mnt"; mkdir -p "$R" "$B"
mount "${L}p2" "$R"; mount "${L}p1" "$B"
mkdir -p "$R/etc/modprobe.d" "$R/etc/default"; printf 'ID=rhel\nVERSION_ID="9.4"\n' > "$R/etc/os-release"
kernel "$R" 5.14.0-427.el9.x86_64 module module yes; rm -rf "$R/boot/grub"
printf 'UUID=%s / ext4 defaults 0 1\nUUID=%s /boot ext4 defaults 0 2\n' "$(blkid -s UUID -o value "${L}p2")" "$(blkid -s UUID -o value "${L}p1")" > "$R/etc/fstab"
umount "$R"
FAKE_BLOCKDEV="$WORK/blockdev-log"; mkdir -p "$FAKE_BLOCKDEV"
cat > "$FAKE_BLOCKDEV/blockdev" <<EOF
#!/bin/bash
echo "\$*" >> "$WORK/blockdev-calls.log"
exec $(command -v blockdev) "\$@"
EOF
chmod +x "$FAKE_BLOCKDEV/blockdev"; : > "$WORK/blockdev-calls.log"
out=$(PATH="$FAKE_BLOCKDEV:$PATH" bash -e "$DETECTOR" "$L" 2>&1); status=$?
touched=$(grep -c -- "--setro ${L}p1\$" "$WORK/blockdev-calls.log" || true)
boot_ro=$(blockdev --getro "${L}p1" 2>/dev/null)
still_mounted=$(findmnt -rn -S "${L}p1" -o TARGET 2>/dev/null)
json=$(printf '%s\n' "$out" | sed -n 's/.*\[MANA-EVIDENCE-JSON\]//p')
if [ "$status" -eq 0 ] && [ "$touched" = "0" ] && [ "$boot_ro" = "0" ] && [ "$still_mounted" = "$B" ] \
    && printf '%s' "$json" | grep -qF '"bootMountMode":"not-mounted"' && printf '%s' "$json" | grep -qF '"verdict":"UNKNOWN"'; then
    echo "PASS boot-already-mounted"; pass=$((pass + 1))
else
    echo "FAIL boot-already-mounted: exit=$status setro-calls=$touched ro=$boot_ro mounted=$still_mounted"; printf '%s\n' "$out" | tail -n 4 | sed 's/^/     /'; fail=$((fail + 1))
fi
umount "$B"; losetup -d "$L"

# Without a device override the detector must exclude the repair VM's own disks (here: this machine's) and fail
# closed, leaving every disk's write state as it was. findmnt is wrapped to report a Btrfs-style root source.
ro_before=$(for d in $(lsblk -dn -o NAME,TYPE | awk '$2=="disk"{print $1}'); do echo "$d=$(blockdev --getro "/dev/$d" 2>/dev/null)"; done)
real_root=$(findmnt -n -o SOURCE /)
FAKE_FINDMNT="$WORK/btrfs-findmnt"; mkdir -p "$FAKE_FINDMNT"
cat > "$FAKE_FINDMNT/findmnt" <<EOF
#!/bin/bash
if [ "\$*" = "-n -o SOURCE /" ]; then echo "${real_root}[/@]"; exit 0; fi
if [ "\$*" = "-n -o MAJ:MIN /" ]; then echo "0:99"; exit 0; fi
exec $(command -v findmnt) "\$@"
EOF
chmod +x "$FAKE_FINDMNT/findmnt"
out=$(PATH="$FAKE_FINDMNT:$PATH" bash -e "$DETECTOR" 2>&1); status=$?
ro_after=$(for d in $(lsblk -dn -o NAME,TYPE | awk '$2=="disk"{print $1}'); do echo "$d=$(blockdev --getro "/dev/$d" 2>/dev/null)"; done)
if [ "$status" -ne 0 ] && [ "$ro_before" = "$ro_after" ] && printf '%s' "$out" | grep -q "resolved: ${real_root}; disks: [a-z]" \
    && ! ls -d /tmp/mana-detect-root-* >/dev/null 2>&1; then
    echo "PASS auto-discovery-excludes-repair-disks"; pass=$((pass + 1))
else
    echo "FAIL auto-discovery-excludes-repair-disks: exit=$status"; printf '%s\n' "$out" | grep -E 'root device|Skipping|Error' | sed 's/^/     /'; fail=$((fail + 1))
fi

# The working directories are created with mktemp -d, never at a predictable path.
if grep -qE 'mktemp -d "/tmp/mana-evidence-' "$DETECTOR" && grep -qE 'mktemp -d "/tmp/mana-detect-root-' "$DETECTOR" \
    && ! grep -qE 'mkdir -p "\$EVIDENCE_DIR"' "$DETECTOR"; then
    echo "PASS private-temp-directories"; pass=$((pass + 1))
else
    echo "FAIL private-temp-directories"; fail=$((fail + 1))
fi

if command -v mkfs.xfs >/dev/null 2>&1; then
    L=$(new_image xfs-root xfs); R="$WORK/xfs-root.mnt"
    kernel "$R" 4.18.0-553.el8_10.x86_64 module module yes
    run_case xfs-root "$L" '"verdict":"READY"' '"mountMode":"snapshot-replayed"'
else
    echo "SKIP xfs-root (mkfs.xfs not installed)"
fi

if command -v xfs_io >/dev/null 2>&1; then
    # ext4 on a disk shut down without unmounting: the snapshot path must mount it and see the newest kernel.
    L=$(new_image ext4-crash-consistent ext4); R="$WORK/ext4-crash-consistent.mnt"
    kernel "$R" 6.8.0-1073-azure module module yes
    umount "$R"; mount "${L}p1" "$R"
    kernel "$R" 6.9.0-custom none module yes
    sync; xfs_io -x -c 'shutdown -f' "$R"
    run_case ext4-crash-consistent "$L" '"newestKernel":"6.9.0-custom"' '"verdict":"NOT_READY"' '"mountMode":"snapshot-replayed"'

    if command -v mkfs.xfs >/dev/null 2>&1; then
        # The newest kernel exists only in the unreplayed XFS log; a no-replay mount would report the older one.
        L=$(new_image xfs-crash-consistent xfs); R="$WORK/xfs-crash-consistent.mnt"
        crash_after_kernel_install "$R" "$L" xfs 4.18.0-553.el8_10.x86_64 5.14.0-427.el9.x86_64
        run_case xfs-crash-consistent "$L" '"newestKernel":"5.14.0-427.el9.x86_64"' '"verdict":"READY"' '"mountMode":"snapshot-replayed"'

        # Without device-mapper the detector must still not write, and must say its view may be stale.
        FAKE_BIN="$WORK/no-dmsetup"; mkdir -p "$FAKE_BIN"; printf '#!/bin/sh\nexit 1\n' > "$FAKE_BIN/dmsetup"; chmod +x "$FAKE_BIN/dmsetup"
        L=$(new_image xfs-no-snapshot xfs); R="$WORK/xfs-no-snapshot.mnt"
        crash_after_kernel_install "$R" "$L" xfs 4.18.0-553.el8_10.x86_64 5.14.0-427.el9.x86_64
        RUN_PATH_PREFIX="$FAKE_BIN:" run_case xfs-no-snapshot "$L" '"mountMode":"no-replay"' '"newestKernel":"4.18.0-553.el8_10.x86_64"'
    fi
else
    echo "SKIP crash-consistent cases (xfs_io not installed)"
fi

# No Linux root filesystem on the device: the detector must fail cleanly with STATUS_ERROR.
img="$WORK/empty.img"; truncate -s 64M "$img"; echo 'label: gpt
,,L' | sfdisk -q "$img" >/dev/null
L=$(losetup -fP --show "$img"); udevadm settle 2>/dev/null || true; mkfs.ext4 -q -F "${L}p1"; udevadm trigger "${L}p1" 2>/dev/null; udevadm settle 2>/dev/null || true
before=$(sha256sum "$img" | cut -d' ' -f1)
out=$(bash -e "$DETECTOR" "$L" 2>&1); status=$?
after=$(sha256sum "$img" | cut -d' ' -f1)
if [ "$status" -eq 1 ] && [ "$before" = "$after" ] && printf '%s' "$out" | grep -q 'No attached Linux root filesystem found' \
    && [ "$(blockdev --getro "${L}p1" 2>/dev/null)" = "0" ]; then
    echo "PASS no-root-filesystem"; pass=$((pass + 1))
else
    echo "FAIL no-root-filesystem: exit=$status"; printf '%s\n' "$out" | tail -n 3 | sed 's/^/     /'; fail=$((fail + 1))
fi
losetup -d "$L"

# The verdict describes the newest kernel, so a generated GRUB default pinned to another installed kernel must not be READY.
L=$(new_image grub-pinned-older ext4); R="$WORK/grub-pinned-older.mnt"
kernel "$R" 5.4.0-1109-azure none module yes
kernel "$R" 6.8.0-1073-azure module module yes
printf 'set default="Advanced options for Ubuntu>gnulinux-5.4.0-1109-azure-advanced"\n' >> "$R/boot/grub/grub.cfg"
run_case grub-pinned-older "$L" '"verdict":"UNKNOWN"' 'boot-default-kernel-not-newest;' '"bootDefaultKernel":"5.4.0-1109-azure"'

# With GRUB_DEFAULT=saved, grub.cfg boots grubenv's saved_entry (RHEL-family BLS entry IDs name it).
L=$(new_image grub-saved-entry-older ext4); R="$WORK/grub-saved-entry-older.mnt"
kernel "$R" 5.14.0-362.el9.x86_64 module module yes
kernel "$R" 5.14.0-427.el9.x86_64 module module yes
printf 'GRUB_DEFAULT=saved\n' > "$R/etc/default/grub"
printf 'if [ "${next_entry}" ] ; then\n   set default="${next_entry}"\nelse\n   set default="${saved_entry}"\nfi\n' >> "$R/boot/grub/grub.cfg"
printf '# GRUB Environment Block\nsaved_entry=0123abcd-5.14.0-362.el9.x86_64\n' > "$R/boot/grub/grubenv"
run_case grub-saved-entry-older "$L" '"verdict":"UNKNOWN"' 'boot-default-kernel-not-newest;' '"bootDefaultKernel":"5.14.0-362.el9.x86_64"'

# A saved_entry that names the newest kernel, and a numeric default, are the newest kernel: still READY.
L=$(new_image grub-saved-entry-newest ext4); R="$WORK/grub-saved-entry-newest.mnt"
kernel "$R" 5.14.0-362.el9.x86_64 module module yes
kernel "$R" 5.14.0-427.el9.x86_64 module module yes
printf 'GRUB_DEFAULT=saved\n' > "$R/etc/default/grub"
printf 'set default="${saved_entry}"\n' >> "$R/boot/grub/grub.cfg"
printf 'saved_entry=0123abcd-5.14.0-427.el9.x86_64\n' > "$R/boot/grub/grubenv"
run_case grub-saved-entry-newest "$L" '"verdict":"READY"' '"bootDefaultKernel":""'

L=$(new_image grub-default-numeric ext4); R="$WORK/grub-default-numeric.mnt"
kernel "$R" 6.8.0-1073-azure module module yes
printf 'GRUB_DEFAULT=0\n' > "$R/etc/default/grub"
printf 'set default="0"\n' >> "$R/boot/grub/grub.cfg"
run_case grub-default-numeric "$L" '"verdict":"READY"' '"bootDefaultKernel":""'

# /etc/default/grub changed to 0 without regenerating grub.cfg: GRUB still boots the older kernel, so not READY.
L=$(new_image grub-default-stale ext4); R="$WORK/grub-default-stale.mnt"
kernel "$R" 5.4.0-1109-azure none module yes
kernel "$R" 6.8.0-1073-azure module module yes
printf 'GRUB_DEFAULT=0\n' > "$R/etc/default/grub"
printf 'set default="Advanced options for Ubuntu>gnulinux-5.4.0-1109-azure-advanced"\n' >> "$R/boot/grub/grub.cfg"
run_case grub-default-stale "$L" '"verdict":"UNKNOWN"' 'boot-default-kernel-not-newest;' '"bootDefaultKernel":"5.4.0-1109-azure"' '"pendingBootDefault":"0"'

# A one-time next_entry in grubenv overrides grub.cfg's default for the next boot.
L=$(new_image grub-next-entry ext4); R="$WORK/grub-next-entry.mnt"
kernel "$R" 5.4.0-1109-azure none module yes
kernel "$R" 6.8.0-1073-azure module module yes
printf 'set default="0"\n' >> "$R/boot/grub/grub.cfg"
printf 'next_entry=Advanced options for Ubuntu>gnulinux-5.4.0-1109-azure-advanced\n' > "$R/boot/grub/grubenv"
run_case grub-next-entry "$L" '"verdict":"UNKNOWN"' '"bootDefaultSource":"grubenv next_entry"' '"bootDefaultKernel":"5.4.0-1109-azure"'

# BLS-only layout with no readable grub.cfg and no saved_entry: the booted kernel cannot be established.
L=$(new_image boot-default-unreadable ext4); R="$WORK/boot-default-unreadable.mnt"
kernel "$R" 5.14.0-427.el9.x86_64 module module yes; rm -f "$R/boot/grub/grub.cfg"
mkdir -p "$R/boot/loader/entries"
printf 'title RHEL\nlinux /vmlinuz-5.14.0-427.el9.x86_64\noptions root=UUID=0000 ro\n' > "$R/boot/loader/entries/abc.conf"
run_case boot-default-unreadable "$L" '"verdict":"UNKNOWN"' 'boot-default-kernel-unknown;' '"kernelCommandLine":"established"'

# A generated grub.cfg linux line can carry GRUB variables too: resolved from grub.cfg when set there...
L=$(new_image grub-cfg-var-resolved ext4); R="$WORK/grub-cfg-var-resolved.mnt"
GRUB_EXTRA='$extra_args' kernel "$R" 6.8.0-1073-azure module module yes
sed -i '1i set extra_args="console=ttyS0 module_blacklist=mana"' "$R/boot/grub/grub.cfg"
run_case grub-cfg-var-resolved "$L" '"verdict":"NOT_READY"' 'mana-driver-disabled;' '"kernelCommandLine":"established"'

# ...and making the command line unknown when they cannot be resolved offline.
L=$(new_image grub-cfg-var-unresolved ext4); R="$WORK/grub-cfg-var-unresolved.mnt"
GRUB_EXTRA='$kernelopts' kernel "$R" 6.8.0-1073-azure module module yes
run_case grub-cfg-var-unresolved "$L" '"verdict":"UNKNOWN"' 'kernel-command-line-unknown;' '"kernelCommandLineUnresolved":"/boot/grub/grub.cfg:$kernelopts;"'

# Control characters are valid in Linux file names; every one must be escaped so the evidence stays valid JSON.
L=$(new_image json-control-char ext4); R="$WORK/json-control-char.mnt"
kernel "$R" 6.8.0-1073-azure module module yes
mkdir -p "$R/etc/netplan"
printf 'network:\n  ethernets:\n    enP12345s1:\n      dhcp4: true\n' > "$R/etc/netplan/70-a"$'\x01'"b"$'\x1f'"c.yaml"
run_case json-control-char "$L" '"verdict":"READY"' '"/etc/netplan/70-a\u0001b\u001fc.yaml"'

# Network configuration is resolved inside the disk: an absolute symlink to a file that exists only on this machine
# is not read, while one that resolves to a file on the disk is.
HOST_NETPLAN="$WORK/host-only-netplan.yaml"
printf 'network:\n  ethernets:\n    eth1:\n      match:\n        driver: mlx5_core\n' > "$HOST_NETPLAN"
L=$(new_image netplan-absolute-symlink ext4); R="$WORK/netplan-absolute-symlink.mnt"
kernel "$R" 6.8.0-1073-azure module module yes
mkdir -p "$R/etc/netplan" "$R/opt/net"
ln -s "$HOST_NETPLAN" "$R/etc/netplan/50-host-link.yaml"
printf 'network:\n  ethernets:\n    enP12345s1:\n      dhcp4: true\n' > "$R/opt/net/vf.yaml"
ln -s /opt/net/vf.yaml "$R/etc/netplan/60-guest-link.yaml"
run_case netplan-absolute-symlink "$L" '"verdict":"READY"' '"vfPinnedConfigFiles":["/etc/netplan/60-guest-link.yaml"]'
rm -f "$HOST_NETPLAN"

rm -rf "$WORK"
echo "RESULT: $pass passed, $fail failed"
[ "$fail" -eq 0 ]
