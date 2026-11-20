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

new_image() {   # $1=name $2=fstype -> prints loop device; root filesystem mounted at $WORK/$1.mnt
    local name=$1 fstype=$2 img="$WORK/$1.img" loop
    truncate -s 300M "$img"
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
    local dir="$1/lib/modules/$2"
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
}

run_case() {    # $1=name $2=loop $3..=jq-free expectations as key=value substrings of the evidence JSON
    local name=$1 loop=$2 before after out json status
    shift 2
    umount "$WORK/$name.mnt"; sync
    before=$(sha256sum "$WORK/$name.img" | cut -d' ' -f1)
    out=$(bash -e "$DETECTOR" "$loop" 2>&1); status=$?
    sync
    after=$(sha256sum "$WORK/$name.img" | cut -d' ' -f1)
    json=$(printf '%s\n' "$out" | sed -n 's/.*\[MANA-EVIDENCE-JSON\]//p')
    local ok=1 reason=""
    [ "$status" -eq 0 ] || { ok=0; reason="exit=$status"; }
    [ "$before" = "$after" ] || { ok=0; reason="$reason image-modified"; }
    [ -n "$json" ] || { ok=0; reason="$reason no-json"; }
    findmnt -rn -S "${loop}p1" >/dev/null 2>&1 && { ok=0; reason="$reason left-mounted"; }
    [ "$(blockdev --getro "${loop}p1" 2>/dev/null)" = "0" ] || { ok=0; reason="$reason left-read-only"; }
    for expect in "$@"; do
        printf '%s' "$json" | grep -qF "$expect" || { ok=0; reason="$reason missing[$expect]"; }
    done
    if [ "$ok" -eq 1 ]; then echo "PASS $name"; pass=$((pass + 1));
    else echo "FAIL $name:$reason"; printf '%s\n' "$out" | tail -n 8 | sed 's/^/     /'; fail=$((fail + 1)); fi
    losetup -d "$loop"
}

L=$(new_image ready ext4); R="$WORK/ready.mnt"
kernel "$R" 6.8.0-1073-azure module module yes
run_case ready "$L" '"verdict":"READY"' '"newestKernelMana":"present-module"' '"newestKernelHvNetvsc":"present-module"' '"problems":""'

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
kernel "$R" 6.8.0-1073-azure module module yes
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

if command -v mkfs.xfs >/dev/null 2>&1; then
    L=$(new_image xfs-root xfs); R="$WORK/xfs-root.mnt"
    kernel "$R" 4.18.0-553.el8_10.x86_64 module module yes
    run_case xfs-root "$L" '"verdict":"READY"'
else
    echo "SKIP xfs-root (mkfs.xfs not installed)"
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

rm -rf "$WORK"
echo "RESULT: $pass passed, $fail failed"
[ "$fail" -eq 0 ]
