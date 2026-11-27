# SR-IOV tc-flower backend (experimental, opt-in)

By default the daemon enforces every policy with nftables inside the pod
network namespace. That cannot see traffic between SR-IOV VFs on a NIC in
**switchdev** mode: the NIC's embedded switch (eSwitch) forwards it without it
ever reaching a kernel netfilter hook.

With `--enable-tc-backend` the daemon enforces such VFs on the host instead,
with `tc flower` filters on the VF's **representor** netdev, offloaded to the
eSwitch. Everything else stays on nftables. A pod with a macvlan interface and
an SR-IOV VF gets nftables for the first and tc flower for the second.

> **Status: experimental.** CI tests the backend against a real kernel: real
> packets through the software datapath over a veth pair, with and without
> conntrack, and the control plane on a simulated switchdev NIC (netdevsim).
> Offloaded enforcement inside a ConnectX eSwitch has **not** been validated
> on hardware yet; see [Validation](#validation) for what is covered and for a
> checklist to run on your NICs before relying on it.

## Opt-in

The backend is **off by default**. Without `--enable-tc-backend` the daemon
behaves exactly as it does without this feature:

- every interface, SR-IOV or not, is enforced by nftables in the pod netns;
- no tc/netlink socket is opened, no sysfs or `devlink` probing happens;
- none of the `multinetworkpolicy_tc_*` metrics are registered;
- `--tc-offload-mode` and `--tc-ct-mode` are ignored (not even validated);
- `--tc-default-deny` other than `none` is rejected at start-up.

The one exception is asked for explicitly: `--tc-cleanup-on-start`, see
[Disabling it again](#disabling-it-again).

The shipped manifests (`deploy.yml`, `config/`, `e2e/`) do not set the flag. No
extra RBAC, capabilities or mounts are needed to enable it: the DaemonSet
already runs with `hostNetwork`, `NET_ADMIN` and the host filesystem under
`--host-prefix`.

### Enabling it

1. Put the NIC in switchdev mode with hardware tc offload on. This is node
   provisioning, not something the daemon does:

   ```sh
   devlink dev eswitch set pci/<pf> mode switchdev
   ethtool -K <pf-netdev> hw-tc-offload on
   ```

2. Add the flag, and the SR-IOV CNI plugin name(s) so those attachments are
   policed at all (the default `--network-plugins` list does not contain them):

   ```
   --enable-tc-backend
   --network-plugins=macvlan,sriov
   ```

3. Check the startup log (`tcflower startup: ...`), which lists each
   Mellanox/NVIDIA PF with its eSwitch mode, VF count and steering mode and
   says what keeps its VFs off the eSwitch.

### Disabling it again

Removing the flag moves all VFs back to nftables. The daemon removes its tc
filters when it shuts down. If it was killed instead, its filters stay on the
representors, and a daemon without the flag never touches tc. For that case,
start the daemon once with `--tc-cleanup-on-start` (and without
`--enable-tc-backend`): at start-up it removes the filters carrying the
daemon's cookie from all VF representors and does nothing else with tc. Drop
the flag again afterwards.

A daemon that is restarted with the backend still enabled needs none of this:
its first pass replaces what it finds and removes what no pod needs any more.

## Flags

| Flag | Default | Effect |
|------|---------|--------|
| `--enable-tc-backend` | `false` | Enables the backend. |
| `--tc-offload-mode` | `hardware` | `hardware`: filters are `skip_sw`, so a filter the NIC cannot offload is rejected instead of silently running in software where it would not see VF-to-VF traffic. `software`: `skip_hw`, kernel datapath only, for testing without offload-capable hardware. |
| `--tc-ct-mode` | `require` | How connection tracking is handled, see below. |
| `--tc-default-deny` | `none` | Default deny for the VFs this backend enforces, see below. Needs `--enable-tc-backend`. |
| `--tc-cleanup-on-start` | `false` | Without `--enable-tc-backend`: remove leftover tc filters once at start-up. |

`--accept-icmp`, `--allow-src-prefix` and `--allow-dst-prefix` apply to both
backends. ICMPv6 is always accepted by this backend: IPv6 does not work
without neighbour discovery, and the flower library in use cannot match the
ICMPv6 type yet, so it cannot be narrowed to neighbour discovery as the
nftables backend does without `--accept-icmpv6`.

### Connection tracking

The nftables backend is stateful: reply traffic of an allowed connection is
accepted. On the eSwitch that needs the `ct` action to be offloaded, which the
daemon only assumes when the PF reports `flow_steering_mode smfs` via
`devlink`.

| `--tc-ct-mode` | SMFS confirmed | Anything else (DMFS, HMFS, `devlink` unreadable) |
|----------------|----------------|--------------------------------------------------|
| `require` (default) | tc flower with conntrack | VF stays on nftables (stateful, in software) |
| `auto` | tc flower with conntrack | tc flower, **stateless**: replies need their own allow rule |
| `off` | tc flower, stateless | tc flower, stateless |

With conntrack, each direction first sends a packet through `ct` and then
accepts it if it belongs to an established or related connection; only new
connections reach the policy rules, and an accept commits the connection.
Both directions of a representor share one conntrack zone, so the replies to
a connection allowed in one direction are recognised in the other.

The steering mode is read once per PF and cached; restart the daemon after
changing it. Set SMFS before switching the eSwitch to switchdev:
`devlink dev param set pci/<pf> name flow_steering_mode value smfs cmode runtime`.

### Default deny

By default, a VF that no MultiNetworkPolicy selects allows all traffic.
`--tc-default-deny` denies traffic on such VFs unless a policy allows it:

| `--tc-default-deny` | VFs that no policy selects |
|---|---|
| `none` (default) | all traffic allowed |
| `ingress` | incoming traffic denied, outgoing allowed |
| `egress` | outgoing traffic denied, incoming allowed |
| `all` | both directions denied |

Any other value is rejected at start-up, and so is any value but `none`
without `--enable-tc-backend`.

The flag covers exactly the interfaces this backend enforces. It is
independent of the interfaces the nftables backend enforces, which have their
own default-deny switch (`--default-deny`, where available): either can be on
without the other. A VF that falls back to nftables (see below) is an
nftables-enforced interface and is **not** covered by `--tc-default-deny`;
watch `multinetworkpolicy_tc_backend_fallback_total` if the posture matters.

Policies stay additive. Default deny gives a VF the same filters as a policy
that selects the pod and allows nothing in that direction: the accepts listed
below, then a drop. Once a policy of a direction selects the VF, the flag
makes no difference for that VF and direction.

In a denied direction, the following stays allowed:

- replies and related traffic of allowed connections, **if conntrack is in
  use** (`--tc-ct-mode=require`, or `auto` on SMFS);
- ICMPv6 (neighbour discovery needs it), and all ICMP with `--accept-icmp`;
- sources in `--allow-src-prefix` (ingress) and destinations in
  `--allow-dst-prefix` (egress);
- ARP, which is not IP traffic and is never matched.

Without conntrack (`--tc-ct-mode=off`, or `auto` without SMFS) there is no
reply tracking: `--tc-default-deny=ingress` then also drops the replies to
connections the pod opens, and they need their own allow rule. Use the default
`--tc-ct-mode=require` with default deny.

As with policies, enforcement starts with the first reconcile after the pod
is running, and the daemon removes its filters when it shuts down.

## Which interfaces use tc

An interface is a candidate when its entry in the Multus
`k8s.v1.cni.cncf.io/network-status` annotation carries `device-info` of type
`pci`. A candidate is enforced with tc only if the daemon can resolve its VF
representor and confirm that the VF belongs to the pod; otherwise it stays on
nftables:

| Condition | `reason` |
|-----------|----------|
| PF not in switchdev mode | `not_switchdev` |
| No VF representor found, or the annotation names a different one | `not_found` |
| No well-formed PCI address, or the PCI device is not a VF | `not_vf` |
| The VF is not the pod's interface | `not_owned` |
| `--tc-ct-mode=require` without confirmed SMFS | `ct_offload_unavailable` |

Each fallback is logged once per VF and reason and counted in
`multinetworkpolicy_tc_backend_fallback_total{reason}`.

The annotation can be edited by anyone who may patch the pod, so the daemon
does not take the host-side device from it. The representor is derived from
the VF's PCI address through sysfs, and the VF has to be the netdev with the
annotated interface name **inside the pod's network namespace** (the daemon
asks the kernel there which device is behind it). A pod can therefore not
point the daemon at another pod's VF or at any other host netdev. The price:
a VF without a kernel netdev in the pod (bound to `vfio-pci` for a VM, for
example) cannot be confirmed and is not enforced by this backend. mlx5 VFs
used with DPDK keep their kernel netdev and are fine.

When an interface changes backend the daemon cleans up after the old one: tc
filters are removed from representors no pod is enforced on any more (pod
deleted, VF handed to another pod, fallback to nftables), and nftables rules
are flushed from a pod whose interfaces all moved to tc.

## How policies are translated

- Policy **ingress** (to the pod) is installed on the representor's clsact
  **egress** hook, policy **egress** on its **ingress** hook: the representor
  is the other end of the VF.
- Each rule expands to ports × peers. `ipBlock` becomes one accept per CIDR
  with a higher-priority drop per `except`; selector peers become one
  `/32` or `/128` accept per peer address on the policy's networks.
- Named ports resolve against the container ports of the pod that receives
  the traffic: the selected pod for ingress, each peer pod for egress (peers
  may give one name different numbers; `ipBlock` peers have no container
  ports). A named port that matches no container port allows nothing.
- A direction with at least one policy ends in a drop for IPv4 and one for
  IPv6. ARP is never matched.
- A rule set is never changed in place. Per direction, one filter in chain 0
  jumps to the chains holding the current rule set (chains 2/3 or 4/5). A
  changed rule set is built completely in the other pair of chains, the jump
  is replaced in one step, and then the old chains are emptied. Every packet
  is judged by one complete rule set, the old or the new one.
- Filters carry the tc action cookie `mnp-nftables`. The daemon only ever
  lists, replaces and deletes filters with that cookie.

## Limitations

- Offloaded enforcement is not validated on hardware yet, see
  [Validation](#validation).
- A VF without a kernel netdev in the pod is not enforced (see above).
- ICMPv6 is always accepted, not only neighbour discovery.
- Without conntrack there is no reply tracking; see `--tc-ct-mode` and default
  deny.
- A VF that falls back to nftables is not covered by `--tc-default-deny`.
- Do not run another tc flower manager with its own rules (for example OVS
  hardware offload) on the same representors: the daemon leaves foreign
  filters alone, but both would filter the same traffic.
- `require` needs the `devlink` binary, which the shipped image contains.

## Validation

What CI runs on every change, against the runner's kernel (`make
test-tc-kernel` runs the same locally; Linux, root, `netdevsim` and `act_ct`
modules):

| Test | Covers | Does not cover |
|------|--------|----------------|
| `TestSoftwareEnforcementE2E` | Real packets across a veth pair standing in for VF and representor: allow, deny, atomic policy change, re-apply is a no-op, flush. Software datapath (`skip_hw`). | Offload. |
| `TestSoftwareConntrackE2E` | The conntrack pipeline with `act_ct`: with ingress denied by default, replies to an allowed outgoing connection pass; without conntrack they are dropped. | CT offload (SMFS). |
| `TestNetdevsimSwitchdev` | A simulated switchdev NIC (netdevsim, 2 VFs): representor discovery from real `phys_switch_id` / `phys_port_name`, the netlink driver on real representor netdevs, direction mapping (which hook the filters land on), generation switch, default deny coming and going, a refused `skip_sw` insert leaving nothing half-installed, `FlushStale`. | netdevsim is not a PCI device (the `physfn`/`virtfn` links are a fixture), has no VF netdevs and passes no traffic through representors, and does not offload flower. |

Still open, and only checkable on a ConnectX-5 or newer in switchdev mode:

1. Start the daemon with `--enable-tc-backend` and check the `tcflower
   startup:` lines for the PF (switchdev, steering mode).
2. Start two pods with a VF each on the same network and a policy that allows
   one TCP port from the first to the second.
3. `tc -s filter show dev <representor> ingress` and `egress` on the second
   pod's representor: every filter of the daemon shows `in_hw`;
   `multinetworkpolicy_tc_filters_not_in_hw` is 0.
4. The allowed port connects, another port does not, and the packet counters
   of the matching filters increase. If allowed and denied look swapped
   between the directions, the direction mapping is wrong for this NIC.
5. Change the allowed port while a connection test loops: no packet of the
   old or the new allowed port is dropped during the change.
6. With `--tc-ct-mode=require` on SMFS and `--tc-default-deny=ingress`: the
   first pod still gets its replies; `conntrack -L` shows the connection
   as offloaded.
7. Delete the second pod: its representor has no filters of the daemon left.

## Metrics

All are prefixed `multinetworkpolicy_tc_` and exist only with the backend
enabled.

| Metric | Labels | Meaning |
|--------|--------|---------|
| `backend_fallback_total` | reason (`not_switchdev`, `not_found`, `not_vf`, `not_owned`, `ct_offload_unavailable`) | Candidate interfaces enforced by nftables instead, counted per reconcile. |
| `filters_installed` | representor, direction | Desired filters. |
| `filters_in_hw`, `filters_not_in_hw` | representor, direction | Offload state read back from the kernel. `not_in_hw > 0` in hardware mode means a filter is not enforced. |
| `filter_apply_errors_total` | representor, reason (`skip_sw`, `add`, `delete`) | Failed filter changes. `skip_sw`: the NIC refused to offload. |
| `representor_resolution_errors_total` | reason | An interface selected for tc could not be resolved at apply time. |
| `ct_offload_ready` | representor | 1 if the PF reports SMFS. |
| `ct_max_offloaded_conns` | representor | `ct_max_offloaded_conns` devlink parameter. |
| `reconcile_duration_seconds` | representor | Time to program one representor. |

## Debugging

```sh
# Is the VF on tc at all? Look for the fallback log line and its reason:
#   SR-IOV interface "net1" (pci=... representor=...) enforced by the nftables backend ... (reason=...)

# eSwitch mode, offload and steering mode of the PF:
devlink dev eswitch show pci/<pf>
ethtool -k <pf-netdev> | grep hw-tc-offload
devlink dev param show pci/<pf> name flow_steering_mode

# The daemon's filters on a representor (policy egress / policy ingress).
# Chain 0 holds one "goto chain" filter per direction; the rules are in the
# chains it points at.
tc -s filter show dev <representor> ingress
tc -s filter show dev <representor> egress
#   in_hw      offloaded to the eSwitch
#   not_in_hw  installed but not offloaded
```

If allow and deny look swapped between directions on real hardware, the
direction mapping above is the first thing to check
(`Direction.parentHandle` in `pkg/tcflower/engine.go`).
