# netpush

Push network config via gNMI from netmodel YAML — OpenConfig-native config deployment.

```
YAML (netmodel output) → netpush apply → gNMI SET → Device
```

## Install

```bash
go install github.com/ndtobs/netpush/cmd/netpush@latest
```

## Quick Start

```bash
# Preview changes (diff)
netpush diff ./ -i inventory.yaml

# Apply config to all devices
netpush apply ./ -i inventory.yaml

# Apply to specific group
netpush apply ./ -i inventory.yaml -g leaf

# Apply to single device
netpush apply ./host_vars/leaf1/ -t leaf1:6030 -u admin -P admin -k

# Delete specific paths
netpush delete -p "interface[Loopback99]" -i inventory.yaml
```

## Commands

| Command | gNMI Op | Description |
|---------|---------|-------------|
| `diff` | GET | Compare YAML to device, show what would change |
| `apply` | SET Update | Merge config (additive, safe) |
| `delete -p` | SET Delete | Remove specific paths |

### diff

Shows what `apply` would change:

```bash
$ netpush diff ./ -i inventory.yaml

=== spine1 ===
✓ Already in sync

=== leaf1 ===
+ interface Loopback99 (new)
~ interface Ethernet1:
    description: "old" → "new"
- interface Vlan999 (not in model)
```

Output:
- `+` = would be added (in model, not on device)
- `~` = would be changed (different values)
- `-` = not in model (on device only, informational)
- `✓` = in sync

### apply

Merges config via gNMI Update (additive, never removes):

```bash
# Preview first
netpush apply ./ -i inventory.yaml --dry-run

# Apply
netpush apply ./ -i inventory.yaml
```

### delete

Surgically removes specific paths:

```bash
# Delete an interface
netpush delete -p "interface[Loopback99]" -t leaf1:6030 -u admin -P admin -k

# Delete multiple paths
netpush delete -p "interface[Vlan10]" -p "interface[Vlan20]" -i inventory.yaml

# Short path syntax supported
netpush delete -p "bgp[default]/neighbors/neighbor[10.0.0.5]" ...
```

## The OpenConfig Ecosystem

```
netmodel (gNMI GET) → YAML ←→ netpush (gNMI SET)
                        ↑
                    netsert (validate)
```

All three tools use the same:
- OpenConfig paths
- Inventory format
- YAML data model

## Full Workflow

```bash
# 1. Extract current config
netmodel export @all -i inventory.yaml -s ansible --dedup -o ./

# 2. Edit the YAML
vim host_vars/leaf1/bgp.yaml

# 3. Preview changes
netpush diff ./ -i inventory.yaml

# 4. Apply changes
netpush apply ./ -i inventory.yaml

# 5. Validate
netsert run assertions.yaml -i inventory.yaml
```

## Inventory Format

Same format as netmodel/netsert:

```yaml
defaults:
  username: admin
  password: admin
  port: 6030
  insecure: true

groups:
  spine: [spine1, spine2]
  leaf: [leaf1, leaf2]
  all: [spine1, spine2, leaf1, leaf2]

hosts:
  spine1:
    address: 192.168.1.1
  leaf1:
    address: 192.168.1.11
```

## Directory Structure

Works with Ansible-style layout from `netmodel --structure ansible --dedup`:

```
model/
├── group_vars/
│   ├── all.yaml        # Common config (NTP, AAA, policies)
│   ├── spine.yaml      # Spine-specific (peer-groups)
│   └── leaf.yaml       # Leaf-specific (EVPN peer-groups)
├── host_vars/
│   ├── spine1/
│   │   ├── interfaces.yaml
│   │   └── bgp.yaml
│   └── leaf1/
│       ├── interfaces.yaml
│       └── bgp.yaml
└── inventory.yaml
```

netpush deep-merges `group_vars/all.yaml` + `group_vars/<group>.yaml` + `host_vars/<host>/` in order.

## Supported Features

| Feature | OpenConfig Path |
|---------|-----------------|
| `interfaces` | `/interfaces` |
| `bgp` | `/network-instances/.../bgp` |
| `system` | `/system` |
| `routing_policy` | `/routing-policy` |
| `evpn` | `/network-instances/.../evpn` |

## Related Tools

- **[netmodel](https://github.com/ndtobs/netmodel)** — Extract config to YAML (gNMI GET)
- **[netsert](https://github.com/ndtobs/netsert)** — Validate network state (gNMI GET + assertions)

## License

MIT
