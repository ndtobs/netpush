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
# Sync all devices using inventory (recommended)
netpush sync ./ -i inventory.yaml

# Sync specific group
netpush sync ./ -i inventory.yaml --group leaf

# Sync single device
netpush sync ./host_vars/leaf1/ -t leaf1:6030 -u admin -P admin -k

# Preview changes (dry run)
netpush sync ./ -i inventory.yaml --dry-run

# Delete config from group
netpush delete ./remove-peer.yaml -i inventory.yaml --group leaf
```

## Operations

| Command | gNMI Operation | Behavior |
|---------|----------------|----------|
| `sync` | GET + SET | **Recommended** - diff and apply minimal changes |
| `apply` | SET Update | Merge config with existing |
| `apply --replace` | SET Replace | Replace entire subtree |
| `delete` | SET Delete | Remove config |
| `diff` | GET + compare | Show what would change |

### sync (recommended)

The safest way to apply config. Computes minimal changes:

```bash
# Preview what would change
netpush sync ./host_vars/leaf1/bgp.yaml -t leaf1:6030 --dry-run -u admin -P admin -k

# Apply minimal changes
netpush sync ./host_vars/leaf1/bgp.yaml -t leaf1:6030 -u admin -P admin -k
```

- Adds config in YAML but not on device
- Updates config that differs
- Deletes config on device but not in YAML
- **Does not touch unchanged config**

## The OpenConfig Ecosystem

```
┌─────────────────────────────────────────────────────────────┐
│                        YAML Data Model                       │
│              (OpenConfig-based, vendor-agnostic)             │
└─────────────────────────────────────────────────────────────┘
        ↑                      ↓                      ↑
   gNMI GET              gNMI SET                gNMI GET
        │                      │                      │
┌───────┴───────┐    ┌────────┴────────┐    ┌────────┴───────┐
│   netmodel    │    │    netpush      │    │    netsert     │
│    export     │    │     apply       │    │      run       │
│  (read config)│    │ (write config)  │    │   (validate)   │
└───────────────┘    └─────────────────┘    └────────────────┘
```

## Full Workflow

```bash
# 1. Extract current config
netmodel export @all -i inventory.yaml -o ./ --structure ansible --dedup

# 2. Edit the YAML (add a BGP neighbor, change NTP, etc.)
vim host_vars/leaf1/bgp.yaml

# 3. Preview changes
netpush diff ./host_vars/leaf1/bgp.yaml -t leaf1:6030 -u admin -P admin -k

# 4. Apply changes
netpush apply ./host_vars/leaf1/bgp.yaml -t leaf1:6030 -u admin -P admin -k

# 5. Validate
netsert run assertions.yaml -i inventory.yaml
```

## Why gNMI?

- **Fast** — No SSH overhead, binary protocol
- **Atomic** — All-or-nothing transactions
- **Streaming** — Subscribe to config changes
- **Standard** — OpenConfig paths work across vendors
- **Modern** — Built for automation from the start

## Supported Features

| Feature | OpenConfig Path |
|---------|-----------------|
| `interfaces` | `/interfaces` |
| `bgp` | `/network-instances/network-instance/protocols/protocol/bgp` |
| `ospf` | `/network-instances/network-instance/protocols/protocol/ospfv2` |
| `system` | `/system` |
| `routing_policy` | `/routing-policy` |
| `evpn` | `/network-instances/network-instance/evpn` |

## Related

- **[netmodel](https://github.com/ndtobs/netmodel)** — Extract network config to YAML
- **[netsert](https://github.com/ndtobs/netsert)** — Validate network state
- **[netgen](https://github.com/ndtobs/netgen)** — Generate Ansible roles (SSH alternative)

## License

MIT
