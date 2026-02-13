// Package transform converts netmodel YAML format to OpenConfig JSON format
package transform

// ToOpenConfig transforms netmodel YAML data to OpenConfig structure
func ToOpenConfig(feature string, data interface{}) (interface{}, error) {
	switch feature {
	case "interfaces":
		return transformInterfaces(data)
	case "bgp":
		return transformBGP(data)
	case "system":
		return transformSystem(data)
	case "routing_policy":
		return transformRoutingPolicy(data)
	case "evpn":
		return transformEVPN(data)
	default:
		// Pass through as-is
		return data, nil
	}
}

// transformInterfaces converts:
//   interfaces:
//     Ethernet1:
//       description: foo
// to:
//   interface:
//     - name: Ethernet1
//       config:
//         description: foo
func transformInterfaces(data interface{}) (interface{}, error) {
	ifaceMap, ok := data.(map[string]interface{})
	if !ok {
		return data, nil
	}

	var interfaces []map[string]interface{}

	for name, ifaceData := range ifaceMap {
		iface := make(map[string]interface{})
		iface["name"] = name

		ifaceConfig, ok := ifaceData.(map[string]interface{})
		if !ok {
			continue
		}

		config := make(map[string]interface{})
		config["name"] = name

		// Map common fields to config
		if desc, ok := ifaceConfig["description"]; ok {
			config["description"] = desc
		}
		if mtu, ok := ifaceConfig["mtu"]; ok {
			config["mtu"] = mtu
		}
		if ifType, ok := ifaceConfig["type"]; ok {
			config["type"] = "iana-if-type:" + ifType.(string)
		}
		if enabled, ok := ifaceConfig["enabled"]; ok {
			config["enabled"] = enabled
		}

		iface["config"] = config

		// Handle subinterfaces with IPv4
		if ipv4, ok := ifaceConfig["ipv4"]; ok {
			iface["subinterfaces"] = map[string]interface{}{
				"subinterface": []map[string]interface{}{
					{
						"index": 0,
						"openconfig-if-ip:ipv4": transformIPv4(ipv4),
					},
				},
			}
		}

		// Handle ethernet config
		if eth, ok := ifaceConfig["ethernet"]; ok {
			iface["openconfig-if-ethernet:ethernet"] = transformEthernet(eth)
		}

		interfaces = append(interfaces, iface)
	}

	return map[string]interface{}{
		"interface": interfaces,
	}, nil
}

func transformIPv4(data interface{}) map[string]interface{} {
	ipv4Map, ok := data.(map[string]interface{})
	if !ok {
		return nil
	}

	result := make(map[string]interface{})

	if addrs, ok := ipv4Map["addresses"]; ok {
		addrList, ok := addrs.([]interface{})
		if ok {
			var addresses []map[string]interface{}
			for _, a := range addrList {
				addr, ok := a.(map[string]interface{})
				if !ok {
					continue
				}
				ip, _ := addr["ip"].(string)
				prefixLen, _ := addr["prefix_length"].(int)

				addresses = append(addresses, map[string]interface{}{
					"ip": ip,
					"config": map[string]interface{}{
						"ip":            ip,
						"prefix-length": prefixLen,
					},
				})
			}
			result["addresses"] = map[string]interface{}{
				"address": addresses,
			}
		}
	}

	return result
}

func transformEthernet(data interface{}) map[string]interface{} {
	ethMap, ok := data.(map[string]interface{})
	if !ok {
		return nil
	}

	config := make(map[string]interface{})

	if speed, ok := ethMap["port_speed"]; ok {
		config["port-speed"] = "openconfig-if-ethernet:" + speed.(string)
	}
	if mac, ok := ethMap["mac_address"]; ok {
		config["mac-address"] = mac
	}

	return map[string]interface{}{
		"config": config,
	}
}

func transformBGP(data interface{}) (interface{}, error) {
	bgpMap, ok := data.(map[string]interface{})
	if !ok {
		return data, nil
	}

	result := make(map[string]interface{})

	// Transform global
	if global, ok := bgpMap["global"]; ok {
		result["global"] = transformBGPGlobal(global)
	}

	// Transform peer groups
	if peerGroups, ok := bgpMap["peer_groups"]; ok {
		result["peer-groups"] = transformPeerGroups(peerGroups)
	}

	// Transform neighbors
	if neighbors, ok := bgpMap["neighbors"]; ok {
		result["neighbors"] = transformNeighbors(neighbors)
	}

	return result, nil
}

func transformBGPGlobal(data interface{}) map[string]interface{} {
	globalMap, ok := data.(map[string]interface{})
	if !ok {
		return nil
	}

	config := make(map[string]interface{})

	if asn, ok := globalMap["as"]; ok {
		config["as"] = asn
	}
	if routerId, ok := globalMap["router_id"]; ok {
		config["router-id"] = routerId
	}

	return map[string]interface{}{
		"config": config,
	}
}

func transformPeerGroups(data interface{}) map[string]interface{} {
	pgMap, ok := data.(map[string]interface{})
	if !ok {
		return nil
	}

	var groups []map[string]interface{}
	for name, pgData := range pgMap {
		pg := make(map[string]interface{})
		pg["peer-group-name"] = name

		pgConfig, ok := pgData.(map[string]interface{})
		if !ok {
			continue
		}

		config := map[string]interface{}{
			"peer-group-name": name,
		}
		if peerAs, ok := pgConfig["peer_as"]; ok {
			config["peer-as"] = peerAs
		}

		pg["config"] = config

		// AFI-SAFI
		if afiSafis, ok := pgConfig["afi_safis"]; ok {
			pg["afi-safis"] = transformAfiSafis(afiSafis)
		}

		groups = append(groups, pg)
	}

	return map[string]interface{}{
		"peer-group": groups,
	}
}

func transformNeighbors(data interface{}) map[string]interface{} {
	nbrMap, ok := data.(map[string]interface{})
	if !ok {
		return nil
	}

	var neighbors []map[string]interface{}
	for addr, nbrData := range nbrMap {
		nbr := make(map[string]interface{})
		nbr["neighbor-address"] = addr

		nbrConfig, ok := nbrData.(map[string]interface{})
		if !ok {
			continue
		}

		config := map[string]interface{}{
			"neighbor-address": addr,
		}
		if peerAs, ok := nbrConfig["peer_as"]; ok {
			config["peer-as"] = peerAs
		}
		if peerGroup, ok := nbrConfig["peer_group"]; ok {
			config["peer-group"] = peerGroup
		}
		if desc, ok := nbrConfig["description"]; ok {
			config["description"] = desc
		}

		nbr["config"] = config

		// AFI-SAFI
		if afiSafis, ok := nbrConfig["afi_safis"]; ok {
			nbr["afi-safis"] = transformAfiSafis(afiSafis)
		}

		neighbors = append(neighbors, nbr)
	}

	return map[string]interface{}{
		"neighbor": neighbors,
	}
}

func transformAfiSafis(data interface{}) map[string]interface{} {
	afiList, ok := data.([]interface{})
	if !ok {
		return nil
	}

	var safis []map[string]interface{}
	for _, afi := range afiList {
		afiMap, ok := afi.(map[string]interface{})
		if !ok {
			continue
		}

		safi := make(map[string]interface{})
		if name, ok := afiMap["afi_safi_name"]; ok {
			safi["afi-safi-name"] = "openconfig-bgp-types:" + name.(string)
			safi["config"] = map[string]interface{}{
				"afi-safi-name": "openconfig-bgp-types:" + name.(string),
				"enabled":       true,
			}
		}
		safis = append(safis, safi)
	}

	return map[string]interface{}{
		"afi-safi": safis,
	}
}

func transformSystem(data interface{}) (interface{}, error) {
	sysMap, ok := data.(map[string]interface{})
	if !ok {
		return data, nil
	}

	result := make(map[string]interface{})

	// Hostname goes in config
	if hostname, ok := sysMap["hostname"]; ok {
		result["config"] = map[string]interface{}{
			"hostname": hostname,
		}
	}

	return result, nil
}

func transformRoutingPolicy(data interface{}) (interface{}, error) {
	// Pass through for now - needs more work
	return data, nil
}

func transformEVPN(data interface{}) (interface{}, error) {
	// Pass through for now - needs more work
	return data, nil
}
