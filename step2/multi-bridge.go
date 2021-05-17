package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io/ioutil"
	"net"
	"os"
	"runtime"
	"strings"
	"syscall"
	"time"

	"github.com/j-keck/arping"
	"github.com/sirupsen/logrus"
	"github.com/vishvananda/netlink"

	"github.com/containernetworking/cni/pkg/skel"
	"github.com/containernetworking/cni/pkg/types"
	current "github.com/containernetworking/cni/pkg/types/current"
	"github.com/containernetworking/cni/pkg/version"
	"github.com/containernetworking/plugins/pkg/ip"
	"github.com/containernetworking/plugins/pkg/ipam"
	"github.com/containernetworking/plugins/pkg/ns"
	"github.com/containernetworking/plugins/pkg/utils"
	bv "github.com/containernetworking/plugins/pkg/utils/buildversion"
	"github.com/containernetworking/plugins/pkg/utils/sysctl"
	"github.com/containernetworking/plugins/plugins/ipam/host-local/backend/allocator"

	dockerclient "github.com/docker/docker/client"
)

var log = logrus.New()

var debugPostIPAMError error

type IPAM struct {
	Type   string      `json:"type,omitempty"`
	Subnet types.IPNet `json:"subnet"`
}

type Bridge struct {
	BrName       string `json:"bridge"`
	IsManNet     bool   `json:"isManagementNetwork"`
	IsGW         bool   `json:"isGateway"`
	IsDefaultGW  bool   `json:"isDefaultGateway"`
	ForceAddress bool   `json:"forceAddress"`
	IPMasq       bool   `json:"ipMasq"`
	MTU          int    `json:"mtu"`
	HairpinMode  bool   `json:"hairpinMode"`
	PromiscMode  bool   `json:"promiscMode"`
	Vlan         int    `json:"vlan"`
	IPAM         *IPAM  `json:"ipam,omitempty"`
	Table        int    `json:"table"`
	Priority     int    `json:"priority"`
}

type NetConf struct {
	types.NetConf
	EtcdHost string    `json:"etcd_host"`
	EtcdPort string    `json:"etcd_port"`
	Bridges  []*Bridge `json:"bridges"`
}

type gwInfo struct {
	gws               []net.IPNet
	family            int
	defaultRouteFound bool
}

func init() {
	// this ensures that main runs only on main thread (thread group leader).
	// since namespace ops (unshare, setns) are done for a single thread, we
	// must ensure that the goroutine does not jump from OS thread to thread
	runtime.LockOSThread()
}

func loadNetConf(bytes []byte) (*NetConf, error) {
	// defaultBrName cni0
	n := &NetConf{}

	if err := json.Unmarshal(bytes, n); err != nil {
		return nil, fmt.Errorf("failed to load netconf: %v", err)
	}

	var numOfMannet int = 0

	for _, bridge := range n.Bridges {
		if bridge.Vlan < 0 || bridge.Vlan > 4094 {
			return nil, fmt.Errorf("Bridge %s invalid VLAN ID %d (must be between 0 and 4094)", bridge.BrName, bridge.Vlan)
		}

		if bridge.IPAM.Type == "" {
			return nil, fmt.Errorf("IPAM for bridge %s is empty. This CNI only supports L3 mode.", bridge.BrName)
		}

		if bridge.IsManNet {
			numOfMannet++
		}
	}

	if numOfMannet != 1 {
		return nil, fmt.Errorf("current number of management network is %d. This CNI supports only one management network.", numOfMannet)
	}

	return n, nil
}

func ensureAddr(br netlink.Link, family int, ipn *net.IPNet, forceAddress bool) error {
	addrs, err := netlink.AddrList(br, family)
	if err != nil && err != syscall.ENOENT {
		return fmt.Errorf("could not get list of IP addresses: %v", err)
	}

	ipnStr := ipn.String()
	for _, a := range addrs {

		// string comp is actually easiest for doing IPNet comps
		if a.IPNet.String() == ipnStr {
			return nil
		}

		// Multiple IPv6 addresses are allowed on the bridge if the
		// corresponding subnets do not overlap. For IPv4 or for
		// overlapping IPv6 subnets, reconfigure the IP address if
		// forceAddress is true, otherwise throw an error.
		if family == netlink.FAMILY_V4 || a.IPNet.Contains(ipn.IP) || ipn.Contains(a.IPNet.IP) {
			if forceAddress {
				if err = deleteAddr(br, a.IPNet); err != nil {
					return err
				}
			} else {
				return fmt.Errorf("%q already has an IP address different from %v", br.Attrs().Name, ipnStr)
			}
		}
	}

	addr := &netlink.Addr{IPNet: ipn, Label: ""}
	if err := netlink.AddrAdd(br, addr); err != nil && err != syscall.EEXIST {
		return fmt.Errorf("could not add IP address to %q: %v", br.Attrs().Name, err)
	}

	// Set the bridge's MAC to itself. Otherwise, the bridge will take the
	// lowest-numbered mac on the bridge, and will change as ifs churn
	if err := netlink.LinkSetHardwareAddr(br, br.Attrs().HardwareAddr); err != nil {
		return fmt.Errorf("could not set bridge's mac: %v", err)
	}

	return nil
}

func deleteAddr(br netlink.Link, ipn *net.IPNet) error {
	addr := &netlink.Addr{IPNet: ipn, Label: ""}

	if err := netlink.AddrDel(br, addr); err != nil {
		return fmt.Errorf("could not remove IP address from %q: %v", br.Attrs().Name, err)
	}

	return nil
}

func bridgeByName(name string) (*netlink.Bridge, error) {
	l, err := netlink.LinkByName(name)
	if err != nil {
		return nil, fmt.Errorf("could not lookup %q: %v", name, err)
	}

	br, ok := l.(*netlink.Bridge)
	if !ok {
		return nil, fmt.Errorf("%q already exists but is not a bridge", name)
	}
	return br, nil
}

func ensureBridge(brName string, mtu int, promiscMode, vlanFiltering bool) (*netlink.Bridge, error) {
	br := &netlink.Bridge{
		LinkAttrs: netlink.LinkAttrs{
			Name: brName,
			MTU:  mtu,
			// Let kernel use default txqueuelen; leaving it unset
			// means 0, and a zero-length TX queue messes up FIFO
			// traffic shapers which use TX queue length as the
			// default packet limit
			TxQLen: -1,
		},
	}
	if vlanFiltering {
		br.VlanFiltering = &vlanFiltering
	}

	err := netlink.LinkAdd(br)
	if err != nil && err != syscall.EEXIST {
		return nil, fmt.Errorf("could not add %q: %v", brName, err)
	}

	if promiscMode {
		if err := netlink.SetPromiscOn(br); err != nil {
			return nil, fmt.Errorf("could not set promiscuous mode on %q: %v", brName, err)
		}
	}

	// Re-fetch link to read all attributes and if it already existed,
	// ensure it's really a bridge with similar configuration
	br, err = bridgeByName(brName)
	if err != nil {
		return nil, err
	}

	// we want to own the routes for this interface
	_, _ = sysctl.Sysctl(fmt.Sprintf("net/ipv6/conf/%s/accept_ra", brName), "0")

	if err := netlink.LinkSetUp(br); err != nil {
		return nil, err
	}

	return br, nil
}

func setupBridge(bridge *Bridge) (*netlink.Bridge, *current.Interface, error) {
	vlanFiltering := false
	if bridge.Vlan != 0 {
		vlanFiltering = true
	}
	// create bridge if necessary
	br, err := ensureBridge(bridge.BrName, bridge.MTU, bridge.PromiscMode, vlanFiltering)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to create bridge %q: %v", bridge.BrName, err)
	}

	return br, &current.Interface{
		Name: br.Attrs().Name,
		Mac:  br.Attrs().HardwareAddr.String(),
	}, nil
}

func ensureVlanInterface(br *netlink.Bridge, vlanId int) (netlink.Link, error) {
	name := fmt.Sprintf("%s.%d", br.Name, vlanId)

	brGatewayVeth, err := netlink.LinkByName(name)
	if err != nil {
		if err.Error() != "Link not found" {
			return nil, fmt.Errorf("failed to find interface %q: %v", name, err)
		}

		hostNS, err := ns.GetCurrentNS()
		if err != nil {
			return nil, fmt.Errorf("faild to find host namespace: %v", err)
		}

		_, brGatewayIface, err := setupVeth(hostNS, br, name, br.MTU, false, vlanId)
		if err != nil {
			return nil, fmt.Errorf("faild to create vlan gateway %q: %v", name, err)
		}

		brGatewayVeth, err = netlink.LinkByName(brGatewayIface.Name)
		if err != nil {
			return nil, fmt.Errorf("failed to lookup %q: %v", brGatewayIface.Name, err)
		}
	}

	return brGatewayVeth, nil
}

func setupVeth(netns ns.NetNS, br *netlink.Bridge, ifName string, mtu int, hairpinMode bool, vlanID int) (*current.Interface, *current.Interface, error) {
	contIface := &current.Interface{}
	hostIface := &current.Interface{}

	err := netns.Do(func(hostNS ns.NetNS) error {
		// create the veth pair in the container and move host end into host netns
		hostVeth, containerVeth, err := ip.SetupVeth(ifName, mtu, hostNS)
		if err != nil {
			return err
		}
		contIface.Name = containerVeth.Name
		contIface.Mac = containerVeth.HardwareAddr.String()
		contIface.Sandbox = netns.Path()
		hostIface.Name = hostVeth.Name
		return nil
	})
	if err != nil {
		return nil, nil, err
	}

	// need to lookup hostVeth again as its index has changed during ns move
	hostVeth, err := netlink.LinkByName(hostIface.Name)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to lookup %q: %v", hostIface.Name, err)
	}
	hostIface.Mac = hostVeth.Attrs().HardwareAddr.String()

	// connect host veth end to the bridge
	if err := netlink.LinkSetMaster(hostVeth, br); err != nil {
		return nil, nil, fmt.Errorf("failed to connect %q to bridge %v: %v", hostVeth.Attrs().Name, br.Attrs().Name, err)
	}

	// set hairpin mode
	if err = netlink.LinkSetHairpin(hostVeth, hairpinMode); err != nil {
		return nil, nil, fmt.Errorf("failed to setup hairpin mode for %v: %v", hostVeth.Attrs().Name, err)
	}

	if vlanID != 0 {
		err = netlink.BridgeVlanAdd(hostVeth, uint16(vlanID), true, true, false, true)
		if err != nil {
			return nil, nil, fmt.Errorf("failed to setup vlan tag on interface %q: %v", hostIface.Name, err)
		}
	}

	return hostIface, contIface, nil
}

func calcGatewayIP(ipn *net.IPNet) net.IP {
	nid := ipn.IP.Mask(ipn.Mask)
	return ip.NextIP(nid)
}

func calcGateways(result *current.Result, bridge *Bridge) (*gwInfo, *gwInfo, error) {

	gwsV4 := &gwInfo{}
	gwsV6 := &gwInfo{}

	for _, ipc := range result.IPs {

		// Determine if this config is IPv4 or IPv6
		var gws *gwInfo
		defaultNet := &net.IPNet{}
		switch {
		case ipc.Address.IP.To4() != nil:
			gws = gwsV4
			gws.family = netlink.FAMILY_V4
			defaultNet.IP = net.IPv4zero
		case len(ipc.Address.IP) == net.IPv6len:
			gws = gwsV6
			gws.family = netlink.FAMILY_V6
			defaultNet.IP = net.IPv6zero
		default:
			return nil, nil, fmt.Errorf("Unknown IP object: %v", ipc)
		}
		defaultNet.Mask = net.IPMask(defaultNet.IP)

		// All IPs currently refer to the container interface
		ipc.Interface = current.Int(2)

		// If not provided, calculate the gateway address corresponding
		// to the selected IP address
		if ipc.Gateway == nil && bridge.IsGW {
			ipc.Gateway = calcGatewayIP(&ipc.Address)
		}

		// Add a default route for this family using the current
		// gateway address if necessary.
		if bridge.IsDefaultGW && !gws.defaultRouteFound {
			for _, route := range result.Routes {
				if route.GW != nil && defaultNet.String() == route.Dst.String() {
					gws.defaultRouteFound = true
					break
				}
			}
			if !gws.defaultRouteFound {
				result.Routes = append(
					result.Routes,
					&types.Route{Dst: *defaultNet, GW: ipc.Gateway},
				)
				gws.defaultRouteFound = true
			}
		}

		// Append this gateway address to the list of gateways
		if bridge.IsGW {
			gw := net.IPNet{
				IP:   ipc.Gateway,
				Mask: ipc.Address.Mask,
			}
			gws.gws = append(gws.gws, gw)
		}
	}
	return gwsV4, gwsV6, nil
}

func disableIPV6DAD(ifName string) error {
	// ehanced_dad sends a nonce with the DAD packets, so that we can safely
	// ignore ourselves
	enh, err := ioutil.ReadFile(fmt.Sprintf("/proc/sys/net/ipv6/conf/%s/enhanced_dad", ifName))
	if err == nil && string(enh) == "1\n" {
		return nil
	}
	f := fmt.Sprintf("/proc/sys/net/ipv6/conf/%s/accept_dad", ifName)
	return ioutil.WriteFile(f, []byte("0"), 0644)
}

func enableIPForward(family int) error {
	if family == netlink.FAMILY_V4 {
		return ip.EnableIP4Forward()
	}
	return ip.EnableIP6Forward()
}

func addProcedure(args *skel.CmdArgs, n *NetConf, bridge *Bridge, ifName string) error {
	var success bool = false

	if bridge.IsDefaultGW {
		bridge.IsGW = true
	}

	if bridge.HairpinMode && bridge.PromiscMode {
		return fmt.Errorf("Bridge %s cannot set hairpin mode and promiscous mode at the same time.", bridge.BrName)
	}

	br, brInterface, err := setupBridge(bridge)
	if err != nil {
		return err
	}

	netns, err := ns.GetNS(args.Netns)
	if err != nil {
		return fmt.Errorf("failed to open netns %q: %v", args.Netns, err)
	}
	defer netns.Close()

	hostInterface, containerInterface, err := setupVeth(netns, br, ifName, bridge.MTU, bridge.HairpinMode, bridge.Vlan)
	if err != nil {
		return err
	}
	// Assume L2 interface only
	result := &current.Result{
		CNIVersion: current.ImplementedSpecVersion,
		Interfaces: []*current.Interface{
			brInterface,
			hostInterface,
			containerInterface,
		},
	}

	reqIPAM := allocator.Net{}
	reqIPAM.CNIVersion = n.CNIVersion
	reqIPAM.Name = n.Name

	IPAMConfig := allocator.IPAMConfig{}
	IPAMConfig.Type = bridge.IPAM.Type

	Range := allocator.Range{}
	Range.Subnet = bridge.IPAM.Subnet

	IPAMConfig.Range = &Range
	reqIPAM.IPAM = &IPAMConfig

	reqB, err := json.Marshal(reqIPAM)
	if err != nil {
		return err
	}

	// run the IPAM plugin and get back the config to apply
	r, err := ipam.ExecAdd(bridge.IPAM.Type, reqB)
	if err != nil {
		return err
	}

	// release IP in case of failure
	defer func() {
		if !success {
			ipam.ExecDel(bridge.IPAM.Type, reqB)
		}
	}()

	// Convert whatever the IPAM result was into the current Result type
	ipamResult, err := current.NewResultFromResult(r)
	if err != nil {
		return err
	}

	result.IPs = ipamResult.IPs
	result.Routes = ipamResult.Routes

	if len(result.IPs) == 0 {
		return errors.New("IPAM plugin returned missing IP config")
	}

	// Gather gateway information for each IP family
	gwsV4, gwsV6, err := calcGateways(result, bridge)
	if err != nil {
		return err
	}

	// Configure the container hardware address and IP address(es)
	if err := netns.Do(func(_ ns.NetNS) error {
		// Disable IPv6 DAD just in case hairpin mode is enabled on the
		// bridge. Hairpin mode causes echos of neighbor solicitation
		// packets, which causes DAD failures.
		for _, ipc := range result.IPs {
			if ipc.Address.IP.To4() == nil && (bridge.HairpinMode || bridge.PromiscMode) {
				if err := disableIPV6DAD(ifName); err != nil {
					return err
				}
				break
			}
		}

		// Add the IP to the interface
		if err := ipam.ConfigureIface(ifName, result, bridge.Table, bridge.Priority); err != nil {
			return err
		}
		return nil
	}); err != nil {
		return err
	}

	// check bridge port state
	retries := []int{0, 50, 500, 1000, 1000}
	for idx, sleep := range retries {
		time.Sleep(time.Duration(sleep) * time.Millisecond)

		hostVeth, err := netlink.LinkByName(hostInterface.Name)
		if err != nil {
			return err
		}
		if hostVeth.Attrs().OperState == netlink.OperUp {
			break
		}

		if idx == len(retries)-1 {
			return fmt.Errorf("bridge port in error state: %s", hostVeth.Attrs().OperState)
		}
	}

	// Send a gratuitous arp
	if err := netns.Do(func(_ ns.NetNS) error {
		contVeth, err := net.InterfaceByName(ifName)
		if err != nil {
			return err
		}

		for _, ipc := range result.IPs {
			if ipc.Address.IP.To4() != nil {
				_ = arping.GratuitousArpOverIface(ipc.Address.IP, *contVeth)
			}
		}
		return nil
	}); err != nil {
		return err
	}

	if bridge.IsGW {
		var firstV4Addr net.IP
		var vlanInterface *current.Interface
		// Set the IP address(es) on the bridge and enable forwarding
		for _, gws := range []*gwInfo{gwsV4, gwsV6} {
			for _, gw := range gws.gws {
				if gw.IP.To4() != nil && firstV4Addr == nil {
					firstV4Addr = gw.IP
				}
				if bridge.Vlan != 0 {
					vlanIface, err := ensureVlanInterface(br, bridge.Vlan)
					if err != nil {
						return fmt.Errorf("failed to create vlan interface: %v", err)
					}

					if vlanInterface == nil {
						vlanInterface = &current.Interface{Name: vlanIface.Attrs().Name,
							Mac: vlanIface.Attrs().HardwareAddr.String()}
						result.Interfaces = append(result.Interfaces, vlanInterface)
					}

					err = ensureAddr(vlanIface, gws.family, &gw, bridge.ForceAddress)
					if err != nil {
						return fmt.Errorf("failed to set vlan interface for bridge with addr: %v", err)
					}
				} else {
					err = ensureAddr(br, gws.family, &gw, bridge.ForceAddress)
					if err != nil {
						return fmt.Errorf("failed to set bridge addr: %v", err)
					}
				}
			}

			if gws.gws != nil {
				if err = enableIPForward(gws.family); err != nil {
					return fmt.Errorf("failed to enable forwarding: %v", err)
				}
			}
		}
	}

	if bridge.IPMasq {
		chain := utils.FormatChainName(bridge.BrName, args.ContainerID)
		comment := utils.FormatComment(bridge.BrName, args.ContainerID)
		for _, ipc := range result.IPs {
			if err = ip.SetupIPMasq(&ipc.Address, chain, comment); err != nil {
				return err
			}
		}
	}

	br, err = bridgeByName(bridge.BrName)
	if err != nil {
		return err
	}
	brInterface.Mac = br.Attrs().HardwareAddr.String()

	result.DNS = n.DNS

	// Return an error requested by testcases, if any
	if debugPostIPAMError != nil {
		return debugPostIPAMError
	}

	success = true

	return nil
}

func findInterface(slice []string, val string) (int, bool) {
	for i, item := range slice {
		if item == val {
			return i, true
		}
	}
	return -1, false
}

func cmdAdd(args *skel.CmdArgs) error {

	n, err := loadNetConf(args.StdinData)
	if err != nil {
		return err
	}

	ctx := context.Background()
	cli, errDocker := dockerclient.NewEnvClient()
	if errDocker != nil {
		return errDocker
	}

	containerJSON, dockerclienterr := cli.ContainerInspect(ctx, args.ContainerID)
	if dockerclienterr != nil {
		return fmt.Errorf("ContainerInspect error %v", dockerclienterr)
	}

	for key, val := range containerJSON.Config.Labels {
		log.WithFields(logrus.Fields{
			"key":   key,
			"value": val,
		}).Info("container labels")
	}

	ifs, foundOtherInterfaces := containerJSON.Config.Labels["annotation.multi-bridge.cni.kubernetes.io/dev"]

	var ifList []string

	if foundOtherInterfaces {
		ifList = strings.Split(ifs, ",")
	}

	for index, bridge := range n.Bridges {
		var ifName string = args.IfName

		if !bridge.IsManNet {
			ifName = fmt.Sprintf("net%d", index)

			_, foundInterface := findInterface(ifList, ifName)

			if !foundInterface {
				continue
			}
		}

		err = addProcedure(args, n, bridge, ifName)
		if err != nil {
			return err
		}
	}

	result := &current.Result{}
	return types.PrintResult(result, n.CNIVersion)
}

func cmdDel(args *skel.CmdArgs) error {
	n, err := loadNetConf(args.StdinData)
	if err != nil {
		return err
	}

	for index, bridge := range n.Bridges {

		reqIPAM := allocator.Net{}
		reqIPAM.CNIVersion = n.CNIVersion
		reqIPAM.Name = n.Name

		IPAMConfig := allocator.IPAMConfig{}
		IPAMConfig.Type = bridge.IPAM.Type

		Range := allocator.Range{}
		Range.Subnet = bridge.IPAM.Subnet

		IPAMConfig.Range = &Range
		reqIPAM.IPAM = &IPAMConfig

		reqB, err := json.Marshal(reqIPAM)
		if err != nil {
			return err
		}

		if err := ipam.ExecDel(bridge.IPAM.Type, reqB); err != nil {
			return err
		}

		if args.Netns == "" {
			return nil
		}

		var ifName string = args.IfName

		if !bridge.IsManNet {
			ifName = fmt.Sprintf("net%d", index)
		}

		// There is a netns so try to clean up. Delete can be called multiple times
		// so don't return an error if the device is already removed.
		// If the device isn't there then don't try to clean up IP masq either.
		var ipnets []*net.IPNet
		err = ns.WithNetNSPath(args.Netns, func(_ ns.NetNS) error {
			var err error
			ipnets, err = ip.DelLinkByNameAddr(ifName)
			if err != nil && err == ip.ErrLinkNotFound {
				return nil
			}
			return err
		})

		if err != nil {
			return err
		}

		if bridge.IPMasq {
			chain := utils.FormatChainName(bridge.BrName, args.ContainerID)
			comment := utils.FormatComment(bridge.BrName, args.ContainerID)
			for _, ipn := range ipnets {
				if err := ip.TeardownIPMasq(ipn, chain, comment); err != nil {
					return err
				}
			}
		}
	}

	return err
}

func main() {
	file, err := os.OpenFile("/var/log/multi-bridge.log", os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0666)
	if err == nil {
		log.Out = file
		defer file.Close()
	} else {
		log.Info("Failed to log to file, using default stderr")
	}

	skel.PluginMain(cmdAdd, cmdCheck, cmdDel, version.All, bv.BuildString("multi-bridge"))
}

func cmdCheck(args *skel.CmdArgs) error {
	return nil
}
