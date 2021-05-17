package main

import (
	"fmt"
	"net"

	"github.com/vishvananda/netlink"
)

func main() {
	ifName := "net1"
	//addr := "10.240.0.2/32"
	gateway := "10.240.10.1"

	link, err := netlink.LinkByName(ifName)
	if err != nil {
		fmt.Errorf("failed to loopup %q: %v", ifName, err)
	}

	/*
	 *_, ipv4Net, err := net.ParseCIDR(addr)
	 *if err != nil {
	 *  fmt.Errorf("failed to parse %q: %v", addr, err)
	 *}
	 */

	gw := net.ParseIP(gateway)
	if gw == nil {
		fmt.Errorf("failed to parse %q", gateway)
	}

	route := netlink.Route{
		Dst:       nil,
		LinkIndex: link.Attrs().Index,
		Gw:        gw,
		Table:     1,
	}

	if err = netlink.RouteAdd(&route); err != nil {
		fmt.Errorf("failed to add route '%v via %v dev %v': %v", nil, gw, ifName, err)
	}

	srcNet := &net.IPNet{IP: net.IPv4(10, 240, 10, 2), Mask: net.CIDRMask(32, 32)}

	r := netlink.NewRule()
	r.Src = srcNet
	r.Table = 1
	r.Priority = 100

	fmt.Println(srcNet)
	fmt.Println(r)

	if err = netlink.RuleAdd(r); err != nil {
		fmt.Errorf("failed to add rule `from %v table %v': %v", srcNet, 1, err)
	}

}
