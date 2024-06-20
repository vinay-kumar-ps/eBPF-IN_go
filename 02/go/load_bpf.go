package main

import (
	"fmt"
	"log"
	"net"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/rlimit"
)

const (
	bpfObjectFile = "filter_traffic.o"
)

func main() {
	// Allow the current process to lock memory for eBPF resources.
	if err := rlimit.RemoveMemlock(); err != nil {
		log.Fatalf("Failed to remove memory lock limit: %v", err)
	}

	spec, err := ebpf.LoadCollectionSpec(bpfObjectFile)
	if err != nil {
		log.Fatalf("Failed to load BPF object: %v", err)
	}

	objs := struct {
		XdpFilterTraffic *ebpf.Program `ebpf:"xdp_filter_traffic"`
		ProcessMap       *ebpf.Map     `ebpf:"process_map"`
	}{}
	if err := spec.LoadAndAssign(&objs, nil); err != nil {
		log.Fatalf("Failed to load and assign BPF object: %v", err)
	}
	defer objs.ProcessMap.Close()
	defer objs.XdpFilterTraffic.Close()

	iface := "wlo1" // Replace with your actual network interface name

	ifaceIndex, err := net.InterfaceByName(iface)
	if err != nil {
		log.Fatalf("Could not find interface %q: %v", iface, err)
	}

	xdpLink, err := link.AttachXDP(link.XDPOptions{
		Program:   objs.XdpFilterTraffic,
		Interface: ifaceIndex.Index,
	})
	if err != nil {
		log.Fatalf("Could not attach XDP program: %v", err)
	}
	defer xdpLink.Close()

	fmt.Printf("Successfully loaded BPF program on interface %s\n", iface)
	select {}
}
