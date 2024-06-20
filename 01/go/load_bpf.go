package main

import (
    "fmt"
    "log"
    "net"
    "os"
    "strconv"

    "github.com/cilium/ebpf"
    "github.com/cilium/ebpf/link"
    "github.com/cilium/ebpf/rlimit"
)

const (
    bpfObjectFile = "drop_port.o"
    mapName       = "port_map"
)

func main() {
    if len(os.Args) != 2 {
        log.Fatalf("Usage: %s <port>", os.Args[0])
    }

    port, err := strconv.ParseUint(os.Args[1], 10, 16)
    if err != nil {
        log.Fatalf("Invalid port number: %s", os.Args[1])
    }

    // Allow the current process to lock memory for eBPF resources.
    if err := rlimit.RemoveMemlock(); err != nil {
        log.Fatalf("Failed to remove memory lock limit: %v", err)
    }

    spec, err := ebpf.LoadCollectionSpec(bpfObjectFile)
    if err != nil {
        log.Fatalf("Failed to load BPF object: %v", err)
    }

    objs := struct {
        XdpDropTcpPort *ebpf.Program `ebpf:"xdp_drop_tcp_port"`
        PortMap        *ebpf.Map     `ebpf:"port_map"`
    }{}
    if err := spec.LoadAndAssign(&objs, nil); err != nil {
        log.Fatalf("Failed to load and assign BPF object: %v", err)
    }
    defer objs.PortMap.Close()
    defer objs.XdpDropTcpPort.Close()

    if err := objs.PortMap.Put(uint32(0), uint16(port)); err != nil {
        log.Fatalf("Failed to update port map: %v", err)
    }

    iface := "wlo1" // Hardcoded interface name

    ifaceIndex, err := net.InterfaceByName(iface)
    if err != nil {
        log.Fatalf("Could not find interface %q: %v", iface, err)
    }

    xdpLink, err := link.AttachXDP(link.XDPOptions{
        Program:   objs.XdpDropTcpPort,
        Interface: ifaceIndex.Index,
    })
    if err != nil {
        log.Fatalf("Could not attach XDP program: %v", err)
    }
    defer xdpLink.Close()

    fmt.Printf("Successfully loaded BPF program and set port to %d on interface %s\n", port, iface)
    select {}
}
