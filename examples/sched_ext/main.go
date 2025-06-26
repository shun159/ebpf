package main

// This program demonstrates attaching an eBPF program to sched_ext

import (
	"log"
	"os"
	"os/signal"
	"syscall"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/rlimit"
)

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -tags linux bpf sched.c -- -I../headers

func main() {
	if err := rlimit.RemoveMemlock(); err != nil {
		log.Fatal(err)
	}

	objs := bpfObjects{}
	if err := loadBpfObjects(&objs, nil); err != nil {
		log.Fatalf("loading objects: %v", err)
	}
	defer objs.Close()

	m := objs.NullSched
	l, err := link.AttachRawLink(link.RawLinkOptions{
		ProgramFd: m.FD(),
		Attach:    ebpf.AttachStructOps,
	})
	if err != nil {
		log.Fatalf("Failed to attach sched_ext: %s", err)
	}
	defer l.Close()

	log.Println("Successfully attached sched_ext struct operations")

	stopper := make(chan os.Signal, 1)
	signal.Notify(stopper, os.Interrupt, syscall.SIGTERM)
	log.Print("Press Ctrl+C to stop...")
	<-stopper
}
