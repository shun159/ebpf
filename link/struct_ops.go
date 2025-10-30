package link

import (
	"fmt"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/internal/sys"
)

type structOpsLink struct {
	*RawLink
}

// AttachStructOps links a StructOps map
func AttachStructOps(m *ebpf.Map) (Link, error) {
	if m == nil {
		return nil, fmt.Errorf("map cannot be nil: %w", errInvalidInput)
	}

	if t := m.Type(); t != ebpf.StructOpsMap {
		return nil, fmt.Errorf("invalid map type %s, expected struct_ops: %w", t, errInvalidInput)
	}

	mapFD := m.FD()
	if mapFD <= 0 {
		return nil, fmt.Errorf("invalid map: %s (was it created?)", sys.ErrClosedFd)
	}

	if (int(m.Flags()) & sys.BPF_F_LINK) != sys.BPF_F_LINK {
		return nil, fmt.Errorf("invalid map: BPF_F_LINK is required: %w", ErrNotSupported)
	}

	fd, err := sys.LinkCreate(&sys.LinkCreateAttr{
		ProgFd:     uint32(mapFD),
		AttachType: sys.AttachType(ebpf.AttachStructOps),
		TargetFd:   0,
	})
	if err != nil {
		return nil, fmt.Errorf("attach StructOps: create link: %w", err)
	}

	return &structOpsLink{&RawLink{fd: fd}}, nil
}
