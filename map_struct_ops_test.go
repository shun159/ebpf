package ebpf

import (
	"bytes"
	"errors"
	"testing"

	"github.com/cilium/ebpf/btf"
	"github.com/cilium/ebpf/internal/unix"
)

// this is a minimum smake testing
func TestStructOpsMapCreate(t *testing.T) {
	spec, err := NewStructOpsMapSpec("dummy_ops", "bpf_dummy_ops")
	if err != nil {
		t.Skipf("struct_ops not available: %v", err)
	}

	m, err := NewMap(spec)
	if err != nil {
		switch {
		case errors.Is(err, unix.EINVAL):
			t.Fatalf("unexpected EINVAL (key_size?) : %v", err)
		default:
			t.Fatalf("unexpected error: %v", err)
		}
		return
	}
	defer m.Close()
}

func TestExtendType(t *testing.T) {
	/*
	   user: struct { a int32; b uint8; }
	   kern: struct { pad uint8; b uint8; a int32; }
	*/
	var (
		int32T = &btf.Int{Size: 4}
		u8T    = &btf.Int{Size: 1}
	)

	user := &btf.Struct{
		Name: "user",
		Members: []btf.Member{
			{Name: "a", Type: int32T, Offset: 0},
			{Name: "b", Type: u8T, Offset: 32},
		},
		Size: 5,
	}
	kern := &btf.Struct{
		Name: "kern",
		Members: []btf.Member{
			{Name: "pad", Type: u8T, Offset: 0},
			{Name: "b", Type: u8T, Offset: 8},
			{Name: "a", Type: int32T, Offset: 16},
		},
		Size: 8,
	}

	src := []byte{1, 0, 0, 0, 2} // a=1, b=2
	out, err := extendType(src, user, kern)
	if err != nil {
		t.Fatal(err)
	}

	want := []byte{0, 2, 1, 0, 0, 0, 0, 0}
	if !bytes.Equal(out, want) {
		t.Fatalf("got %v, want %v", out, want)
	}
}
