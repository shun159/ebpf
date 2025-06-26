package link

import (
	"testing"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/internal/testutils"
)

func TestLoadSimpleStructOps(t *testing.T) {
	file := testutils.NativeFile(t, "../testdata/struct_ops-%s.elf")
	spec, err := ebpf.LoadCollectionSpec(file)
	if err != nil {
		t.Fatal(err)
	}

	var obj struct {
		DummyTest1 *ebpf.Program `ebpf:"dummy_test_1"`
		DummyOps   *ebpf.Map     `ebpf:"dummy_ops"`
	}

	err = spec.LoadAndAssign(&obj, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer obj.DummyOps.Close()

	ln, err := AttachRawLink(RawLinkOptions{
		ProgramFd: obj.DummyOps.FD(),
		Attach:    ebpf.AttachStructOps,
	})

	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
}

func TestLoadBadStructOps(t *testing.T) {
	file := testutils.NativeFile(t, "../testdata/struct_ops_bad-%s.elf")
	spec, err := ebpf.LoadCollectionSpec(file)
	if err != nil {
		t.Fatal(err)
	}

	var obj struct {
		DummyTest1 *ebpf.Program `ebpf:"dummy_test_1"`
		DummyTest2 *ebpf.Program `ebpf:"dummy_test_2"`
		DummyOps1  *ebpf.Map     `ebpf:"dummy_ops_1"`
		DummyOps2  *ebpf.Map     `ebpf:"dummy_ops_2"`
	}

	// This should be failed
	err = spec.LoadAndAssign(&obj, nil)
	if err == nil {
		t.Fatal(err)
	}
}
