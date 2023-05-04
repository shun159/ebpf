package ringbuf

import (
	"log"
	"syscall"
	"testing"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/internal"
	"github.com/cilium/ebpf/internal/testutils"
)

const filePath = "../testdata/user_ringbuf-e*.elf"

// testdata
type testData struct {
	data1 int8
	pad   [15]int8
}

var obj struct {
	Main        *ebpf.Program `ebpf:"test_user_ringbuf"`
	RingBuf     *ebpf.Map     `ebpf:"kernel_ringbuf"`
	UserRingBuf *ebpf.Map     `ebpf:"user_ringbuf"`
}

func TestUserRingBufWriter(t *testing.T) {
	testutils.SkipOnOldKernel(t, "6.1", "BPF user ring buffer")
	testutils.Files(t, testutils.Glob(t, filePath), func(t *testing.T, file string) {
		spec, err := ebpf.LoadCollectionSpec(file)
		if err != nil {
			t.Fatal(err)
		}

		if spec.ByteOrder != internal.NativeEndian {
			return
		}

		err = spec.LoadAndAssign(&obj, nil)
		testutils.SkipIfNotSupported(t, err)
		if err != nil {
			t.Fatalf("%v+", err)
		}
		defer func() {
			if err := obj.Main.Close(); err != nil {
				log.Printf("failed to close program: %v", err)
			}

			if err := obj.RingBuf.Close(); err != nil {
				log.Printf("failed to close ringbuf: %v", err)
			}

			if err := obj.UserRingBuf.Close(); err != nil {
				log.Printf("failed to close user ringbuf: %v", err)
			}
		}()

		kern_rd, err := NewReader(obj.RingBuf)
		if err != nil {
			t.Fatal(err)
		}
		defer kern_rd.Close()

		user_rd, err := NewWriter(obj.UserRingBuf)
		if err != nil {
			t.Fatal(err)
		}
		defer user_rd.Close()

		data := testData{1, [15]int8{}}
		if err := user_rd.Write(data); err != nil {
			t.Fatal(err)
		}

		ret, _, err := obj.Main.Test(internal.EmptyBPFContext)
		testutils.SkipIfNotSupported(t, err)
		if err != nil {
			t.Fatal(err)
		}

		if errno := syscall.Errno(-int32(ret)); errno != 0 {
			t.Fatal("Expected 0 as return value, got", errno)
		}

		resp, err := kern_rd.Read()
		if err != nil {
			t.Fatal("Can't read first sample:", err)
		}

		if resp.RawSample[0] != 2 {
			t.Fatalf("Expected ringbuf response should be 2, got %d", resp.RawSample[0])
		}
	})
}
