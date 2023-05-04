package ringbuf

import (
	"errors"
	"fmt"
	"os"
	"sync"
	"unsafe"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/internal/epoll"
	"github.com/cilium/ebpf/internal/unix"
)

// 8-byte ring buffer header structure
type userRingbufHeader struct {
	Len uint32
	Pad uint32
}

type Writer struct {
	poller *epoll.Poller

	mutex sync.Mutex
	ring  *userRingbufEventRing
}

// NewWriter creates a new BPF user ringbuf writer.
func NewWriter(rbuf *ebpf.Map) (*Writer, error) {
	if rbuf.Type() != ebpf.UserRingBuf {
		return nil, fmt.Errorf("invalid Map type;: %s", rbuf.Type())
	}

	mapFd := rbuf.FD()
	maxEntries := int(rbuf.MaxEntries())
	if (maxEntries & (maxEntries - 1)) != 0 {
		return nil, fmt.Errorf("user ringbuffer map size %d is not a power of two", maxEntries)
	}

	poller, err := epoll.New()
	if err != nil {
		return nil, err
	}

	if err := poller.AddwithEvents(mapFd, 0, unix.EPOLLOUT); err != nil {
		poller.Close()
		return nil, err
	}

	ring, err := newUserRingbufEventRing(mapFd, maxEntries)
	if err != nil {
		poller.Close()
		return nil, fmt.Errorf("failed to create user ringbuf ring: %w", err)
	}

	return &Writer{
		poller: poller,
		mutex:  sync.Mutex{},
		ring:   ring,
	}, nil
}

func (w *Writer) Close() error {
	if err := w.poller.Close(); err != nil {
		if errors.Is(err, os.ErrClosed) {
			return nil
		}
		return err
	}

	w.mutex.Lock()
	defer w.mutex.Unlock()

	if w.ring != nil {
		w.ring.Close()
		w.ring = nil
	}

	return nil
}

func (w *Writer) Write(data interface{}) error {
	w.mutex.Lock()
	defer w.mutex.Unlock()

	data_size := unsafe.Sizeof(data)
	buf, err := ebpf.MarshalBytes(data, int(data_size))
	if err != nil {
		return fmt.Errorf("user ringbuf write marshal data: %w", err)
	}

	sample, err := w.ring.reserve(uint32(data_size))
	if err != nil {
		return fmt.Errorf("user ringbuf write reserve memory: %w", err)
	}

	copy(sample, buf)
	w.ring.commit(sample, false)

	return nil
}
