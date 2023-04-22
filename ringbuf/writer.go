package ringbuf

import (
	"errors"
	"fmt"
	"os"
	"sync"
	"sync/atomic"
	"time"
	"unsafe"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/internal/epoll"
	"github.com/cilium/ebpf/internal/unix"
)

type userRingbufHeader struct {
	Len uint32
	Pad uint32
}

func (rh *userRingbufHeader) isBusy() bool {
	return rh.Len&unix.BPF_RINGBUF_BUSY_BIT != 0
}

func (rh *userRingbufHeader) isDiscard() bool {
	return rh.Len&unix.BPF_RINGBUF_DISCARD_BIT != 0
}

func (rh *userRingbufHeader) dataLen() int {
	return int(rh.Len & ^uint32(unix.BPF_RINGBUF_BUSY_BIT|unix.BPF_RINGBUF_DISCARD_BIT))
}

type Writer struct {
	poller      *epoll.Poller
	mu          sync.Mutex
	epollEvents []unix.EpollEvent
	prod        []byte
	cons        []byte
	prodPos     *uint64
	consPos     *uint64
	data        *byte
	mask        uint64
	mapFd       int
}

func NewWriter(userRingbufMap *ebpf.Map) (*Writer, error) {
	if !mapIsRingbuf(userRingbufMap) {
		return nil, fmt.Errorf("invalid Map type;: %s", userRingbufMap.Type())
	}

	mapFd := userRingbufMap.FD()
	maxEntries := int(userRingbufMap.MaxEntries())
	if (maxEntries & (maxEntries - 1)) != 0 {
		return nil, fmt.Errorf("user ringbuffer map size %d is not a power of two", maxEntries)
	}

	poller, err := epoll.New()
	if err != nil {
		return nil, err
	}

	if err := poller.Add(mapFd, 0, unix.EPOLLOUT); err != nil {
		poller.Close()
		return nil, err
	}

	pageSize := os.Getpagesize()

	cons, err := unix.Mmap(mapFd, 0, pageSize, unix.PROT_READ, unix.MAP_SHARED)
	if err != nil {
		return nil, fmt.Errorf("can't mmap consumer page: %w", err)
	}

	prod, err := unix.Mmap(
		mapFd,
		(int64)(os.Getpagesize()),
		pageSize+2*maxEntries,
		unix.PROT_READ|unix.PROT_WRITE,
		unix.MAP_SHARED,
	)
	if err != nil {
		_ = unix.Munmap(cons)
		return nil, fmt.Errorf("can't mmap data pages: %w", err)
	}

	data := (*byte)(unsafe.Add(unsafe.Pointer(&prod[0]), pageSize))
	mask := uint64(maxEntries) - 1
	consPos := (*uint64)(unsafe.Pointer(&cons[0]))
	prodPos := (*uint64)(unsafe.Pointer(&prod[0]))

	return &Writer{
		poller:      poller,
		mu:          sync.Mutex{},
		epollEvents: make([]unix.EpollEvent, 1),
		prod:        prod,
		cons:        cons,
		consPos:     consPos,
		prodPos:     prodPos,
		data:        data,
		mask:        mask,
		mapFd:       mapFd,
	}, nil
}

func (w *Writer) Close() error {
	if err := w.poller.Close(); err != nil {
		if errors.Is(err, os.ErrClosed) {
			return nil
		}
		return err
	}

	w.mu.Lock()
	defer w.mu.Unlock()

	_ = unix.Munmap(w.prod)
	_ = unix.Munmap(w.cons)

	w.prod = nil
	w.cons = nil

	if w.poller != nil {
		w.poller.Close()
	}

	return nil
}

func (w *Writer) Commit(sample []byte, discard bool) {
	ofs :=
		uintptr(w.mask) + 1 +
			uintptr(unsafe.Pointer(&sample[0])) -
			uintptr(unsafe.Pointer(w.data)) -
			unix.BPF_RINGBUF_HDR_SZ
	hdr := (*userRingbufHeader)(
		unsafe.Pointer(
			uintptr(unsafe.Pointer(w.data)) +
				(ofs & uintptr(w.mask))))

	new_len := hdr.Len & ^uint32(unix.BPF_RINGBUF_BUSY_BIT)
	if discard {
		new_len |= unix.BPF_RINGBUF_DISCARD_BIT
	}

	// Synchronizes with smp_load_acquire() in __bpf_user_ringbuf_peek() in the kernel
	atomic.SwapUint32(&hdr.Len, new_len)
}

func (w *Writer) Reserve(size uint32) ([]byte, error) {
	w.mu.Lock()
	defer w.mu.Unlock()

	// Synchronizes with smp_store_release() in __bpf_user_ringbuf_peek() in kernel
	cons_pos := atomic.LoadUint64(w.consPos)
	// Synchronizes with smp_store_release() in user_ringbuf_commit()
	prod_pos := atomic.LoadUint64(w.prodPos)

	max_size := w.mask + 1
	avail_size := max_size - (prod_pos - cons_pos)

	// Round up total size to a multiple of 8.
	total_size := uint64((size + unix.BPF_RINGBUF_HDR_SZ + 7) / 8 * 8)

	if total_size > max_size {
		return nil, unix.E2BIG
	}

	if avail_size < total_size {
		return nil, unix.ENOSPC
	}

	p := unsafe.Pointer(uintptr(unsafe.Pointer(w.data)) + uintptr(prod_pos))
	hdr := (*userRingbufHeader)(p)
	hdr.Len = size | unix.BPF_RINGBUF_BUSY_BIT
	hdr.Pad = 0

	// synchronizes with smp_load_acquire in __bpf_user_ringbuf_peek in the kernel
	atomic.StoreUint64(w.prodPos, prod_pos+total_size)

	ofs := uintptr((prod_pos + unix.BPF_RINGBUF_HDR_SZ) & w.mask)
	ptr := (*byte)(unsafe.Pointer(uintptr(unsafe.Pointer(w.data)) + ofs))
	sample := unsafe.Slice(ptr, size)

	return sample, nil
}

func (w *Writer) Submit(sample []byte) {
	w.Commit(sample, false)
}
func (w *Writer) Discard(sample []byte) {
	w.Commit(sample, true)
}

func (w *Writer) ReserveBlocking(size uint32, timeout int) ([]byte, error) {
	var sample []byte
	var start time.Time

	ms_remaining := int64(timeout)

	if timeout < 0 && timeout != -1 {
		return sample, unix.EINVAL
	} else if timeout != -1 {
		start = time.Now()
	}

	for ms_remaining > 0 {
		sample, err := w.Reserve(size)
		if err == nil {
			return sample, nil
		} else if err != nil && !errors.Is(err, unix.ENOSPC) {
			return []byte{}, err
		}

		ms_epoll_wait := time.Now().Add(time.Millisecond * time.Duration(ms_remaining))
		if _, err = w.poller.Wait(w.epollEvents[:1], ms_epoll_wait); err != nil {
			return []byte{}, err
		}

		if timeout == -1 {
			continue
		}

		curr := time.Now()
		ms_remaining = int64(timeout) - curr.Sub(start).Milliseconds()

	}

	return w.Reserve(size)
}

func (w *Writer) Free() {}
