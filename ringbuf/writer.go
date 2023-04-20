package ringbuf

import (
	"errors"
	"fmt"
	"os"
	"sync"
	"sync/atomic"
	"unsafe"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/internal/epoll"
	"github.com/cilium/ebpf/internal/unix"
)

const userRingbufHeaderSize = 8

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
	poller  *epoll.Poller
	mu      sync.Mutex
	prod    []byte
	cons    []byte
	prodPos *uint64
	consPos *uint64
	data    unsafe.Pointer
	mask    uint64
	mapFd   int
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

	data := unsafe.Add(unsafe.Pointer(&prod[0]), pageSize)
	mask := uint64(maxEntries) - 1
	consPos := (*uint64)(unsafe.Pointer(&cons[0]))
	prodPos := (*uint64)(unsafe.Pointer(&prod[0]))

	return &Writer{
		poller:  poller,
		mu:      sync.Mutex{},
		prod:    prod,
		cons:    cons,
		consPos: consPos,
		prodPos: prodPos,
		data:    data,
		mask:    mask,
		mapFd:   mapFd,
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

func (w *Writer) Commit(sample []byte, discard bool) error {
	hdrOff := (uintptr(w.data)) + 100 - uintptr(w.data) - userRingbufHeaderSize
	fmt.Println(hdrOff)
	hdr := (*(*userRingbufHeader)(unsafe.Pointer(uintptr(unsafe.Pointer(&w.prod[0]))))) //+ (hdrOff & uintptr(w.mask)))))
	newLen := hdr.Len & ^uint32(unix.BPF_RINGBUF_BUSY_BIT)
	if discard {
		newLen |= unix.BPF_RINGBUF_DISCARD_BIT
	}
	atomic.SwapUint32(&hdr.Len, newLen)

	fmt.Println(hdr)
	return nil
}

func (w *Writer) Reserve(size uint32) ([]byte, error) {
	w.mu.Lock()
	defer w.mu.Unlock()

	cons_pos := atomic.LoadUint64(w.consPos)
	prod_pos := atomic.LoadUint64(w.prodPos)

	max_size := w.mask + 1
	avail_size := max_size - (prod_pos - cons_pos)

	// Round up total size to a multiple of 8.
	total_size := uint64((size + userRingbufHeaderSize + 7) / 8 * 8)

	if total_size > max_size {
		return nil, unix.E2BIG
	}

	if avail_size < total_size {
		return nil, unix.ENOSPC
	}

	hdr := (*userRingbufHeader)(unsafe.Slice((*byte)(w.data), userRingbufHeaderSize)[0])
	hdr.Len = size | unix.BPF_RINGBUF_BUSY_BIT
	atomic.StoreUint64(w.prodPos, (prod_pos + total_size))

	fmt.Println(w.prod[:10])
	//offset := (prod_pos + userRingbufHeaderSize) & w.mask
	w.data = unsafe.Add(w.data, userRingbufHeaderSize)
	sample := unsafe.Slice(w.data, size)

	return sample, nil
}

func (w *Writer) ReserveBlocking() {}
func (w *Writer) Discard()         {}
func (w *Writer) Free()            {}
