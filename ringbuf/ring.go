package ringbuf

import (
	"fmt"
	"io"
	"os"
	"runtime"
	"sync/atomic"
	"unsafe"

	"github.com/cilium/ebpf/internal/unix"
)

type ringbufEventRing struct {
	prod []byte
	cons []byte
	*ringReader
}

func newRingBufEventRing(mapFD, size int) (*ringbufEventRing, error) {
	cons, err := unix.Mmap(mapFD, 0, os.Getpagesize(), unix.PROT_READ|unix.PROT_WRITE, unix.MAP_SHARED)
	if err != nil {
		return nil, fmt.Errorf("can't mmap consumer page: %w", err)
	}

	prod, err := unix.Mmap(mapFD, (int64)(os.Getpagesize()), os.Getpagesize()+2*size, unix.PROT_READ, unix.MAP_SHARED)
	if err != nil {
		_ = unix.Munmap(cons)
		return nil, fmt.Errorf("can't mmap data pages: %w", err)
	}

	cons_pos := (*uint64)(unsafe.Pointer(&cons[0]))
	prod_pos := (*uint64)(unsafe.Pointer(&prod[0]))

	ring := &ringbufEventRing{
		prod:       prod,
		cons:       cons,
		ringReader: newRingReader(cons_pos, prod_pos, prod[os.Getpagesize():]),
	}
	runtime.SetFinalizer(ring, (*ringbufEventRing).Close)

	return ring, nil
}

func (ring *ringbufEventRing) Close() {
	runtime.SetFinalizer(ring, nil)

	_ = unix.Munmap(ring.prod)
	_ = unix.Munmap(ring.cons)

	ring.prod = nil
	ring.cons = nil
}

type ringReader struct {
	// These point into mmap'ed memory and must be accessed atomically.
	prod_pos, cons_pos *uint64
	cons               uint64
	mask               uint64
	ring               []byte
}

func newRingReader(cons_ptr, prod_ptr *uint64, ring []byte) *ringReader {
	return &ringReader{
		prod_pos: prod_ptr,
		cons_pos: cons_ptr,
		cons:     atomic.LoadUint64(cons_ptr),
		// cap is always a power of two
		mask: uint64(cap(ring)/2 - 1),
		ring: ring,
	}
}

func (rr *ringReader) loadConsumer() {
	rr.cons = atomic.LoadUint64(rr.cons_pos)
}

func (rr *ringReader) storeConsumer() {
	atomic.StoreUint64(rr.cons_pos, rr.cons)
}

// clamp delta to 'end' if 'start+delta' is beyond 'end'
func clamp(start, end, delta uint64) uint64 {
	if remainder := end - start; delta > remainder {
		return remainder
	}
	return delta
}

func (rr *ringReader) skipRead(skipBytes uint64) {
	rr.cons += clamp(rr.cons, atomic.LoadUint64(rr.prod_pos), skipBytes)
}

func (rr *ringReader) Read(p []byte) (int, error) {
	prod := atomic.LoadUint64(rr.prod_pos)

	n := clamp(rr.cons, prod, uint64(len(p)))

	start := rr.cons & rr.mask

	copy(p, rr.ring[start:start+n])
	rr.cons += n

	if prod == rr.cons {
		return int(n), io.EOF
	}

	return int(n), nil
}

// UserRingBuf Definitions

type userRingbufEventRing struct {
	prod []byte
	cons []byte
	*ringWriter
}

func newUserRingbufEventRing(mapFD, size int) (*userRingbufEventRing, error) {
	pageSize := os.Getpagesize()

	cons, err := unix.Mmap(mapFD, 0, pageSize, unix.PROT_READ, unix.MAP_SHARED)
	if err != nil {
		return nil, fmt.Errorf("can't mmap consumer page: %w", err)
	}

	prod, err := unix.Mmap(
		mapFD,
		(int64)(os.Getpagesize()),
		pageSize+2*size,
		unix.PROT_READ|unix.PROT_WRITE,
		unix.MAP_SHARED,
	)
	if err != nil {
		_ = unix.Munmap(cons)
		return nil, fmt.Errorf("can't mmap data pages: %w", err)
	}

	cons_pos := (*uint64)(unsafe.Pointer(&cons[0]))
	prod_pos := (*uint64)(unsafe.Pointer(&prod[0]))
	mask := uint64(size - 1)

	ring := &userRingbufEventRing{
		prod:       prod,
		cons:       cons,
		ringWriter: newRingWriter(cons_pos, prod_pos, mask, prod[pageSize:]),
	}
	runtime.SetFinalizer(ring, (*userRingbufEventRing).Close)

	return ring, nil
}

func (ring *userRingbufEventRing) Close() {
	runtime.SetFinalizer(ring, nil)

	_ = unix.Munmap(ring.prod)
	_ = unix.Munmap(ring.cons)

	ring.prod = nil
	ring.cons = nil
}

type ringWriter struct {
	prod_pos *uint64
	cons_pos *uint64
	mask     uint64
	ring     []byte
}

func newRingWriter(cons, prod *uint64, mask uint64, ring []byte) *ringWriter {
	return &ringWriter{
		prod_pos: prod,
		cons_pos: cons,
		mask:     mask,
		ring:     ring,
	}
}

func (rw *ringWriter) commit(sample []byte, discard bool) {
	ofs := uint64(
		uintptr(rw.mask+1) +
			uintptr(unsafe.Pointer(&sample[0])) -
			uintptr(unsafe.Pointer(&rw.ring[0])) -
			unix.BPF_RINGBUF_HDR_SZ)
	hdr := (*userRingbufHeader)(unsafe.Pointer(&rw.ring[ofs&rw.mask:][0]))
	new_len := hdr.Len & ^uint32(unix.BPF_RINGBUF_BUSY_BIT)
	if discard {
		new_len |= unix.BPF_RINGBUF_DISCARD_BIT
	}

	// Synchronizes with smp_load_acquire() in __bpf_user_ringbuf_peek() in the kernel
	atomic.SwapUint32(&hdr.Len, new_len)
}

func (rw *ringWriter) reserve(size uint32) ([]byte, error) {
	// Synchronizes with smp_store_release() in __bpf_user_ringbuf_peek() in kernel
	cons_pos := atomic.LoadUint64(rw.cons_pos)
	// Synchronizes with smp_store_release() in user_ringbuf_commit()
	prod_pos := atomic.LoadUint64(rw.prod_pos)

	max_size := rw.mask + 1
	avail_size := max_size - (prod_pos - cons_pos)

	// Round up total size to a multiple of 8.
	total_size := uint64((size + unix.BPF_RINGBUF_HDR_SZ + 7) / 8 * 8)

	if total_size > max_size {
		return nil, unix.E2BIG
	}

	if avail_size < total_size {
		return nil, unix.ENOSPC
	}

	hdr := (*userRingbufHeader)(unsafe.Pointer(&rw.ring[prod_pos&rw.mask:][0]))
	hdr.Len = size | unix.BPF_RINGBUF_BUSY_BIT
	hdr.Pad = 0

	// synchronizes with smp_load_acquire in __bpf_user_ringbuf_peek in the kernel
	atomic.StoreUint64(rw.prod_pos, prod_pos+total_size)

	ofs := (prod_pos + unix.BPF_RINGBUF_HDR_SZ) & rw.mask
	return rw.ring[ofs : ofs+uint64(size)], nil
}
