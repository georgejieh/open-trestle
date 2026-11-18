package syntaxwasm

import (
	"maps"
	"slices"
)

// imagePageBytes is the unit in which memory images are stored; pages of
// zeros are left out.
const imagePageBytes = 64 << 10

// memoryImage is a copy of an instance's linear memory after it compiled
// the queries in queries. Compiled queries live in the guest heap, so an
// instance whose memory is replaced by the image has them too. The image
// holds only state derived from the module and the project's own queries,
// never repository content.
type memoryImage struct {
	size    uint32
	pages   map[uint32][]byte
	queries map[int]loadedQuery
}

// restore replaces the memory of a fresh instance with the image. The
// stack pointer and the other mutable globals hold the same values in
// every instance between calls, so the memory is the whole state that
// differs.
func (inst *instance) restore(image *memoryImage) bool {
	size := inst.memory.Size()
	if size > image.size {
		return false
	}
	if size < image.size {
		if _, ok := inst.memory.Grow((image.size - size) / imagePageBytes); !ok || inst.memory.Size() != image.size {
			return false
		}
	}
	zero := make([]byte, imagePageBytes)
	for at := uint32(0); at < image.size; at += imagePageBytes {
		page, ok := image.pages[at]
		if !ok {
			current, ok := inst.memory.Read(at, imagePageBytes)
			if !ok {
				return false
			}
			if allZero(current) {
				continue
			}
			page = zero
		}
		if !inst.memory.Write(at, page) {
			return false
		}
	}
	inst.queries = maps.Clone(image.queries)
	return true
}

// snapshot copies the memory of a pristine instance into an image.
func (inst *instance) snapshot() (*memoryImage, bool) {
	size := inst.memory.Size()
	if !inst.pristine || size%imagePageBytes != 0 {
		return nil, false
	}
	image := &memoryImage{size: size, pages: map[uint32][]byte{}, queries: maps.Clone(inst.queries)}
	for at := uint32(0); at < size; at += imagePageBytes {
		view, ok := inst.memory.Read(at, imagePageBytes)
		if !ok {
			return nil, false
		}
		if !allZero(view) {
			image.pages[at] = slices.Clone(view)
		}
	}
	return image, true
}

func allZero(b []byte) bool {
	for _, c := range b {
		if c != 0 {
			return false
		}
	}
	return true
}
