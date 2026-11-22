package repoindex

import (
	"bufio"
	"encoding/binary"
	"hash/crc32"
	"io"
	"os"

	"github.com/georgejieh/open-trestle/internal/varcodec"
)

// A segment file holds blob records, written once and never changed:
//
//	header    "OTIXSEG1", the 32-byte analysis identity
//	records   the encoded records, back to back
//	directory a count, then per record its key, flags, offset, length and
//	          CRC-32C
//	trailer   the directory's offset and length (uint64), its CRC-32C
//	          (uint32) and "OTIXEND1"
const (
	segmentMagic   = "OTIXSEG1"
	segmentEnd     = "OTIXEND1"
	segmentHeader  = len(segmentMagic) + 32
	segmentTrailer = 8 + 8 + 4 + len(segmentEnd)
)

var crcTable = crc32.MakeTable(crc32.Castagnoli)

// maxDirectoryBytes and maxRecordBytes bound what one read of a segment
// allocates, whatever lengths the file claims: a directory of a million
// records, and a record of the most an analysis within the default limits
// encodes to, many times over.
const (
	maxDirectoryBytes = 64 << 20
	maxRecordBytes    = 64 << 20
)

// location is where a record lies in a segment.
type location struct {
	segment int
	offset  int64
	length  int64
	crc     uint32
	// flags are the record's binary and generated flags, so that a build
	// that reuses a record does not read it.
	flags byte
}

// segmentWriter writes a new segment to a temporary file.
type segmentWriter struct {
	file    *os.File
	name    string
	out     *bufio.Writer
	offset  int64
	keys    []Key
	entries map[Key]location
}

func newSegmentWriter(file *os.File, name string, identity [32]byte) (*segmentWriter, error) {
	w := &segmentWriter{file: file, name: name, out: bufio.NewWriterSize(file, 1<<20), entries: map[Key]location{}}
	if _, err := w.out.WriteString(segmentMagic); err != nil {
		return nil, err
	}
	if _, err := w.out.Write(identity[:]); err != nil {
		return nil, err
	}
	w.offset = int64(segmentHeader)
	return w, nil
}

// add appends a record unless the segment holds its key already.
func (w *segmentWriter) add(key Key, flags byte, record []byte) error {
	if _, ok := w.entries[key]; ok {
		return nil
	}
	if len(record) > maxRecordBytes {
		return errCorrupt
	}
	if _, err := w.out.Write(record); err != nil {
		return err
	}
	w.keys = append(w.keys, key)
	w.entries[key] = location{offset: w.offset, length: int64(len(record)), crc: crc32.Checksum(record, crcTable), flags: flags}
	w.offset += int64(len(record))
	return nil
}

// finish writes the directory and trailer and syncs the file.
func (w *segmentWriter) finish() error {
	directory := varcodec.AppendUvarint(nil, uint64(len(w.keys)))
	for _, key := range w.keys {
		l := w.entries[key]
		directory = append(directory, key[:]...)
		directory = append(directory, l.flags)
		directory = varcodec.AppendUvarint(directory, uint64(l.offset))
		directory = varcodec.AppendUvarint(directory, uint64(l.length))
		directory = binary.LittleEndian.AppendUint32(directory, l.crc)
	}
	trailer := binary.LittleEndian.AppendUint64(nil, uint64(w.offset))
	trailer = binary.LittleEndian.AppendUint64(trailer, uint64(len(directory)))
	trailer = binary.LittleEndian.AppendUint32(trailer, crc32.Checksum(directory, crcTable))
	trailer = append(trailer, segmentEnd...)
	if _, err := w.out.Write(directory); err != nil {
		return err
	}
	if _, err := w.out.Write(trailer); err != nil {
		return err
	}
	if err := w.out.Flush(); err != nil {
		return err
	}
	return w.file.Sync()
}

// readSegmentDirectory checks a segment's header and trailer and returns its
// records' locations. A segment of another analysis identity is stale.
func readSegmentDirectory(file *os.File, size int64, identity [32]byte, segment int) (map[Key]location, error) {
	if size < int64(segmentHeader+segmentTrailer) {
		return nil, errCorrupt
	}
	header := make([]byte, segmentHeader)
	if _, err := file.ReadAt(header, 0); err != nil || string(header[:len(segmentMagic)]) != segmentMagic {
		return nil, errCorrupt
	}
	if [32]byte(header[len(segmentMagic):]) != identity {
		return nil, errStale
	}
	trailer := make([]byte, segmentTrailer)
	if _, err := file.ReadAt(trailer, size-int64(segmentTrailer)); err != nil || string(trailer[20:]) != segmentEnd {
		return nil, errCorrupt
	}
	at, length := binary.LittleEndian.Uint64(trailer), binary.LittleEndian.Uint64(trailer[8:])
	if at < uint64(segmentHeader) || length > maxDirectoryBytes || length > uint64(size) || at+length != uint64(size)-uint64(segmentTrailer) {
		return nil, errCorrupt
	}
	directory := make([]byte, length)
	if _, err := file.ReadAt(directory, int64(at)); err != nil || crc32.Checksum(directory, crcTable) != binary.LittleEndian.Uint32(trailer[16:]) {
		return nil, errCorrupt
	}
	r := varcodec.NewReader(directory)
	n := r.Count(32 + 1 + 1 + 1 + 4)
	entries := make(map[Key]location, n)
	for i := 0; i < n; i++ {
		raw := r.Fixed(32)
		if raw == nil {
			return nil, errCorrupt
		}
		key := Key(raw)
		flags := r.Byte()
		l := location{segment: segment, offset: int64(r.Uvarint()), length: int64(r.Uvarint()), crc: r.Uint32(), flags: flags}
		if r.Err() != nil || flags > recordFlags || l.offset < int64(segmentHeader) || l.offset > int64(at) || l.length < 1 || l.length > maxRecordBytes || l.length > int64(at)-l.offset {
			return nil, errCorrupt
		}
		entries[key] = l
	}
	if r.Done() != nil {
		return nil, errCorrupt
	}
	return entries, nil
}

// readRecord reads and checks one record.
func readRecord(file io.ReaderAt, l location) ([]byte, error) {
	record := make([]byte, l.length)
	if _, err := file.ReadAt(record, l.offset); err != nil || crc32.Checksum(record, crcTable) != l.crc {
		return nil, errCorrupt
	}
	return record, nil
}
