package scm

import (
	"bufio"
	"bytes"
	"compress/zlib"
	"context"
	"encoding/binary"
	"fmt"
	"hash/crc32"
	"io"
)

const (
	localGitPackTypeCommit   = 1
	localGitPackTypeTree     = 2
	localGitPackTypeBlob     = 3
	localGitPackTypeTag      = 4
	localGitPackTypeOFSDelta = 6
	localGitPackTypeREFDelta = 7
)

type localGitPackObjectHeader struct {
	typeCode         int
	declaredSize     uint64
	headerEnd        uint64
	compressedOffset uint64
	baseOffset       uint64
	baseOID          []byte
}

type localGitDecodedPackObject struct {
	objectType string
	payload    []byte
}

func (c *localGitPackIndexCatalog) resolveObject(ctx context.Context, ref localGitPackObjectRef, expectedType string, maxPayloadBytes int64, scope *localGitPackScope) ([]byte, string, error) {
	if scope == nil {
		scope = newLocalGitPackScope(nil, c)
	}
	chain, err := c.resolveObjectChain(ctx, ref, scope)
	if err != nil {
		return nil, "", err
	}
	if len(chain) == 0 {
		return nil, "", LocalGitRevisionInvalidGraph
	}
	base := chain[len(chain)-1]
	decoded, ok, err := scope.cacheGet(base.ref)
	if err != nil {
		return nil, "", err
	}
	if !ok {
		payload, err := readPackedObjectInflated(ctx, base.ref, base.header, scope, maxPayloadBytes)
		if err != nil {
			return nil, "", err
		}
		objectType, ok := localGitUndeltifiedTypeName(base.header.typeCode)
		if !ok || objectType == "tag" {
			return nil, "", LocalGitRevisionInvalidGraph
		}
		if err := verifyGitObjectPayloadDigest(c.algorithm, base.ref.oid, objectType, payload); err != nil {
			return nil, "", LocalGitRevisionInvalidGraph
		}
		decoded = localGitDecodedPackObject{objectType: objectType, payload: payload}
		if err := scope.cachePut(base.ref, decoded); err != nil {
			return nil, "", err
		}
	}
	if decoded.objectType != expectedType {
		return nil, "", LocalGitRevisionInvalidGraph
	}
	current := decoded
	for i := len(chain) - 2; i >= 0; i-- {
		entry := chain[i]
		cached, ok, err := scope.cacheGet(entry.ref)
		if err != nil {
			return nil, "", err
		}
		if ok {
			current = cached
			continue
		}
		delta, err := readPackedObjectInflated(ctx, entry.ref, entry.header, scope, maxLocalGitPackCompressedObjectBytes)
		if err != nil {
			return nil, "", err
		}
		payload, err := applyLocalGitPackDelta(ctx, current.payload, delta, maxPayloadBytes, scope)
		if err != nil {
			return nil, "", err
		}
		current = localGitDecodedPackObject{objectType: current.objectType, payload: payload}
		if err := verifyGitObjectPayloadDigest(c.algorithm, entry.ref.oid, current.objectType, current.payload); err != nil {
			return nil, "", LocalGitRevisionInvalidGraph
		}
		if err := scope.cachePut(entry.ref, current); err != nil {
			return nil, "", err
		}
	}
	if current.objectType != expectedType {
		return nil, "", LocalGitRevisionInvalidGraph
	}
	if err := scope.chargeDecompressedWork(int64(len(current.payload))); err != nil {
		return nil, "", err
	}
	return append([]byte{}, current.payload...), current.objectType, ctx.Err()
}

type localGitPackChainEntry struct {
	ref    localGitPackObjectRef
	header localGitPackObjectHeader
}

func (c *localGitPackIndexCatalog) resolveObjectChain(ctx context.Context, ref localGitPackObjectRef, scope *localGitPackScope) ([]localGitPackChainEntry, error) {
	chain := make([]localGitPackChainEntry, 0, c.limits.maxDeltaDepth+1)
	visited := make(map[string]struct{}, c.limits.maxDeltaDepth+1)
	current := ref
	for depth := 0; ; depth++ {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		key := current.pack.stem + ":" + fmt.Sprintf("%d", current.offset)
		if _, exists := visited[key]; exists {
			return nil, LocalGitRevisionInvalidGraph
		}
		visited[key] = struct{}{}
		header, err := current.pack.readObjectHeaderAt(ctx, current.offset, c.hashLen, scope)
		if err != nil {
			return nil, err
		}
		chain = append(chain, localGitPackChainEntry{ref: current, header: header})
		switch header.typeCode {
		case localGitPackTypeCommit, localGitPackTypeTree, localGitPackTypeBlob:
			return chain, ctx.Err()
		case localGitPackTypeTag:
			return nil, LocalGitRevisionInvalidGraph
		case localGitPackTypeOFSDelta, localGitPackTypeREFDelta:
			if depth >= c.limits.maxDeltaDepth {
				return nil, LocalGitRevisionResourceLimit
			}
			base, err := c.baseRefForHeader(ctx, current.pack, header, scope)
			if err != nil {
				return nil, err
			}
			current = base
		default:
			return nil, LocalGitRevisionInvalidGraph
		}
	}
}

func (c *localGitPackIndexCatalog) baseRefForHeader(ctx context.Context, pack *localGitPackFile, header localGitPackObjectHeader, scope *localGitPackScope) (localGitPackObjectRef, error) {
	switch header.typeCode {
	case localGitPackTypeOFSDelta:
		slot, ok := pack.slotForOffset(header.baseOffset)
		if !ok {
			return localGitPackObjectRef{}, LocalGitRevisionInvalidGraph
		}
		oid, err := pack.oidAtSlot(ctx, slot, c.hashLen, scope)
		if err != nil {
			return localGitPackObjectRef{}, err
		}
		ref, ok, err := pack.refForSlot(ctx, slot, oid, c.hashLen, scope)
		if err != nil || !ok {
			return localGitPackObjectRef{}, err
		}
		return ref, ctx.Err()
	case localGitPackTypeREFDelta:
		ref, ok, err := pack.lookupOID(ctx, header.baseOID, c.hashLen, scope)
		if err != nil {
			return localGitPackObjectRef{}, err
		}
		if !ok {
			return localGitPackObjectRef{}, LocalGitRevisionInvalidGraph
		}
		return ref, ctx.Err()
	default:
		return localGitPackObjectRef{}, LocalGitRevisionInvalidGraph
	}
}

func (p *localGitPackFile) readObjectHeaderAt(ctx context.Context, offset uint64, hashLen int, scope *localGitPackScope) (localGitPackObjectHeader, error) {
	if offset < localGitPackHeaderBytes || offset >= p.packDataEnd {
		return localGitPackObjectHeader{}, LocalGitRevisionInvalidGraph
	}
	reader := scopedCatalogReader(ctx, scope)
	cursor := int64(offset)
	var first [1]byte
	if err := reader.readAt(p.packFile, first[:], cursor); err != nil {
		return localGitPackObjectHeader{}, err
	}
	cursor++
	typeCode := int((first[0] >> 4) & 7)
	size := uint64(first[0] & 0x0f)
	shift := uint(4)
	for first[0]&0x80 != 0 {
		if cursor >= int64(p.packDataEnd) || shift > 63 {
			return localGitPackObjectHeader{}, LocalGitRevisionInvalidGraph
		}
		if err := reader.readAt(p.packFile, first[:], cursor); err != nil {
			return localGitPackObjectHeader{}, err
		}
		cursor++
		size |= uint64(first[0]&0x7f) << shift
		shift += 7
	}
	header := localGitPackObjectHeader{typeCode: typeCode, declaredSize: size, headerEnd: uint64(cursor)}
	switch typeCode {
	case localGitPackTypeCommit, localGitPackTypeTree, localGitPackTypeBlob, localGitPackTypeTag:
		header.compressedOffset = uint64(cursor)
	case localGitPackTypeOFSDelta:
		baseDistance, err := readLocalGitPackOFSDeltaBase(ctx, p, &cursor, reader)
		if err != nil {
			return localGitPackObjectHeader{}, err
		}
		if baseDistance == 0 || baseDistance >= offset {
			return localGitPackObjectHeader{}, LocalGitRevisionInvalidGraph
		}
		header.baseOffset = offset - baseDistance
		header.compressedOffset = uint64(cursor)
	case localGitPackTypeREFDelta:
		header.baseOID = make([]byte, hashLen)
		if err := reader.readAt(p.packFile, header.baseOID, cursor); err != nil {
			return localGitPackObjectHeader{}, err
		}
		cursor += int64(hashLen)
		header.compressedOffset = uint64(cursor)
	default:
		return localGitPackObjectHeader{}, LocalGitRevisionInvalidGraph
	}
	if header.compressedOffset >= p.packDataEnd {
		return localGitPackObjectHeader{}, LocalGitRevisionInvalidGraph
	}
	return header, ctx.Err()
}

func readLocalGitPackOFSDeltaBase(ctx context.Context, pack *localGitPackFile, cursor *int64, reader *localGitCatalogReader) (uint64, error) {
	var raw [1]byte
	if err := reader.readAt(pack.packFile, raw[:], *cursor); err != nil {
		return 0, err
	}
	*cursor = *cursor + 1
	base := uint64(raw[0] & 0x7f)
	for raw[0]&0x80 != 0 {
		if err := ctx.Err(); err != nil {
			return 0, err
		}
		if *cursor >= int64(pack.packDataEnd) || base > ^uint64(0)>>7 {
			return 0, LocalGitRevisionInvalidGraph
		}
		if err := reader.readAt(pack.packFile, raw[:], *cursor); err != nil {
			return 0, err
		}
		*cursor = *cursor + 1
		base = ((base + 1) << 7) | uint64(raw[0]&0x7f)
	}
	return base, ctx.Err()
}

func readPackedObjectInflated(ctx context.Context, ref localGitPackObjectRef, header localGitPackObjectHeader, scope *localGitPackScope, maxInflatedBytes int64) ([]byte, error) {
	if ref.nextOffset <= header.compressedOffset || ref.nextOffset > ref.pack.packDataEnd {
		return nil, LocalGitRevisionInvalidGraph
	}
	objectRangeBytes := int64(ref.nextOffset - ref.offset)
	if objectRangeBytes < 0 || objectRangeBytes > scope.catalog.limits.maxCompressedObjectBytes {
		return nil, LocalGitRevisionResourceLimit
	}
	crc, err := crcLocalGitPackObjectRange(ctx, ref, scope)
	if err != nil {
		return nil, err
	}
	if crc != ref.crc {
		return nil, LocalGitRevisionInvalidGraph
	}
	compressedBytes := int64(ref.nextOffset - header.compressedOffset)
	section := io.NewSectionReader(ref.pack.packFile, int64(header.compressedOffset), compressedBytes)
	buffered := bufio.NewReader(&localGitPackReadChargingReader{ctx: ctx, reader: section, scope: scope})
	compressed, err := zlib.NewReader(buffered)
	if err != nil {
		return nil, LocalGitRevisionInvalidGraph
	}
	payload, readErr := readAllLocalGitPackInflated(ctx, compressed, maxInflatedBytes, scope)
	closeErr := compressed.Close()
	if readErr != nil {
		return nil, readErr
	}
	if closeErr != nil {
		return nil, LocalGitRevisionInvalidGraph
	}
	if uint64(len(payload)) != header.declaredSize {
		return nil, LocalGitRevisionInvalidGraph
	}
	if trailing, err := buffered.Peek(1); len(trailing) != 0 || err == nil {
		return nil, LocalGitRevisionInvalidGraph
	} else if err != io.EOF {
		return nil, LocalGitRevisionInvalidGraph
	}
	return payload, ctx.Err()
}

func crcLocalGitPackObjectRange(ctx context.Context, ref localGitPackObjectRef, scope *localGitPackScope) (uint32, error) {
	hasher := crc32.NewIEEE()
	reader := scopedCatalogReader(ctx, scope)
	buffer := make([]byte, 64*1024)
	remaining := int64(ref.nextOffset - ref.offset)
	cursor := int64(ref.offset)
	for remaining > 0 {
		if err := ctx.Err(); err != nil {
			return 0, err
		}
		chunk := int64(len(buffer))
		if remaining < chunk {
			chunk = remaining
		}
		if err := reader.readAt(ref.pack.packFile, buffer[:int(chunk)], cursor); err != nil {
			return 0, err
		}
		_, _ = hasher.Write(buffer[:int(chunk)])
		cursor += chunk
		remaining -= chunk
	}
	return hasher.Sum32(), ctx.Err()
}

type localGitPackReadChargingReader struct {
	ctx    context.Context
	reader io.Reader
	scope  *localGitPackScope
}

func (r *localGitPackReadChargingReader) Read(buffer []byte) (int, error) {
	if err := r.ctx.Err(); err != nil {
		return 0, err
	}
	read, err := r.reader.Read(buffer)
	if read > 0 {
		if chargeErr := r.scope.chargePhysicalRead(int64(read)); chargeErr != nil {
			return read, chargeErr
		}
	}
	if contextErr := r.ctx.Err(); contextErr != nil {
		return read, contextErr
	}
	return read, err
}

func readAllLocalGitPackInflated(ctx context.Context, reader io.Reader, limit int64, scope *localGitPackScope) ([]byte, error) {
	if limit < 0 {
		return nil, LocalGitRevisionResourceLimit
	}
	var output bytes.Buffer
	buffer := make([]byte, 32*1024)
	for {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		read, err := reader.Read(buffer)
		if read > 0 {
			if int64(read) > limit-int64(output.Len()) {
				return nil, LocalGitRevisionResourceLimit
			}
			if err := scope.chargeDecompressedWork(int64(read)); err != nil {
				return nil, err
			}
			_, _ = output.Write(buffer[:read])
		}
		if err == io.EOF {
			return output.Bytes(), ctx.Err()
		}
		if err != nil {
			return nil, LocalGitRevisionInvalidGraph
		}
	}
}

func applyLocalGitPackDelta(ctx context.Context, base []byte, delta []byte, limit int64, scope *localGitPackScope) ([]byte, error) {
	cursor := 0
	sourceSize, err := readLocalGitPackDeltaSize(delta, &cursor)
	if err != nil {
		return nil, err
	}
	resultSize, err := readLocalGitPackDeltaSize(delta, &cursor)
	if err != nil {
		return nil, err
	}
	if sourceSize != uint64(len(base)) || resultSize > uint64(limit) {
		return nil, LocalGitRevisionResourceLimit
	}
	if err := scope.chargeDecompressedWork(int64(resultSize)); err != nil {
		return nil, err
	}
	result := make([]byte, 0, int(resultSize))
	for cursor < len(delta) {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		opcode := delta[cursor]
		cursor++
		if opcode&0x80 != 0 {
			copyOffset := 0
			copySize := 0
			for bit := 0; bit < 4; bit++ {
				if opcode&(1<<uint(bit)) != 0 {
					if cursor >= len(delta) {
						return nil, LocalGitRevisionInvalidGraph
					}
					copyOffset |= int(delta[cursor]) << uint(8*bit)
					cursor++
				}
			}
			for bit := 0; bit < 3; bit++ {
				if opcode&(1<<uint(4+bit)) != 0 {
					if cursor >= len(delta) {
						return nil, LocalGitRevisionInvalidGraph
					}
					copySize |= int(delta[cursor]) << uint(8*bit)
					cursor++
				}
			}
			if copySize == 0 {
				copySize = 0x10000
			}
			if copyOffset < 0 || copySize < 0 || copyOffset > len(base) || copySize > len(base)-copyOffset || uint64(len(result)+copySize) > resultSize {
				return nil, LocalGitRevisionInvalidGraph
			}
			result = append(result, base[copyOffset:copyOffset+copySize]...)
		} else {
			insertSize := int(opcode)
			if insertSize == 0 || insertSize > len(delta)-cursor || uint64(len(result)+insertSize) > resultSize {
				return nil, LocalGitRevisionInvalidGraph
			}
			result = append(result, delta[cursor:cursor+insertSize]...)
			cursor += insertSize
		}
	}
	if uint64(len(result)) != resultSize {
		return nil, LocalGitRevisionInvalidGraph
	}
	return result, ctx.Err()
}

func readLocalGitPackDeltaSize(delta []byte, cursor *int) (uint64, error) {
	var size uint64
	shift := uint(0)
	for {
		if *cursor >= len(delta) || shift > 63 {
			return 0, LocalGitRevisionInvalidGraph
		}
		next := delta[*cursor]
		*cursor = *cursor + 1
		size |= uint64(next&0x7f) << shift
		if next&0x80 == 0 {
			return size, nil
		}
		shift += 7
	}
}

func localGitUndeltifiedTypeName(typeCode int) (string, bool) {
	switch typeCode {
	case localGitPackTypeCommit:
		return "commit", true
	case localGitPackTypeTree:
		return "tree", true
	case localGitPackTypeBlob:
		return "blob", true
	case localGitPackTypeTag:
		return "tag", true
	default:
		return "", false
	}
}

func uint32FromBytes(buffer []byte) uint32 {
	return binary.BigEndian.Uint32(buffer)
}
