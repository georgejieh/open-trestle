package scm

import (
	"context"
	"crypto/sha1"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"hash"
	"io"
	"os"
	"regexp"
	"sort"
	"strings"

	"github.com/georgejieh/open-trestle/internal/evidence"
)

const (
	maxLocalGitPackCount                        = 4
	maxLocalGitPackFileBytes                    = 536870912
	maxLocalGitTotalAdmittedPackBytes           = 536870912
	maxLocalGitPackObjectsPerPack               = 1000000
	maxLocalGitTotalIndexedObjects              = 1000000
	maxLocalGitPackIndexMetadataBytes           = 33554432
	maxLocalGitPackDeltaDepth                   = 32
	maxLocalGitPackBaseCacheBytes               = 33554432
	maxLocalGitPackBaseCacheEntries             = 64
	maxLocalGitPackCompressedObjectBytes        = 67108864
	maxLocalGitPackDecompressedWorkBytes        = 536870912
	maxLocalGitPackPhysicalReadBytes            = 2147483648
	maxLocalGitPackChecksumPassesPerAcquisition = 2
	maxLocalGitPackConcurrentDecodesPerStore    = 1
	maxLocalGitPackDirectoryEntries             = 24
	localGitPackHeaderBytes                     = 12
	localGitPackIndexMagic                      = "\xfftOc"
)

type localGitPackLimits struct {
	maxPackCount                 int
	maxPackFileBytes             int64
	maxTotalPackBytes            int64
	maxObjectsPerPack            uint32
	maxTotalIndexedObjects       uint32
	maxIndexMetadataBytes        int64
	maxDeltaDepth                int
	maxBaseCacheBytes            int64
	maxBaseCacheEntries          int
	maxCompressedObjectBytes     int64
	maxDecompressedWorkBytes     int64
	maxPhysicalReadBytes         int64
	maxChecksumPasses            int
	maxConcurrentDecodesPerStore int
}

func standardLocalGitPackLimits() localGitPackLimits {
	return localGitPackLimits{
		maxPackCount:                 maxLocalGitPackCount,
		maxPackFileBytes:             maxLocalGitPackFileBytes,
		maxTotalPackBytes:            maxLocalGitTotalAdmittedPackBytes,
		maxObjectsPerPack:            maxLocalGitPackObjectsPerPack,
		maxTotalIndexedObjects:       maxLocalGitTotalIndexedObjects,
		maxIndexMetadataBytes:        maxLocalGitPackIndexMetadataBytes,
		maxDeltaDepth:                maxLocalGitPackDeltaDepth,
		maxBaseCacheBytes:            maxLocalGitPackBaseCacheBytes,
		maxBaseCacheEntries:          maxLocalGitPackBaseCacheEntries,
		maxCompressedObjectBytes:     maxLocalGitPackCompressedObjectBytes,
		maxDecompressedWorkBytes:     maxLocalGitPackDecompressedWorkBytes,
		maxPhysicalReadBytes:         maxLocalGitPackPhysicalReadBytes,
		maxChecksumPasses:            maxLocalGitPackChecksumPassesPerAcquisition,
		maxConcurrentDecodesPerStore: maxLocalGitPackConcurrentDecodesPerStore,
	}
}

type localGitPackIndexCatalog struct {
	objectsRoot           *os.Root
	packRoot              *os.Root
	packDirInfo           os.FileInfo
	algorithm             evidence.RevisionAlgorithm
	hashLen               int
	limits                localGitPackLimits
	packs                 []*localGitPackFile
	catalogPhysicalBytes  int64
	catalogChecksumPasses int
}

type localGitPackFile struct {
	stem                   string
	packName               string
	idxName                string
	packFile               *os.File
	idxFile                *os.File
	packInfo               os.FileInfo
	idxInfo                os.FileInfo
	objectCount            uint32
	fanout                 [256]uint32
	oidTableOffset         int64
	crcTableOffset         int64
	offsetTableOffset      int64
	largeOffsetTableOffset int64
	packChecksumOffset     int64
	idxChecksumOffset      int64
	packChecksum           []byte
	idxChecksum            []byte
	packDataEnd            uint64
	offsetSlots            []localGitPackOffsetSlot
}

type localGitPackOffsetSlot struct {
	offset uint64
	slot   uint32
}

type localGitPackObjectRef struct {
	pack       *localGitPackFile
	slot       uint32
	oid        []byte
	offset     uint64
	nextOffset uint64
	crc        uint32
}

type localGitPackDirectoryEntry struct {
	stem string
	ext  string
	name string
}

type localGitPackStemFiles struct {
	stem     string
	packName string
	idxName  string
	sidecars map[string]string
}

var localGitPackFileNamePattern = regexp.MustCompile(`^pack-([0-9a-f]{40}|[0-9a-f]{64})\.(pack|idx|keep|bitmap|rev|mtimes)$`)

func ValidateLocalGitPackedLayout(objectsRoot *os.Root) error {
	if objectsRoot == nil {
		return fmt.Errorf("Git object root is nil")
	}
	if err := rejectLocalGitPackedRootMetadata(objectsRoot); err != nil {
		return err
	}
	if err := validateLocalGitInfoDirectory(objectsRoot); err != nil {
		return err
	}
	packInfo, err := objectsRoot.Lstat("pack")
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return fmt.Errorf("inspect Git pack directory: %w", err)
	}
	if !packInfo.IsDir() {
		return fmt.Errorf("Git pack path is not a directory")
	}
	packRoot, err := objectsRoot.OpenRoot("pack/.")
	if err != nil {
		return fmt.Errorf("open Git pack directory: %w", err)
	}
	defer packRoot.Close()
	openedInfo, err := packRoot.Stat(".")
	if err != nil {
		return fmt.Errorf("inspect opened Git pack directory: %w", err)
	}
	if !openedInfo.IsDir() || !os.SameFile(packInfo, openedInfo) {
		return fmt.Errorf("Git pack directory changed while opening")
	}
	if _, err := readLocalGitPackDirectory(packRoot); err != nil {
		return err
	}
	afterInfo, err := objectsRoot.Lstat("pack")
	if err != nil {
		return fmt.Errorf("reinspect Git pack directory: %w", err)
	}
	if !afterInfo.IsDir() || !os.SameFile(openedInfo, afterInfo) {
		return fmt.Errorf("Git pack directory changed while validating")
	}
	return nil
}

func newLocalGitPackIndexCatalog(ctx context.Context, root *os.Root, algorithm evidence.RevisionAlgorithm, limits localGitPackLimits) (*localGitPackIndexCatalog, error) {
	if isNilInterface(ctx) {
		return nil, fmt.Errorf("Git pack catalog context is nil")
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if root == nil {
		return nil, fmt.Errorf("Git object root is nil")
	}
	hashLen, err := localGitObjectHashLength(algorithm)
	if err != nil {
		return nil, err
	}
	if err := rejectLocalGitPackedRootMetadata(root); err != nil {
		return nil, err
	}
	if err := validateLocalGitInfoDirectory(root); err != nil {
		return nil, err
	}
	packInfo, err := root.Lstat("pack")
	if err != nil {
		if os.IsNotExist(err) {
			return &localGitPackIndexCatalog{objectsRoot: root, algorithm: algorithm, hashLen: hashLen, limits: limits}, nil
		}
		return nil, fmt.Errorf("inspect Git pack directory: %w", err)
	}
	if !packInfo.IsDir() {
		return nil, fmt.Errorf("Git pack path is not a directory")
	}
	packRoot, err := root.OpenRoot("pack/.")
	if err != nil {
		return nil, fmt.Errorf("open Git pack directory: %w", err)
	}
	catalog := &localGitPackIndexCatalog{objectsRoot: root, packRoot: packRoot, packDirInfo: packInfo, algorithm: algorithm, hashLen: hashLen, limits: limits}
	if err := catalog.build(ctx); err != nil {
		_ = catalog.close()
		return nil, err
	}
	return catalog, nil
}

func (c *localGitPackIndexCatalog) build(ctx context.Context) error {
	openedInfo, err := c.packRoot.Stat(".")
	if err != nil {
		return fmt.Errorf("inspect opened Git pack directory: %w", err)
	}
	if !openedInfo.IsDir() || !os.SameFile(c.packDirInfo, openedInfo) {
		return fmt.Errorf("Git pack directory changed while opening")
	}
	files, err := readLocalGitPackDirectory(c.packRoot)
	if err != nil {
		return err
	}
	if len(files) > c.limits.maxPackCount {
		return LocalGitRevisionResourceLimit
	}
	if len(files) == 0 {
		return c.validatePackDirectoryStable()
	}
	buildScope := newLocalGitPackScope(nil, c)
	var totalPackBytes int64
	var totalObjects uint32
	var metadataBytes int64
	for _, pair := range files {
		if err := ctx.Err(); err != nil {
			return err
		}
		if len(pair.stem) != len("pack-")+c.hashLen*2 {
			return fmt.Errorf("Git pack stem does not match repository object algorithm")
		}
		pack, err := c.openPackPair(ctx, pair, buildScope)
		if err != nil {
			return err
		}
		c.packs = append(c.packs, pack)
		totalPackBytes += pack.packInfo.Size()
		if totalPackBytes < 0 || totalPackBytes > c.limits.maxTotalPackBytes {
			return LocalGitRevisionResourceLimit
		}
		if pack.objectCount > c.limits.maxObjectsPerPack || totalObjects > c.limits.maxTotalIndexedObjects-pack.objectCount {
			return LocalGitRevisionResourceLimit
		}
		totalObjects += pack.objectCount
		metadataBytes += int64(len(pack.offsetSlots)) * 16
		if metadataBytes < 0 || metadataBytes > c.limits.maxIndexMetadataBytes {
			return LocalGitRevisionResourceLimit
		}
	}
	if err := c.rejectDuplicateOIDsAcrossPacks(ctx, buildScope); err != nil {
		return err
	}
	if err := c.validatePackDirectoryStable(); err != nil {
		return err
	}
	c.catalogPhysicalBytes = buildScope.physicalReadBytes
	c.catalogChecksumPasses = 1
	return ctx.Err()
}

func (c *localGitPackIndexCatalog) openPackPair(ctx context.Context, pair localGitPackStemFiles, buildScope *localGitPackScope) (*localGitPackFile, error) {
	packBefore, err := c.packRoot.Lstat(pair.packName)
	if err != nil {
		return nil, fmt.Errorf("inspect Git pack %q: %w", pair.packName, err)
	}
	idxBefore, err := c.packRoot.Lstat(pair.idxName)
	if err != nil {
		return nil, fmt.Errorf("inspect Git pack index %q: %w", pair.idxName, err)
	}
	if !packBefore.Mode().IsRegular() || !idxBefore.Mode().IsRegular() {
		return nil, fmt.Errorf("Git pack and index files must be regular")
	}
	if packBefore.Size() < localGitPackHeaderBytes+int64(c.hashLen) || packBefore.Size() > c.limits.maxPackFileBytes || idxBefore.Size() > c.limits.maxPackFileBytes {
		return nil, LocalGitRevisionResourceLimit
	}
	packFile, err := c.packRoot.OpenFile(pair.packName, regularFileOpenFlags(), 0)
	if err != nil {
		return nil, fmt.Errorf("open Git pack %q: %w", pair.packName, err)
	}
	pack := &localGitPackFile{stem: pair.stem, packName: pair.packName, idxName: pair.idxName, packFile: packFile}
	committed := false
	defer func() {
		if !committed {
			_ = pack.close()
		}
	}()
	packInfo, err := packFile.Stat()
	if err != nil {
		return nil, fmt.Errorf("inspect opened Git pack %q: %w", pair.packName, err)
	}
	if !sameRegularFileWithStableMetadata(packBefore, packInfo) {
		return nil, fmt.Errorf("Git pack changed while opening")
	}
	idxFile, err := c.packRoot.OpenFile(pair.idxName, regularFileOpenFlags(), 0)
	if err != nil {
		return nil, fmt.Errorf("open Git pack index %q: %w", pair.idxName, err)
	}
	pack.idxFile = idxFile
	idxInfo, err := idxFile.Stat()
	if err != nil {
		return nil, fmt.Errorf("inspect opened Git pack index %q: %w", pair.idxName, err)
	}
	if !sameRegularFileWithStableMetadata(idxBefore, idxInfo) {
		return nil, fmt.Errorf("Git pack index changed while opening")
	}
	pack.packInfo = packInfo
	pack.idxInfo = idxInfo
	pack.packDataEnd = uint64(packInfo.Size() - int64(c.hashLen))
	if err := c.verifyIndex(ctx, pack, buildScope); err != nil {
		return nil, err
	}
	if err := c.verifyPack(ctx, pack, buildScope); err != nil {
		return nil, err
	}
	if err := c.validateIndexedObjectHeaders(ctx, pack, buildScope); err != nil {
		return nil, err
	}
	packAfter, err := c.packRoot.Lstat(pair.packName)
	if err != nil {
		return nil, fmt.Errorf("reinspect Git pack %q: %w", pair.packName, err)
	}
	idxAfter, err := c.packRoot.Lstat(pair.idxName)
	if err != nil {
		return nil, fmt.Errorf("reinspect Git pack index %q: %w", pair.idxName, err)
	}
	if !sameRegularFileWithStableMetadata(packInfo, packAfter) || !sameRegularFileWithStableMetadata(idxInfo, idxAfter) {
		return nil, fmt.Errorf("Git pack pair changed while cataloging")
	}
	committed = true
	return pack, nil
}

func (c *localGitPackIndexCatalog) verifyIndex(ctx context.Context, pack *localGitPackFile, buildScope *localGitPackScope) error {
	if pack.idxInfo.Size() < int64(8+256*4+2*c.hashLen) {
		return fmt.Errorf("Git pack index is too small")
	}
	reader := localGitCatalogReader{ctx: ctx, limit: c.limits.maxPhysicalReadBytes, scope: buildScope}
	var header [8]byte
	if err := reader.readAt(pack.idxFile, header[:], 0); err != nil {
		return err
	}
	if string(header[:4]) != localGitPackIndexMagic || binary.BigEndian.Uint32(header[4:8]) != 2 {
		return fmt.Errorf("unsupported Git pack index version")
	}
	var fanoutBytes [256 * 4]byte
	if err := reader.readAt(pack.idxFile, fanoutBytes[:], 8); err != nil {
		return err
	}
	var previous uint32
	for i := 0; i < 256; i++ {
		value := binary.BigEndian.Uint32(fanoutBytes[i*4 : i*4+4])
		if value < previous {
			return fmt.Errorf("Git pack index fanout is not monotonic")
		}
		pack.fanout[i] = value
		previous = value
	}
	pack.objectCount = pack.fanout[255]
	if pack.objectCount == 0 || pack.objectCount > c.limits.maxObjectsPerPack {
		return LocalGitRevisionResourceLimit
	}
	count := int64(pack.objectCount)
	pack.oidTableOffset = 8 + 256*4
	pack.crcTableOffset = pack.oidTableOffset + count*int64(c.hashLen)
	pack.offsetTableOffset = pack.crcTableOffset + count*4
	pack.largeOffsetTableOffset = pack.offsetTableOffset + count*4
	pack.packChecksumOffset = pack.idxInfo.Size() - int64(2*c.hashLen)
	pack.idxChecksumOffset = pack.idxInfo.Size() - int64(c.hashLen)
	if pack.largeOffsetTableOffset > pack.packChecksumOffset || (pack.packChecksumOffset-pack.largeOffsetTableOffset)%8 != 0 {
		return fmt.Errorf("Git pack index table bounds are invalid")
	}
	if err := c.verifyIndexChecksum(ctx, pack, &reader); err != nil {
		return err
	}
	if err := c.verifySortedOIDs(ctx, pack, &reader); err != nil {
		return err
	}
	if err := c.loadIndexOffsets(ctx, pack, &reader); err != nil {
		return err
	}
	return nil
}

func (c *localGitPackIndexCatalog) verifyIndexChecksum(ctx context.Context, pack *localGitPackFile, reader *localGitCatalogReader) error {
	hasher, err := newLocalGitObjectHasher(c.algorithm)
	if err != nil {
		return err
	}
	if err := streamLocalGitFileRange(ctx, pack.idxFile, 0, pack.idxChecksumOffset, hasher, reader); err != nil {
		return err
	}
	stored := make([]byte, c.hashLen)
	if err := reader.readAt(pack.idxFile, stored, pack.idxChecksumOffset); err != nil {
		return err
	}
	if string(hasher.Sum(nil)) != string(stored) {
		return fmt.Errorf("Git pack index checksum mismatch")
	}
	pack.idxChecksum = append([]byte{}, stored...)
	pack.packChecksum = make([]byte, c.hashLen)
	if err := reader.readAt(pack.idxFile, pack.packChecksum, pack.packChecksumOffset); err != nil {
		return err
	}
	return ctx.Err()
}

func (c *localGitPackIndexCatalog) verifySortedOIDs(ctx context.Context, pack *localGitPackFile, reader *localGitCatalogReader) error {
	var previous []byte
	counts := make([]uint32, 256)
	current := make([]byte, c.hashLen)
	for slot := uint32(0); slot < pack.objectCount; slot++ {
		if err := ctx.Err(); err != nil {
			return err
		}
		if err := reader.readAt(pack.idxFile, current, pack.oidOffset(slot)); err != nil {
			return err
		}
		if slot > 0 && string(previous) >= string(current) {
			return fmt.Errorf("Git pack index object IDs are not sorted and unique")
		}
		counts[int(current[0])]++
		previous = append(previous[:0], current...)
	}
	var cumulative uint32
	for i := 0; i < 256; i++ {
		cumulative += counts[i]
		if cumulative != pack.fanout[i] {
			return fmt.Errorf("Git pack index fanout does not match object IDs")
		}
	}
	return ctx.Err()
}

func (c *localGitPackIndexCatalog) loadIndexOffsets(ctx context.Context, pack *localGitPackFile, reader *localGitCatalogReader) error {
	largeRows := (pack.packChecksumOffset - pack.largeOffsetTableOffset) / 8
	pack.offsetSlots = make([]localGitPackOffsetSlot, 0, pack.objectCount)
	for slot := uint32(0); slot < pack.objectCount; slot++ {
		if err := ctx.Err(); err != nil {
			return err
		}
		offset, err := pack.offsetForSlot(ctx, slot, c.hashLen, reader)
		if err != nil {
			return err
		}
		if offset < localGitPackHeaderBytes || offset >= pack.packDataEnd {
			return fmt.Errorf("Git pack object offset is out of range")
		}
		if raw, err := pack.rawOffsetEntry(ctx, slot, reader); err != nil {
			return err
		} else if raw&0x80000000 != 0 && int64(raw&0x7fffffff) >= largeRows {
			return fmt.Errorf("Git pack index large-offset row is out of range")
		}
		pack.offsetSlots = append(pack.offsetSlots, localGitPackOffsetSlot{offset: offset, slot: slot})
	}
	sort.Slice(pack.offsetSlots, func(i, j int) bool { return pack.offsetSlots[i].offset < pack.offsetSlots[j].offset })
	if len(pack.offsetSlots) == 0 || pack.offsetSlots[0].offset != localGitPackHeaderBytes {
		return fmt.Errorf("Git pack first object offset is invalid")
	}
	for i := 1; i < len(pack.offsetSlots); i++ {
		if pack.offsetSlots[i-1].offset == pack.offsetSlots[i].offset {
			return fmt.Errorf("Git pack index contains duplicate offsets")
		}
	}
	return ctx.Err()
}

func (c *localGitPackIndexCatalog) verifyPack(ctx context.Context, pack *localGitPackFile, buildScope *localGitPackScope) error {
	reader := localGitCatalogReader{ctx: ctx, limit: c.limits.maxPhysicalReadBytes, scope: buildScope}
	var header [12]byte
	if err := reader.readAt(pack.packFile, header[:], 0); err != nil {
		return err
	}
	if string(header[:4]) != "PACK" || binary.BigEndian.Uint32(header[4:8]) != 2 || binary.BigEndian.Uint32(header[8:12]) != pack.objectCount {
		return fmt.Errorf("unsupported Git pack header")
	}
	hasher, err := newLocalGitObjectHasher(c.algorithm)
	if err != nil {
		return err
	}
	if err := streamLocalGitFileRange(ctx, pack.packFile, 0, pack.packInfo.Size()-int64(c.hashLen), hasher, &reader); err != nil {
		return err
	}
	trailer := make([]byte, c.hashLen)
	if err := reader.readAt(pack.packFile, trailer, pack.packInfo.Size()-int64(c.hashLen)); err != nil {
		return err
	}
	if string(hasher.Sum(nil)) != string(trailer) || string(trailer) != string(pack.packChecksum) {
		return fmt.Errorf("Git pack checksum mismatch")
	}
	return ctx.Err()
}

func (c *localGitPackIndexCatalog) validateIndexedObjectHeaders(ctx context.Context, pack *localGitPackFile, buildScope *localGitPackScope) error {
	for i, slot := range pack.offsetSlots {
		if err := ctx.Err(); err != nil {
			return err
		}
		next := pack.packDataEnd
		if i+1 < len(pack.offsetSlots) {
			next = pack.offsetSlots[i+1].offset
		}
		header, err := pack.readObjectHeaderAt(ctx, slot.offset, c.hashLen, buildScope)
		if err != nil {
			return err
		}
		if header.compressedOffset >= next {
			return fmt.Errorf("Git pack object compressed data is out of range")
		}
		switch header.typeCode {
		case localGitPackTypeCommit, localGitPackTypeTree, localGitPackTypeBlob, localGitPackTypeTag:
		case localGitPackTypeOFSDelta:
			if header.baseOffset >= slot.offset {
				return fmt.Errorf("Git pack OFS_DELTA base offset is invalid")
			}
			if _, ok := pack.slotForOffset(header.baseOffset); !ok {
				return fmt.Errorf("Git pack OFS_DELTA base offset is not indexed")
			}
		case localGitPackTypeREFDelta:
			if _, ok, err := pack.lookupOID(ctx, header.baseOID, c.hashLen, buildScope); err != nil {
				return err
			} else if !ok {
				return fmt.Errorf("Git pack REF_DELTA base object is not in the same pack")
			}
		default:
			return fmt.Errorf("unsupported Git pack object type")
		}
	}
	return ctx.Err()
}

func (c *localGitPackIndexCatalog) rejectDuplicateOIDsAcrossPacks(ctx context.Context, buildScope *localGitPackScope) error {
	if len(c.packs) < 2 {
		return nil
	}
	type cursor struct {
		pack *localGitPackFile
		slot uint32
		oid  []byte
		done bool
	}
	cursors := make([]cursor, len(c.packs))
	for i, pack := range c.packs {
		oid, err := pack.oidAtSlot(ctx, 0, c.hashLen, buildScope)
		if err != nil {
			return err
		}
		cursors[i] = cursor{pack: pack, oid: oid}
	}
	for {
		if err := ctx.Err(); err != nil {
			return err
		}
		minIndex := -1
		for i := range cursors {
			if cursors[i].done {
				continue
			}
			if minIndex < 0 || string(cursors[i].oid) < string(cursors[minIndex].oid) {
				minIndex = i
			}
		}
		if minIndex < 0 {
			return nil
		}
		for i := range cursors {
			if i != minIndex && !cursors[i].done && string(cursors[i].oid) == string(cursors[minIndex].oid) {
				return fmt.Errorf("duplicate Git object ID across pack indexes")
			}
		}
		cursors[minIndex].slot++
		if cursors[minIndex].slot >= cursors[minIndex].pack.objectCount {
			cursors[minIndex].done = true
			continue
		}
		oid, err := cursors[minIndex].pack.oidAtSlot(ctx, cursors[minIndex].slot, c.hashLen, buildScope)
		if err != nil {
			return err
		}
		cursors[minIndex].oid = oid
	}
}

func (c *localGitPackIndexCatalog) readObject(ctx context.Context, digest string, expectedType string, maxPayloadBytes int64) ([]byte, error) {
	scope := newLocalGitPackScope(nil, c)
	return c.readObjectWithScope(ctx, digest, expectedType, maxPayloadBytes, scope)
}

func (c *localGitPackIndexCatalog) readObjectWithScope(ctx context.Context, digest string, expectedType string, maxPayloadBytes int64, scope *localGitPackScope) ([]byte, error) {
	if c == nil {
		return nil, LocalGitRevisionObjectUnavailable
	}
	expected, err := decodeGitObjectDigest(c.algorithm, digest)
	if err != nil {
		return nil, err
	}
	ref, ok, err := c.lookup(ctx, expected, scope)
	if err != nil {
		return nil, err
	}
	if !ok {
		return nil, LocalGitRevisionObjectUnavailable
	}
	payload, objectType, err := c.resolveObject(ctx, ref, expectedType, maxPayloadBytes, scope)
	if err != nil {
		return nil, err
	}
	if objectType != expectedType {
		return nil, LocalGitRevisionInvalidGraph
	}
	if err := verifyGitObjectPayloadDigest(c.algorithm, expected, expectedType, payload); err != nil {
		return nil, LocalGitRevisionInvalidGraph
	}
	return payload, ctx.Err()
}

func (c *localGitPackIndexCatalog) validateStable(ctx context.Context) error {
	scope := newLocalGitPackScope(nil, c)
	return c.validateStableWithScope(ctx, scope)
}

func (c *localGitPackIndexCatalog) validateStableWithScope(ctx context.Context, scope *localGitPackScope) error {
	if c == nil || isNilInterface(ctx) {
		return fmt.Errorf("Git pack catalog validation is nil")
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	if c.packRoot == nil {
		return nil
	}
	if err := scope.chargeChecksumPass(); err != nil {
		return err
	}
	if err := c.validatePackDirectoryStable(); err != nil {
		return err
	}
	for _, pack := range c.packs {
		if err := c.revalidateOpenedPack(ctx, pack, scope); err != nil {
			return err
		}
	}
	return ctx.Err()
}

func (c *localGitPackIndexCatalog) revalidateOpenedPack(ctx context.Context, pack *localGitPackFile, scope *localGitPackScope) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	packAfter, err := c.packRoot.Lstat(pack.packName)
	if err != nil {
		return fmt.Errorf("reinspect Git pack %q: %w", pack.packName, err)
	}
	idxAfter, err := c.packRoot.Lstat(pack.idxName)
	if err != nil {
		return fmt.Errorf("reinspect Git pack index %q: %w", pack.idxName, err)
	}
	if !sameRegularFileWithStableMetadata(pack.packInfo, packAfter) || !sameRegularFileWithStableMetadata(pack.idxInfo, idxAfter) {
		return fmt.Errorf("Git pack pair changed after acquisition")
	}
	reader := localGitCatalogReader{ctx: ctx, limit: c.limits.maxPhysicalReadBytes, scope: scope}
	hasher, err := newLocalGitObjectHasher(c.algorithm)
	if err != nil {
		return err
	}
	if err := streamLocalGitFileRange(ctx, pack.packFile, 0, pack.packInfo.Size()-int64(c.hashLen), hasher, &reader); err != nil {
		return err
	}
	trailer := make([]byte, c.hashLen)
	if err := reader.readAt(pack.packFile, trailer, pack.packInfo.Size()-int64(c.hashLen)); err != nil {
		return err
	}
	if string(hasher.Sum(nil)) != string(trailer) || string(trailer) != string(pack.packChecksum) {
		return fmt.Errorf("Git pack checksum changed")
	}
	hasher, err = newLocalGitObjectHasher(c.algorithm)
	if err != nil {
		return err
	}
	if err := streamLocalGitFileRange(ctx, pack.idxFile, 0, pack.idxChecksumOffset, hasher, &reader); err != nil {
		return err
	}
	stored := make([]byte, c.hashLen)
	if err := reader.readAt(pack.idxFile, stored, pack.idxChecksumOffset); err != nil {
		return err
	}
	if string(hasher.Sum(nil)) != string(stored) || string(stored) != string(pack.idxChecksum) {
		return fmt.Errorf("Git pack index checksum changed")
	}
	return ctx.Err()
}

func (c *localGitPackIndexCatalog) validatePackDirectoryStable() error {
	if c.packRoot == nil {
		return nil
	}
	afterInfo, err := c.objectsRoot.Lstat("pack")
	if err != nil {
		return fmt.Errorf("reinspect Git pack directory: %w", err)
	}
	openedInfo, err := c.packRoot.Stat(".")
	if err != nil {
		return fmt.Errorf("inspect opened Git pack directory: %w", err)
	}
	if !afterInfo.IsDir() || !openedInfo.IsDir() || !os.SameFile(c.packDirInfo, openedInfo) || !os.SameFile(openedInfo, afterInfo) {
		return fmt.Errorf("Git pack directory changed")
	}
	return nil
}

func (c *localGitPackIndexCatalog) close() error {
	if c == nil {
		return nil
	}
	var closeErr error
	for _, pack := range c.packs {
		if err := pack.close(); err != nil && closeErr == nil {
			closeErr = err
		}
	}
	if c.packRoot != nil {
		if err := c.packRoot.Close(); err != nil && closeErr == nil {
			closeErr = err
		}
		c.packRoot = nil
	}
	return closeErr
}

func (p *localGitPackFile) close() error {
	if p == nil {
		return nil
	}
	var closeErr error
	if p.packFile != nil {
		if err := p.packFile.Close(); err != nil {
			closeErr = err
		}
		p.packFile = nil
	}
	if p.idxFile != nil {
		if err := p.idxFile.Close(); err != nil && closeErr == nil {
			closeErr = err
		}
		p.idxFile = nil
	}
	return closeErr
}

func (c *localGitPackIndexCatalog) lookup(ctx context.Context, oid []byte, scope *localGitPackScope) (localGitPackObjectRef, bool, error) {
	for _, pack := range c.packs {
		ref, ok, err := pack.lookupOID(ctx, oid, c.hashLen, scope)
		if err != nil || ok {
			return ref, ok, err
		}
	}
	return localGitPackObjectRef{}, false, ctx.Err()
}

func (p *localGitPackFile) lookupOID(ctx context.Context, oid []byte, hashLen int, scope *localGitPackScope) (localGitPackObjectRef, bool, error) {
	if len(oid) != hashLen || p.objectCount == 0 {
		return localGitPackObjectRef{}, false, nil
	}
	start := uint32(0)
	if oid[0] > 0 {
		start = p.fanout[int(oid[0])-1]
	}
	end := p.fanout[int(oid[0])]
	lo, hi := start, end
	for lo < hi {
		if err := ctx.Err(); err != nil {
			return localGitPackObjectRef{}, false, err
		}
		mid := lo + (hi-lo)/2
		current, err := p.oidAtSlot(ctx, mid, hashLen, scope)
		if err != nil {
			return localGitPackObjectRef{}, false, err
		}
		if string(current) < string(oid) {
			lo = mid + 1
		} else {
			hi = mid
		}
	}
	if lo >= end {
		return localGitPackObjectRef{}, false, ctx.Err()
	}
	current, err := p.oidAtSlot(ctx, lo, hashLen, scope)
	if err != nil {
		return localGitPackObjectRef{}, false, err
	}
	if string(current) != string(oid) {
		return localGitPackObjectRef{}, false, ctx.Err()
	}
	return p.refForSlot(ctx, lo, current, hashLen, scope)
}

func (p *localGitPackFile) refForSlot(ctx context.Context, slot uint32, oid []byte, hashLen int, scope *localGitPackScope) (localGitPackObjectRef, bool, error) {
	offset, err := p.offsetForSlot(ctx, slot, hashLen, scopedCatalogReader(ctx, scope))
	if err != nil {
		return localGitPackObjectRef{}, false, err
	}
	index := sort.Search(len(p.offsetSlots), func(i int) bool { return p.offsetSlots[i].offset >= offset })
	if index >= len(p.offsetSlots) || p.offsetSlots[index].offset != offset {
		return localGitPackObjectRef{}, false, fmt.Errorf("Git pack object offset is not indexed")
	}
	nextOffset := p.packDataEnd
	if index+1 < len(p.offsetSlots) {
		nextOffset = p.offsetSlots[index+1].offset
	}
	crc, err := p.crcForSlot(ctx, slot, scopedCatalogReader(ctx, scope))
	if err != nil {
		return localGitPackObjectRef{}, false, err
	}
	return localGitPackObjectRef{pack: p, slot: slot, oid: append([]byte{}, oid...), offset: offset, nextOffset: nextOffset, crc: crc}, true, nil
}

func (p *localGitPackFile) slotForOffset(offset uint64) (uint32, bool) {
	index := sort.Search(len(p.offsetSlots), func(i int) bool { return p.offsetSlots[i].offset >= offset })
	if index >= len(p.offsetSlots) || p.offsetSlots[index].offset != offset {
		return 0, false
	}
	return p.offsetSlots[index].slot, true
}

func (p *localGitPackFile) oidAtSlot(ctx context.Context, slot uint32, hashLen int, scope *localGitPackScope) ([]byte, error) {
	if slot >= p.objectCount {
		return nil, fmt.Errorf("Git pack index slot is out of range")
	}
	oid := make([]byte, hashLen)
	if err := scopedCatalogReader(ctx, scope).readAt(p.idxFile, oid, p.oidOffset(slot)); err != nil {
		return nil, err
	}
	return oid, ctx.Err()
}

func (p *localGitPackFile) oidOffset(slot uint32) int64 {
	return p.oidTableOffset + int64(slot)*int64(len(p.packChecksum))
}

func (p *localGitPackFile) crcForSlot(ctx context.Context, slot uint32, reader *localGitCatalogReader) (uint32, error) {
	var raw [4]byte
	if err := reader.readAt(p.idxFile, raw[:], p.crcTableOffset+int64(slot)*4); err != nil {
		return 0, err
	}
	return binary.BigEndian.Uint32(raw[:]), ctx.Err()
}

func (p *localGitPackFile) rawOffsetEntry(ctx context.Context, slot uint32, reader *localGitCatalogReader) (uint32, error) {
	var raw [4]byte
	if err := reader.readAt(p.idxFile, raw[:], p.offsetTableOffset+int64(slot)*4); err != nil {
		return 0, err
	}
	return binary.BigEndian.Uint32(raw[:]), ctx.Err()
}

func (p *localGitPackFile) offsetForSlot(ctx context.Context, slot uint32, hashLen int, reader *localGitCatalogReader) (uint64, error) {
	raw, err := p.rawOffsetEntry(ctx, slot, reader)
	if err != nil {
		return 0, err
	}
	if raw&0x80000000 == 0 {
		return uint64(raw), ctx.Err()
	}
	row := int64(raw & 0x7fffffff)
	largeRows := (p.packChecksumOffset - p.largeOffsetTableOffset) / 8
	if row < 0 || row >= largeRows {
		return 0, fmt.Errorf("Git pack index large-offset row is out of range")
	}
	var rawLarge [8]byte
	if err := reader.readAt(p.idxFile, rawLarge[:], p.largeOffsetTableOffset+row*8); err != nil {
		return 0, err
	}
	return binary.BigEndian.Uint64(rawLarge[:]), ctx.Err()
}

type localGitCatalogReader struct {
	ctx       context.Context
	limit     int64
	readBytes int64
	scope     *localGitPackScope
}

func scopedCatalogReader(ctx context.Context, scope *localGitPackScope) *localGitCatalogReader {
	limit := int64(maxLocalGitPackPhysicalReadBytes)
	if scope != nil && scope.catalog != nil {
		limit = scope.catalog.limits.maxPhysicalReadBytes
	}
	return &localGitCatalogReader{ctx: ctx, limit: limit, scope: scope}
}

func (r *localGitCatalogReader) readAt(file *os.File, buffer []byte, offset int64) error {
	if err := r.ctx.Err(); err != nil {
		return err
	}
	readBytes := int64(len(buffer))
	if offset < 0 {
		return LocalGitRevisionResourceLimit
	}
	if r.scope != nil {
		if err := r.scope.chargePhysicalRead(readBytes); err != nil {
			return err
		}
	} else if readBytes > r.limit-r.readBytes {
		return LocalGitRevisionResourceLimit
	}
	if _, err := file.ReadAt(buffer, offset); err != nil {
		return err
	}
	r.readBytes += readBytes
	return r.ctx.Err()
}

func streamLocalGitFileRange(ctx context.Context, file *os.File, offset int64, length int64, hasher hash.Hash, reader *localGitCatalogReader) error {
	if length < 0 {
		return fmt.Errorf("Git file range is invalid")
	}
	buffer := make([]byte, 64*1024)
	remaining := length
	cursor := offset
	for remaining > 0 {
		if err := ctx.Err(); err != nil {
			return err
		}
		chunk := int64(len(buffer))
		if remaining < chunk {
			chunk = remaining
		}
		if err := reader.readAt(file, buffer[:int(chunk)], cursor); err != nil {
			return err
		}
		_, _ = hasher.Write(buffer[:int(chunk)])
		cursor += chunk
		remaining -= chunk
	}
	return ctx.Err()
}

func localGitObjectHashLength(algorithm evidence.RevisionAlgorithm) (int, error) {
	switch algorithm {
	case evidence.RevisionAlgorithmSHA1:
		return sha1.Size, nil
	case evidence.RevisionAlgorithmSHA256:
		return sha256.Size, nil
	default:
		return 0, fmt.Errorf("unsupported Git object algorithm %q", algorithm)
	}
}

func newLocalGitObjectHasher(algorithm evidence.RevisionAlgorithm) (hash.Hash, error) {
	switch algorithm {
	case evidence.RevisionAlgorithmSHA1:
		return sha1.New(), nil
	case evidence.RevisionAlgorithmSHA256:
		return sha256.New(), nil
	default:
		return nil, fmt.Errorf("unsupported Git object algorithm %q", algorithm)
	}
}

func readLocalGitPackDirectory(packRoot *os.Root) ([]localGitPackStemFiles, error) {
	dir, err := packRoot.OpenFile(".", regularFileOpenFlags(), 0)
	if err != nil {
		return nil, fmt.Errorf("open Git pack directory for listing: %w", err)
	}
	defer dir.Close()
	entries, err := dir.ReadDir(maxLocalGitPackDirectoryEntries + 1)
	if err != nil && err != io.EOF {
		return nil, fmt.Errorf("read Git pack directory: %w", err)
	}
	if len(entries) > maxLocalGitPackDirectoryEntries {
		return nil, LocalGitRevisionResourceLimit
	}
	stems := map[string]*localGitPackStemFiles{}
	for _, entry := range entries {
		name := entry.Name()
		if strings.HasPrefix(name, "multi-pack-index") || strings.HasSuffix(name, ".promisor") {
			return nil, fmt.Errorf("unsupported Git pack authority file %q", name)
		}
		match := localGitPackFileNamePattern.FindStringSubmatch(name)
		if match == nil {
			return nil, fmt.Errorf("unsupported Git pack directory entry %q", name)
		}
		info, err := packRoot.Lstat(name)
		if err != nil {
			return nil, fmt.Errorf("inspect Git pack directory entry %q: %w", name, err)
		}
		if !info.Mode().IsRegular() {
			return nil, fmt.Errorf("Git pack directory entry %q is not regular", name)
		}
		stem := "pack-" + match[1]
		ext := match[2]
		files := stems[stem]
		if files == nil {
			files = &localGitPackStemFiles{stem: stem, sidecars: map[string]string{}}
			stems[stem] = files
		}
		switch ext {
		case "pack":
			if files.packName != "" {
				return nil, fmt.Errorf("duplicate Git pack file stem %q", stem)
			}
			files.packName = name
		case "idx":
			if files.idxName != "" {
				return nil, fmt.Errorf("duplicate Git pack index stem %q", stem)
			}
			files.idxName = name
		default:
			if _, exists := files.sidecars[ext]; exists {
				return nil, fmt.Errorf("duplicate Git pack sidecar %q", name)
			}
			files.sidecars[ext] = name
		}
	}
	result := make([]localGitPackStemFiles, 0, len(stems))
	for _, files := range stems {
		if files.packName == "" || files.idxName == "" {
			return nil, fmt.Errorf("Git pack stem %q is missing its pack/index pair", files.stem)
		}
		result = append(result, *files)
	}
	sort.Slice(result, func(i, j int) bool { return result[i].stem < result[j].stem })
	return result, nil
}

func rejectLocalGitPackedRootMetadata(objectsRoot *os.Root) error {
	for _, name := range []string{"alternates", "http-alternates", "commondir", "gitdir", ".git", "objects", "HEAD", "config"} {
		info, err := objectsRoot.Lstat(name)
		if err == nil {
			if info.Mode().IsRegular() || info.IsDir() || info.Mode()&os.ModeType != 0 {
				return fmt.Errorf("unsupported Git object-root metadata %q", name)
			}
		}
		if err != nil && !os.IsNotExist(err) {
			return fmt.Errorf("inspect Git object-root metadata %q: %w", name, err)
		}
	}
	return nil
}

func validateLocalGitInfoDirectory(objectsRoot *os.Root) error {
	info, err := objectsRoot.Lstat("info")
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return fmt.Errorf("inspect Git objects info directory: %w", err)
	}
	if !info.IsDir() {
		return fmt.Errorf("Git objects info path is not a directory")
	}
	infoRoot, err := objectsRoot.OpenRoot("info/.")
	if err != nil {
		return fmt.Errorf("open Git objects info directory: %w", err)
	}
	defer infoRoot.Close()
	openedInfo, err := infoRoot.Stat(".")
	if err != nil {
		return fmt.Errorf("inspect opened Git objects info directory: %w", err)
	}
	if !openedInfo.IsDir() || !os.SameFile(info, openedInfo) {
		return fmt.Errorf("Git objects info directory changed while opening")
	}
	for _, name := range []string{"alternates", "http-alternates"} {
		_, err := infoRoot.Lstat(name)
		if err == nil {
			return fmt.Errorf("unsupported Git objects info metadata %q", name)
		}
		if err != nil && !os.IsNotExist(err) {
			return fmt.Errorf("inspect Git objects info metadata %q: %w", name, err)
		}
	}
	return nil
}

func sameRegularFileWithStableMetadata(first, second os.FileInfo) bool {
	return first != nil && second != nil && first.Mode().IsRegular() && second.Mode().IsRegular() && os.SameFile(first, second) && first.Size() == second.Size() && first.ModTime().Equal(second.ModTime())
}

func hexOID(oid []byte) string {
	return hex.EncodeToString(oid)
}
