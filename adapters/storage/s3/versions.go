package s3

import (
	"bytes"
	"context"
	"encoding/xml"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/georgejieh/open-trestle/artifact"
)

func validErasureCursor(key string, cursor artifact.VersionCursor) bool {
	if cursor.KeyMarker == "" && cursor.VersionIDMarker == "" {
		return true
	}
	return cursor.KeyMarker == key && validErasureVersionID(cursor.VersionIDMarker)
}
func (b *ErasureBackend) newErasureVersionListRequest(ctx context.Context, key artifact.ExactObjectKey, owner string, cursor artifact.VersionCursor, limit uint16) (*http.Request, error) {
	query := url.Values{"versions": {""}, "prefix": {key.Key()}, "max-keys": {strconv.Itoa(int(limit))}}
	if cursor.KeyMarker != "" {
		query.Set("key-marker", cursor.KeyMarker)
		query.Set("version-id-marker", cursor.VersionIDMarker)
	}
	requestURL := *b.base.endpoint
	requestURL.Path = "/" + b.base.bucket
	requestURL.RawPath = "/" + url.PathEscape(b.base.bucket)
	requestURL.RawQuery = canonicalQuery(query)
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, requestURL.String(), nil)
	if err != nil {
		return nil, ErrInvalidRequest
	}
	provider := b.base.credentials.(*staticCredentialsProvider)
	credentials := provider.credentials
	at := b.base.clock.Now().UTC()
	if at.UnixMilli() <= 0 {
		return nil, ErrInvalidRequest
	}
	request.Header.Set("X-Amz-Expected-Bucket-Owner", owner)
	request.Header.Set("X-Amz-Date", at.Format("20060102T150405Z"))
	request.Header.Set("X-Amz-Content-Sha256", digestHex(nil))
	if credentials.sessionToken != "" {
		request.Header.Set("X-Amz-Security-Token", credentials.sessionToken)
	}
	signRequest(request, credentials, b.base.region, at)
	request.Close = true
	request.GetBody = nil
	request.ContentLength = 0
	return request, nil
}
func (b *ErasureBackend) ListObjectVersions(ctx context.Context, key artifact.ExactObjectKey, owner string, cursor artifact.VersionCursor, limit uint16, maximum uint32) (artifact.VersionPage, error) {
	if err := b.erasurePreflight(ctx, key, owner); err != nil {
		return artifact.VersionPage{}, err
	}
	if limit < 1 || limit > 256 || maximum < 4096 || maximum > 1<<20 || !validErasureCursor(key.Key(), cursor) {
		return artifact.VersionPage{}, ErrInvalidRequest
	}
	request, err := b.newErasureVersionListRequest(ctx, key, owner, cursor, limit)
	if err != nil {
		return artifact.VersionPage{}, err
	}
	response, content, err := b.erasureExchange(request, maximum)
	if err != nil {
		return artifact.VersionPage{}, err
	}
	defer clear(content)
	if response.StatusCode != 200 {
		return artifact.VersionPage{}, erasureStatusError(response.StatusCode)
	}
	return decodeVersionPage(content, b.base.bucket, key, cursor, limit)
}

// The XML tree is private, bounded and local to one response. No decoder skips
// unknown subtrees or accepts partial output. Checksum fields are metadata only.
type erasureXMLNode struct {
	name, text string
	children   []erasureXMLNode
}
type erasureXMLParser struct {
	decoder        *xml.Decoder
	namespace      string
	nodes, decoded int
}

func erasureXMLWhitespace(value []byte) bool {
	for _, c := range value {
		if c != ' ' && c != '\t' && c != '\r' && c != '\n' {
			return false
		}
	}
	return true
}
func parseErasureXML(content []byte, rootName string) (erasureXMLNode, error) {
	if len(content) == 0 || !utf8.Valid(content) {
		return erasureXMLNode{}, artifact.ErrRemoteObjectIntegrity
	}
	if len(content) > 1<<20 {
		return erasureXMLNode{}, artifact.ErrRemoteObjectTooLarge
	}
	parser := erasureXMLParser{decoder: xml.NewDecoder(bytes.NewReader(content))}
	parser.decoder.Strict = true
	declaration := false
	initial := true
	var root erasureXMLNode
	for {
		token, err := parser.decoder.Token()
		if err != nil {
			return erasureXMLNode{}, artifact.ErrRemoteObjectIntegrity
		}
		switch value := token.(type) {
		case xml.CharData:
			if !erasureXMLWhitespace(value) {
				return erasureXMLNode{}, artifact.ErrRemoteObjectIntegrity
			}
			initial = false
		case xml.ProcInst:
			if !initial || declaration || value.Target != "xml" || !validErasureXMLDeclaration(string(value.Inst)) {
				return erasureXMLNode{}, artifact.ErrRemoteObjectIntegrity
			}
			declaration = true
			initial = false
		case xml.StartElement:
			if value.Name.Local != rootName || value.Name.Space != "" && value.Name.Space != "http://s3.amazonaws.com/doc/2006-03-01/" {
				return erasureXMLNode{}, artifact.ErrRemoteObjectIntegrity
			}
			parser.namespace = value.Name.Space
			root, err = parser.element(value, 1)
			if err != nil {
				return erasureXMLNode{}, err
			}
			for {
				trailing, endErr := parser.decoder.Token()
				if endErr == io.EOF {
					return root, nil
				}
				if endErr != nil {
					return erasureXMLNode{}, artifact.ErrRemoteObjectIntegrity
				}
				whitespace, ok := trailing.(xml.CharData)
				if !ok || !erasureXMLWhitespace(whitespace) {
					return erasureXMLNode{}, artifact.ErrRemoteObjectIntegrity
				}
			}
		default:
			return erasureXMLNode{}, artifact.ErrRemoteObjectIntegrity
		}
	}
}
func validErasureXMLDeclaration(value string) bool {
	// No alternate encodings, standalone directive, or XML1.1 behavior.
	valid, _ := regexp.MatchString(`^version=("1\.0"|'1\.0')([ \t\r\n]+encoding=("UTF-8"|'UTF-8'))?[ \t\r\n]*$`, value)
	return valid
}
func (p *erasureXMLParser) element(start xml.StartElement, depth int) (erasureXMLNode, error) {
	if depth > 4 || p.nodes >= 8192 {
		return erasureXMLNode{}, artifact.ErrRemoteObjectTooLarge
	}
	p.nodes++
	if start.Name.Space != p.namespace {
		return erasureXMLNode{}, artifact.ErrRemoteObjectIntegrity
	}
	namespaceSeen := false
	for _, attr := range start.Attr {
		if namespaceSeen || attr.Name.Space != "" || attr.Name.Local != "xmlns" || attr.Value != p.namespace {
			return erasureXMLNode{}, artifact.ErrRemoteObjectIntegrity
		}
		namespaceSeen = true
	}
	node := erasureXMLNode{name: start.Name.Local}
	container := node.name == "ListVersionsResult" || node.name == "Error" || node.name == "Version" || node.name == "DeleteMarker" || node.name == "Owner"
	var text strings.Builder
	for {
		token, err := p.decoder.Token()
		if err != nil {
			return erasureXMLNode{}, artifact.ErrRemoteObjectIntegrity
		}
		switch value := token.(type) {
		case xml.StartElement:
			if !container {
				return erasureXMLNode{}, artifact.ErrRemoteObjectIntegrity
			}
			child, err := p.element(value, depth+1)
			if err != nil {
				return erasureXMLNode{}, err
			}
			node.children = append(node.children, child)
		case xml.CharData:
			p.decoded += len(value)
			if p.decoded > 1<<20 {
				return erasureXMLNode{}, artifact.ErrRemoteObjectTooLarge
			}
			if container {
				if !erasureXMLWhitespace(value) {
					return erasureXMLNode{}, artifact.ErrRemoteObjectIntegrity
				}
			} else {
				if text.Len()+len(value) > 1200 {
					return erasureXMLNode{}, artifact.ErrRemoteObjectTooLarge
				}
				text.Write(value)
			}
		case xml.EndElement:
			if value.Name != start.Name {
				return erasureXMLNode{}, artifact.ErrRemoteObjectIntegrity
			}
			node.text = text.String()
			return node, nil
		default:
			return erasureXMLNode{}, artifact.ErrRemoteObjectIntegrity
		}
	}
}
func erasureScalar(value string, minimum, maximum int) error {
	if len(value) > maximum {
		return artifact.ErrRemoteObjectTooLarge
	}
	if len(value) < minimum || !utf8.ValidString(value) {
		return artifact.ErrRemoteObjectIntegrity
	}
	for _, c := range value {
		if unicode.IsControl(c) {
			return artifact.ErrRemoteObjectIntegrity
		}
	}
	return nil
}
func erasureDecimal(value string, maximum uint64) bool {
	if len(value) == 0 {
		return false
	}
	for _, c := range value {
		if c < '0' || c > '9' {
			return false
		}
	}
	n, err := strconv.ParseUint(value, 10, 64)
	return err == nil && n <= maximum
}
func validErasureErrorXML(content []byte, code, bucket, key, version string) bool {
	if len(content) > 4096 {
		return false
	}
	root, err := parseErasureXML(content, "Error")
	if err != nil {
		return false
	}
	seen := make(map[string]bool)
	for _, field := range root.children {
		if seen[field.name] || len(field.children) != 0 {
			return false
		}
		seen[field.name] = true
		switch field.name {
		case "Code":
			if field.text != code {
				return false
			}
		case "Message", "RequestId", "HostId":
			if erasureScalar(field.text, 0, 1024) != nil {
				return false
			}
		case "Key":
			if erasureScalar(field.text, 1, 1024) != nil || field.text != key {
				return false
			}
		case "Resource":
			if erasureScalar(field.text, 1, 1200) != nil || field.text != "/"+bucket+"/"+key {
				return false
			}
		case "VersionId":
			if code != "NoSuchVersion" || erasureScalar(field.text, 1, 504) != nil || field.text != version {
				return false
			}
		default:
			return false
		}
	}
	return seen["Code"]
}

func decodeVersionPage(content []byte, bucket string, key artifact.ExactObjectKey, cursor artifact.VersionCursor, limit uint16) (artifact.VersionPage, error) {
	root, err := parseErasureXML(content, "ListVersionsResult")
	if err != nil {
		return artifact.VersionPage{}, err
	}
	scalars := make(map[string]string)
	entries := make([]artifact.VersionEntry, 0)
	versions := make(map[string]bool)
	latest := 0
	for _, node := range root.children {
		if node.name == "Version" || node.name == "DeleteMarker" {
			if len(entries) >= int(limit) || len(entries) >= 256 {
				return artifact.VersionPage{}, artifact.ErrRemoteObjectTooLarge
			}
			entry, err := decodeErasureVersionEntry(node, key)
			if err != nil {
				return artifact.VersionPage{}, err
			}
			id := entry.Version.VersionID()
			if versions[id] {
				return artifact.VersionPage{}, artifact.ErrRemoteObjectIntegrity
			}
			versions[id] = true
			if entry.IsLatest {
				latest++
			}
			if latest > 1 {
				return artifact.VersionPage{}, artifact.ErrRemoteObjectIntegrity
			}
			entries = append(entries, entry)
			continue
		}
		if len(node.children) != 0 {
			return artifact.VersionPage{}, artifact.ErrRemoteObjectIntegrity
		}
		if _, ok := scalars[node.name]; ok {
			return artifact.VersionPage{}, artifact.ErrRemoteObjectIntegrity
		}
		switch node.name {
		case "Name":
			if node.text != bucket {
				return artifact.VersionPage{}, artifact.ErrRemoteObjectIntegrity
			}
		case "Prefix":
			if node.text != key.Key() {
				return artifact.VersionPage{}, artifact.ErrRemoteObjectIntegrity
			}
		case "MaxKeys":
			if !erasureDecimal(node.text, 256) {
				return artifact.VersionPage{}, artifact.ErrRemoteObjectIntegrity
			}
			n, _ := strconv.ParseUint(node.text, 10, 16)
			if uint16(n) != limit {
				return artifact.VersionPage{}, artifact.ErrRemoteObjectIntegrity
			}
		case "IsTruncated":
			if node.text != "true" && node.text != "false" {
				return artifact.VersionPage{}, artifact.ErrRemoteObjectIntegrity
			}
		case "KeyMarker", "NextKeyMarker":
			if err := erasureScalar(node.text, 0, 1024); err != nil {
				return artifact.VersionPage{}, err
			}
		case "VersionIdMarker", "NextVersionIdMarker":
			if err := erasureScalar(node.text, 0, 504); err != nil {
				return artifact.VersionPage{}, err
			}
		default:
			return artifact.VersionPage{}, artifact.ErrRemoteObjectIntegrity
		}
		scalars[node.name] = node.text
	}
	for _, name := range []string{"Name", "Prefix", "MaxKeys", "IsTruncated"} {
		if _, ok := scalars[name]; !ok {
			return artifact.VersionPage{}, artifact.ErrRemoteObjectIntegrity
		}
	}
	if scalars["KeyMarker"] != cursor.KeyMarker || scalars["VersionIdMarker"] != cursor.VersionIDMarker {
		return artifact.VersionPage{}, artifact.ErrRemoteObjectIntegrity
	}
	page := artifact.VersionPage{Entries: entries, Truncated: scalars["IsTruncated"] == "true", ResponseBytes: uint32(len(content))}
	next := artifact.VersionCursor{KeyMarker: scalars["NextKeyMarker"], VersionIDMarker: scalars["NextVersionIdMarker"]}
	if page.Truncated {
		if len(entries) == 0 || next.KeyMarker == "" || !validErasureCursor(key.Key(), next) || next == cursor {
			return artifact.VersionPage{}, artifact.ErrRemoteObjectIntegrity
		}
		page.Next = next
	} else if next != (artifact.VersionCursor{}) {
		return artifact.VersionPage{}, artifact.ErrRemoteObjectIntegrity
	}
	// Continuation pages need not contain latest: an earlier page can hold it.
	// Whole-scan history and terminal fence acceptance belong to the core.
	if cursor == (artifact.VersionCursor{}) && !page.Truncated && len(entries) != 0 && latest != 1 {
		return artifact.VersionPage{}, artifact.ErrRemoteObjectIntegrity
	}
	return page, nil
}
func decodeErasureVersionEntry(node erasureXMLNode, key artifact.ExactObjectKey) (artifact.VersionEntry, error) {
	kind := artifact.ObjectVersionData
	if node.name == "DeleteMarker" {
		kind = artifact.ObjectVersionDeleteMarker
	}
	fields := make(map[string]string)
	algorithms := make(map[string]bool)
	ownerSeen := false
	for _, field := range node.children {
		if field.name == "Owner" {
			if ownerSeen {
				return artifact.VersionEntry{}, artifact.ErrRemoteObjectIntegrity
			}
			ownerSeen = true
			if err := validateErasureXMLOwner(field); err != nil {
				return artifact.VersionEntry{}, err
			}
			continue
		}
		if len(field.children) != 0 {
			return artifact.VersionEntry{}, artifact.ErrRemoteObjectIntegrity
		}
		if field.name == "ChecksumAlgorithm" {
			if kind != artifact.ObjectVersionData || algorithms[field.text] {
				return artifact.VersionEntry{}, artifact.ErrRemoteObjectIntegrity
			}
			switch field.text {
			case "CRC32", "CRC32C", "SHA1", "SHA256", "CRC64NVME":
			default:
				return artifact.VersionEntry{}, artifact.ErrRemoteObjectIntegrity
			}
			algorithms[field.text] = true
			continue
		}
		if _, ok := fields[field.name]; ok {
			return artifact.VersionEntry{}, artifact.ErrRemoteObjectIntegrity
		}
		switch field.name {
		case "Key":
			if err := erasureScalar(field.text, 1, 1024); err != nil {
				return artifact.VersionEntry{}, err
			}
			if field.text != key.Key() {
				return artifact.VersionEntry{}, artifact.ErrRemoteObjectIntegrity
			}
		case "VersionId":
			if err := erasureScalar(field.text, 1, 504); err != nil {
				return artifact.VersionEntry{}, err
			}
			if !validErasureVersionID(field.text) {
				return artifact.VersionEntry{}, artifact.ErrRemoteObjectIntegrity
			}
		case "IsLatest":
			if field.text != "true" && field.text != "false" {
				return artifact.VersionEntry{}, artifact.ErrRemoteObjectIntegrity
			}
		case "Size":
			if kind != artifact.ObjectVersionData || !erasureDecimal(field.text, maximumObjectBytes) {
				return artifact.VersionEntry{}, artifact.ErrRemoteObjectIntegrity
			}
		case "ETag":
			if kind != artifact.ObjectVersionData {
				return artifact.VersionEntry{}, artifact.ErrRemoteObjectIntegrity
			}
			if err := erasureScalar(field.text, 1, 256); err != nil {
				return artifact.VersionEntry{}, err
			}
		case "LastModified":
			if err := erasureScalar(field.text, 1, 64); err != nil {
				return artifact.VersionEntry{}, err
			}
			if _, err := time.Parse(time.RFC3339Nano, field.text); err != nil {
				return artifact.VersionEntry{}, artifact.ErrRemoteObjectIntegrity
			}
		case "StorageClass":
			if kind != artifact.ObjectVersionData {
				return artifact.VersionEntry{}, artifact.ErrRemoteObjectIntegrity
			}
			if err := erasureScalar(field.text, 1, 64); err != nil {
				return artifact.VersionEntry{}, err
			}
		case "ChecksumType":
			if kind != artifact.ObjectVersionData || field.text != "FULL_OBJECT" && field.text != "COMPOSITE" {
				return artifact.VersionEntry{}, artifact.ErrRemoteObjectIntegrity
			}
		default:
			return artifact.VersionEntry{}, artifact.ErrRemoteObjectIntegrity
		}
		fields[field.name] = field.text
	}
	for _, required := range []string{"Key", "VersionId", "IsLatest"} {
		if _, ok := fields[required]; !ok {
			return artifact.VersionEntry{}, artifact.ErrRemoteObjectIntegrity
		}
	}
	if _, ok := fields["Size"]; kind == artifact.ObjectVersionData && !ok {
		return artifact.VersionEntry{}, artifact.ErrRemoteObjectIntegrity
	}
	version, err := artifact.NewObjectVersion(key.NamespaceIdentity(), key.Key(), kind, fields["VersionId"])
	if err != nil {
		return artifact.VersionEntry{}, artifact.ErrRemoteObjectIntegrity
	}
	return artifact.VersionEntry{Version: version, IsLatest: fields["IsLatest"] == "true"}, nil
}
func validateErasureXMLOwner(node erasureXMLNode) error {
	seen := make(map[string]bool)
	for _, field := range node.children {
		if seen[field.name] || len(field.children) != 0 {
			return artifact.ErrRemoteObjectIntegrity
		}
		seen[field.name] = true
		switch field.name {
		case "ID":
			if err := erasureScalar(field.text, 1, 256); err != nil {
				return err
			}
		case "DisplayName":
			if err := erasureScalar(field.text, 0, 256); err != nil {
				return err
			}
		default:
			return artifact.ErrRemoteObjectIntegrity
		}
	}
	if !seen["ID"] {
		return artifact.ErrRemoteObjectIntegrity
	}
	return nil
}
