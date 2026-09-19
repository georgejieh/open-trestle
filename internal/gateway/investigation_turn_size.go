package gateway

import (
	"errors"
	"math"
	"reflect"
	"strconv"
)

const (
	investigationTurnSizeRequestLimit  = uint64(8 << 20)
	investigationTurnSizeResponseLimit = uint64(8 << 20)
	investigationTurnSizePartLimit     = 2 << 20
	investigationTurnSizePartCount     = 64
	investigationTurnSizeDepthLimit    = 16
)

var errInvestigationTurnSize = errors.New("invalid investigation turn size estimate")

// EstimateInvestigationTurnPayloadBytes bounds raw retained-turn encoding before dispatch.
// The caller must measure the same request it dispatches and separately check artifact
// payload admission, exact artifact metadata and actual framing. No authority is issued.
func EstimateInvestigationTurnPayloadBytes(requestPayloadBytes uint64) (uint64, error) {
	if requestPayloadBytes == 0 || requestPayloadBytes > investigationTurnSizeRequestLimit {
		return 0, errInvestigationTurnSize
	}
	metadata, err := investigationTurnMetadataBound(investigationTurnEncodingShape)
	if err != nil {
		return 0, err
	}
	request, err := investigationTurnBase64Bound(requestPayloadBytes)
	if err != nil {
		return 0, err
	}
	response, err := investigationTurnBase64Bound(investigationTurnSizeResponseLimit)
	if err != nil {
		return 0, err
	}
	// Fragmented base64 adds at most four bytes per additional part, not a new 2 MiB payload.
	response, err = investigationTurnSizeAdd(response, 4*(investigationTurnSizePartCount-1))
	if err != nil {
		return 0, err
	}
	bound, err := investigationTurnSizeAdd(metadata, request)
	if err != nil {
		return 0, err
	}
	return investigationTurnSizeAdd(bound, response)
}

func investigationTurnBase64Bound(size uint64) (uint64, error) {
	padded, err := investigationTurnSizeAdd(size, 2)
	if err != nil {
		return 0, err
	}
	return investigationTurnSizeMultiply(padded/3, 4)
}

func investigationTurnSizeAdd(left, right uint64) (uint64, error) {
	if left > math.MaxUint64-right {
		return 0, errInvestigationTurnSize
	}
	return left + right, nil
}

func investigationTurnSizeMultiply(left, right uint64) (uint64, error) {
	if right != 0 && left > math.MaxUint64/right {
		return 0, errInvestigationTurnSize
	}
	return left * right, nil
}

type investigationTurnSizeWalk struct {
	ancestors        [investigationTurnSizeDepthLimit + 1]*investigationTurnShape
	requestPayloads  int
	responsePayloads int
	responseArrays   int
}

func investigationTurnMetadataBound(shape *investigationTurnShape) (uint64, error) {
	walk := investigationTurnSizeWalk{}
	bound, err := walk.value(shape, "", 0)
	if err != nil || walk.requestPayloads != 1 || walk.responsePayloads != 1 || walk.responseArrays != 1 {
		return 0, errInvestigationTurnSize
	}
	return bound, nil
}

func (w *investigationTurnSizeWalk) value(shape *investigationTurnShape, path string, depth int) (uint64, error) {
	if shape == nil || depth > investigationTurnSizeDepthLimit {
		return 0, errInvestigationTurnSize
	}
	for _, ancestor := range w.ancestors[:depth] {
		if ancestor == shape {
			return 0, errInvestigationTurnSize
		}
	}
	w.ancestors[depth] = shape
	if shape.limit < 0 || shape.payload != "" && shape.kind != reflect.String || shape.element != nil && shape.kind != reflect.Slice || len(shape.fields) != 0 && shape.kind != reflect.Struct || shape.selectionCount && shape.kind != reflect.Slice {
		return 0, errInvestigationTurnSize
	}
	switch path {
	case "", "request", "dispatch", "dispatch.response", "dispatch.response.parts[]":
		if shape.kind != reflect.Struct {
			return 0, errInvestigationTurnSize
		}
	case "dispatch.response.parts":
		if shape.kind != reflect.Slice || shape.limit != investigationTurnSizePartCount {
			return 0, errInvestigationTurnSize
		}
		w.responseArrays++
		if w.responseArrays != 1 {
			return 0, errInvestigationTurnSize
		}
	case "request.payload_b64":
		if shape.kind != reflect.String || shape.payload != "request" || uint64(shape.limit) != investigationTurnSizeRequestLimit {
			return 0, errInvestigationTurnSize
		}
	case "dispatch.response.parts[].payload_b64":
		if shape.kind != reflect.String || shape.payload != "response" || shape.limit != investigationTurnSizePartLimit {
			return 0, errInvestigationTurnSize
		}
	}
	if shape.payload != "" {
		switch {
		case path == "request.payload_b64" && shape.payload == "request":
			w.requestPayloads++
			if w.requestPayloads != 1 {
				return 0, errInvestigationTurnSize
			}
		case path == "dispatch.response.parts[].payload_b64" && shape.payload == "response":
			w.responsePayloads++
			if w.responsePayloads != 1 {
				return 0, errInvestigationTurnSize
			}
		default:
			return 0, errInvestigationTurnSize
		}
	}
	switch shape.kind {
	case reflect.Struct:
		if shape.bits != 0 || shape.limit != 0 {
			return 0, errInvestigationTurnSize
		}
		bound := uint64(2)
		for i, field := range shape.fields {
			name, ok := investigationTurnSizeFieldName(field.prefix)
			if !ok {
				return 0, errInvestigationTurnSize
			}
			for _, previous := range shape.fields[:i] {
				if previous.prefix == field.prefix {
					return 0, errInvestigationTurnSize
				}
			}
			childPath := name
			if path != "" {
				childPath = path + "." + name
			}
			child, err := w.value(field.shape, childPath, depth+1)
			if err != nil {
				return 0, err
			}
			child, err = investigationTurnSizeAdd(child, uint64(len(field.prefix)))
			if err != nil {
				return 0, err
			}
			if i > 0 {
				child, err = investigationTurnSizeAdd(child, 1)
				if err != nil {
					return 0, err
				}
			}
			bound, err = investigationTurnSizeAdd(bound, child)
			if err != nil {
				return 0, err
			}
		}
		return bound, nil
	case reflect.Slice:
		if shape.bits != 0 || shape.limit == 0 {
			return 0, errInvestigationTurnSize
		}
		element, err := w.value(shape.element, path+"[]", depth+1)
		if err != nil {
			return 0, err
		}
		count := uint64(shape.limit)
		bound, err := investigationTurnSizeMultiply(element, count)
		if err != nil {
			return 0, err
		}
		bound, err = investigationTurnSizeAdd(bound, count-1)
		if err != nil {
			return 0, err
		}
		return investigationTurnSizeAdd(bound, 2)
	case reflect.String:
		if shape.bits != 0 || shape.limit == 0 {
			return 0, errInvestigationTurnSize
		}
		if shape.payload != "" {
			return 2, nil
		}
		// JSON escaping uses at most six encoded bytes per decoded UTF-8 byte.
		text, err := investigationTurnSizeMultiply(uint64(shape.limit), 6)
		if err != nil {
			return 0, err
		}
		return investigationTurnSizeAdd(text, 2)
	case reflect.Bool:
		if shape.bits != 0 || shape.limit != 0 {
			return 0, errInvestigationTurnSize
		}
		return 5, nil
	case reflect.Int, reflect.Int64, reflect.Uint8, reflect.Uint32, reflect.Uint64:
		if shape.limit != 0 {
			return 0, errInvestigationTurnSize
		}
		expectedBits, digits := 64, uint64(20)
		switch shape.kind {
		case reflect.Int:
			expectedBits = strconv.IntSize
		case reflect.Uint8:
			expectedBits, digits = 8, 3
		case reflect.Uint32:
			expectedBits, digits = 32, 10
		}
		if shape.bits != expectedBits {
			return 0, errInvestigationTurnSize
		}
		return digits, nil
	default:
		return 0, errInvestigationTurnSize
	}
}

func investigationTurnSizeFieldName(prefix string) (string, bool) {
	if len(prefix) < 4 || prefix[0] != '"' || prefix[len(prefix)-2:] != `":` {
		return "", false
	}
	name := prefix[1 : len(prefix)-2]
	for i := 0; i < len(name); i++ {
		value := name[i]
		if value >= 'a' && value <= 'z' || value >= 'A' && value <= 'Z' || value >= '0' && value <= '9' || value == '_' || value == '-' {
			continue
		}
		return "", false
	}
	return name, true
}
