package agentprofile

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"strings"
)

var errDuplicateJSONKey = errors.New("duplicate JSON object key")

// decodeStrictJSON rejects empty input, duplicate keys, unknown fields, and trailing data.
func decodeStrictJSON(encoded []byte, destination any) error {
	if len(bytes.TrimSpace(encoded)) == 0 {
		return errors.New("empty JSON document")
	}
	if err := rejectDuplicateKeys(encoded); err != nil {
		return err
	}
	decoder := json.NewDecoder(bytes.NewReader(encoded))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(destination); err != nil {
		return err
	}
	if err := decoder.Decode(&struct{}{}); err != io.EOF {
		return errors.New("trailing JSON data")
	}
	return nil
}

func rejectDuplicateKeys(encoded []byte) error {
	decoder := json.NewDecoder(bytes.NewReader(encoded))
	var scan func(depth int) error
	scan = func(depth int) error {
		if depth > 32 {
			return errors.New("JSON nesting too deep")
		}
		token, err := decoder.Token()
		if err != nil {
			return err
		}
		delimiter, ok := token.(json.Delim)
		if !ok {
			return nil
		}
		switch delimiter {
		case '{':
			// encoding/json matches struct fields case-insensitively, so keys
			// that are equal under Unicode simple folding are duplicates too.
			seen := map[string]struct{}{}
			for decoder.More() {
				keyToken, err := decoder.Token()
				if err != nil {
					return err
				}
				key, ok := keyToken.(string)
				if !ok {
					return errors.New("invalid JSON object key")
				}
				folded := strings.ToLower(strings.ToUpper(key))
				if _, exists := seen[folded]; exists {
					return errDuplicateJSONKey
				}
				seen[folded] = struct{}{}
				if err := scan(depth + 1); err != nil {
					return err
				}
			}
		case '[':
			for decoder.More() {
				if err := scan(depth + 1); err != nil {
					return err
				}
			}
		default:
			return errors.New("unexpected JSON delimiter")
		}
		_, err = decoder.Token()
		return err
	}
	return scan(0)
}
