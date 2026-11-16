package mcpserver

import (
	"bytes"
	"context"
	"encoding/json"
	"testing"
)

func TestServerRejectsInvalidUTF8BeforeDispatch(t *testing.T) {
	for _, method := range []string{"tools/list", "tools/call"} {
		t.Run(method, func(t *testing.T) {
			reader := &readerStub{receipt: mcpReceipt(t)}
			server, err := New(reader)
			if err != nil {
				t.Fatal(err)
			}
			meta := requestMeta()
			meta["io.modelcontextprotocol/clientCapabilities"] = map[string]any{"invalid_marker": true}
			params := map[string]any{"_meta": meta}
			if method == "tools/call" {
				params["name"] = "open_trestle.run_status"
				params["arguments"] = map[string]any{"tenant_id": "tenant-a", "repository_id": "repo-a", "review_run_id": "run-a"}
			}
			input := bytes.Replace(requestLine(1, method, params), []byte("invalid_marker"), []byte{0xff}, 1)
			var output bytes.Buffer
			if err = server.Serve(context.Background(), bytes.NewReader(input), &output); err != nil {
				t.Fatal(err)
			}
			var response struct {
				ID    json.RawMessage `json:"id"`
				Error struct {
					Code int `json:"code"`
				} `json:"error"`
			}
			if err = json.Unmarshal(output.Bytes(), &response); err != nil {
				t.Fatal(err)
			}
			if string(response.ID) != "null" || response.Error.Code != -32700 || reader.calls != 0 {
				t.Fatalf("invalid UTF-8 reached dispatch: id=%s code=%d calls=%d", response.ID, response.Error.Code, reader.calls)
			}
		})
	}
}
