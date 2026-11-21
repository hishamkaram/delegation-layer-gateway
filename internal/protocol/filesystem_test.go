package protocol

import (
	"encoding/base64"
	"testing"
	"time"
)

func TestFilesystemSelectionRoundTripsUnixNamesAndRejectsTraversal(t *testing.T) {
	for _, name := range []string{".", "project:blue", "a\\b", ".hidden", "space dir/file", string([]byte{'a', 0xff, 'b'}), "line\nbreak"} {
		selection := FileSelection{ScopeID: "workspace", RelativePathBase64: base64.StdEncoding.EncodeToString([]byte(name))}
		got, err := selection.Path()
		if err != nil || got != name {
			t.Fatalf("lossless name selector rejected: %v", err)
		}
	}
	for _, name := range []string{"../outside", "/tmp", "a/../../outside", "a/./b", "a//b", "a\x00b"} {
		selection := FileSelection{ScopeID: "workspace", RelativePathBase64: base64.StdEncoding.EncodeToString([]byte(name))}
		if selection.Validate() == nil {
			t.Fatal("accepted escaping or noncanonical path")
		}
	}
	if (FileSelection{ScopeID: "workspace", RelativePath: "a", RelativePathBase64: "YQ=="}).Validate() == nil {
		t.Fatal("accepted ambiguous dual selector")
	}
}

func TestFilesystemWireRequiresRootAddressingAndRejectsLegacyWire(t *testing.T) {
	request := FilesystemRequest{Selection: FileSelection{ScopeID: "workspace", RelativePath: "."}}
	body, err := Encode(request, MaxFrameBytes)
	if err != nil {
		t.Fatal(err)
	}
	for _, op := range []Operation{ListDirectory, ReadFile, InspectFile, InspectGit} {
		command := Command{Operation: op, Root: WireContextGuard("root"), Body: body}
		if command.ValidateVersion(WireVersion2) != nil {
			t.Fatal("rooted filesystem command rejected")
		}
		if command.ValidateVersion(Version) == nil {
			t.Fatal("filesystem silently downgraded to legacy wire")
		}
		command.Root = ""
		command.Project = "alias"
		if command.ValidateVersion(WireVersion2) == nil {
			t.Fatal("filesystem accepted project alias instead of approved root routing")
		}
	}
}

func TestFilesystemRangeRequiresExactBytesCursorAndText(t *testing.T) {
	text := "PONG"
	request := FilesystemRequest{Selection: FileSelection{ScopeID: "workspace", RelativePath: "a"}, Limit: 4, ExpectedVersion: "metadata-v1"}
	valid := FilesystemResponse{SchemaVersion: 1, Operation: "read", ObservedAt: time.Now(), Read: &FileRange{DataBase64: "UE9ORw==", Text: &text, Offset: 0, NextOffset: 4, EOF: true, Version: "metadata-v1"}}
	if err := valid.ValidateFor(ReadFile, request); err != nil {
		t.Fatal(err)
	}
	mutations := []func(*FileRange){func(r *FileRange) { r.NextOffset = 3 }, func(r *FileRange) { r.DataBase64 = "UE9OR1g=" }, func(r *FileRange) { r.Version = "changed" }, func(r *FileRange) { wrong := "other"; r.Text = &wrong }}
	for _, mutate := range mutations {
		changed := *valid.Read
		mutate(&changed)
		result := valid
		result.Read = &changed
		if result.ValidateFor(ReadFile, request) == nil {
			t.Fatal("accepted a mismatched read range")
		}
	}
	ambiguous := valid
	ambiguous.List = &DirectoryPage{}
	if ambiguous.ValidateFor(ReadFile, request) == nil {
		t.Fatal("accepted multiple result bodies")
	}
}
