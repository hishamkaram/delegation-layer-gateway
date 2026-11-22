package protocol

import (
	"strings"
	"testing"
	"time"
)

func TestNativeModelFactsPaginateLongOpaqueIDs(t *testing.T) {
	facts := make([]ModelFact, 0, 145)
	for i := range 145 {
		facts = append(facts, ModelFact{ID: strings.Repeat("long namespace with spaces/", 20) + string(rune(0x1000+i)), Efforts: []string{"very high"}})
	}
	first, eof := PageModelFacts(facts, 0, 100)
	if len(first) != 100 || eof {
		t.Fatal("first page imposed a total catalog ceiling")
	}
	second, eof := PageModelFacts(facts, 100, 100)
	if len(second) != 45 || !eof {
		t.Fatal("second page lost Native facts")
	}
	q := ModelQuery{Selection: FileSelection{ScopeID: "workspace", RelativePath: "."}, Provider: "provider"}
	page := ModelPage{Provider: "provider", ObservedAt: time.Now(), Status: "available", ReasonCode: "discovered", Source: "native", CatalogComplete: true, Version: strings.Repeat("a", 64), Models: second, Efforts: []string{"very high"}, EOF: true}
	if err := page.ValidateFor(q); err != nil {
		t.Fatal("valid Native catalog text rejected", err)
	}
}

func TestModelCursorBindsObservationAndSelectionWithoutRetainingState(t *testing.T) {
	binding, catalog := strings.Repeat("a", 64), strings.Repeat("b", 64)
	encoded, err := EncodeModelCursor(ModelCursor{Version: 1, BindingSHA256: binding, CatalogSHA256: catalog, Next: 100})
	if err != nil {
		t.Fatal(err)
	}
	cursor, err := DecodeModelCursor(encoded, binding, catalog)
	if err != nil || cursor.Next != 100 {
		t.Fatal("cursor changed pagination position")
	}
	if _, err = DecodeModelCursor(encoded, strings.Repeat("c", 64), catalog); err == nil {
		t.Fatal("cursor retargeted another selection")
	}
	if _, err = DecodeModelCursor(encoded, binding, strings.Repeat("c", 64)); err == nil {
		t.Fatal("cursor silently crossed a changed catalog")
	}
}

func TestModelPagePreservesNativeReasonTextWithinFrameBound(t *testing.T) {
	query := ModelQuery{Selection: FileSelection{ScopeID: "workspace", RelativePath: "."}, Provider: "provider"}
	page := ModelPage{Provider: "provider", ObservedAt: time.Now(), Status: "blocked", ReasonCode: strings.Repeat("Native metadata ü ", 30), Source: "native", Version: strings.Repeat("a", 64), Models: []ModelFact{}, Efforts: []string{}, EOF: true}
	if err := page.ValidateFor(query); err != nil {
		t.Fatalf("Native-shaped reason metadata rejected: %v", err)
	}
	if _, err := Encode(page, MaxFrameBytes); err != nil {
		t.Fatalf("bounded Native-shaped metadata could not be encoded: %v", err)
	}
	for _, reason := range []string{"", "reason\nmetadata", "reason\x00metadata", string([]byte{0xff}), strings.Repeat("r", MaxFrameBytes+1)} {
		page.ReasonCode = reason
		if page.ValidateFor(query) == nil {
			t.Fatal("invalid Native reason text accepted")
		}
	}
	page.ReasonCode = strings.Repeat("r", MaxFrameBytes)
	if page.ValidateFor(query) != nil {
		t.Fatal("valid reason text was coupled to its containing frame's overhead")
	}
	if _, err := Encode(page, MaxFrameBytes); err == nil {
		t.Fatal("reason metadata bypassed the complete encoded frame bound")
	}
}
