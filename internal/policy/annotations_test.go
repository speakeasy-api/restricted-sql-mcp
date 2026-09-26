package policy

import "testing"

func TestAccessAnnotationParsing(t *testing.T) {
	for _, tc := range []struct {
		comment string
		tier    Tier
	}{
		{"@access: safe", Safe}, {"Description\r\n\t@access: pii \t\r\n", PII},
		{"@access: content", Content}, {"@access: secret", Secret}, {"@access: restricted", Restricted},
		{"", ""}, {"ordinary comment", ""}, {"@access: public", ""}, {"@access: safe\n@access: nonsense", ""},
		{"@access: safe\n@access: safe", ""}, {"@access: safe\nextra prose", ""}, {"@access:\nsafe", ""},
		{"prefix @access: safe", ""}, {"@access: Safe", ""}, {"@access: safe extra", ""},
	} {
		t.Run(tc.comment, func(t *testing.T) {
			tier, err := ParseAccessTier(tc.comment)
			if tc.tier == "" {
				if err == nil {
					t.Fatal("invalid annotation accepted")
				}
			} else if err != nil || tier != tc.tier {
				t.Fatalf("got %q,%v", tier, err)
			}
		})
	}
}
func TestAnnotationSnapshotHasNoInheritance(t *testing.T) {
	ref := TableRef{Schema: "public", Name: "records"}
	c := &Catalog{Relations: []Relation{{Ref: ref, Identity: "10", Kind: "table", Columns: []CatalogColumn{{Name: "id", Position: 1, Tier: Safe, AnnotationStatus: "valid"}, {Name: "new_phi", Position: 2, AnnotationStatus: "not annotated"}, {Name: "email", Position: 3, Tier: PII, AnnotationStatus: "valid"}}}}}
	if err := c.Seal(); err != nil {
		t.Fatal(err)
	}
	p := (&Policy{AnnotationTiers: map[Tier]bool{Safe: true}}).WithCatalog(c)
	if !p.CanRead(ref) || !p.CanReadColumn(ref, "id") || p.CanReadColumn(ref, "email") || p.CanReadColumn(ref, "new_phi") {
		t.Fatal("unexpected column access")
	}
	names, ok := p.Columns(ref)
	if !ok || len(names) != 3 {
		t.Fatal("denied columns must remain in binding inventory")
	}
}
