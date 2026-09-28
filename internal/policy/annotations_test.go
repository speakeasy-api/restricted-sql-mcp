package policy

import (
	"strings"
	"testing"
)

func TestAccessAnnotationParsing(t *testing.T) {
	for _, tc := range []struct {
		comment string
		tier    Tier
	}{
		{"@access: safe", Tier("safe")}, {"Description\r\n\t@access: pii \t\r\n", Tier("pii")},
		{"@access: content", Tier("content")}, {"@access: secret", Tier("secret")}, {"@access: restricted", Tier("restricted")},
		{"@access: opaque-restricted", Tier("opaque-restricted")}, {"@access: public", Tier("public")},
		{"@access: -x", ""}, {"@access: x-", ""}, {"@access: a--b", ""}, {"@access: a_b", ""}, {"@access: 1x", ""},
		{"@access: safe,pii", ""}, {"@access: " + strings.Repeat("a", 64), ""},
		{"", ""}, {"ordinary comment", ""}, {"@access: safe\n@access: nonsense", ""},
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
	c := &Catalog{Relations: []Relation{{Ref: ref, Identity: "10", Kind: "table", Columns: []CatalogColumn{{Name: "id", Position: 1, Tier: Tier("safe"), AnnotationStatus: "valid"}, {Name: "new_phi", Position: 2, AnnotationStatus: "not annotated"}, {Name: "email", Position: 3, Tier: Tier("pii"), AnnotationStatus: "valid"}}}}}
	if err := c.Seal(); err != nil {
		t.Fatal(err)
	}
	p := (&Policy{AnnotationTiers: map[Tier]bool{Tier("safe"): true}}).WithCatalog(c)
	if !p.CanRead(ref) || !p.CanReadColumn(ref, "id") || p.CanReadColumn(ref, "email") || p.CanReadColumn(ref, "new_phi") {
		t.Fatal("unexpected column access")
	}
	names, ok := p.Columns(ref)
	if !ok || len(names) != 3 {
		t.Fatal("denied columns must remain in binding inventory")
	}
}

// The server has no built-in vocabulary: only allowlisted classes are
// readable, whatever their names, and every other class is denied.
func TestAnnotationClassesAreDeploymentDefined(t *testing.T) {
	ref := TableRef{Schema: "public", Name: "records"}
	c := &Catalog{Relations: []Relation{{Ref: ref, Identity: "10", Kind: "table", Columns: []CatalogColumn{
		{Name: "id", Position: 1, Tier: "operational", AnnotationStatus: "valid"},
		{Name: "body", Position: 2, Tier: "opaque-restricted", AnnotationStatus: "valid"},
		{Name: "email", Position: 3, Tier: "safe", AnnotationStatus: "valid"},
	}}}}
	if err := c.Seal(); err != nil {
		t.Fatal(err)
	}
	p := (&Policy{AnnotationTiers: map[Tier]bool{"operational": true}}).WithCatalog(c)
	if !p.CanReadColumn(ref, "id") || p.CanReadColumn(ref, "body") || p.CanReadColumn(ref, "email") {
		t.Fatal("only allowlisted classes may be readable")
	}
}
