package sourceanalysis

import (
	"testing"

	"github.com/google/osv-scanner/v2/internal/sourceanalysis/govulncheck"
	"github.com/google/osv-scanner/v2/internal/testutility"
	"github.com/google/osv-scanner/v2/pkg/models"
	"github.com/ossf/osv-schema/bindings/go/osvschema"
	"google.golang.org/protobuf/types/known/structpb"
)

func Test_matchAnalysisWithPackageVulns(t *testing.T) {
	t.Parallel()

	pkgs := testutility.LoadJSONFixture[[]models.PackageVulns](t, "testdata/json/input.json")
	gvcResByVulnID := testutility.LoadJSONFixture[map[string][]*govulncheck.Finding](t, "testdata/json/govulncheckinput.json")
	vulnsByID := testutility.LoadVulnMapFixture(t, "testdata/json/vulnbyid.json")

	matchAnalysisWithPackageVulns(pkgs, gvcResByVulnID, vulnsByID)

	testutility.NewSnapshot().MatchJSON(t, pkgs)
}

func Test_matchEmptyAnalysisWithPackageVulns(t *testing.T) {
	t.Parallel()

	pkgs := testutility.LoadJSONFixture[[]models.PackageVulns](t, "testdata/json/input-no-call-data.json")
	// When there is no ecosystem specific data, govulncheck will return no results
	gvcResByVulnID := map[string][]*govulncheck.Finding{}
	vulnsByID := testutility.LoadVulnMapFixture(t, "testdata/json/vulnbyid-no-call-data.json")

	matchAnalysisWithPackageVulns(pkgs, gvcResByVulnID, vulnsByID)

	testutility.NewSnapshot().MatchJSON(t, pkgs)
}

func Test_matchAnalysisWithPackageVulnsCalledIsOrderIndependent(t *testing.T) {
	t.Parallel()

	// govulncheck emits one finding per vulnerable symbol, so multi-symbol advisories
	// routinely mix called findings (trace frame with a function) with uncalled ones
	// (single frame, no function). The verdict for the vulnerability must not depend
	// on which of those findings happens to come last.
	const vulnID = "GO-2021-0053"
	vulnsByID := map[string]*osvschema.Vulnerability{
		vulnID: {
			Id: vulnID,
			Affected: []*osvschema.Affected{
				{
					Package: &osvschema.Package{
						Name:      "github.com/gogo/protobuf",
						Ecosystem: "Go",
					},
					// The vuln entry carries symbol information, so a called
					// result is useful for this package.
					EcosystemSpecific: &structpb.Struct{
						Fields: map[string]*structpb.Value{
							"imports": structpb.NewListValue(&structpb.ListValue{
								Values: []*structpb.Value{
									structpb.NewStringValue("github.com/gogo/protobuf/types"),
								},
							}),
						},
					},
				},
			},
		},
	}

	newPkgs := func() []models.PackageVulns {
		return []models.PackageVulns{
			{
				Package: models.PackageInfo{
					Name:      "github.com/gogo/protobuf",
					Version:   "v1.3.1",
					Ecosystem: "Go",
				},
				Groups: []models.GroupInfo{
					{IDs: []string{vulnID}},
				},
			},
		}
	}

	orders := []struct {
		name     string
		findings []*govulncheck.Finding
		want     bool
	}{
		{
			name: "called finding first, uncalled second",
			findings: []*govulncheck.Finding{
				{OSV: vulnID, Trace: []*govulncheck.Frame{{Module: "github.com/gogo/protobuf", Function: "proto.Marshal"}}},
				{OSV: vulnID, Trace: []*govulncheck.Frame{{Module: "github.com/gogo/protobuf"}}},
			},
			want: true,
		},
		{
			name: "uncalled finding first, called second",
			findings: []*govulncheck.Finding{
				{OSV: vulnID, Trace: []*govulncheck.Frame{{Module: "github.com/gogo/protobuf"}}},
				{OSV: vulnID, Trace: []*govulncheck.Frame{{Module: "github.com/gogo/protobuf", Function: "proto.Marshal"}}},
			},
			want: true,
		},
		{
			name: "uncalled finding only",
			findings: []*govulncheck.Finding{
				{OSV: vulnID, Trace: []*govulncheck.Frame{{Module: "github.com/gogo/protobuf"}}},
			},
			want: false,
		},
	}

	for _, order := range orders {
		t.Run(order.name, func(t *testing.T) {
			t.Parallel()

			pkgs := newPkgs()
			matchAnalysisWithPackageVulns(pkgs, map[string][]*govulncheck.Finding{vulnID: order.findings}, vulnsByID)

			analysis, ok := pkgs[0].Groups[0].ExperimentalAnalysis[vulnID]
			if !ok {
				t.Fatalf("no experimental analysis recorded for %s", vulnID)
			}
			if analysis.Called != order.want {
				t.Errorf("Called = %v, want %v", analysis.Called, order.want)
			}
		})
	}
}
