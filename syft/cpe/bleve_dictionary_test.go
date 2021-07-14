package cpe

import (
	"encoding/json"
	"github.com/anchore/syft/internal/config"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"

	"github.com/scylladb/go-set/strset"

	"github.com/scylladb/go-set"

	"github.com/anchore/syft/syft/pkg"
)

func TestBleveIdentifyPackageCPEs(t *testing.T) {
	var tests []struct {
		name     string
		path     string
	}

	filepath.Walk("test-fixtures/packages", func(path string, info os.FileInfo, err error) error {
		if !strings.HasSuffix(info.Name(), ".json") {
			return nil
		}

		tests = append(tests, struct {
			name     string
			path     string
		}{
			name: strings.TrimSuffix(info.Name(), ".json"),
			path: path,
		})
		return nil
	})

	//tempDir, _ := ioutil.TempDir("", "bleve_dictionary_test")
	cpeDictionaryConfig := config.CPEDictionary{
		CacheDir:         "test-fixtures/cpe-dictionary",
		AutoUpdate:       false,
		ValidateChecksum: false,
		MinimumScore:     4,
		SpecificVendors:  []config.SpecificMatch{},
		SpecificProducts: []config.SpecificMatch{},
	}

	curator := NewCurator(cpeDictionaryConfig)
	_ = curator.ImportFrom("/Users/glebiller/Workspace/platform/chef/google-vision/official-cpe-dictionary_v2.3.xml.gz")
	dictionary, _ := curator.GetDictionary()

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			file, _ := os.Open(test.path)
			defer file.Close()

			var p pkg.Package
			_ = json.NewDecoder(file).Decode(&p)
			actual := dictionary.IdentifyPackageCPEs(p)

			expected := make([]string, len(p.CPEs))
			for i, cpe := range p.CPEs {
				expected[i] = cpe.BindToFmtString()
			}

			expectedCpeSet := set.NewStringSet(expected...)
			actualCpeSet := set.NewStringSet()
			for _, a := range actual {
				actualCpeSet.Add(a.BindToFmtString())
			}

			extra := strset.Difference(actualCpeSet, expectedCpeSet).List()
			sort.Strings(extra)
			for _, d := range extra {
				t.Errorf("extra CPE: %+v", d)
			}

			missing := strset.Difference(expectedCpeSet, actualCpeSet).List()
			sort.Strings(missing)
			for _, d := range missing {
				t.Errorf("missing CPE: %+v", d)
			}

		})
	}

	//_ = curator.Delete()
}
