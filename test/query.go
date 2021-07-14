package main

import (
	"encoding/json"
	"fmt"
	"github.com/anchore/syft/syft/cpe"
	"github.com/anchore/syft/syft/pkg"
	"github.com/blevesearch/bleve/v2"
	"github.com/blevesearch/bleve/v2/analysis/analyzer/simple"
	"github.com/facebookincubator/nvdtools/wfn"
	"io/ioutil"
	"net/url"
	"os"
	"path"
	"strings"
)

func main() {
	matching := 0

	fmt.Println(cpe.NvdAnalyzerName)
	fmt.Println(simple.Name)
	index, _ := bleve.Open("example.bleve")
	directory := "/Users/glebiller/Workspace/platform/chef/syft/syft/cpe/test-fixtures/packages/rpmdb-cataloger"
	files, _ := ioutil.ReadDir(directory)
	for _, file := range files {
		data, _ := os.Open(path.Join(directory, file.Name()))
		var p = &pkg.Package{}
		_ = json.NewDecoder(data).Decode(p)
		if p.MetadataType == pkg.RpmdbMetadataType {
			m := p.Metadata.(*pkg.RpmdbMetadata)
			if m.URL != "" {
				urlParts := strings.SplitAfterN(m.URL, "//", 2)
				globalQuery := bleve.NewBooleanQuery()
				refQuery := bleve.NewMatchPhraseQuery(strings.TrimSuffix(urlParts[1], "/"))
				refQuery.SetField("references")
				globalQuery.AddMust(refQuery)
				nameQuery := bleve.NewTermQuery(p.Name)
				nameQuery.SetField("product")
				globalQuery.AddShould(nameQuery)
				if parsedUrl, err := url.Parse(m.URL); err == nil {
					vendorQuery := bleve.NewMatchQuery(cpe.CleanHost(parsedUrl.Host))
					vendorQuery.SetField("vendor")
					globalQuery.AddShould(vendorQuery)
				}
				searchResults, _ := index.Search(bleve.NewSearchRequest(globalQuery))
				if len(searchResults.Hits) > 0 {
					for _, result := range searchResults.Hits {
						if result.Score > 1 {
							foundCpe := wfn.NewAttributesWithAny()
							resultParts := strings.Split(result.ID, ":")
							foundCpe.Vendor = resultParts[0]
							foundCpe.Product = resultParts[1]
							foundCpe.Version = m.Version
							foundCpe.Update = m.Release
							if len(p.CPEs) >= 1 && wfn.Match(&p.CPEs[0], foundCpe) {
								matching += 1
							} else {
								fmt.Println(p.Name + ": NOT MATCHING " + result.ID + "(%f)", result.Score)
							}
						}
						break
					}
				} else {
					if len(p.CPEs) == 0 {
						matching += 1
					} else {
						fmt.Println(p.Name + ": NOT FOUND")
					}
				}
			} else {
				if len(p.CPEs) == 0 {
					matching += 1
				} else {
					fmt.Println(p.Name + ": NOT FOUND")
				}
			}
		}
	}
	fmt.Printf("Matching %d/%d\n", matching, len(files))
}
