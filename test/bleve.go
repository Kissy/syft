package main

import (
	"encoding/json"
	"fmt"
	"github.com/anchore/syft/syft/cpe"
	"github.com/blevesearch/bleve/v2"
	"github.com/blevesearch/bleve/v2/analysis/analyzer/simple"
	"os"
	"strings"
)

type CPE struct {
	Titles     []string `json:"titles"`
	References []string `json:"references"`
}

type IndexedCpe struct {
	Vendor     string   `json:"vendor"`
	Product    string   `json:"product"`
	TargetSw   string   `json:"target_sw"`
	Titles     []string `json:"titles"`
	References []string `json:"references"`
}

func (_ IndexedCpe) Type() string {
	return "cpe"
}

func main() {
	cpeList := readCpeList()
	index := createBleveIndex()

	var batchIndex = index.NewBatch()
	for id, item := range *cpeList {
		parts := strings.Split(id, ":")
		var refs []string
		for _, r :=range item.References {
			urlParts := strings.SplitAfterN(r, "//", 2)
			refs = append(refs, strings.TrimSuffix(urlParts[1], "/"))
		}
		err := batchIndex.Index(id, IndexedCpe{
			Vendor:  parts[0],
			Product: parts[1],
			TargetSw: parts[2],
			Titles: item.Titles,
			References: refs,
		})
		if err != nil {
			fmt.Println(err)
		}
	}

	err := index.Batch(batchIndex)
	if err != nil {
		fmt.Println(err)
	}

	count, _ := index.DocCount()
	fmt.Printf("finished indexing %d", count)
	_ = index.Close()
}

func createBleveIndex() bleve.Index {
	mapping := bleve.NewIndexMapping()
	_ = cpe.RegisterNvdAnalyzer(mapping)

	textFieldMapping := bleve.NewTextFieldMapping()
	textFieldMapping.Analyzer = cpe.NvdAnalyzerName
	textFieldMapping.Store = false
	textFieldMapping.IncludeTermVectors = false
	textFieldMapping.IncludeInAll = false
	textFieldMapping.DocValues = false

	simpleFieldMapping := bleve.NewTextFieldMapping()
	simpleFieldMapping.Analyzer = simple.Name
	simpleFieldMapping.Store = false
	simpleFieldMapping.IncludeTermVectors = true
	simpleFieldMapping.IncludeInAll = false
	simpleFieldMapping.DocValues = false

	docMapping := bleve.NewDocumentMapping()
	docMapping.AddFieldMappingsAt("vendor", textFieldMapping)
	docMapping.AddFieldMappingsAt("product", textFieldMapping)
	docMapping.AddFieldMappingsAt("titles", textFieldMapping)
	docMapping.AddFieldMappingsAt("references", simpleFieldMapping)
	mapping.AddDocumentMapping("cpe", docMapping)

	_ = os.RemoveAll("./example.bleve")
	index, err := bleve.New("example.bleve", mapping)
	if err != nil {
		fmt.Println(err)
	}
	return index
}

func readCpeList() *map[string]CPE {
	data, _ := os.Open("test/processed.json")
	cpeList := &map[string]CPE{}
	_ = json.NewDecoder( data).Decode(cpeList)
	defer func() {
		_ = data.Close()
	}()
	return cpeList
}
