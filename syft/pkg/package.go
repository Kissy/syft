/*
Package pkg provides the data structures for a package, a package catalog, package types, and domain-specific metadata.
*/
package pkg

import (
	"encoding/json"
	"fmt"
	"github.com/anchore/syft/syft/source"
	"github.com/mitchellh/mapstructure"
)

// ID represents a unique value for each package added to a package catalog.
type ID int64

// Package represents an application or library that has been bundled into a distributable format.
type Package struct {
	id           ID                `mapstructure:"id" json:"id"`                       // uniquely identifies a package, set by the cataloger
	Name         string            `mapstructure:"name" json:"name"`                   // the package name
	Version      string            `mapstructure:"version" json:"version"`             // the version of the package
	FoundBy      string            `mapstructure:"found_by" json:"found_by"`           // the specific cataloger that discovered this package
	Locations    []source.Location `mapstructure:"locations" json:"locations"`         // the locations that lead to the discovery of this package (note: this is not necessarily the locations that make up this package)
	Licenses     []string          `mapstructure:"licenses" json:"licenses"`           // TODO: should we move licenses into metadata?  // licenses discovered with the package metadata
	Language     Language          `mapstructure:"language" json:"language"`           // the language ecosystem this package belongs to (e.g. JavaScript, Python, etc)
	Type         Type              `mapstructure:"types" json:"type"`                  // the package type (e.g. Npm, Yarn, Python, Rpm, Deb, etc)
	CPEs         []CPE             `mapstructure:"cpes" json:"cpes"`                   // all possible Common Platform Enumerators
	PURL         string            `mapstructure:"purl" json:"purl"`                   // the Package URL (see https://github.com/package-url/purl-spec)
	MetadataType MetadataType      `mapstructure:"metadata_type" json:"metadata_type"` // the shape of the additional data in the "metadata" field
	Metadata     interface{}       `json:"metadata"`                                   // additional data found while parsing the package source
}

// ID returns the package ID, which is unique relative to a package catalog.
func (p Package) ID() ID {
	return p.id
}

// Stringer to represent a package.
func (p Package) String() string {
	return fmt.Sprintf("Pkg(type=%s, name=%s, version=%s)", p.Type, p.Name, p.Version)
}

// UnmarshalJSON is a custom unmarshaller for handling basic values and values with ambiguous types.
func (p *Package) UnmarshalJSON(b []byte) error {
	var fields map[string]interface{}
	if err := json.Unmarshal(b, &fields); err != nil {
		return err
	}

	var decodedPackage Package
	if err := mapstructure.Decode(fields, &decodedPackage); err != nil {
		return fmt.Errorf("unable to parse package yaml: %w", err)
	}

	metadataBytes, _ := json.Marshal(fields["metadata"])

	switch decodedPackage.MetadataType {
	case ApkMetadataType:
		metadata := ApkMetadata {}
		if err := json.Unmarshal(metadataBytes, &metadata); err != nil {
			return fmt.Errorf("unable to parse Package metadata yaml: %w", err)
		}
		decodedPackage.Metadata = &metadata
	case DpkgMetadataType:
		metadata := DpkgMetadata{}
		if err := json.Unmarshal(metadataBytes, &metadata); err != nil {
			return fmt.Errorf("unable to parse Package metadata yaml: %w", err)
		}
		decodedPackage.Metadata = &metadata
	case GemMetadataType:
		metadata := GemMetadata{}
		if err := json.Unmarshal(metadataBytes, &metadata); err != nil {
			return fmt.Errorf("unable to parse Package metadata yaml: %w", err)
		}
		decodedPackage.Metadata = &metadata
	case JavaMetadataType:
		metadata := JavaMetadata{}
		if err := json.Unmarshal(metadataBytes, &metadata); err != nil {
			return fmt.Errorf("unable to parse Package metadata yaml: %w", err)
		}
		decodedPackage.Metadata = &metadata
	case NpmPackageJSONMetadataType:
		metadata := NpmPackageJSONMetadata{}
		if err := json.Unmarshal(metadataBytes, &metadata); err != nil {
			return fmt.Errorf("unable to parse Package metadata yaml: %w", err)
		}
		decodedPackage.Metadata = &metadata
	case RpmdbMetadataType:
		metadata := RpmdbMetadata{}
		if err := json.Unmarshal(metadataBytes, &metadata); err != nil {
			return fmt.Errorf("unable to parse Package metadata yaml: %w", err)
		}
		decodedPackage.Metadata = &metadata
	case PythonPackageMetadataType:
		metadata := PythonPackageMetadata{}
		if err := json.Unmarshal(metadataBytes, &metadata); err != nil {
			return fmt.Errorf("unable to parse Package metadata yaml: %w", err)
		}
		decodedPackage.Metadata = &metadata
	}

	*p = decodedPackage

	return nil
}
