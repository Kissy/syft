package source

import (
	"fmt"
	"io"
	"os"
	"path"
	"path/filepath"

	"github.com/anchore/stereoscope/pkg/file"
	"github.com/anchore/syft/internal/log"
	"github.com/bmatcuk/doublestar/v2"
)

var _ Resolver = (*DirectoryResolver)(nil)

// DirectoryResolver implements path and content access for the directory data source.
type DirectoryResolver struct {
	Path string
}

func (r DirectoryResolver) requestPath(userPath string) string {
	fullPath := userPath
	if filepath.IsAbs(fullPath) {
		// a path relative to root should be prefixed with the resolvers directory path, otherwise it should be left as is
		fullPath = path.Join(r.Path, fullPath)
	}
	return fullPath
}

// HasPath indicates if the given path exists in the underlying source.
func (r *DirectoryResolver) HasPath(userPath string) bool {
	_, err := os.Stat(r.requestPath(userPath))
	return !os.IsNotExist(err)
}

// Stringer to represent a directory path data source
func (r DirectoryResolver) String() string {
	return fmt.Sprintf("dir:%s", r.Path)
}

// FilesByPath returns all file.References that match the given paths from the directory.
func (r DirectoryResolver) FilesByPath(userPaths ...string) ([]Location, error) {
	var references = make([]Location, 0)

	for _, userPath := range userPaths {
		userStrPath := r.requestPath(userPath)
		fileMeta, err := os.Stat(userStrPath)
		if os.IsNotExist(err) {
			continue
		} else if err != nil {
			log.Errorf("path (%r) is not valid: %v", userStrPath, err)
		}

		// don't consider directories
		if fileMeta.IsDir() {
			continue
		}

		references = append(references, NewLocation(userStrPath))
	}

	return references, nil
}

// FilesByGlob returns all file.References that match the given path glob pattern from any layer in the image.
func (r DirectoryResolver) FilesByGlob(patterns ...string) ([]Location, error) {
	result := make([]Location, 0)

	for _, pattern := range patterns {
		pathPattern := path.Join(r.Path, pattern)
		pathMatches, err := doublestar.Glob(pathPattern)
		if err != nil {
			return nil, err
		}
		for _, matchedPath := range pathMatches {
			fileMeta, err := os.Stat(matchedPath)
			if err != nil {
				continue
			}

			// don't consider directories
			if fileMeta.IsDir() {
				continue
			}

			result = append(result, NewLocation(matchedPath))
		}
	}

	return result, nil
}

// RelativeFileByPath fetches a single file at the given path relative to the layer squash of the given reference.
// This is helpful when attempting to find a file that is in the same layer or lower as another file. For the
// DirectoryResolver, this is a simple path lookup.
func (r *DirectoryResolver) RelativeFileByPath(_ Location, path string) *Location {
	paths, err := r.FilesByPath(path)
	if err != nil {
		return nil
	}
	if len(paths) == 0 {
		return nil
	}

	return &paths[0]
}

// MultipleFileContentsByLocation returns the file contents for all file.References relative a directory.
func (r DirectoryResolver) MultipleFileContentsByLocation(locations []Location) (map[Location]io.ReadCloser, error) {
	refContents := make(map[Location]io.ReadCloser)
	for _, location := range locations {
		refContents[location] = file.NewDeferredReadCloser(location.RealPath)
	}
	return refContents, nil
}

// FileContentsByLocation fetches file contents for a single file reference relative to a directory.
// If the path does not exist an error is returned.
func (r DirectoryResolver) FileContentsByLocation(location Location) (io.ReadCloser, error) {
	return file.NewDeferredReadCloser(location.RealPath), nil
}
