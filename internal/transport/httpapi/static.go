package httpapi

import (
	"errors"
	"io/fs"
	"net/http"
	"os"
	"path"
	"path/filepath"
	"strings"
	"unicode/utf8"
)

// StaticWeb serves an explicitly selected package web directory. The retained
// root handle prevents a symlink or concurrent rename from escaping that root.
// API/health requests always use the original router and its authority checks.
type StaticWeb struct {
	api  http.Handler
	root *os.Root
}

func NewStaticWeb(api http.Handler, directory string) (*StaticWeb, error) {
	invalid := errors.New("static web root unavailable or invalid")
	if api == nil || directory == "" {
		return nil, invalid
	}
	directory = filepath.Clean(directory)
	info, err := os.Lstat(directory)
	if err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
		return nil, invalid
	}
	root, err := os.OpenRoot(directory)
	if err != nil {
		return nil, invalid
	}
	info, err = root.Lstat("index.html")
	if err != nil || !info.Mode().IsRegular() {
		_ = root.Close()
		return nil, invalid
	}
	return &StaticWeb{api: api, root: root}, nil
}

func (s *StaticWeb) Close() error { return s.root.Close() }

func (s *StaticWeb) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	requestPath := r.URL.Path
	if strings.HasPrefix(strings.ToLower(requestPath), "/api") || requestPath == "/livez" || requestPath == "/readyz" {
		s.api.ServeHTTP(w, r)
		return
	}
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.Header().Set("Cache-Control", "no-cache")
	if r.Method != http.MethodGet && r.Method != http.MethodHead {
		w.Header().Set("Allow", "GET, HEAD")
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	name := strings.TrimPrefix(requestPath, "/")
	if requestPath == "/" {
		name = "index.html"
	}
	if !strings.HasPrefix(requestPath, "/") || !utf8.ValidString(name) || !fs.ValidPath(name) || strings.ContainsAny(name, "\\:%\x00") {
		http.NotFound(w, r)
		return
	}
	for _, part := range strings.Split(name, "/") {
		if strings.HasPrefix(part, ".") {
			http.NotFound(w, r)
			return
		}
	}
	info, err := s.root.Lstat(name)
	if err != nil || !info.Mode().IsRegular() {
		http.NotFound(w, r)
		return
	}
	file, err := s.root.Open(name)
	if err != nil {
		http.NotFound(w, r)
		return
	}
	defer file.Close()
	info, err = file.Stat()
	if err != nil || !info.Mode().IsRegular() {
		http.NotFound(w, r)
		return
	}
	http.ServeContent(w, r, path.Base(name), info.ModTime(), file)
}
