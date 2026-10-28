// audit-anchor is an explicit offline operator tool. The API/Agent has no
// signing endpoint and never receives this private key.
package main

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"

	"zhiyu.local/zhiyu-go/internal/audit"
	executionaudit "zhiyu.local/zhiyu-go/internal/execution/audit"
)

var keyIDPattern = regexp.MustCompile(`^[A-Za-z0-9_-]{1,64}$`)

func writeNew(path string, raw []byte) error {
	f, err := os.OpenFile(path, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
	if err != nil {
		return errors.New("new explicit output file required")
	}
	if _, err = f.Write(raw); err != nil {
		_ = f.Close()
		return errors.New("output write failed")
	}
	return f.Close()
}

func run(args []string) error {
	if len(args) < 1 {
		return errors.New("explicit keygen or sign command required")
	}
	f := flag.NewFlagSet("audit-anchor", flag.ContinueOnError)
	f.SetOutput(io.Discard)
	var privatePath, output, keyID, capturePath, nativeTrust, nativeTrustSHA, configSHA string
	f.StringVar(&privatePath, "private-key", "", "local private key path")
	f.StringVar(&output, "output", "", "new public output file")
	f.StringVar(&keyID, "key-id", "", "operator key identifier")
	f.StringVar(&capturePath, "capture", "", "retained captured bundle JSON")
	f.StringVar(&nativeTrust, "native-trust", "", "explicit independent public trust-v2 profile for native signing")
	f.StringVar(&nativeTrustSHA, "native-trust-sha256", "", "exact public profile original SHA256")
	f.StringVar(&configSHA, "config-sha256", "", "independent expected public configuration SHA256")
	if f.Parse(args[1:]) != nil || f.NArg() != 0 || privatePath == "" || output == "" || !keyIDPattern.MatchString(keyID) {
		return errors.New("invalid explicit local tool arguments")
	}
	switch args[0] {
	case "keygen":
		if capturePath != "" || nativeTrust != "" || nativeTrustSHA != "" || configSHA != "" {
			return errors.New("keygen takes no capture")
		}
		privateAbsolute, e1 := filepath.Abs(privatePath)
		publicAbsolute, e2 := filepath.Abs(output)
		if e1 != nil || e2 != nil || privateAbsolute == publicAbsolute {
			return errors.New("distinct new private and public files required")
		}
		for _, path := range []string{privatePath, output} {
			if _, err := os.Lstat(path); !errors.Is(err, os.ErrNotExist) {
				return errors.New("new explicit output file required")
			}
		}
		public, private, err := ed25519.GenerateKey(rand.Reader)
		if err != nil {
			return errors.New("key generation failed")
		}
		if err = writeNew(privatePath, private); err != nil {
			return err
		}
		raw, _ := json.MarshalIndent(map[string]string{"key_id": keyID, "algorithm": audit.AnchorAlgorithm, "public_key": base64.StdEncoding.EncodeToString(public)}, "", "  ")
		if err = writeNew(output, append(raw, '\n')); err != nil {
			return err
		}
		fmt.Println(`{"status":"LOCAL_KEY_CREATED","private_key_printed":false}`)
		return nil
	case "sign":
		if capturePath == "" {
			return errors.New("retained capture required")
		}
		private, err := os.ReadFile(privatePath)
		if err != nil || len(private) != ed25519.PrivateKeySize {
			return errors.New("local private key unavailable")
		}
		file, err := os.Open(capturePath)
		if err != nil {
			return errors.New("capture unavailable")
		}
		defer file.Close()
		raw, err := io.ReadAll(io.LimitReader(file, 32*1024*1024+1))
		if err != nil || len(raw) > 32*1024*1024 {
			return errors.New("capture exceeds physical capacity")
		}
		if _, err = audit.ParseRawObject(raw); err != nil {
			return errors.New("capture JSON rejected")
		}
		var bundle audit.CapturedBundle
		decoder := json.NewDecoder(bytes.NewReader(raw))
		decoder.DisallowUnknownFields()
		if decoder.Decode(&bundle) != nil {
			return errors.New("capture schema rejected")
		}
		var extra any
		if decoder.Decode(&extra) != io.EOF {
			return errors.New("capture trailing bytes rejected")
		}
		registry := audit.NewRegistry()
		if executionaudit.RegisterBusiness(registry) != nil {
			return errors.New("business verifier unavailable")
		}
		if nativeCapture(bundle) {
			trust, err := loadNativeTrust(nativeTrust, nativeTrustSHA, configSHA, keyID, ed25519.PrivateKey(private), bundle)
			if err != nil {
				return err
			}
			if executionaudit.RegisterNativeBusinessV3WithTrust(registry, trust) != nil {
				return errors.New("native verifier unavailable")
			}
		} else if nativeTrust != "" || nativeTrustSHA != "" || configSHA != "" {
			return trustRefusal("NATIVE_PROFILE_REQUIRES_NATIVE_CAPTURE")
		}
		result := audit.VerifyCaptured(bundle, registry, audit.CaptureOptions{Bounds: audit.DefaultBounds()})
		if result.Status != audit.Valid {
			return fmt.Errorf("capture is not a complete valid supported business scope (status=%s); no anchor signed", result.Status)
		}
		anchor, err := audit.SignAnchor(bundle.Manifest, keyID, ed25519.PrivateKey(private))
		if err != nil {
			return errors.New("anchor signing failed")
		}
		encoded, _ := json.MarshalIndent(anchor, "", "  ")
		if err = writeNew(output, append(encoded, '\n')); err != nil {
			return err
		}
		fmt.Println(`{"status":"LOCAL_CAPTURE_SIGNED","private_key_printed":false}`)
		return nil
	default:
		return errors.New("unsupported offline command")
	}
}

func main() {
	if err := run(os.Args[1:]); err != nil {
		fmt.Fprintln(os.Stderr, err.Error())
		os.Exit(1)
	}
}
