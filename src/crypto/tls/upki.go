// Copyright 2026 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package tls

import (
	"crypto/internal/upki"
	"crypto/x509"
	"errors"
	"fmt"
	"internal/godebug"
	"os"
	"path/filepath"
	"runtime"
)

// tlsupki is a GODEBUG setting that can be set to 0 to disable UPKI
// revocation checking for configurations that rely on platform-default
// cache discovery.
var tlsupki = godebug.New("tlsupki")

// UPKIRevocationConfig controls local, offline UPKI revocation checking of
// server certificates.
//
// The zero value has the same behavior as a nil [Config.UPKIRevocation].
// It doesn't configure downloading or updating revocation data.
type UPKIRevocationConfig struct {
	// Disabled disables UPKI revocation checking, including automatic
	// discovery of a platform-default cache.
	Disabled bool

	// Directory is a C2SP upki-revocation cache directory. It contains
	// index.bin directly.
	//
	// If Directory is empty, platform-default directories are searched for
	// index.bin in user-before-system order. A directory without index.bin is
	// skipped.
	Directory string

	// MissingData controls the result when a cache lookup is needed but a
	// selected or explicitly configured cache has no index.bin. It does not
	// apply to absent indexes during automatic cache discovery.
	MissingData UPKIRevocationPolicy

	// NotCovered controls the result when the revocation data cannot
	// determine a certificate's status, including when covering filters have
	// no information about the certificate's issuer or disagree with the
	// cache index about what they cover.
	NotCovered UPKIRevocationPolicy

	// MissingSCTs controls the result when a certificate contains no embedded
	// Signed Certificate Timestamps. It is handled before reading the cache
	// index or filter files.
	MissingSCTs UPKIRevocationPolicy
}

// ErrUPKIRevoked is returned as a wrapped [CertificateVerificationError]
// when a certificate is determined to be revoked.
var ErrUPKIRevoked = errors.New("certificate is revoked according to UPKI")

// UPKIRevocationPolicy controls the result of an inconclusive UPKI revocation
// check.
type UPKIRevocationPolicy uint8

const (
	// UPKIRevocationPolicyDefault uses the default for the corresponding
	// UPKIRevocationConfig field.
	UPKIRevocationPolicyDefault UPKIRevocationPolicy = iota

	// UPKIRevocationPolicyAllow allows the connection to proceed when the
	// revocation check is inconclusive for the corresponding reason.
	UPKIRevocationPolicyAllow

	// UPKIRevocationPolicyReject rejects the connection when the revocation
	// check is inconclusive for the corresponding reason.
	UPKIRevocationPolicyReject
)

func (c *Config) checkUPKIRevocation(chains [][]*x509.Certificate) error {
	if c.InsecureSkipVerify {
		return nil
	}

	var cfg UPKIRevocationConfig
	if c.UPKIRevocation != nil {
		cfg = *c.UPKIRevocation
	}
	// By default, a selected cache must contain data. Missing coverage and
	// missing SCTs are soft failures because either can occur for otherwise
	// valid certificates outside the public Web PKI data set.
	missingDataRejects, err := upkiPolicyReject(cfg.MissingData, true)
	if err != nil {
		return err
	}
	notCoveredRejects, err := upkiPolicyReject(cfg.NotCovered, false)
	if err != nil {
		return err
	}
	missingSCTsRejects, err := upkiPolicyReject(cfg.MissingSCTs, false)
	if err != nil {
		return err
	}

	if cfg.Disabled {
		return nil
	}
	// GODEBUG=tlsupki=0 turns off the default-on checking. A Config that
	// names a cache directory explicitly keeps checking it.
	if cfg.Directory == "" && tlsupki.Value() == "0" {
		tlsupki.IncNonDefault()

		return nil
	}

	scts, err := upki.EmbeddedSCTs(chains[0][0])
	if err != nil {
		return fmt.Errorf("UPKI revocation check failed: extracting SCTs: %w", err)
	}
	if len(scts) == 0 {
		if missingSCTsRejects {
			return errors.New("UPKI revocation check requires embedded SCTs")
		}

		return nil
	}

	dir, index, err := cfg.openCacheIndex()
	if err != nil {
		if errors.Is(err, os.ErrNotExist) && !missingDataRejects {
			return nil
		}
		if errors.Is(err, os.ErrNotExist) {
			return fmt.Errorf("%w at %s", upki.ErrNoData, filepath.Join(dir, upki.IndexFilename))
		}

		return err
	}
	if index == nil {
		return nil
	}

	result, err := upki.Check(dir, index, chains)
	if err != nil {
		if errors.Is(err, upki.ErrNoData) && !missingDataRejects {
			return nil
		}

		return fmt.Errorf("UPKI revocation check failed: %w", err)
	}

	switch result {
	case upki.Revoked:
		return ErrUPKIRevoked
	case upki.NotRevoked:
		return nil
	case upki.NotCovered:
		if notCoveredRejects {
			return errors.New("certificate is not covered by UPKI revocation data")
		}

		return nil
	default:
		return fmt.Errorf("UPKI revocation check returned invalid result %d", result)
	}
}

func upkiPolicyReject(policy UPKIRevocationPolicy, defaultReject bool) (bool, error) {
	switch policy {
	case UPKIRevocationPolicyDefault:
		return defaultReject, nil
	case UPKIRevocationPolicyAllow:
		return false, nil
	case UPKIRevocationPolicyReject:
		return true, nil
	default:
		return false, fmt.Errorf("invalid UPKI revocation policy %d", policy)
	}
}

func (c UPKIRevocationConfig) openCacheIndex() (string, *os.File, error) {
	if c.Directory != "" {
		path := filepath.Join(c.Directory, upki.IndexFilename)
		index, err := os.Open(path)
		if err != nil {
			return c.Directory, nil, fmt.Errorf("opening UPKI revocation index %s: %w", path, err)
		}

		return c.Directory, index, nil
	}

	return openUPKICacheIndex(defaultUPKIRevocationDirectories())
}

func openUPKICacheIndex(directories []string) (string, *os.File, error) {
	for _, dir := range directories {
		path := filepath.Join(dir, upki.IndexFilename)
		index, err := os.Open(path)
		switch {
		case err == nil:
			return dir, index, nil
		case errors.Is(err, os.ErrNotExist):
			continue
		default:
			return dir, nil, fmt.Errorf("opening UPKI revocation index %s: %w", path, err)
		}
	}

	return "", nil, nil
}

func defaultUPKIRevocationDirectories() []string {
	userCache, _ := os.UserCacheDir()
	return upkiRevocationDirectories(runtime.GOOS, userCache, os.Getenv("ProgramData"))
}

func upkiRevocationDirectories(goos, userCache, programData string) []string {
	var directories []string
	if userCache != "" {
		switch goos {
		case "darwin":
			directories = append(directories, filepath.Join(userCache, "dev.rustls.upki", "revocation"))
		case "windows":
			directories = append(directories, filepath.Join(userCache, "rustls", "upki", "cache", "revocation"))
		default:
			directories = append(directories, filepath.Join(userCache, "upki", "revocation"))
		}
	}

	switch goos {
	case "darwin":
		directories = append(directories, "/Library/Caches/dev.rustls.upki/revocation")
	case "windows":
		if programData == "" {
			programData = `C:\ProgramData`
		}
		directories = append(directories, filepath.Join(programData, "rustls", "upki", "cache", "revocation"))
	case "aix", "dragonfly", "freebsd", "illumos", "linux", "netbsd", "openbsd", "solaris":
		directories = append(directories, "/var/cache/upki/revocation")
	}

	return directories
}

func (c *Conn) verifyUPKIRevocation() error {
	if err := c.config.checkUPKIRevocation(c.verifiedChains); err != nil {
		c.sendAlert(alertBadCertificate)
		return &CertificateVerificationError{
			UnverifiedCertificates: c.peerCertificates,
			Err:                    err,
		}
	}

	return nil
}
