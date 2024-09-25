// Copyright 2024 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// A module wrapper adapting the Go FIPS module to the protocol used by the
// BoringSSL project's `acvptool`.
//
// The `acvptool` "lowers" the NIST ACVP server JSON test vectors into a simpler
// stdin/stdout protocol that can be implemented by a module shim. The tool
// will fork this binary, request the supported configuration, and then provide
// test cases over stdin, expecting results to be returned on stdout.
//
// See "Testing other FIPS modules"[0] from the BoringSSL ACVP.md documentation
// for a more detailed description of the protocol used between the acvptool
// and module wrappers.
//
// [0]:https://boringssl.googlesource.com/boringssl/+/refs/heads/master/util/fipstools/acvp/ACVP.md#testing-other-fips-modules
package fips_test

import (
	"bufio"
	"bytes"
	"crypto/internal/fips"
	"crypto/internal/fips/hmac"
	"crypto/internal/fips/sha256"
	"crypto/internal/fips/sha512"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"internal/testenv"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

func TestMain(m *testing.M) {
	if os.Getenv("ACVP_WRAPPER") == "1" {
		wrapperMain()
	} else {
		os.Exit(m.Run())
	}
}

func wrapperMain() {
	writer := bufio.NewWriter(os.Stdout)
	defer func() { _ = writer.Flush() }()

	if err := processingLoop(bufio.NewReader(os.Stdin), writer); err != nil {
		_, _ = fmt.Fprintf(os.Stderr, "processing error: %v\n", err)
		os.Exit(1)
	}
}

type request struct {
	name string
	args [][]byte
}

type commandHandler func([][]byte) ([][]byte, error)

type command struct {
	// requiredArgs enforces that an exact number of arguments are provided to the handler.
	requiredArgs int
	handler      commandHandler
}

var (
	// configuration returned from getConfig command. This data represents the algorithms
	// our module supports and is used to determine which test cases are applicable.
	config = []interface{}{
		// HASH algorithm capabilities
		// See https://pages.nist.gov/ACVP/draft-celi-acvp-sha.html#section-7.2
		hashCapability("SHA2-224"),
		hashCapability("SHA2-256"),
		hashCapability("SHA2-384"),
		hashCapability("SHA2-512"),
		hashCapability("SHA2-512/256"),

		// HMAC algorithm capabilities
		// See https://pages.nist.gov/ACVP/draft-fussell-acvp-mac.html#section-7
		hmacCapability("HMAC-SHA2-224", 224),
		hmacCapability("HMAC-SHA2-256", 256),
		hmacCapability("HMAC-SHA2-384", 384),
		hmacCapability("HMAC-SHA2-512", 512),
		hmacCapability("HMAC-SHA2-512/256", 256),
	}

	// commands should reflect what config says we support. E.g. adding a command here will be a NOP
	// unless the configuration indicates the command's associated algorithm is supported.
	commands = map[string]command{
		"getConfig":        cmdGetConfig(),
		"SHA2-224":         cmdHashAft(sha256.New224()),
		"SHA2-224/MCT":     cmdHashMct(sha256.New224()),
		"SHA2-256":         cmdHashAft(sha256.New()),
		"SHA2-256/MCT":     cmdHashMct(sha256.New()),
		"SHA2-384":         cmdHashAft(sha512.New384()),
		"SHA2-384/MCT":     cmdHashMct(sha512.New384()),
		"SHA2-512":         cmdHashAft(sha512.New()),
		"SHA2-512/MCT":     cmdHashMct(sha512.New()),
		"SHA2-512/256":     cmdHashAft(sha512.New512_256()),
		"SHA2-512/256/MCT": cmdHashMct(sha512.New512_256()),

		"HMAC-SHA2-224":     cmdHmacAft(sha256.New224(), sha256.New224()),
		"HMAC-SHA2-256":     cmdHmacAft(sha256.New(), sha256.New()),
		"HMAC-SHA2-384":     cmdHmacAft(sha512.New384(), sha512.New384()),
		"HMAC-SHA2-512":     cmdHmacAft(sha512.New(), sha512.New()),
		"HMAC-SHA2-512/256": cmdHmacAft(sha512.New512_256(), sha512.New512_256()),
	}
)

func hashCapability(algName string) map[string]interface{} {
	return map[string]interface{}{
		"algorithm": algName,
		"revision":  "1.0",
		// Matching BSSL's config:
		"messageLength": []map[string]int{{
			"min": 0, "max": 65528, "increment": 8,
		}},
	}
}

func hmacCapability(algName string, macLenMax int) map[string]interface{} {
	return map[string]interface{}{
		"algorithm": algName,
		"revision":  "1.0",
		// Matching BSSL's config:
		"keyLen": []map[string]int{{
			"min": 8, "max": 524288, "increment": 8,
		}},
		"macLen": []map[string]int{{
			"min": 32, "max": macLenMax, "increment": 8,
		}},
	}
}

func processingLoop(reader io.Reader, writer *bufio.Writer) error {
	// Per ACVP.md:
	//   The protocol is request–response: the subprocess only speaks in response to a request
	//   and there is exactly one response for every request.
	for {
		req, err := readRequest(reader)
		if errors.Is(err, io.EOF) {
			break
		} else if err != nil {
			return fmt.Errorf("reading request: %w", err)
		}

		cmd, exists := commands[req.name]
		if !exists {
			return fmt.Errorf("unknown command: %q", req.name)
		}

		if gotArgs := len(req.args); gotArgs != cmd.requiredArgs {
			return fmt.Errorf("command %q expected %d args, got %d", req.name, cmd.requiredArgs, gotArgs)
		}

		response, err := cmd.handler(req.args)
		if err != nil {
			return fmt.Errorf("command %q failed: %w", req.name, err)
		}

		if err = writeResponse(writer, response); err != nil {
			return fmt.Errorf("command %q response failed: %w", req.name, err)
		}
	}

	return nil
}

func readRequest(reader io.Reader) (*request, error) {
	// Per ACVP.md:
	//   Requests consist of one or more byte strings and responses consist
	//   of zero or more byte strings. A request contains: the number of byte
	//   strings, the length of each byte string, and the contents of each byte
	//   string. All numbers are 32-bit little-endian and values are
	//   concatenated in the order specified.
	var numArgs uint32
	if err := binary.Read(reader, binary.LittleEndian, &numArgs); err != nil {
		return nil, err
	}
	if numArgs == 0 {
		return nil, errors.New("invalid request: zero args")
	}

	args, err := readArgs(reader, numArgs)
	if err != nil {
		return nil, err
	}

	return &request{
		name: string(args[0]),
		args: args[1:],
	}, nil
}

func readArgs(reader io.Reader, requiredArgs uint32) ([][]byte, error) {
	argLengths := make([]uint32, requiredArgs)
	args := make([][]byte, requiredArgs)

	for i := range argLengths {
		if err := binary.Read(reader, binary.LittleEndian, &argLengths[i]); err != nil {
			return nil, fmt.Errorf("invalid request: failed to read %d-th arg len: %w", i, err)
		}
	}

	for i, length := range argLengths {
		buf := make([]byte, length)
		if _, err := io.ReadFull(reader, buf); err != nil {
			return nil, fmt.Errorf("invalid request: failed to read %d-th arg data: %w", i, err)
		}
		args[i] = buf
	}

	return args, nil
}

func writeResponse(writer *bufio.Writer, args [][]byte) error {
	// See `readRequest` for details on the base format. Per ACVP.md:
	//   A response has the same format except that there may be zero byte strings
	//   and the first byte string has no special meaning.
	numArgs := uint32(len(args))
	if err := binary.Write(writer, binary.LittleEndian, numArgs); err != nil {
		return fmt.Errorf("writing arg count: %w", err)
	}

	for i, arg := range args {
		if err := binary.Write(writer, binary.LittleEndian, uint32(len(arg))); err != nil {
			return fmt.Errorf("writing %d-th arg length: %w", i, err)
		}
	}

	for i, b := range args {
		if _, err := writer.Write(b); err != nil {
			return fmt.Errorf("writing %d-th arg data: %w", i, err)
		}
	}

	return writer.Flush()
}

// "All implementations must support the getConfig command
// which takes no arguments and returns a single byte string
// which is a JSON blob of ACVP algorithm configuration."
func cmdGetConfig() command {
	return command{
		handler: func(args [][]byte) ([][]byte, error) {
			configJSON, err := json.Marshal(config)
			if err != nil {
				return nil, err
			}
			return [][]byte{configJSON}, nil
		},
	}
}

// cmdHashAft returns a command handler for the specified hash
// algorithm for algorithm functional test (AFT) test cases.
//
// This shape of command expects a message as the sole argument,
// and writes the resulting digest as a response.
//
// See https://pages.nist.gov/ACVP/draft-celi-acvp-sha.html
func cmdHashAft(h fips.Hash) command {
	return command{
		requiredArgs: 1, // Message to hash.
		handler: func(args [][]byte) ([][]byte, error) {
			h.Reset()
			h.Write(args[0])
			digest := make([]byte, 0, h.Size())
			digest = h.Sum(digest)

			return [][]byte{digest}, nil
		},
	}
}

// cmdHashAft returns a command handler for the specified hash
// algorithm for monte carlo test (MCT) test cases.
//
// This shape of command expects a seed as the sole argument,
// and writes the resulting digest as a response.
//
// This algorithm was ported from `HashMCT` in BSSL's `modulewrapper.cc`
// and is not an exact match to the NIST MCT[0] algorithm due to
// footnote #1 in the ACVP.md docs[1].
//
// [0]: https://pages.nist.gov/ACVP/draft-celi-acvp-sha.html#section-6.2
// [1]: https://boringssl.googlesource.com/boringssl/+/refs/heads/master/util/fipstools/acvp/ACVP.md#testing-other-fips-modules
func cmdHashMct(h fips.Hash) command {
	return command{
		requiredArgs: 1, // Seed message.
		handler: func(args [][]byte) ([][]byte, error) {
			hSize := h.Size()
			seed := args[0]

			if seedLen := len(seed); seedLen != hSize {
				return nil, fmt.Errorf("invalid seed size: expected %d got %d", hSize, seedLen)
			}

			digest := make([]byte, 0, hSize)
			buf := make([]byte, 0, 3*hSize)
			buf = append(buf, seed...)
			buf = append(buf, seed...)
			buf = append(buf, seed...)

			for i := 0; i < 1000; i++ {
				h.Reset()
				h.Write(buf)
				digest = h.Sum(digest)
				h.Sum(digest[:0])

				copy(buf, buf[hSize:])
				copy(buf[2*hSize:], digest)
			}

			return [][]byte{buf[hSize*2:]}, nil
		},
	}
}

func cmdHmacAft(h1, h2 fips.Hash) command {
	return command{
		requiredArgs: 2, // Message and key
		handler: func(args [][]byte) ([][]byte, error) {
			msg := args[0]
			key := args[1]
			h1.Reset()
			h2.Reset()
			mac := hmac.New(h1, h2, key)
			mac.Write(msg)
			return [][]byte{mac.Sum(nil)}, nil
		},
	}
}

func TestACVP(t *testing.T) {
	testenv.SkipIfShortAndSlow(t)
	testenv.MustHaveExternalNetwork(t)
	testenv.MustHaveGoRun(t)
	testenv.MustHaveExec(t)

	if testing.Short() {
		t.Skip("skipping in short mode")
	}

	// In crypto/tls/bogo_shim_test.go the test is skipped if run on a builder with runtime.GOOS == "windows"
	// due to flaky networking. It may be necessary to do the same here.

	// Stat the acvp test config file so the test will be re-run if it changes, invalidating cached results
	// from the old config.
	if _, err := os.Stat("acvp_test.config.json"); err != nil {
		t.Fatalf("failed to stat config file: %s", err)
	}

	cwd, err := os.Getwd()
	if err != nil {
		t.Fatalf("failed to fetch cwd: %s", err)
	}

	// Create a temporary mod cache dir for the BSSL module/tooling.
	d := t.TempDir()
	modcache := filepath.Join(d, "modcache")
	if err := os.Mkdir(modcache, 0777); err != nil {
		t.Fatal(err)
	}
	t.Setenv("GOMODCACHE", modcache)

	// Fetch the BSSL module and use the JSON output to find the absolute path to the dir.
	goTool := testenv.GoToolPath(t)
	var bsslDir string
	const bsslModVer = "v0.0.0-20240927212533-72a60506ded3"
	output, err := exec.Command(goTool, "mod", "download", "-json", "-modcacherw", "boringssl.googlesource.com/boringssl.git@"+bsslModVer).CombinedOutput()
	if err != nil {
		t.Fatalf("failed to download boringssl: %s", err)
	}
	var j struct {
		Dir string
	}
	if err := json.Unmarshal(output, &j); err != nil {
		t.Fatalf("failed to parse 'go mod download' output: %s", err)
	}
	bsslDir = j.Dir

	// Build the acvptool binary.
	cmd := exec.Command(goTool,
		"build",
		"./util/fipstools/acvp/acvptool")
	cmd.Dir = bsslDir
	out := &strings.Builder{}
	cmd.Stderr = out
	err = cmd.Run()
	if err != nil {
		t.Fatalf("failed to build acvptool: %s\n%s", err, out.String())
	}

	// Run the check_expected test driver using the acvptool we built, and this test binary as the
	// module wrapper. The file paths in the config file are specified relative to the BSSL root.
	args := []string{
		"run",
		"util/fipstools/acvp/acvptool/test/check_expected.go",
		"-tool", "./acvptool",
		// Note: module prefix must match Wrapper value in acvp_test.config.json.
		"-module-wrappers", "go:" + os.Args[0],
		// Note: In/Out values in config.json must be relative to BSSL root.
		"-tests", filepath.Join(cwd, "acvp_test.config.json"),
	}
	cmd = exec.Command(goTool, args...)
	cmd.Dir = bsslDir
	cmd.Env = []string{"ACVP_WRAPPER=1", "GOCACHE=" + modcache}
	output, err = cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("failed to run acvp tests: %s\n%s", err, string(output))
	}
	fmt.Println(string(output))
}

func TestTooFewArgs(t *testing.T) {
	commands["test"] = command{
		requiredArgs: 1,
		handler: func(args [][]byte) ([][]byte, error) {
			if gotArgs := len(args); gotArgs != 1 {
				return nil, fmt.Errorf("expected 1 args, got %d", gotArgs)
			}
			return nil, nil
		},
	}

	var output bytes.Buffer
	err := processingLoop(mockRequest(t, "test", nil), bufio.NewWriter(&output))
	if err == nil {
		t.Fatalf("expected error, got nil")
	}
	expectedErr := "expected 1 args, got 0"
	if !strings.Contains(err.Error(), expectedErr) {
		t.Errorf("expected error to contain %q, got %v", expectedErr, err)
	}
}

func TestTooManyArgs(t *testing.T) {
	commands["test"] = command{
		requiredArgs: 1,
		handler: func(args [][]byte) ([][]byte, error) {
			if gotArgs := len(args); gotArgs != 1 {
				return nil, fmt.Errorf("expected 1 args, got %d", gotArgs)
			}
			return nil, nil
		},
	}

	var output bytes.Buffer
	err := processingLoop(mockRequest(
		t, "test", [][]byte{[]byte("one"), []byte("two")}), bufio.NewWriter(&output))
	if err == nil {
		t.Fatalf("expected error, got nil")
	}
	expectedErr := "expected 1 args, got 2"
	if !strings.Contains(err.Error(), expectedErr) {
		t.Errorf("expected error to contain %q, got %v", expectedErr, err)
	}
}

func TestGetConfig(t *testing.T) {
	var output bytes.Buffer
	err := processingLoop(mockRequest(t, "getConfig", nil), bufio.NewWriter(&output))
	if err != nil {
		t.Errorf("unexpected error: %v", err)
	}

	respArgs := readResponse(t, &output)
	if len(respArgs) != 1 {
		t.Fatalf("expected 1 response arg, got %d", len(respArgs))
	}

	expectedConfig, _ := json.Marshal(config)
	if string(respArgs[0]) != string(expectedConfig) {
		t.Errorf("expected config %s, got %s", expectedConfig, respArgs[0])
	}
}

func TestSha2256(t *testing.T) {
	testMessage := []byte("gophers eat grass")
	expectedDigest := []byte{
		188, 142, 10, 214, 48, 236, 72, 143, 70, 216, 223, 205, 219, 69, 53, 29,
		205, 207, 162, 6, 14, 70, 113, 60, 251, 170, 201, 236, 119, 39, 141, 172,
	}

	var output bytes.Buffer
	err := processingLoop(mockRequest(t, "SHA2-256", [][]byte{testMessage}), bufio.NewWriter(&output))
	if err != nil {
		t.Errorf("unexpected error: %v", err)
	}

	respArgs := readResponse(t, &output)
	if len(respArgs) != 1 {
		t.Fatalf("expected 1 response arg, got %d", len(respArgs))
	}

	if !bytes.Equal(respArgs[0], expectedDigest) {
		t.Errorf("expected digest %v, got %v", expectedDigest, respArgs[0])
	}
}

func mockRequest(t *testing.T, cmd string, args [][]byte) io.Reader {
	t.Helper()

	msgData := append([][]byte{[]byte(cmd)}, args...)

	var buf bytes.Buffer
	if err := writeResponse(bufio.NewWriter(&buf), msgData); err != nil {
		t.Fatalf("writeResponse error: %v", err)
	}

	return &buf
}

func readResponse(t *testing.T, reader io.Reader) [][]byte {
	var numArgs uint32
	if err := binary.Read(reader, binary.LittleEndian, &numArgs); err != nil {
		t.Fatalf("failed to read response args count: %v", err)
	}

	args, err := readArgs(reader, numArgs)
	if err != nil {
		t.Fatalf("failed to read %d response args: %v", numArgs, err)
	}

	return args
}
