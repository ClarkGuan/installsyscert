package main

import (
	"bufio"
	"bytes"
	"crypto/md5"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"slices"
	"strings"
)

func main() {
	if len(os.Args) < 2 {
		fmt.Fprintf(os.Stderr, "no certificate file (PEM) path specified\n")
		os.Exit(1)
	}

	devices, err := emulators()
	if err != nil {
		fmt.Fprintf(os.Stderr, "adb devices execution failed: %v\n", err)
		os.Exit(1)
	}

	path := os.Args[1]
	name, err := newName(path)
	if err != nil {
		fmt.Fprintf(os.Stderr, "failed to extract X509_NAME_hash_old: %v\n", err)
		os.Exit(1)
	}

	for _, device := range devices {
		fmt.Printf("[%s] start installing certificate...\n", device)
		if err := installCert(device, path, name); err != nil {
			fmt.Fprintf(os.Stderr, "\tfailed to install certificate: %v\n", err)
		} else {
			fmt.Printf("\tcertificate installation successful\n")
		}
	}
}

func parsePem(path string) ([]byte, error) {
	content, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	block, _ := pem.Decode(content)
	if block == nil {
		return nil, errors.New("pem decode error")
	}
	return block.Bytes, nil
}

func subjectMd5Of(content []byte) (r uint64, err error) {
	certificate, err := x509.ParseCertificate(content)
	if err != nil {
		return 0, err
	}
	if len(certificate.RawSubject) == 0 {
		return 0, errors.New("no raw subject")
	}
	md := md5.Sum(certificate.RawSubject)
	r = (uint64(md[0]) | (uint64(md[1]) << 8) | (uint64(md[2]) << 16) | (uint64(md[3]) << 24)) & 0xffffffff
	return
}

func newName(path string) (string, error) {
	var derContent []byte
	content, err := parsePem(path)
	if err != nil {
		return "", err
	}
	derContent = content

	r, err := subjectMd5Of(derContent)
	if err != nil {
		return "", err
	}

	return fmt.Sprintf("%08x.0", r), nil
}

func run(name string, stdout, stderr io.Writer, args ...string) error {
	cmd := exec.Command(name, args...)
	cmd.Stdout = stdout
	cmd.Stderr = stderr
	cmd.Env = os.Environ()
	return cmd.Run()
}

func linesOfRun(name string, args ...string) ([]string, error) {
	b := bytes.NewBuffer(nil)
	if err := run(name, b, nil, args...); err != nil {
		return nil, err
	}
	buf := bufio.NewReader(b)
	var ret []string
	for {
		line, err := buf.ReadString('\n')
		if err != nil {
			if err == io.EOF {
				break
			} else {
				return nil, err
			}
		}
		if line = strings.TrimSpace(line); len(line) > 0 {
			ret = append(ret, line)
		}
	}
	return ret, nil
}

func listDevices() ([]string, error) {
	lines, err := linesOfRun("adb", "devices")
	if err != nil {
		return nil, err
	}
	var ret []string
	for _, line := range lines[1:] {
		index := strings.Index(line, "\t")
		if index != -1 {
			ret = append(ret, line[:index])
		}
	}
	return ret, nil
}

func emulators() ([]string, error) {
	names, err := listDevices()
	if err != nil {
		return nil, err
	}
	var ret []string
	for _, name := range names {
		if strings.HasPrefix(name, "emulator-") {
			ret = append(ret, name)
		}
	}
	return ret, nil
}

func listAllCerts(name string) ([]string, error) {
	lines, err := linesOfRun("adb", "-s", name, "shell", "ls", "/system/etc/security/cacerts")
	if err != nil {
		return nil, err
	}
	return lines, nil
}

func contains(device string, filename string) (bool, error) {
	certs, err := listAllCerts(device)
	if err != nil {
		return false, err
	}
	return slices.Contains(certs, filename), nil
}

func remount(device string) error {
	return run("adb", nil, nil, "-s", device, "remount")
}

func root(device string) error {
	return run("adb", nil, nil, "-s", device, "root")
}

func push(device string, path string, name string) error {
	return run("adb", nil, nil, "-s", device, "push", path,
		fmt.Sprintf("/system/etc/security/cacerts/%s", name))
}

func installCert(device string, path string, name string) error {
	b, err := contains(device, name)
	if err != nil {
		return err
	}
	if b {
		return nil
	}
	if err := remount(device); err != nil {
		return err
	}
	if err := root(device); err != nil {
		return err
	}
	return push(device, path, name)
}
