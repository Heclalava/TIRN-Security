package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
)

const (
	dataDir       = "/data/adb/tirnsecurity"
	cache         = dataDir + "/apps.json"
	identity      = dataDir + "/apps.identity"
	lockDir       = dataDir + "/apps.lock"
	refreshSingle = "/data/adb/modules/tirnsecurity/refresh_app_single"
)

type App struct {
	User   string `json:"user"`
	UID    string `json:"uid"`
	Pkg    string `json:"pkg"`
	Name   string `json:"name"`
	System bool   `json:"system"`
}

type Profile struct {
	ID   string `json:"id"`
	Name string `json:"name"`
}

type Cache struct {
	Status   string    `json:"status"`
	Profiles []Profile `json:"profiles"`
	Apps     []App     `json:"apps"`
}

var (
	packageRE = regexp.MustCompile(`^[A-Za-z0-9._]+$`)
	numericRE = regexp.MustCompile(`^[0-9]+$`)
)

func fail(format string, args ...interface{}) {
	fmt.Fprintf(os.Stderr, format+"\n", args...)
	os.Exit(1)
}

func getProcStart(pid int) (string, error) {
	statPath := fmt.Sprintf("/proc/%d/stat", pid)

	data, err := os.ReadFile(statPath)
	if err != nil {
		return "", err
	}

	line := string(data)
	end := strings.LastIndex(line, ")")
	if end < 0 || end+2 > len(line) {
		return "", fmt.Errorf("invalid /proc/%d/stat", pid)
	}

	fields := strings.Fields(line[end+2:])
	if len(fields) < 20 {
		return "", fmt.Errorf("invalid /proc/%d/stat", pid)
	}

	return fields[19], nil
}

func acquireLock() error {
	owner := filepath.Join(lockDir, "owner")

	if err := os.Mkdir(lockDir, 0755); err == nil {
		start, err := getProcStart(os.Getpid())
		if err != nil {
			os.Remove(owner)
			os.Remove(lockDir)
			return err
		}

		if err := os.WriteFile(
			owner,
			[]byte(fmt.Sprintf("%d %s\n", os.Getpid(), start)),
			0644,
		); err != nil {
			os.Remove(owner)
			os.Remove(lockDir)
			return err
		}

		return nil
	} else if !os.IsExist(err) {
		return err
	}

	data, err := os.ReadFile(owner)
	if err != nil {
		return fmt.Errorf("APPS_BUSY")
	}

	parts := strings.Fields(string(data))
	if len(parts) != 2 || !numericRE.MatchString(parts[0]) ||
		!numericRE.MatchString(parts[1]) {
		return fmt.Errorf("APPS_BUSY")
	}

	var pid int
	if _, err := fmt.Sscanf(parts[0], "%d", &pid); err != nil || pid <= 0 {
		return fmt.Errorf("APPS_BUSY")
	}

	currentStart, err := getProcStart(pid)
	if err != nil {
		if os.IsNotExist(err) {
			if err := os.Remove(owner); err != nil && !os.IsNotExist(err) {
				return fmt.Errorf("APPS_BUSY")
			}
			if err := os.Remove(lockDir); err != nil {
				return fmt.Errorf("APPS_BUSY")
			}
		} else {
			return fmt.Errorf("APPS_BUSY")
		}
	} else if currentStart == parts[1] {
		return fmt.Errorf("APPS_BUSY")
	} else {
		if err := os.Remove(owner); err != nil && !os.IsNotExist(err) {
			return fmt.Errorf("APPS_BUSY")
		}
		if err := os.Remove(lockDir); err != nil {
			return fmt.Errorf("APPS_BUSY")
		}
	}

	if err := os.Mkdir(lockDir, 0755); err != nil {
		return fmt.Errorf("APPS_BUSY")
	}

	start, err := getProcStart(os.Getpid())
	if err != nil {
		os.Remove(owner)
		os.Remove(lockDir)
		return err
	}

	if err := os.WriteFile(
		owner,
		[]byte(fmt.Sprintf("%d %s\n", os.Getpid(), start)),
		0644,
	); err != nil {
		os.Remove(owner)
		os.Remove(lockDir)
		return err
	}

	return nil
}

func releaseLock() {
	owner := filepath.Join(lockDir, "owner")
	os.Remove(owner)
	os.Remove(lockDir)
}

func loadCache() (Cache, error) {
	var c Cache

	data, err := os.ReadFile(cache)
	if err != nil {
		return c, err
	}

	if err := json.Unmarshal(data, &c); err != nil {
		return c, fmt.Errorf("invalid apps.json: %w", err)
	}

	if c.Status != "OK" {
		return c, fmt.Errorf("unexpected cache status %q", c.Status)
	}

	return c, nil
}

func runPackageRecord(user, pkg string) ([]App, error) {
	cmd := exec.Command("/system/bin/sh", refreshSingle, user, pkg)

	out, err := cmd.CombinedOutput()

	if err != nil {
		if exitErr, ok := err.(*exec.ExitError); ok {
			switch exitErr.ExitCode() {
			case 3:
				return nil, fmt.Errorf("NOT_INSTALLED")
			case 4:
				return nil, fmt.Errorf("CONFLICTING_UID")
			}
		}
		detail := strings.TrimSpace(string(out))
		if detail == "" {
			return nil, fmt.Errorf("refresh_app_single failed: %w", err)
		}
		return nil, fmt.Errorf(
			"refresh_app_single failed: %w: %s",
			err,
			detail,
		)
	}

	var record *App
	status := ""
	identityUID := ""

	for _, line := range strings.Split(string(out), "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}

		switch {
		case strings.HasPrefix(line, "STATUS|"):
			status = strings.TrimPrefix(line, "STATUS|")

		case strings.HasPrefix(line, "RECORD|"):
			var app App
			if err := json.Unmarshal(
				[]byte(strings.TrimPrefix(line, "RECORD|")),
				&app,
			); err != nil {
				return nil, fmt.Errorf("invalid generated app record: %w", err)
			}
			record = &app

		case strings.HasPrefix(line, "IDENTITY|"):
			fields := strings.Split(strings.TrimPrefix(line, "IDENTITY|"), "|")
			if len(fields) != 3 ||
				fields[0] != user ||
				fields[2] != pkg ||
				!numericRE.MatchString(fields[1]) {
				return nil, fmt.Errorf("invalid identity response")
			}
			identityUID = fields[1]
		}
	}

	switch status {
	case "OK":
		if record == nil {
			return nil, fmt.Errorf("missing RECORD")
		}
		if record.User != user || record.Pkg != pkg ||
			!numericRE.MatchString(record.UID) ||
			identityUID == "" ||
			record.UID != identityUID {
			return nil, fmt.Errorf("record identity mismatch")
		}
		return []App{*record}, nil

	case "IGNORED_UID":
		return nil, nil

	case "NOT_INSTALLED":
		return nil, fmt.Errorf("NOT_INSTALLED")

	case "CONFLICTING_UID":
		return nil, fmt.Errorf("CONFLICTING_UID")

	default:
		if status == "" {
			return nil, fmt.Errorf("missing STATUS")
		}
		return nil, fmt.Errorf("refresh_app_single status %s", status)
	}
}

func sortApps(apps []App) {
	sort.SliceStable(apps, func(i, j int) bool {
		if apps[i].User != apps[j].User {
			return apps[i].User < apps[j].User
		}
		if apps[i].Pkg != apps[j].Pkg {
			return apps[i].Pkg < apps[j].Pkg
		}
		if apps[i].UID != apps[j].UID {
			return apps[i].UID < apps[j].UID
		}
		return apps[i].Name < apps[j].Name
	})
}

func writeCache(c Cache) error {
	tmp, err := os.CreateTemp(dataDir, "apps.json.apphelper.*")
	if err != nil {
		return err
	}

	tmpPath := tmp.Name()
	defer os.Remove(tmpPath)

	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)

	if err := enc.Encode(c); err != nil {
		tmp.Close()
		return err
	}

	if _, err := tmp.Write(buf.Bytes()); err != nil {
		tmp.Close()
		return err
	}

	if err := tmp.Sync(); err != nil {
		tmp.Close()
		return err
	}

	if err := tmp.Close(); err != nil {
		return err
	}

	if err := os.Chmod(tmpPath, 0644); err != nil {
		return err
	}

	if err := os.Rename(tmpPath, cache); err != nil {
		return err
	}

	return nil
}

func matchingApp(apps []App, user, pkg string) []App {
	var result []App

	for _, app := range apps {
		if app.User == user && app.Pkg == pkg {
			result = append(result, app)
		}
	}

	sortApps(result)
	return result
}

func sameApps(a, b []App) bool {
	if len(a) != len(b) {
		return false
	}

	aa := append([]App(nil), a...)
	bb := append([]App(nil), b...)

	sortApps(aa)
	sortApps(bb)

	for i := range aa {
		if aa[i] != bb[i] {
			return false
		}
	}

	return true
}

func sameAppIdentity(a, b []App) bool {
	if len(a) != len(b) {
		return false
	}

	aa := append([]App(nil), a...)
	bb := append([]App(nil), b...)

	sortApps(aa)
	sortApps(bb)

	for i := range aa {
		if aa[i].User != bb[i].User ||
			aa[i].Pkg != bb[i].Pkg ||
			aa[i].UID != bb[i].UID {
			return false
		}
	}

	return true
}

func verifyCacheApp(user, pkg string, expected []App) error {
	c, err := loadCache()
	if err != nil {
		return fmt.Errorf("verification: %w", err)
	}

	actual := matchingApp(c.Apps, user, pkg)
	if !sameApps(actual, expected) {
		return fmt.Errorf(
			"verification failed for %s|%s: expected %d record(s), found %d",
			user, pkg, len(expected), len(actual),
		)
	}

	return nil
}

func identityLines(apps []App) ([]string, error) {
	seen := make(map[string]string, len(apps))
	lines := make([]string, 0, len(apps))

	for _, app := range apps {
		if !numericRE.MatchString(app.User) ||
			!packageRE.MatchString(app.Pkg) ||
			!numericRE.MatchString(app.UID) {
			return nil, fmt.Errorf("invalid app identity %s|%s|%s",
				app.User, app.Pkg, app.UID)
		}

		key := app.User + "|" + app.Pkg
		line := key + "|" + app.UID

		if old, ok := seen[key]; ok {
			if old != line {
				return nil, fmt.Errorf(
					"CONFLICTING_UID for %s|%s",
					app.User, app.Pkg,
				)
			}
			continue
		}

		seen[key] = line
		lines = append(lines, line)
	}

	sort.Slice(lines, func(i, j int) bool {
		ai := strings.Split(lines[i], "|")
		aj := strings.Split(lines[j], "|")

		aiUser := ai[0]
		ajUser := aj[0]

		if aiUser != ajUser {
			// User IDs have already been validated as decimal strings.
			if len(aiUser) != len(ajUser) {
				return len(aiUser) < len(ajUser)
			}
			return aiUser < ajUser
		}
		if ai[1] != aj[1] {
			return ai[1] < aj[1]
		}
		return ai[2] < aj[2]
	})

	return lines, nil
}

func writeIdentity(apps []App) error {
	lines, err := identityLines(apps)
	if err != nil {
		return err
	}

	tmp, err := os.CreateTemp(dataDir, "apps.identity.apphelper.*")
	if err != nil {
		return err
	}

	tmpPath := tmp.Name()
	defer os.Remove(tmpPath)

	if len(lines) > 0 {
		if _, err := tmp.WriteString(strings.Join(lines, "\n") + "\n"); err != nil {
			tmp.Close()
			return err
		}
	}

	if err := tmp.Sync(); err != nil {
		tmp.Close()
		return err
	}

	if err := tmp.Close(); err != nil {
		return err
	}

	if err := os.Chmod(tmpPath, 0644); err != nil {
		return err
	}

	return os.Rename(tmpPath, identity)
}

func main() {
	if len(os.Args) != 4 {
		fmt.Fprintf(os.Stderr,
			"Usage: %s {ADDED|REMOVED|REPLACED} user package\n",
			os.Args[0])
		os.Exit(1)
	}

	action := strings.ToUpper(os.Args[1])
	user := os.Args[2]
	pkg := os.Args[3]

	switch action {
	case "ADDED", "REMOVED", "REPLACED":
	default:
		fail("INVALID_ACTION")
	}

	if !numericRE.MatchString(user) {
		fail("INVALID_USER")
	}

	if !packageRE.MatchString(pkg) {
		fail("INVALID_PACKAGE")
	}

	if err := acquireLock(); err != nil {
		if err.Error() == "APPS_BUSY" {
			fmt.Fprintln(os.Stderr, "APPS_BUSY")
			os.Exit(2)
		}
		fail("LOCK_FAILED: %v", err)
	}
	defer releaseLock()

	cacheData, err := loadCache()
	if err != nil {
		fail("CACHE_ERROR: %v", err)
	}

	old := matchingApp(cacheData.Apps, user, pkg)

	var expected []App

	if action != "REMOVED" {
		expected, err = runPackageRecord(user, pkg)
		if err != nil {
			fail("APP_REFRESH_FAILED: %v", err)
		}
	}

	updated := make([]App, 0, len(cacheData.Apps)+len(expected))
	inserted := false

	for _, app := range cacheData.Apps {
		if app.User == user && app.Pkg == pkg {
			if !inserted && len(expected) > 0 {
				updated = append(updated, expected...)
				inserted = true
			}
			continue
		}

		updated = append(updated, app)
	}

	if !inserted && len(expected) > 0 {
		updated = append(updated, expected...)
	}

	sortApps(updated)

	cacheData.Apps = updated

	newApps := matchingApp(cacheData.Apps, user, pkg)

	if sameApps(old, newApps) {
		fmt.Printf("UNCHANGED|%s|%s|%s\n", action, user, pkg)
		return
	}

	if err := writeCache(cacheData); err != nil {
		fail("CACHE_WRITE_FAILED: %v", err)
	}

	if err := verifyCacheApp(user, pkg, newApps); err != nil {
		fail("%v", err)
	}

	if err := writeIdentity(cacheData.Apps); err != nil {
		fail("IDENTITY_WRITE_FAILED: %v", err)
	}

	switch {
	case len(old) == 0 && len(newApps) > 0:
		fmt.Printf("ADDED|%s|%s\n", user, pkg)

	case len(old) > 0 && len(newApps) == 0:
		fmt.Printf("REMOVED|%s|%s\n", user, pkg)

	case len(old) > 0 && len(newApps) > 0 &&
		!sameAppIdentity(old, newApps):
		fmt.Printf("UPDATED|%s|%s\n", user, pkg)

	default:
		fmt.Printf("UNCHANGED|%s|%s|%s\n", action, user, pkg)
	}
}
