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
	dataDir = "/data/adb/tirnsecurity"
	cache   = dataDir + "/apps.json"
	lockDir = dataDir + "/apps.lock"
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

func runPackageRecords(pkg string) ([]App, error) {
	/*
		app-common.sh remains the source of truth for:
		  - APK path discovery
		  - labels.conf overrides
		  - APK labels
		  - package-name fallback
		  - ignored UID filtering
		  - system-package detection
		  - JSON-safe record generation

		refresh_apps continues to use its optimized bulk AWK implementation.
	*/

	script := `
. /data/adb/tirnsecurity/app-common.sh || exit 1

PACKAGE="$1"
APK="$(get_apk_path "$PACKAGE")"
[ -n "$APK" ] || exit 0

USERS="$(mktemp "$DATA_DIR/apphelper.XXXXXX")"
SYSTEMS="$(mktemp "$DATA_DIR/apphelper.XXXXXX")"

trap 'rm -f "$USERS" "$SYSTEMS"' EXIT

pm list users 2>/dev/null |
sed -n 's/.*UserInfo{\([0-9][0-9]*\):[^:}]*:.*/\1/p' |
sort -n -u > "$USERS" || exit 1

while IFS= read -r USER
do
	[ -z "$USER" ] && continue

	pm list packages -s --user "$USER" </dev/null 2>/dev/null |
	sed 's/^package://' > "$SYSTEMS" || exit 1

	pm list packages --user "$USER" -U </dev/null 2>/dev/null |
	sed -n 's/^package:\([^ ]*\) uid:\([0-9]*\)$/\1|\2/p' |
	while IFS='|' read -r PKG UID
	do
		[ "$PKG" = "$PACKAGE" ] || continue
		build_app_record "$USER" "$UID" "$PKG" "$SYSTEMS" "$APK"
	done
done < "$USERS"
`

	cmd := exec.Command("/system/bin/sh", "-c", script, "apphelper", pkg)

	out, err := cmd.Output()
	if err != nil {
		if exitErr, ok := err.(*exec.ExitError); ok {
			return nil, fmt.Errorf("package scan failed: %s", strings.TrimSpace(string(exitErr.Stderr)))
		}
		return nil, err
	}

	var records []App

	for _, line := range strings.Split(strings.TrimSpace(string(out)), "\n") {
		if strings.TrimSpace(line) == "" {
			continue
		}

		var app App
		if err := json.Unmarshal([]byte(line), &app); err != nil {
			return nil, fmt.Errorf("invalid generated app record: %w", err)
		}

		if app.Pkg != pkg {
			return nil, fmt.Errorf("generated record has unexpected package %q", app.Pkg)
		}

		records = append(records, app)
	}

	sortApps(records)

	return records, nil
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

func matchingApps(apps []App, pkg string) []App {
	var result []App

	for _, app := range apps {
		if app.Pkg == pkg {
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

func verify(action, pkg string, expected []App) error {
	c, err := loadCache()
	if err != nil {
		return fmt.Errorf("verification: %w", err)
	}

	actual := matchingApps(c.Apps, pkg)

	switch action {
	case "REMOVED":
		if len(actual) != 0 {
			return fmt.Errorf("verification failed: %d record(s) remain for %s", len(actual), pkg)
		}

	case "ADDED", "REPLACED":
		if !sameApps(actual, expected) {
			return fmt.Errorf(
				"verification failed: expected %d record(s), found %d for %s",
				len(expected), len(actual), pkg,
			)
		}
	}

	return nil
}

func main() {
	if len(os.Args) != 3 {
		fmt.Fprintf(os.Stderr, "Usage: %s {ADDED|REMOVED|REPLACED} package\n", os.Args[0])
		os.Exit(1)
	}

	action := strings.ToUpper(os.Args[1])
	pkg := os.Args[2]

	switch action {
	case "ADDED", "REMOVED", "REPLACED":
	default:
		fail("INVALID_ACTION")
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

	var expected []App

	if action != "REMOVED" {
		expected, err = runPackageRecords(pkg)
		if err != nil {
			fail("PACKAGE_SCAN_FAILED: %v", err)
		}

		if len(expected) == 0 {
			fail("PACKAGE_NOT_FOUND")
		}
	}

	updated := make([]App, 0, len(cacheData.Apps)+len(expected))
	inserted := false

	for _, app := range cacheData.Apps {
		if app.Pkg == pkg {
			if !inserted && action != "REMOVED" {
				updated = append(updated, expected...)
				inserted = true
			}
			continue
		}

		updated = append(updated, app)
	}

	if !inserted && action != "REMOVED" {
		updated = append(updated, expected...)
	}

	cacheData.Apps = updated

	if err := writeCache(cacheData); err != nil {
		fail("CACHE_WRITE_FAILED: %v", err)
	}

	if err := verify(action, pkg, expected); err != nil {
		fail("%v", err)
	}

	fmt.Printf("OK|%s|%s|%d\n", action, pkg, len(expected))
}
