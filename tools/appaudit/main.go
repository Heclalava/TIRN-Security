package main

import (
	"archive/zip"
	"bufio"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"os/exec"
	"sort"
	"strings"
)

type Profile struct {
	ID   string `json:"id"`
	Name string `json:"name"`
}

type App struct {
	User    string `json:"user"`
	UID     string `json:"uid"`
	Package string `json:"pkg"`
	Name    string `json:"name"`
	System  bool   `json:"system"`
}

type AppsFile struct {
	Status   string    `json:"status"`
	Profiles []Profile `json:"profiles"`
	Apps     []App     `json:"apps"`
}

type PackageInfo struct {
	CodePath      string
	VersionCode   string
	VersionName   string
	Installer     string
	EnabledByUser map[string]string
}

func runDumpsysPackage() (string, error) {
	out, err := exec.Command("/system/bin/dumpsys", "package").Output()
	if err != nil {
		return "", err
	}
	return string(out), nil
}

func parsePackageDump(data string) map[string]*PackageInfo {
	result := make(map[string]*PackageInfo)
	scanner := bufio.NewScanner(strings.NewReader(data))

	var pkg string
	var info *PackageInfo

	flush := func() {
		if pkg != "" && info != nil {
			result[pkg] = info
		}
	}

	for scanner.Scan() {
		line := scanner.Text()
		trim := strings.TrimSpace(line)

		if strings.HasPrefix(trim, "Package [") && strings.HasSuffix(trim, "]:") == false {
			start := strings.Index(trim, "[")
			end := strings.Index(trim, "]")
			if start >= 0 && end > start {
				flush()
				pkg = trim[start+1 : end]
				info = &PackageInfo{
					EnabledByUser: make(map[string]string),
				}
				continue
			}
		}

		if info == nil {
			continue
		}

		switch {
		case strings.HasPrefix(trim, "codePath="):
			info.CodePath = strings.TrimSpace(strings.TrimPrefix(trim, "codePath="))

		case strings.HasPrefix(trim, "versionCode="):
			value := strings.TrimSpace(strings.TrimPrefix(trim, "versionCode="))
			if i := strings.IndexByte(value, ' '); i >= 0 {
				value = value[:i]
			}
			info.VersionCode = value

		case strings.HasPrefix(trim, "versionName="):
			info.VersionName = strings.TrimSpace(strings.TrimPrefix(trim, "versionName="))

		case strings.HasPrefix(trim, "installerPackageName="):
			info.Installer = strings.TrimSpace(strings.TrimPrefix(trim, "installerPackageName="))

		case strings.HasPrefix(trim, "User "):
			userEnd := strings.IndexByte(trim, ':')
			if userEnd <= 5 {
				continue
			}
			userID := strings.TrimSpace(trim[5:userEnd])
			for _, field := range strings.Fields(trim[userEnd+1:]) {
				if strings.HasPrefix(field, "enabled=") {
					info.EnabledByUser[userID] = strings.TrimPrefix(field, "enabled=")
					break
				}
			}
		}
	}

	flush()
	return result
}

func profileMap(profiles []Profile) map[string]string {
	out := make(map[string]string, len(profiles))
	for _, p := range profiles {
		out[p.ID] = p.Name
	}
	return out
}

func enabledState(value string) string {
	switch value {
	case "0":
		return "Enabled"
	case "1":
		return "Disabled"
	default:
		return "Unknown"
	}
}

func createZip(zipPath, root string, files []string) error {
	out, err := os.Create(zipPath)
	if err != nil {
		return err
	}
	defer out.Close()

	zw := zip.NewWriter(out)
	for _, name := range files {
		path := root + "/" + name
		info, err := os.Stat(path)
		if err != nil {
			return err
		}
		if !info.Mode().IsRegular() {
			continue
		}

		in, err := os.Open(path)
		if err != nil {
			return err
		}

		header, err := zip.FileInfoHeader(info)
		if err != nil {
			in.Close()
			return err
		}
		header.Name = name
		header.Method = zip.Deflate

		entry, err := zw.CreateHeader(header)
		if err != nil {
			in.Close()
			return err
		}

		if _, err := io.Copy(entry, in); err != nil {
			in.Close()
			return err
		}
		if err := in.Close(); err != nil {
			return err
		}
	}

	return zw.Close()
}

func zipMode() {
	if len(os.Args) < 5 {
		fmt.Fprintf(os.Stderr, "Usage: %s --zip output.zip root-dir file...\n", os.Args[0])
		os.Exit(1)
	}

	zipPath := os.Args[2]
	root := os.Args[3]

	if err := createZip(zipPath, root, os.Args[4:]); err != nil {
		fmt.Fprintf(os.Stderr, "create zip: %v\n", err)
		os.Exit(1)
	}
}

func policyMode() {
	if len(os.Args) != 5 {
		fmt.Fprintf(os.Stderr, "Usage: %s --policy apps.json policy-file output.txt\n", os.Args[0])
		os.Exit(1)
	}

	appsPath := os.Args[2]
	policyPath := os.Args[3]
	outputPath := os.Args[4]

	data, err := os.ReadFile(appsPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "read apps.json: %v\n", err)
		os.Exit(1)
	}

	var appsFile AppsFile
	if err := json.Unmarshal(data, &appsFile); err != nil {
		fmt.Fprintf(os.Stderr, "parse apps.json: %v\n", err)
		os.Exit(1)
	}

	type policyApp struct {
		Name    string
		Package string
	}

	appsByUID := make(map[string]policyApp, len(appsFile.Apps))
	for _, app := range appsFile.Apps {
		if _, exists := appsByUID[app.UID]; !exists {
			appsByUID[app.UID] = policyApp{
				Name:    app.Name,
				Package: app.Package,
			}
		}
	}

	in, err := os.Open(policyPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "open policy: %v\n", err)
		os.Exit(1)
	}
	defer in.Close()

	type policyRow struct {
		UID     string
		Network string
		Action  string
		AppName string
		Package string
	}

	var rows []policyRow
	scanner := bufio.NewScanner(in)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" {
			continue
		}

		parts := strings.Split(line, "|")
		if len(parts) != 3 {
			continue
		}

		uid := strings.TrimSpace(parts[0])
		network := strings.TrimSpace(parts[1])
		action := strings.TrimSpace(parts[2])
		if uid == "" || network == "" || action == "" {
			continue
		}

		app := appsByUID[uid]
		name := app.Name
		pkg := app.Package
		if name == "" {
			name = "Unknown"
		}
		if pkg == "" {
			pkg = "Unknown"
		}

		rows = append(rows, policyRow{
			UID:     uid,
			Network: network,
			Action:  action,
			AppName: name,
			Package: pkg,
		})
	}

	if err := scanner.Err(); err != nil {
		fmt.Fprintf(os.Stderr, "read policy: %v\n", err)
		os.Exit(1)
	}

	out, err := os.Create(outputPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "create policy audit: %v\n", err)
		os.Exit(1)
	}
	defer out.Close()

	fmt.Fprintln(out, "================================================")
	fmt.Fprintf(out, "TIRN Security Policy Audit: %s\n", policyPath)
	generated := mustCommand("/system/bin/date", "+%Y-%m-%d %H:%M:%S %Z%z")
	fmt.Fprintf(out, "Generated: %s\n", strings.TrimSpace(string(generated)))
	fmt.Fprintf(out, "Device: %s\n", strings.TrimSpace(string(mustCommand("/system/bin/getprop", "ro.product.model"))))
	fmt.Fprintf(out, "Android: %s\n", strings.TrimSpace(string(mustCommand("/system/bin/getprop", "ro.build.version.release"))))
	fmt.Fprintln(out, "================================================")
	fmt.Fprintln(out)

	headers := []string{"UID", "APP NAME", "PACKAGE", "INTERFACE", "ACTION"}
	widths := []int{
		len(headers[0]),
		len(headers[1]),
		len(headers[2]),
		len(headers[3]),
		len(headers[4]),
	}

	for _, row := range rows {
		values := []string{row.UID, row.AppName, row.Package, row.Network, row.Action}
		for i, value := range values {
			if len(value) > widths[i] {
				widths[i] = len(value)
			}
		}
	}

	format := fmt.Sprintf(
		"%%-%ds  %%-%ds  %%-%ds  %%-%ds  %%-%ds\n",
		widths[0], widths[1], widths[2], widths[3], widths[4],
	)

	fmt.Fprintf(out, format, headers[0], headers[1], headers[2], headers[3], headers[4])

	totalWidth := widths[0] + widths[1] + widths[2] + widths[3] + widths[4] + 8
	fmt.Fprintln(out, strings.Repeat("-", totalWidth))

	for _, row := range rows {
		fmt.Fprintf(out, format, row.UID, row.AppName, row.Package, row.Network, row.Action)
	}

	fmt.Fprintln(out)
	fmt.Fprintf(out, "Policy entries: %d\n", len(rows))
}

func main() {
	if len(os.Args) > 1 && os.Args[1] == "--zip" {
		zipMode()
		return
	}

	if len(os.Args) > 1 && os.Args[1] == "--policy" {
		policyMode()
		return
	}

	if len(os.Args) != 3 {
		fmt.Fprintf(os.Stderr, "Usage: %s apps.json output.txt\n", os.Args[0])
		os.Exit(1)
	}

	appsPath := os.Args[1]
	outputPath := os.Args[2]

	data, err := os.ReadFile(appsPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "read apps.json: %v\n", err)
		os.Exit(1)
	}

	var appsFile AppsFile
	if err := json.Unmarshal(data, &appsFile); err != nil {
		fmt.Fprintf(os.Stderr, "parse apps.json: %v\n", err)
		os.Exit(1)
	}

	dump, err := runDumpsysPackage()
	if err != nil {
		fmt.Fprintf(os.Stderr, "dumpsys package: %v\n", err)
		os.Exit(1)
	}

	packages := parsePackageDump(dump)
	profiles := profileMap(appsFile.Profiles)

	sort.SliceStable(appsFile.Apps, func(i, j int) bool {
		if appsFile.Apps[i].User != appsFile.Apps[j].User {
			return appsFile.Apps[i].User < appsFile.Apps[j].User
		}
		return strings.ToLower(appsFile.Apps[i].Name) < strings.ToLower(appsFile.Apps[j].Name)
	})

	out, err := os.Create(outputPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "create audit: %v\n", err)
		os.Exit(1)
	}
	defer out.Close()

	fmt.Fprintln(out, "================================================")
	fmt.Fprintln(out, "TIRN Security App Audit")
	generated := mustCommand("/system/bin/date", "+%Y-%m-%d %H:%M:%S %Z%z")
	fmt.Fprintf(out, "Generated: %s\n", strings.TrimSpace(string(generated)))
	fmt.Fprintf(out, "Device: %s\n", strings.TrimSpace(string(mustCommand("/system/bin/getprop", "ro.product.model"))))
	fmt.Fprintf(out, "Android: %s\n", strings.TrimSpace(string(mustCommand("/system/bin/getprop", "ro.build.version.release"))))
	fmt.Fprintln(out, "================================================")

	currentUser := ""
	for _, app := range appsFile.Apps {
		if app.User != currentUser {
			if currentUser != "" {
				fmt.Fprintln(out)
			}
			currentUser = app.User
			name := profiles[currentUser]
			if name == "" {
				name = "Profile " + currentUser
			}
			fmt.Fprintln(out)
			fmt.Fprintln(out, name)
			fmt.Fprintln(out, "================================================")
		}

		info := packages[app.Package]

		fmt.Fprintln(out)
		fmt.Fprintln(out, app.Name)
		fmt.Fprintln(out, "------------------------------------------------")
		fmt.Fprintf(out, "Package : %s\n", app.Package)
		fmt.Fprintf(out, "UID     : %s\n", app.UID)
		fmt.Fprintf(out, "Profile : %s (%s)\n", profiles[app.User], app.User)

		if app.System {
			fmt.Fprintln(out, "Type    : System app")
		} else {
			fmt.Fprintln(out, "Type    : User installed")
		}

		if info == nil {
			fmt.Fprintln(out, "APK     : Unknown")
			fmt.Fprintln(out, "Version : Unknown")
			fmt.Fprintln(out, "Enabled : Unknown")
			fmt.Fprintln(out, "Installer: Unknown")
			continue
		}

		fmt.Fprintf(out, "APK     : %s\n", info.CodePath)
		fmt.Fprintf(out, "Version : %s (code %s)\n", info.VersionName, info.VersionCode)
		fmt.Fprintf(out, "Enabled : %s\n", enabledState(info.EnabledByUser[app.User]))
		if info.Installer == "" || info.Installer == "null" {
			fmt.Fprintln(out, "Installer: Unknown")
		} else {
			fmt.Fprintf(out, "Installer: %s\n", info.Installer)
		}
	}
}

func mustCommand(name string, args ...string) []byte {
	out, _ := exec.Command(name, args...).Output()
	return out
}
