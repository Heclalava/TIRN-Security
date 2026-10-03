package main

import (
	"archive/zip"
	"bytes"
	"fmt"
	"io"
	"os"
	"os/exec"
	"strings"

	"github.com/chenhuifeng/androidbinary"
)

type Manifest struct {
	App Application `xml:"application"`
}

type Application struct {
	Label androidbinary.String `xml:"http://schemas.android.com/apk/res/android label,attr"`
}

func deviceLocale() *androidbinary.ResTableConfig {
	locale := strings.TrimSpace(os.Getenv("TIRN_LOCALE"))
	if locale == "" {
		out, err := exec.Command("/system/bin/getprop", "persist.sys.locale").Output()
		if err != nil {
			return &androidbinary.ResTableConfig{}
		}
		locale = strings.TrimSpace(string(out))
	}
	if i := strings.Index(locale, "-u-"); i >= 0 {
		locale = locale[:i]
	}

	parts := strings.Split(locale, "-")
	if len(parts) == 0 || len(parts[0]) != 2 {
		return &androidbinary.ResTableConfig{}
	}

	c := &androidbinary.ResTableConfig{}
	c.Language = [2]uint8{parts[0][0], parts[0][1]}

	if len(parts) >= 2 && len(parts[1]) == 2 {
		c.Country = [2]uint8{parts[1][0], parts[1][1]}
	}

	return c
}

func main() {
	if len(os.Args) != 2 {
		os.Exit(2)
	}

	f, err := os.Open(os.Args[1])
	if err != nil {
		os.Exit(1)
	}
	defer f.Close()

	st, err := f.Stat()
	if err != nil {
		os.Exit(1)
	}

	zr, err := zip.NewReader(f, st.Size())
	if err != nil {
		os.Exit(1)
	}

	readZip := func(name string) ([]byte, error) {
		for _, z := range zr.File {
			if z.Name != name {
				continue
			}
			r, err := z.Open()
			if err != nil {
				return nil, err
			}
			defer r.Close()
			return io.ReadAll(r)
		}
		return nil, fmt.Errorf("missing %s", name)
	}

	resData, err := readZip("resources.arsc")
	if err != nil {
		os.Exit(1)
	}

	table, err := androidbinary.NewTableFile(bytes.NewReader(resData))
	if err != nil {
		os.Exit(1)
	}

	xmlData, err := readZip("AndroidManifest.xml")
	if err != nil {
		os.Exit(1)
	}

	xmlFile, err := androidbinary.NewXMLFile(bytes.NewReader(xmlData))
	if err != nil {
		os.Exit(1)
	}

	var manifest Manifest
	if err := xmlFile.Decode(&manifest, table, nil); err != nil {
		os.Exit(1)
	}

	config := deviceLocale()
	label, err := manifest.App.Label.WithResTableConfig(config).String()

	if err != nil || label == "" || androidbinary.IsResID(label) {
		if config.Language != [2]uint8{} {
			languageOnly := &androidbinary.ResTableConfig{Language: config.Language}
			label, err = manifest.App.Label.WithResTableConfig(languageOnly).String()
		}
	}

	if err != nil || label == "" || androidbinary.IsResID(label) {
		english := &androidbinary.ResTableConfig{Language: [2]uint8{'e', 'n'}}
		label, err = manifest.App.Label.WithResTableConfig(english).String()
	}

	if err != nil || label == "" || androidbinary.IsResID(label) {
		label, err = manifest.App.Label.WithResTableConfig(&androidbinary.ResTableConfig{}).String()
	}

	if err != nil || label == "" || androidbinary.IsResID(label) {
		os.Exit(1)
	}

	fmt.Println(label)
}
