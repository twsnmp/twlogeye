package datastore

import (
	"embed"
	"io/fs"
	"log"
	"os"
	"path"
	"path/filepath"
	"strings"
)

//go:embed all:sigma
var sigmaFS embed.FS

// ForEachSigmaConfig : for each sigma config data
func ForEachSigmaConfig(callBack func(c string, d []byte)) {
	for _, c := range []string{"windows"} {
		p := path.Join("sigma", "config", c+".yaml")
		if d, err := sigmaFS.ReadFile(p); err == nil {
			callBack(c, d)
		}
	}
	if Config.SigmaConfigs == "" {
		return
	}
	filepath.WalkDir(Config.SigmaConfigs, func(path string, info fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if info.IsDir() {
			return nil
		}
		ext := strings.ToLower(filepath.Ext(path))
		if ext != ".yaml" && ext != ".yml" {
			return nil
		}
		c := strings.Replace(filepath.Base(path), filepath.Ext(path), "", 1)
		if d, err := os.ReadFile(path); err == nil {
			callBack(c, d)
		}
		return nil
	})
}

// ForEachSigmaRules : call back with sigma rule data
func ForEachSigmaRules(callBack func(c []byte, path string)) {
	if Config.SigmaRules == "" {
		log.Fatalln("no sigma rule path")
	}
	if strings.HasPrefix(Config.SigmaRules, "embed:") {
		p := path.Join("sigma", "rules", Config.SigmaRules[6:])
		l, err := sigmaFS.ReadDir(p)
		if err != nil {
			log.Fatalf("invalid rule path=%s err=%v", p, err)
		}
		for _, f := range l {
			if f.IsDir() {
				continue
			}
			pf := path.Join(p, f.Name())
			c, err := sigmaFS.ReadFile(pf)
			if err != nil {
				log.Fatalf("invalid rule=path %s err=%v", p, err)
			}
			callBack(c, p)
		}
	}
	for _, path := range getRulePath(Config.SigmaRules) {
		c, err := os.ReadFile(path)
		if err != nil {
			log.Fatalf("invalid rule %s %s", path, err)
		}
		callBack(c, path)
	}
}

// getRulePath : get rule path list
func getRulePath(root string) []string {
	ret := []string{}
	filepath.WalkDir(root, func(path string, info fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if info.IsDir() {
			if path != root && path != "." {
				ret = append(ret, getRulePath(path)...)
			}
			return nil
		}
		ext := strings.ToLower(filepath.Ext(path))
		if ext != ".yaml" && ext != ".yml" {
			return nil
		}
		ret = append(ret, path)
		return nil
	})
	return ret
}
