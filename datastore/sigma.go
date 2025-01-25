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

// GetSigmaConfig : return sigma config data
func GetSigmaConfig() ([]byte, error) {
	if Config.SigmaConfig == "" {
		return nil, nil
	}
	if strings.HasPrefix(Config.SigmaConfig, "embed:") {
		p := path.Join("sigma", "config", Config.SigmaConfig[6:]+".yaml")
		log.Printf("user sigma config %s", p)
		return sigmaFS.ReadFile(p)
	}
	return os.ReadFile(Config.SigmaConfig)
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
	filepath.WalkDir(Config.SigmaRules, func(path string, info fs.DirEntry, err error) error {
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
		c, err := os.ReadFile(path)
		if err != nil {
			log.Fatalf("invalid rule %s %s", path, err)
		}
		callBack(c, path)
		return nil
	})
}
