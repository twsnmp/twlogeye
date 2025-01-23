package datastore

import (
	"embed"
	"fmt"
	"io/fs"
	"log"
	"os"
	"path/filepath"
	"strings"
)

//go:embed sigma/**
var sigmafs embed.FS

// GetSigmaConfig : return sigma config data
func GetSigmaConfig() ([]byte, error) {
	if Config.SigmaConfig == "" {
		return nil, nil
	}
	if strings.HasPrefix(Config.SigmaConfig, "embed:") {
		path := fmt.Sprintf("sigma/config/%s.yaml", Config.SigmaConfig[6:])
		return sigmafs.ReadFile(path)
	}
	return os.ReadFile(Config.SigmaConfig)
}

// ForEachSigmaRules : call back with sigma rule data
func ForEachSigmaRules(callBack func(c []byte, path string)) {
	if Config.SigmaRules == "" {
		log.Fatalln("no sigma rule path")
	}
	if strings.HasPrefix(Config.SigmaConfig, "embed:") {
		path := fmt.Sprintf("sigma/rules/%s", Config.SigmaRules[6:])
		l, err := sigmafs.ReadDir(path)
		if err != nil {
			log.Fatalf("invalid rule path=%s err=%v", path, err)
		}
		for _, f := range l {
			if f.IsDir() {
				continue
			}
			p := filepath.Join(path, f.Name())
			c, err := sigmafs.ReadFile(p)
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
