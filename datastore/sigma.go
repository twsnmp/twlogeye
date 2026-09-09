package datastore

import (
	"embed"
	"fmt"
	"io/fs"
	"log"
	"os"
	"path"
	"path/filepath"
	"strings"

	"github.com/dgraph-io/badger/v4"
)

//go:embed all:sigma
var sigmaFS embed.FS

// GetAvailableSigmaPacks : returns list of available embedded rule packs
func GetAvailableSigmaPacks() []string {
	ret := []string{}
	entries, err := sigmaFS.ReadDir("sigma/rules/packs")
	if err != nil {
		return ret
	}
	for _, entry := range entries {
		if entry.IsDir() {
			ret = append(ret, entry.Name())
		}
	}
	return ret
}

// SigmaPackInfo contains metadata about an embedded Sigma rule pack
type SigmaPackInfo struct {
	Name        string   `json:"name"`
	RuleCount   int      `json:"rule_count"`
	Description string   `json:"description"`
	Rules       []string `json:"rules,omitempty"`
}

// GetSigmaPackDescription returns a brief human-readable description of the pack
func GetSigmaPackDescription(pack string) string {
	switch pack {
	case "windows-essential":
		return "Essential security monitoring for Windows environments (failed logons, privilege escalation, defender tampering)"
	case "windows-ad":
		return "Active Directory / Domain Controller threats (Kerberoasting, AS-REP roasting, DCSync, trust changes)"
	case "windows-client":
		return "Windows endpoint & client threats (suspicious RDP, UAC bypass, USB media, LSASS dump)"
	case "linux-auth":
		return "Linux authentication and privilege escalation (SSH brute-force, sudo abuse, PAM failures)"
	case "linux-system":
		return "Linux persistence, rootkits, suspicious cron jobs, and system tampering"
	case "network-threats":
		return "Network devices, firewalls, and VPN threats (Cisco, Fortinet, PAN-OS, brute-force)"
	case "web-attacks":
		return "Web application attacks (SQL injection, XSS, directory traversal, web shells)"
	case "wazuh-compliance":
		return "Wazuh compliance and hardening verification rules"
	case "wazuh-linux":
		return "Wazuh converted Linux security and daemon rules"
	case "wazuh-network":
		return "Wazuh converted network device and firewall rules"
	case "wazuh-web":
		return "Wazuh converted web application and server access rules"
	default:
		return "Embedded Sigma rule pack: " + pack
	}
}

// GetSigmaPackInfo returns pack information including rule count and optional rule list
func GetSigmaPackInfo(pack string, includeRules bool) (*SigmaPackInfo, error) {
	packDir := path.Join("sigma", "rules", "packs", pack)
	info := &SigmaPackInfo{
		Name:        pack,
		Description: GetSigmaPackDescription(pack),
	}
	err := fs.WalkDir(sigmaFS, packDir, func(filePath string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return nil
		}
		ext := strings.ToLower(filepath.Ext(filePath))
		if ext == ".yaml" || ext == ".yml" {
			info.RuleCount++
			if includeRules {
				info.Rules = append(info.Rules, filepath.Base(filePath))
			}
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	if info.RuleCount == 0 {
		return nil, fmt.Errorf("pack %s not found or contains no rules", pack)
	}
	return info, nil
}

// GetAllSigmaPacksInfo returns metadata for all available packs
func GetAllSigmaPacksInfo() []*SigmaPackInfo {
	packs := GetAvailableSigmaPacks()
	var ret []*SigmaPackInfo
	for _, p := range packs {
		if info, err := GetSigmaPackInfo(p, false); err == nil {
			ret = append(ret, info)
		}
	}
	return ret
}

// ForEachSigmaConfig : for each sigma config data
func ForEachSigmaConfig(callBack func(c string, d []byte)) {
	entries, err := sigmaFS.ReadDir("sigma/config")
	if err == nil {
		for _, entry := range entries {
			if entry.IsDir() {
				continue
			}
			ext := strings.ToLower(filepath.Ext(entry.Name()))
			if ext == ".yaml" || ext == ".yml" {
				c := strings.TrimSuffix(entry.Name(), filepath.Ext(entry.Name()))
				p := path.Join("sigma", "config", entry.Name())
				if d, err := sigmaFS.ReadFile(p); err == nil {
					callBack(c, d)
				}
			}
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

// ForEachSigmaRules : call back with sigma rule data (backward compatible)
func ForEachSigmaRules(callBack func(c []byte, path string)) {
	ForEachSigmaRulesWithSource(func(c []byte, path, _ string) {
		callBack(c, path)
	})
}

// ForEachSigmaRulesWithSource : call back with sigma rule data and source information
func ForEachSigmaRulesWithSource(callBack func(c []byte, path, source string)) {
	// 1. Load packs from embed
	for _, pack := range Config.SigmaPacks {
		packDir := path.Join("sigma", "rules", "packs", pack)
		source := "pack:" + pack
		_ = fs.WalkDir(sigmaFS, packDir, func(filePath string, info fs.DirEntry, err error) error {
			if err != nil || info.IsDir() {
				return nil
			}
			ext := strings.ToLower(filepath.Ext(filePath))
			if ext != ".yaml" && ext != ".yml" {
				return nil
			}
			if c, err := sigmaFS.ReadFile(filePath); err == nil {
				callBack(c, filePath, source)
			}
			return nil
		})
	}

	// 2. Load individual rules from path or default embed if nothing specified
	rulePath := Config.SigmaRules
	if rulePath == "" && len(Config.SigmaPacks) == 0 {
		rulePath = "embed:"
	}

	if rulePath != "" {
		if strings.HasPrefix(rulePath, "embed:") {
			sub := ""
			if len(rulePath) > 6 {
				sub = rulePath[6:]
			}
			p := "sigma/rules"
			if sub != "" {
				p = path.Join("sigma", "rules", sub)
			}
			source := "embed"
			if sub != "" {
				source = "embed:" + sub
			}
			_ = fs.WalkDir(sigmaFS, p, func(filePath string, info fs.DirEntry, err error) error {
				if err != nil || info.IsDir() {
					return nil
				}
				ext := strings.ToLower(filepath.Ext(filePath))
				if ext != ".yaml" && ext != ".yml" {
					return nil
				}
				c, err := sigmaFS.ReadFile(filePath)
				if err != nil {
					log.Printf("invalid rule path %s err=%v", filePath, err)
					return nil
				}
				callBack(c, filePath, source)
				return nil
			})
		} else {
			for _, p := range getRulePath(rulePath) {
				c, err := os.ReadFile(p)
				if err != nil {
					log.Fatalf("invalid rule %s %s", p, err)
				}
				callBack(c, p, "file:"+p)
			}
		}
	}

	// 3. Load from DB
	ForEachSigmaRuleOnDB(func(c []byte, id string) {
		callBack(c, id, "db")
	})
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

func AddSigmaRuleToDB(id, rule string) error {
	if db == nil {
		return fmt.Errorf("db not open")
	}
	return db.Update(func(txn *badger.Txn) error {
		k := fmt.Sprintf("sigma:rule:%s", id)
		e := badger.NewEntry([]byte(k), []byte(rule))
		return txn.SetEntry(e)
	})
}

func GetSigmaRuleFromDB(id string) (string, error) {
	if db == nil {
		return "", fmt.Errorf("db not open")
	}
	r := ""
	err := db.View(func(txn *badger.Txn) error {
		if item, err := txn.Get([]byte("sigma:rule:" + id)); err == nil {
			item.Value(func(v []byte) error {
				r = string(v)
				return nil
			})
			return nil
		} else {
			return err
		}
	})
	return r, err
}

func DeleteSigmaRuleFromDB(id string) error {
	if db == nil {
		return fmt.Errorf("db not open")
	}
	return db.Update(func(txn *badger.Txn) error {
		k := fmt.Sprintf("sigma:rule:%s", id)
		return txn.Delete([]byte(k))
	})
}

func ForEachSigmaRuleOnDB(callBack func(c []byte, id string)) {
	if db == nil {
		return
	}
	db.View(func(txn *badger.Txn) error {
		it := txn.NewIterator(badger.DefaultIteratorOptions)
		defer it.Close()
		prefix := []byte("sigma:rule:")
		for it.Seek(prefix); it.ValidForPrefix(prefix); it.Next() {
			item := it.Item()
			k := item.Key()
			item.Value(func(v []byte) error {
				callBack(v, string(k))
				return nil
			})
		}
		return nil
	})
}
