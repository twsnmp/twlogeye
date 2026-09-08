package cmd

import (
	"testing"
)

func TestServiceCommand(t *testing.T) {
	if serviceCmd == nil {
		t.Fatal("serviceCmd is nil")
	}

	subCommands := map[string]bool{
		"install": false,
		"remove":  false,
		"start":   false,
		"stop":    false,
		"status":  false,
	}

	for _, c := range serviceCmd.Commands() {
		if _, ok := subCommands[c.Name()]; ok {
			subCommands[c.Name()] = true
		}
	}

	for name, found := range subCommands {
		if !found {
			t.Errorf("expected sub-command '%s' not found under serviceCmd", name)
		}
	}

	// Verify flags on serviceCmd
	if serviceCmd.PersistentFlags().Lookup("name") == nil {
		t.Error("flag --name not found on serviceCmd")
	}

	// Verify flags on serviceInstallCmd
	if serviceInstallCmd.Flags().Lookup("displayName") == nil {
		t.Error("flag --displayName not found on serviceInstallCmd")
	}
	if serviceInstallCmd.Flags().Lookup("description") == nil {
		t.Error("flag --description not found on serviceInstallCmd")
	}
	if serviceInstallCmd.Flags().Lookup("config") == nil {
		t.Error("flag --config not found on serviceInstallCmd")
	}
	if serviceInstallCmd.Flags().Lookup("autoStart") == nil {
		t.Error("flag --autoStart not found on serviceInstallCmd")
	}
}
