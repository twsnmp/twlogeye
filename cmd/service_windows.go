//go:build windows

/*
Copyright © 2025 Masayuki Yamai <twsnmp@gmail.com>

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

	http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/
package cmd

import (
	"context"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"sync"
	"time"

	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/svc"
	"golang.org/x/sys/windows/svc/eventlog"
	"golang.org/x/sys/windows/svc/mgr"
)

func isWindowsService() bool {
	isSvc, err := svc.IsWindowsService()
	if err != nil {
		return false
	}
	return isSvc
}

type twlogeyeWindowsService struct {
	elog *eventlog.Log
}

func (ws *twlogeyeWindowsService) Execute(args []string, r <-chan svc.ChangeRequest, changes chan<- svc.Status) (bool, uint32) {
	const cmdsAccepted = svc.AcceptStop | svc.AcceptShutdown
	changes <- svc.Status{State: svc.StartPending}

	if ws.elog != nil {
		_ = ws.elog.Info(1, "TWLogEye service is starting")
	}

	ctx, cancel := context.WithCancel(context.Background())
	var wg sync.WaitGroup
	sigterm := make(chan os.Signal, 1)

	startServerDaemons(ctx, &wg, sigterm)

	changes <- svc.Status{State: svc.Running, Accepts: cmdsAccepted}
	if ws.elog != nil {
		_ = ws.elog.Info(1, "TWLogEye service started successfully")
	}

	for {
		select {
		case c := <-r:
			switch c.Cmd {
			case svc.Interrogate:
				changes <- c.CurrentStatus
			case svc.Stop, svc.Shutdown:
				if ws.elog != nil {
					_ = ws.elog.Info(1, "TWLogEye service stopping by SCM request")
				}
				changes <- svc.Status{State: svc.StopPending}
				stopServerDaemons(cancel, &wg)
				changes <- svc.Status{State: svc.Stopped}
				if ws.elog != nil {
					_ = ws.elog.Info(1, "TWLogEye service stopped")
				}
				return false, 0
			default:
				// ignore other requests
			}
		case <-sigterm:
			if ws.elog != nil {
				_ = ws.elog.Info(1, "TWLogEye service stopping by internal API request")
			}
			changes <- svc.Status{State: svc.StopPending}
			stopServerDaemons(cancel, &wg)
			changes <- svc.Status{State: svc.Stopped}
			if ws.elog != nil {
				_ = ws.elog.Info(1, "TWLogEye service stopped")
			}
			return false, 0
		}
	}
}

func runWindowsService() error {
	// Set working directory to executable directory to resolve relative paths correctly
	if exe, err := os.Executable(); err == nil {
		_ = os.Chdir(filepath.Dir(exe))
	}

	elog, err := eventlog.Open(serviceName)
	if err != nil {
		log.Printf("failed to open eventlog for %s: %v", serviceName, err)
		elog = nil
	} else {
		defer elog.Close()
	}

	return svc.Run(serviceName, &twlogeyeWindowsService{elog: elog})
}

func runServiceInstall() {
	exePath, err := os.Executable()
	if err != nil {
		log.Fatalf("failed to get executable path: %v", err)
	}
	exePath, err = filepath.Abs(exePath)
	if err != nil {
		log.Fatalf("failed to get absolute executable path: %v", err)
	}

	m, err := mgr.Connect()
	if err != nil {
		log.Fatalf("failed to connect to service manager: %v (are you running as Administrator?)", err)
	}
	defer m.Disconnect()

	s, err := m.OpenService(serviceName)
	if err == nil {
		s.Close()
		log.Fatalf("service '%s' already exists", serviceName)
	}

	startType := mgr.StartAutomatic
	if !serviceAutoStart {
		startType = mgr.StartManual
	}

	args := []string{"start"}
	if serviceConfigFile != "" {
		absCfg, err := filepath.Abs(serviceConfigFile)
		if err == nil {
			args = append(args, "--config", absCfg)
		} else {
			args = append(args, "--config", serviceConfigFile)
		}
	}

	config := mgr.Config{
		ServiceType:  windows.SERVICE_WIN32_OWN_PROCESS,
		StartType:    uint32(startType),
		ErrorControl: mgr.ErrorNormal,
		DisplayName:  serviceDisplayName,
		Description:  serviceDescription,
	}

	s, err = m.CreateService(serviceName, exePath, config, args...)
	if err != nil {
		log.Fatalf("failed to create service: %v", err)
	}
	defer s.Close()

	// Register eventlog source
	err = eventlog.InstallAsEventCreate(serviceName, eventlog.Error|eventlog.Warning|eventlog.Info)
	if err != nil {
		log.Printf("warning: could not register eventlog source: %v", err)
	}

	fmt.Printf("Service '%s' installed successfully.\n", serviceName)
	if serviceAutoStart {
		fmt.Println("Startup type: Automatic")
	} else {
		fmt.Println("Startup type: Manual")
	}
}

func runServiceRemove() {
	m, err := mgr.Connect()
	if err != nil {
		log.Fatalf("failed to connect to service manager: %v (are you running as Administrator?)", err)
	}
	defer m.Disconnect()

	s, err := m.OpenService(serviceName)
	if err != nil {
		log.Fatalf("service '%s' does not exist", serviceName)
	}
	defer s.Close()

	status, err := s.Query()
	if err == nil && status.State == svc.Running {
		fmt.Printf("Stopping service '%s' before removal...\n", serviceName)
		_, _ = s.Control(svc.Stop)
		time.Sleep(2 * time.Second)
	}

	err = s.Delete()
	if err != nil {
		log.Fatalf("failed to delete service: %v", err)
	}

	_ = eventlog.Remove(serviceName)
	fmt.Printf("Service '%s' removed successfully.\n", serviceName)
}

func runServiceStart() {
	m, err := mgr.Connect()
	if err != nil {
		log.Fatalf("failed to connect to service manager: %v (are you running as Administrator?)", err)
	}
	defer m.Disconnect()

	s, err := m.OpenService(serviceName)
	if err != nil {
		log.Fatalf("service '%s' does not exist", serviceName)
	}
	defer s.Close()

	err = s.Start()
	if err != nil {
		log.Fatalf("failed to start service: %v", err)
	}

	fmt.Printf("Service '%s' start command sent.\n", serviceName)
}

func runServiceStop() {
	m, err := mgr.Connect()
	if err != nil {
		log.Fatalf("failed to connect to service manager: %v (are you running as Administrator?)", err)
	}
	defer m.Disconnect()

	s, err := m.OpenService(serviceName)
	if err != nil {
		log.Fatalf("service '%s' does not exist", serviceName)
	}
	defer s.Close()

	status, err := s.Control(svc.Stop)
	if err != nil {
		log.Fatalf("failed to stop service: %v", err)
	}

	fmt.Printf("Service '%s' stop command sent (current state: %d).\n", serviceName, status.State)
}

func runServiceStatus() {
	m, err := mgr.Connect()
	if err != nil {
		log.Fatalf("failed to connect to service manager: %v (are you running as Administrator?)", err)
	}
	defer m.Disconnect()

	s, err := m.OpenService(serviceName)
	if err != nil {
		log.Fatalf("service '%s' does not exist", serviceName)
	}
	defer s.Close()

	status, err := s.Query()
	if err != nil {
		log.Fatalf("failed to query service status: %v", err)
	}

	var stateStr string
	switch status.State {
	case svc.Stopped:
		stateStr = "Stopped"
	case svc.StartPending:
		stateStr = "StartPending"
	case svc.StopPending:
		stateStr = "StopPending"
	case svc.Running:
		stateStr = "Running"
	case svc.ContinuePending:
		stateStr = "ContinuePending"
	case svc.PausePending:
		stateStr = "PausePending"
	case svc.Paused:
		stateStr = "Paused"
	default:
		stateStr = fmt.Sprintf("Unknown (%d)", status.State)
	}

	fmt.Printf("Service '%s' status: %s\n", serviceName, stateStr)
}
