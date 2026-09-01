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
	"log"
	"os"

	"github.com/modelcontextprotocol/go-sdk/mcp"
	"github.com/spf13/cobra"
	"github.com/twsnmp/twlogeye/server"
)

// mcpCmd represents the mcp command
var mcpCmd = &cobra.Command{
	Use:   "mcp",
	Short: "Run MCP server via stdio",
	Long:  `Run TwLogEye Model Context Protocol (MCP) server over standard input/output (stdio) for local AI clients like Claude Desktop or Cursor.`,
	Run: func(cmd *cobra.Command, args []string) {
		log.SetOutput(os.Stderr)
		server.SetGRPCClient(getClient())
		s := server.NewMCPServer(Version)
		if err := s.Run(context.Background(), &mcp.StdioTransport{}); err != nil {
			log.Fatalf("mcp server error: %v", err)
		}
	},
}

func init() {
	rootCmd.AddCommand(mcpCmd)
}
