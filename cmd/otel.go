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
	"errors"
	"fmt"
	"io"
	"log"
	"strings"

	"github.com/spf13/cobra"
	"github.com/twsnmp/twlogeye/api"
)

// otelCmd represents the otel command
var otelCmd = &cobra.Command{
	Use:   "otel <metric|trace> <list|id>",
	Short: "Get OpenTelemetry info",
	Long:  `Get OpenTelemetry info via api`,
	Run: func(cmd *cobra.Command, args []string) {
		if len(args) < 2 {
			log.Fatalln("twlogeye otel <metric|trace> <list|id>")
		}
		switch args[0] {
		case "trace":
			getOTelTrace(args[1])
		default:
			getOTelMetric(args[1])
		}
	},
}

func init() {
	rootCmd.AddCommand(otelCmd)
}

func getOTelMetric(id string) {
	client := getClient()
	if id != "list" {
		r, err := client.GetOTelMetric(context.Background(), &api.IDRequest{Id: id})
		if err != nil {
			log.Fatalf("get otel metric err=%v", err)
		}
		fmt.Printf("host: %s\nservie: %s\nscope:%s\nname: %s\ndescr: %s\ndata(%s):----\n", r.Host, r.Service, r.Scope, r.Name, r.Description, r.Type)
		lastTime := int64(0)
		switch r.Type {
		case "Sum":
			for _, d := range r.DataPoints {
				if lastTime != d.Time {
					fmt.Printf("time: %s\n", getTimeStr(d.Time))
					lastTime = d.Time
				}
				fmt.Printf("%s: %f/%f/%f\n", strings.Join(d.Attributes, "/"), d.Sum, d.Min, d.Max)
			}
		case "Gauge":
			for _, d := range r.DataPoints {
				if lastTime != d.Time {
					fmt.Printf("time: %s\n", getTimeStr(d.Time))
					lastTime = d.Time
				}
				fmt.Printf("%s: %f\n", strings.Join(d.Attributes, "/"), d.Gauge)
			}
		case "Histogram":
			for _, d := range r.DataPoints {
				if lastTime != d.Time {
					fmt.Printf("time: %s\n", getTimeStr(d.Time))
					lastTime = d.Time
				}
				fmt.Printf("%s\n", strings.Join(d.Attributes, "/"))
				fmt.Printf("%v %v\n", d.BucketCounts, d.ExplicitBounds)
			}
		case "ExponentialHistogram":
			for _, d := range r.DataPoints {
				if lastTime != d.Time {
					fmt.Printf("time: %s\n", getTimeStr(d.Time))
					lastTime = d.Time
				}
				fmt.Printf("%s\n", strings.Join(d.Attributes, "/"))
				fmt.Printf("%d %f/%f/%f\n", d.Count, d.Sum, d.Min, d.Max)
				fmt.Printf("%v %v\n", d.Positive, d.Negative)
			}
		}
		return
	}
	s, err := client.GetOTelMetricList(context.Background(), &api.Empty{})
	if err != nil {
		log.Fatalf("get otel metric err=%v", err)
	}
	for {
		r, err := s.Recv()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			log.Fatalf("get otel metric err=%v", err)
		}
		fmt.Printf("%s\n", r.String())
	}
}

func getOTelTrace(id string) {
	client := getClient()
	if id != "list" {
		r, err := client.GetOTelTrace(context.Background(), &api.IDRequest{Id: id})
		if err != nil {
			log.Fatalf("get otel trace err=%v", err)
		}
		fmt.Printf("%s\n", r.String())
		return
	}
	s, err := client.GetOTelTraceList(context.Background(), &api.Empty{})
	if err != nil {
		log.Fatalf("get otel trace err=%v", err)
	}
	for {
		r, err := s.Recv()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			log.Fatalf("get otel trace err=%v", err)
		}
		fmt.Printf("%s\n", r.String())
	}
}
