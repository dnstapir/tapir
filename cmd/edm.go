/*
 * Copyright (c) 2024 Johan Stenstam, johan.stenstam@internetstiftelsen.se
 */

package cmd

import (
	"bufio"
	"fmt"
	"io"
	"log"
	"net/http"
	"strconv"
	"strings"

	"github.com/ryanuber/columnize"
	"github.com/spf13/cobra"
)

var EdmCmd = &cobra.Command{
	Use:   "edm",
	Short: "Prefix command for EDM (Edge DNSTAP Minimiser) operations",
}

var EdmStatsCmd = &cobra.Command{
	Use:   "stats",
	Short: "Get statistics from the EDM metrics endpoint",
	Run: func(cmd *cobra.Command, args []string) {
		if len(args) != 0 {
			log.Fatal("stats must have no arguments")
		}

		// Get the metrics endpoint URL (hardcoded in EDM as 127.0.0.1:2112)
		metricsURL := "http://127.0.0.1:2112/metrics"

		// Make HTTP GET request
		resp, err := http.Get(metricsURL)
		if err != nil {
			log.Fatalf("Error connecting to EDM metrics endpoint at %s: %v\n"+
				"Is EDM running?", metricsURL, err)
		}
		defer resp.Body.Close()

		if resp.StatusCode != http.StatusOK {
			log.Fatalf("HTTP error from metrics endpoint: %s", resp.Status)
		}

		// Parse Prometheus text format
		metrics, err := parsePrometheusMetrics(resp.Body)
		if err != nil {
			log.Fatalf("Error parsing metrics: %v", err)
		}

		// Display EDM metrics in table format
		displayEdmMetrics(metrics)
	},
}

func init() {
	EdmCmd.AddCommand(EdmStatsCmd)
}

// parsePrometheusMetrics parses Prometheus text format and returns a map of metric name to value
func parsePrometheusMetrics(r io.Reader) (map[string]float64, error) {
	metrics := make(map[string]float64)
	scanner := bufio.NewScanner(r)

	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())

		// Skip empty lines and comments
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}

		// Parse metric line: "metric_name value"
		// Can also have labels like: metric_name{label="value"} value
		parts := strings.Fields(line)
		if len(parts) < 2 {
			continue
		}

		metricName := parts[0]
		// Remove any labels from metric name (everything after {)
		if idx := strings.Index(metricName, "{"); idx != -1 {
			metricName = metricName[:idx]
		}

		value, err := strconv.ParseFloat(parts[1], 64)
		if err != nil {
			// Skip lines that can't be parsed
			continue
		}

		metrics[metricName] = value
	}

	if err := scanner.Err(); err != nil {
		return nil, err
	}

	return metrics, nil
}

// displayEdmMetrics displays EDM-specific metrics in a table format
func displayEdmMetrics(metrics map[string]float64) {
	// Define the EDM metrics we want to display, in order
	edmMetrics := []struct {
		name        string
		description string
	}{
		{"edm_processed_dnstap_total", "DNSTAP packets processed"},
		{"edm_new_qname_queued_total", "New qname events queued"},
		{"edm_new_qname_discarded_total", "New qname events discarded"},
		{"edm_new_qname_ch_len", "New qname channel buffer length"},
		{"edm_seen_qname_lru_evicted_total", "Qname LRU cache evictions"},
		{"edm_cryptopan_lru_hit_total", "Crypto-PAn LRU cache hits"},
		{"edm_cryptopan_lru_evicted_total", "Crypto-PAn LRU cache evictions"},
		{"edm_ignored_client_ip_total", "Packets ignored (client IP filter)"},
		{"edm_ignored_client_ip_error_total", "Client IP filter errors"},
		{"edm_ignored_question_name_total", "Packets ignored (question name filter)"},
	}

	fmt.Println("EDM Statistics")
	fmt.Println()

	out := []string{"Metric|Value|Description"}

	for _, metric := range edmMetrics {
		value, exists := metrics[metric.name]
		if exists {
			// Format the metric name to remove "edm_" prefix for display
			displayName := strings.TrimPrefix(metric.name, "edm_")

			// Format value based on whether it's a counter or gauge
			var valueStr string
			if value == float64(int64(value)) {
				// Integer value
				valueStr = fmt.Sprintf("%d", int64(value))
			} else {
				// Float value
				valueStr = fmt.Sprintf("%.2f", value)
			}

			out = append(out, fmt.Sprintf("%s|%s|%s",
				displayName,
				valueStr,
				metric.description))
		}
	}

	if len(out) == 1 {
		fmt.Println("No EDM metrics found")
		return
	}

	fmt.Printf("%s\n", columnize.SimpleFormat(out))
}
