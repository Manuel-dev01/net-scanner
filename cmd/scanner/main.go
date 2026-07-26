package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/Manuel-dev01/net-scanner/internal/config"
	"github.com/Manuel-dev01/net-scanner/internal/dashboard"
	"github.com/Manuel-dev01/net-scanner/internal/scanner"
	"github.com/jackc/pgx/v5/pgxpool"
)

func main() {
	// Initialize modern structured JSON logging to stderr
	logger := slog.New(slog.NewJSONHandler(os.Stderr, nil))
	slog.SetDefault(logger)

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	// Load configuration once; every subcommand shares it.
	cfg := config.Load()

	// Connect to Database
	pool, err := pgxpool.New(ctx, cfg.DatabaseURL)
	if err != nil {
		slog.Error("Database link breakdown", "error", err)
		os.Exit(1)
	}
	defer pool.Close()

	// Verify a subcommand was passed
	if len(os.Args) < 2 {
		fmt.Println("Usage: scanner <command> [options]\nCommands:\n  scan --cidr <cidr>        Run a network sweep\n  list                      List all tracked subnets\n  diff --cidr <cidr>        Show host status changes between last two scans\n  dashboard [--mode poller]  Start traffic analytics dashboard")
		os.Exit(1)
	}

	// Parse subcommands
	switch os.Args[1] {
	case "scan":
		scanCmd := flag.NewFlagSet("scan", flag.ExitOnError)
		cidrFlag := scanCmd.String("cidr", "", "Target CIDR block (e.g., 192.168.1.0/29)")
		scanCmd.Parse(os.Args[2:])

		if *cidrFlag == "" {
			slog.Error("Missing required flag: --cidr")
			os.Exit(1)
		}
		executeScan(ctx, pool, *cidrFlag)

	case "list":
		executeList(ctx, pool)

	case "diff":
		diffCmd := flag.NewFlagSet("diff", flag.ExitOnError)
		cidrFlag := diffCmd.String("cidr", "", "Target CIDR block to analyze")
		diffCmd.Parse(os.Args[2:])

		if *cidrFlag == "" {
			slog.Error("Missing required flag: --cidr")
			os.Exit(1)
		}
		executeDiff(ctx, pool, *cidrFlag)

	case "dashboard":
		dashCmd := flag.NewFlagSet("dashboard", flag.ExitOnError)
		// Flag defaults are seeded from config so the NS_* environment
		// variables apply unless a flag is explicitly passed.
		modeFlag := dashCmd.String("mode", cfg.CaptureMode, "Capture mode: poller or pcap")
		geoipFlag := dashCmd.String("geoip", cfg.GeoIPDBPath, "Path to GeoLite2-City.mmdb")
		portFlag := dashCmd.Int("port", cfg.MetricsPort, "Prometheus metrics port")
		dashCmd.Parse(os.Args[2:])

		cfg.CaptureMode = *modeFlag
		cfg.MetricsPort = *portFlag
		cfg.GeoIPDBPath = *geoipFlag
		if err := dashboard.Run(ctx, pool, cfg); err != nil {
			slog.Error("Dashboard error", "error", err)
			os.Exit(1)
		}

	default:
		fmt.Printf("Unknown command: %s\n", os.Args[1])
		os.Exit(1)
	}
}

// 1. SCAN SUBCOMMAND ENGINE
func executeScan(ctx context.Context, pool *pgxpool.Pool, cidr string) {
	slog.Info("Initiating concurrent scan", "cidr", cidr)

	var subnetID int
	err := pool.QueryRow(ctx, `
		INSERT INTO subnets (cidr, description) VALUES ($1, 'Asset Track Layer') 
		ON CONFLICT (cidr) DO UPDATE SET description = EXCLUDED.description RETURNING id;`, cidr).Scan(&subnetID)
	if err != nil {
		slog.Error("Subnet tracking write failure", "error", err)
		return
	}

	var scanID int64
	scanStart := time.Now()
	err = pool.QueryRow(ctx, "INSERT INTO scans (subnet_id, started_at) VALUES ($1, $2) RETURNING id;", subnetID, scanStart).Scan(&scanID)
	if err != nil {
		slog.Error("Failed to create scan row", "error", err)
		return
	}

	results, err := scanner.Run(ctx, scanner.Config{CIDR: cidr})
	if err != nil {
		slog.Error("Scanner engine fault", "error", err)
		return
	}
	scanEnd := time.Now()

	for _, host := range results {
        rttMs := float64(host.RTT) / float64(time.Millisecond)
        _, err = pool.Exec(ctx, `
            INSERT INTO hosts (scan_id, ip, hostname, rtt_ms, is_up, open_ports, first_seen_at, last_seen_at)
            VALUES ($1, $2, $3, $4, $5, $6, $7, $8);`,
            scanID, host.IP, host.Hostname, rttMs, host.IsUp, host.OpenPorts, host.ScannedAt, host.ScannedAt,
        )
        if err != nil {
            slog.Error("Failed to insert host row", "ip", host.IP, "error", err)
        }
    }
	
	pool.Exec(ctx, "UPDATE scans SET ended_at = $1 WHERE id = $2;", scanEnd, scanID)
	slog.Info("Scan sweep complete and persisted securely", "targets", len(results), "duration", scanEnd.Sub(scanStart))
}

// 2. LIST SUBCOMMAND ENGINE
func executeList(ctx context.Context, pool *pgxpool.Pool) {
	// Show tracked subnets
	rows, err := pool.Query(ctx, "SELECT id, cidr::text, description, created_at FROM subnets ORDER BY created_at DESC;")
	if err != nil {
		slog.Error("Query failed", "error", err)
		return
	}
	defer rows.Close()

	fmt.Printf("\n%-5s %-20s %-25s %-20s\n", "ID", "CIDR BLOCK", "DESCRIPTION", "TRACKED AT")
	fmt.Println("-------------------------------------------------------------------------------------")
	var subnetIDs []int
	for rows.Next() {
		var id int
		var cidr, desc string
		var createdAt time.Time
		if err := rows.Scan(&id, &cidr, &desc, &createdAt); err != nil {
			slog.Error("Failed to scan subnet row", "error", err)
			continue
		}
		fmt.Printf("%-5d %-20s %-25s %-20s\n", id, cidr, desc, createdAt.Format("2006-01-02 15:04"))
		subnetIDs = append(subnetIDs, id)
	}
	if err := rows.Err(); err != nil {
		slog.Error("Row iteration error", "error", err)
	}
	rows.Close()

	if len(subnetIDs) == 0 {
		fmt.Println("\nNo subnets tracked yet. Run: scanner scan --cidr <cidr>")
		return
	}

	// Show discovered hosts from the latest scan per subnet
	for _, subnetID := range subnetIDs {
		var scanID int64
		var cidr string
		err := pool.QueryRow(ctx, `
			SELECT s.id, sub.cidr::text FROM scans s
			JOIN subnets sub ON s.subnet_id = sub.id
			WHERE sub.id = $1 ORDER BY s.started_at DESC LIMIT 1;`, subnetID).Scan(&scanID, &cidr)
		if err != nil {
			slog.Error("Failed to fetch latest scan", "subnet_id", subnetID, "error", err)
			continue
		}

		hostRows, err := pool.Query(ctx, `
			SELECT ip::text, COALESCE(hostname, ''), COALESCE(rtt_ms, 0), is_up, COALESCE(open_ports, '{}')
			FROM hosts WHERE scan_id = $1 ORDER BY ip;`, scanID)
		if err != nil {
			slog.Error("Failed to query hosts", "scan_id", scanID, "error", err)
			continue
		}

		fmt.Printf("\nHosts for %s (scan #%d):\n", cidr, scanID)
		fmt.Printf("%-18s %-25s %-10s %-6s %-15s\n", "IP", "HOSTNAME", "RTT(ms)", "UP", "OPEN PORTS")
		fmt.Println("-------------------------------------------------------------------------------------")
		found := 0
		for hostRows.Next() {
			var ip, hostname string
			var rttMs float64
			var isUp bool
			var openPorts []int32
			if err := hostRows.Scan(&ip, &hostname, &rttMs, &isUp, &openPorts); err != nil {
				slog.Error("Failed to scan host row", "error", err)
				continue
			}
			// Strip /32 suffix from PostgreSQL INET cast
			if idx := strings.Index(ip, "/"); idx != -1 {
				ip = ip[:idx]
			}
			upStr := "no"
			if isUp {
				upStr = "yes"
			}
			portsStr := "-"
			if len(openPorts) > 0 {
				b, _ := json.Marshal(openPorts)
				portsStr = string(b)
			}
			hostDisplay := hostname
			if hostDisplay == "" {
				hostDisplay = "-"
			}
			fmt.Printf("%-18s %-25s %-10.2f %-6s %-15s\n", ip, hostDisplay, rttMs, upStr, portsStr)
			found++
		}
		hostRows.Close()
		if found == 0 {
			fmt.Println("  (no hosts recorded for this scan)")
		}
	}
}

// 3. DIFF SUBCOMMAND ENGINE
func executeDiff(ctx context.Context, pool *pgxpool.Pool, cidr string) {
	// Query the IDs of the last two historical scans run against this specific subnet block
	rows, err := pool.Query(ctx, `
		SELECT s.id FROM scans s JOIN subnets sub ON s.subnet_id = sub.id 
		WHERE sub.cidr = $1 ORDER BY s.started_at DESC LIMIT 2;`, cidr)
	if err != nil {
		slog.Error("Failed to fetch historical scan metadata", "error", err)
		return
	}
	defer rows.Close()

	var scanIDs []int64
	for rows.Next() {
		var id int64
		if err := rows.Scan(&id); err == nil {
			scanIDs = append([]int64{id}, scanIDs...) // Prepend to preserve historical order
		}
	}

	if len(scanIDs) < 2 {
		slog.Warn("Insufficient history to calculate drift. Run at least two scans first.", "cidr", cidr)
		return
	}

	prevScanID := scanIDs[0]
	latestScanID := scanIDs[1]

	// SQL self-join mapping to isolate structural changes between the two unique scanning snapshots.
	//
	// The comparison uses IS DISTINCT FROM rather than !=. On a FULL OUTER JOIN an IP present in
	// only one snapshot yields NULL on the other side, and `NULL != true` evaluates to NULL --
	// which is not true, so plain != silently discards every appeared/disappeared host. IS DISTINCT
	// FROM is NULL-safe and is the correct expression of the set symmetric difference we want.
	query := `
		WITH prev AS (SELECT ip, is_up FROM hosts WHERE scan_id = $1),
		     curr AS (SELECT ip, is_up FROM hosts WHERE scan_id = $2),
		     drift AS (
		         SELECT
		             COALESCE(prev.ip, curr.ip)::text AS ip,
		             CASE
		                 WHEN prev.ip IS NULL AND curr.is_up = true THEN 'NEW'
		                 WHEN prev.is_up = false AND curr.is_up = true THEN 'NEW'
		                 WHEN curr.ip IS NULL AND prev.is_up = true THEN 'REMOVED'
		                 WHEN prev.is_up = true AND curr.is_up = false THEN 'REMOVED'
		                 ELSE 'NO_CHANGE'
		             END AS status
		         FROM prev FULL OUTER JOIN curr ON prev.ip = curr.ip
		         WHERE prev.is_up IS DISTINCT FROM curr.is_up
		     )
		SELECT ip, status FROM drift WHERE status <> 'NO_CHANGE' ORDER BY ip;`

	diffRows, err := pool.Query(ctx, query, prevScanID, latestScanID)
	if err != nil {
		slog.Error("Drift calculation anomaly execution failure", "error", err)
		return
	}
	defer diffRows.Close()

	subDiff := scanner.SubnetDiff{CIDR: cidr, Changes: []scanner.HostDiff{}}
	for diffRows.Next() {
		var hd scanner.HostDiff
		if err := diffRows.Scan(&hd.IP, &hd.Status); err == nil {
			subDiff.Changes = append(subDiff.Changes, hd)
		}
	}

	// Output clean JSON drift analysis to stdout
	out, _ := json.MarshalIndent(subDiff, "", "  ")
	fmt.Println(string(out))
}
