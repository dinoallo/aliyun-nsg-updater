package main

import (
	"flag"
	"fmt"
	"log"
	"os"
)

func main() {
	configPath := flag.String("config", "config.yaml", "Path to the YAML configuration file")
	flag.Parse()

	log.SetFlags(log.Ltime | log.Lshortfile)

	// Load configuration.
	cfg, err := LoadConfig(*configPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error loading config: %v\n", err)
		os.Exit(1)
	}

	// Detect public IP.
	publicIP, err := GetPublicIP(cfg.PublicIPProviders)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error detecting public IP: %v\n", err)
		os.Exit(1)
	}
	log.Printf("Detected public IP: %s", publicIP)

	// Create Aliyun client.
	client, err := NewAliyunClient(cfg.Aliyun.AccessKeyID, cfg.Aliyun.AccessKeySecret, cfg.Aliyun.RegionID)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error creating Aliyun client: %v\n", err)
		os.Exit(1)
	}

	// Sync each rule.
	hadError := false
	for i, rule := range cfg.Rules {
		log.Printf("[%d/%d] Processing rule: %s/%s %s on sg=%s",
			i+1, len(cfg.Rules), rule.Protocol, rule.PortRange, rule.Direction, rule.SecurityGroupID)

		if err := client.SyncRule(rule, publicIP); err != nil {
			log.Printf("[ERROR] Rule %d failed: %v", i+1, err)
			hadError = true
		}
	}

	if hadError {
		log.Println("Completed with errors.")
		os.Exit(1)
	}
	log.Println("All rules synced successfully.")
}
