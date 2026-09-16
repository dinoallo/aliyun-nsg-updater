package main

import (
	"fmt"
	"os"

	"gopkg.in/yaml.v3"
)

// Config represents the top-level configuration.
type Config struct {
	Aliyun AliyunConfig   `yaml:"aliyun"`
	Rules  []RuleTemplate `yaml:"rules"`
}

// AliyunConfig holds Alibaba Cloud API credentials and region.
type AliyunConfig struct {
	AccessKeyID     string `yaml:"access_key_id"`
	AccessKeySecret string `yaml:"access_key_secret"`
	RegionID        string `yaml:"region_id"`
}

// RuleTemplate describes a security group rule to maintain.
type RuleTemplate struct {
	SecurityGroupID string `yaml:"security_group_id"`
	Direction       string `yaml:"direction"`   // ingress or egress
	Protocol        string `yaml:"protocol"`    // tcp, udp, icmp, gre, all
	PortRange       string `yaml:"port_range"`  // e.g. "22/22", "-1/-1" for icmp
	Priority        string `yaml:"priority"`    // 1-100, default 1
	NicType         string `yaml:"nic_type"`    // internet or intranet, default internet
	Policy          string `yaml:"policy"`      // accept or drop, default accept
	Description     string `yaml:"description"`
}

// setDefaults applies default values for optional fields.
func (r *RuleTemplate) setDefaults() {
	if r.Priority == "" {
		r.Priority = "1"
	}
	if r.NicType == "" {
		r.NicType = "internet"
	}
	if r.Policy == "" {
		r.Policy = "accept"
	}
}

// Validate checks that the configuration is sane.
func (c *Config) Validate() error {
	if c.Aliyun.AccessKeyID == "" {
		return fmt.Errorf("aliyun.access_key_id is required")
	}
	if c.Aliyun.AccessKeySecret == "" {
		return fmt.Errorf("aliyun.access_key_secret is required")
	}
	if c.Aliyun.RegionID == "" {
		return fmt.Errorf("aliyun.region_id is required")
	}
	for i := range c.Rules {
		r := &c.Rules[i]
		r.setDefaults()
		if r.SecurityGroupID == "" {
			return fmt.Errorf("rules[%d].security_group_id is required", i)
		}
		if r.Direction != "ingress" && r.Direction != "egress" {
			return fmt.Errorf("rules[%d].direction must be 'ingress' or 'egress'", i)
		}
		if r.Protocol == "" {
			return fmt.Errorf("rules[%d].protocol is required", i)
		}
		if r.Description == "" {
			return fmt.Errorf("rules[%d].description is required as a tag to identify managed rules", i)
		}
	}
	return nil
}

// LoadConfig reads and parses a YAML configuration file.
func LoadConfig(path string) (*Config, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read config file: %w", err)
	}
	var cfg Config
	if err := yaml.Unmarshal(data, &cfg); err != nil {
		return nil, fmt.Errorf("parse config file: %w", err)
	}
	if err := cfg.Validate(); err != nil {
		return nil, err
	}
	return &cfg, nil
}
