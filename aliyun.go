package main

import (
	"fmt"
	"log"

	"github.com/aliyun/alibaba-cloud-sdk-go/services/ecs"
)

// AliyunClient wraps the ECS SDK client and provides security group helpers.
type AliyunClient struct {
	ecsClient *ecs.Client
	regionID  string
}

// NewAliyunClient creates a new ECS client with the given credentials.
func NewAliyunClient(accessKeyID, accessKeySecret, regionID string) (*AliyunClient, error) {
	client, err := ecs.NewClientWithAccessKey(regionID, accessKeyID, accessKeySecret)
	if err != nil {
		return nil, fmt.Errorf("create ECS client: %w", err)
	}
	return &AliyunClient{ecsClient: client, regionID: regionID}, nil
}

// SecurityGroupRule represents a single rule returned by the Aliyun API.
type SecurityGroupRule struct {
	SecurityGroupRuleID string
	Direction           string // ingress or egress
	IPProtocol          string
	PortRange           string
	SourceCidrIP        string // ingress source
	DestCidrIP          string // egress destination
	Priority            string
	NicType             string
	Policy              string
	Description         string
}

// describeIngressRules lists all ingress rules for a security group.
func (a *AliyunClient) describeIngressRules(sgID string) ([]SecurityGroupRule, error) {
	request := ecs.CreateDescribeSecurityGroupAttributeRequest()
	request.Scheme = "https"
	request.SecurityGroupId = sgID
	request.RegionId = a.regionID
	request.Direction = "ingress"

	response, err := a.ecsClient.DescribeSecurityGroupAttribute(request)
	if err != nil {
		return nil, fmt.Errorf("describe security group ingress rules: %w", err)
	}

	var rules []SecurityGroupRule
	for _, r := range response.Permissions.Permission {
		rules = append(rules, SecurityGroupRule{
			SecurityGroupRuleID: r.SecurityGroupRuleId,
			Direction:           "ingress",
			IPProtocol:          r.IpProtocol,
			PortRange:           r.PortRange,
			SourceCidrIP:        r.SourceCidrIp,
			Priority:            r.Priority,
			NicType:             r.NicType,
			Policy:              r.Policy,
			Description:         r.Description,
		})
	}
	return rules, nil
}

// describeEgressRules lists all egress rules for a security group.
func (a *AliyunClient) describeEgressRules(sgID string) ([]SecurityGroupRule, error) {
	request := ecs.CreateDescribeSecurityGroupAttributeRequest()
	request.Scheme = "https"
	request.SecurityGroupId = sgID
	request.RegionId = a.regionID
	request.Direction = "egress"

	response, err := a.ecsClient.DescribeSecurityGroupAttribute(request)
	if err != nil {
		return nil, fmt.Errorf("describe security group egress rules: %w", err)
	}

	var rules []SecurityGroupRule
	for _, r := range response.Permissions.Permission {
		rules = append(rules, SecurityGroupRule{
			SecurityGroupRuleID: r.SecurityGroupRuleId,
			Direction:           "egress",
			IPProtocol:          r.IpProtocol,
			PortRange:           r.PortRange,
			DestCidrIP:          r.DestCidrIp,
			Priority:            r.Priority,
			NicType:             r.NicType,
			Policy:              r.Policy,
			Description:         r.Description,
		})
	}
	return rules, nil
}

// ruleMatchesTemplate checks if an existing rule matches a rule template
// on all attributes except the CIDR.
func ruleMatchesTemplate(rule SecurityGroupRule, tpl RuleTemplate, publicIP string) bool {
	if rule.IPProtocol != tpl.Protocol {
		return false
	}
	if rule.PortRange != tpl.PortRange {
		return false
	}
	if rule.Priority != tpl.Priority {
		return false
	}
	if rule.NicType != tpl.NicType {
		return false
	}
	if rule.Policy != tpl.Policy {
		return false
	}
	return true
}

// ruleHasCIDR checks if the rule already has the desired public IP as its CIDR.
func ruleHasCIDR(rule SecurityGroupRule, tpl RuleTemplate, cidr string) bool {
	if tpl.Direction == "ingress" {
		return rule.SourceCidrIP == cidr
	}
	return rule.DestCidrIP == cidr
}

// SyncRule ensures that a single rule template is satisfied: the security
// group has exactly one rule matching the template's parameters with the
// given public IP as the source/destination CIDR.
func (a *AliyunClient) SyncRule(tpl RuleTemplate, publicIP string) error {
	cidr := publicIP + "/32"

	// List existing rules for the appropriate direction.
	var existingRules []SecurityGroupRule
	var err error
	if tpl.Direction == "ingress" {
		existingRules, err = a.describeIngressRules(tpl.SecurityGroupID)
	} else {
		existingRules, err = a.describeEgressRules(tpl.SecurityGroupID)
	}
	if err != nil {
		return err
	}

	// Find a matching rule (same protocol/port/etc.) that already has the
	// desired CIDR — if so, nothing to do.
	for _, rule := range existingRules {
		if ruleMatchesTemplate(rule, tpl, publicIP) && ruleHasCIDR(rule, tpl, cidr) {
			log.Printf("[SKIP] Rule already up-to-date: %s/%s %s -> %s (sg=%s)",
				tpl.Protocol, tpl.PortRange, tpl.Direction, cidr, tpl.SecurityGroupID)
			return nil
		}
	}

	// Find any old rule(s) matching the template but with a different CIDR
	// and revoke them.
	for _, rule := range existingRules {
		if ruleMatchesTemplate(rule, tpl, publicIP) && !ruleHasCIDR(rule, tpl, cidr) {
			var oldCIDR string
			if tpl.Direction == "ingress" {
				oldCIDR = rule.SourceCidrIP
			} else {
				oldCIDR = rule.DestCidrIP
			}
			log.Printf("[REVOKE] Removing old rule: %s/%s %s -> %s (sg=%s)",
				tpl.Protocol, tpl.PortRange, tpl.Direction, oldCIDR, tpl.SecurityGroupID)

			if err := a.revokeRule(tpl, oldCIDR); err != nil {
				return fmt.Errorf("revoke old rule: %w", err)
			}
		}
	}

	// Authorize the rule with the current public IP.
	log.Printf("[AUTHORIZE] Adding rule: %s/%s %s -> %s (sg=%s, desc=%s)",
		tpl.Protocol, tpl.PortRange, tpl.Direction, cidr, tpl.SecurityGroupID, tpl.Description)

	if err := a.authorizeRule(tpl, cidr); err != nil {
		return fmt.Errorf("authorize rule: %w", err)
	}

	return nil
}

func (a *AliyunClient) revokeRule(tpl RuleTemplate, cidr string) error {
	if tpl.Direction == "ingress" {
		request := ecs.CreateRevokeSecurityGroupRequest()
		request.Scheme = "https"
		request.SecurityGroupId = tpl.SecurityGroupID
		request.IpProtocol = tpl.Protocol
		request.PortRange = tpl.PortRange
		request.SourceCidrIp = cidr
		request.Priority = tpl.Priority
		request.NicType = tpl.NicType
		request.Policy = tpl.Policy
		_, err := a.ecsClient.RevokeSecurityGroup(request)
		return err
	}

	request := ecs.CreateRevokeSecurityGroupEgressRequest()
	request.Scheme = "https"
	request.SecurityGroupId = tpl.SecurityGroupID
	request.IpProtocol = tpl.Protocol
	request.PortRange = tpl.PortRange
	request.DestCidrIp = cidr
	request.Priority = tpl.Priority
	request.NicType = tpl.NicType
	request.Policy = tpl.Policy
	_, err := a.ecsClient.RevokeSecurityGroupEgress(request)
	return err
}

func (a *AliyunClient) authorizeRule(tpl RuleTemplate, cidr string) error {
	if tpl.Direction == "ingress" {
		request := ecs.CreateAuthorizeSecurityGroupRequest()
		request.Scheme = "https"
		request.SecurityGroupId = tpl.SecurityGroupID
		request.IpProtocol = tpl.Protocol
		request.PortRange = tpl.PortRange
		request.SourceCidrIp = cidr
		request.Priority = tpl.Priority
		request.NicType = tpl.NicType
		request.Policy = tpl.Policy
		request.Description = tpl.Description
		_, err := a.ecsClient.AuthorizeSecurityGroup(request)
		return err
	}

	request := ecs.CreateAuthorizeSecurityGroupEgressRequest()
	request.Scheme = "https"
	request.SecurityGroupId = tpl.SecurityGroupID
	request.IpProtocol = tpl.Protocol
	request.PortRange = tpl.PortRange
	request.DestCidrIp = cidr
	request.Priority = tpl.Priority
	request.NicType = tpl.NicType
	request.Policy = tpl.Policy
	request.Description = tpl.Description
	_, err := a.ecsClient.AuthorizeSecurityGroupEgress(request)
	return err
}
