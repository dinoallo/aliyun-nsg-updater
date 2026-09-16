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

// isOurRule checks if an existing rule belongs to the given template.
// A rule is considered "ours" only if it matches on protocol, port range,
// priority, nic type, policy, AND description.
// The description field serves as a tag to distinguish our rules from
// manually created ones, preventing accidental deletion.
func isOurRule(rule SecurityGroupRule, tpl RuleTemplate) bool {
	if tpl.Description == "" {
		return false
	}
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
	if rule.Description != tpl.Description {
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
//
// It only touches rules that match the template's description — this acts
// as a tag to distinguish managed rules from manually created ones.
func (a *AliyunClient) SyncRule(tpl RuleTemplate, publicIP string) error {
	cidr := publicIP + "/32"

	// Description is required as a tag to identify "our" rules.
	if tpl.Description == "" {
		return fmt.Errorf("rule description is required to identify managed rules; set a non-empty description in the config")
	}

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

	// Collect rules that are "ours" — matching on all fields including description.
	var ourRules []SecurityGroupRule
	for _, rule := range existingRules {
		if isOurRule(rule, tpl) {
			ourRules = append(ourRules, rule)
		}
	}

	// Track whether a rule with the desired CIDR already exists.
	desiredExists := false

	// Revoke our old rules with different CIDRs.
	for _, rule := range ourRules {
		if ruleHasCIDR(rule, tpl, cidr) {
			desiredExists = true
			continue
		}
		var oldCIDR string
		if tpl.Direction == "ingress" {
			oldCIDR = rule.SourceCidrIP
		} else {
			oldCIDR = rule.DestCidrIP
		}
		log.Printf("[REVOKE] Removing old rule: %s/%s %s -> %s (sg=%s, desc=%s, ruleID=%s)",
			tpl.Protocol, tpl.PortRange, tpl.Direction, oldCIDR, tpl.SecurityGroupID, tpl.Description, rule.SecurityGroupRuleID)

		if err := a.revokeRuleByID(rule.SecurityGroupRuleID, tpl.Direction); err != nil {
			return fmt.Errorf("revoke old rule: %w", err)
		}
	}

	if desiredExists {
		log.Printf("[SKIP] Rule already up-to-date: %s/%s %s -> %s (sg=%s, desc=%s)",
			tpl.Protocol, tpl.PortRange, tpl.Direction, cidr, tpl.SecurityGroupID, tpl.Description)
		return nil
	}

	// Authorize the rule with the current public IP.
	log.Printf("[AUTHORIZE] Adding rule: %s/%s %s -> %s (sg=%s, desc=%s)",
		tpl.Protocol, tpl.PortRange, tpl.Direction, cidr, tpl.SecurityGroupID, tpl.Description)

	if err := a.authorizeRule(tpl, cidr); err != nil {
		return fmt.Errorf("authorize rule: %w", err)
	}

	return nil
}

// revokeRuleByID revokes a security group rule by its unique rule ID.
// Using the rule ID is safer than identifying by network tuple, as it
// prevents accidentally deleting a non-managed rule that happens to
// share the same protocol/port/CIDR/priority/nicType/policy.
func (a *AliyunClient) revokeRuleByID(ruleID, direction string) error {
	if ruleID == "" {
		return fmt.Errorf("empty rule ID, cannot revoke")
	}
	if direction == "ingress" {
		request := ecs.CreateRevokeSecurityGroupRequest()
		request.Scheme = "https"
		request.SecurityGroupRuleId = &[]string{ruleID}
		_, err := a.ecsClient.RevokeSecurityGroup(request)
		return err
	}

	request := ecs.CreateRevokeSecurityGroupEgressRequest()
	request.Scheme = "https"
	request.SecurityGroupRuleId = &[]string{ruleID}
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
