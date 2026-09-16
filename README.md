# aliyun-nsg-updater

> 自动检测本地公网 IP 并同步到阿里云安全组规则。  
> Automatically detect your public IP and keep Alibaba Cloud security group rules in sync.

## Features

- **Auto-detect public IP** — queries multiple upstream services (`ipify.org`, `checkip.amazonaws.com`, `ipinfo.io`, `icanhazip.com`) with fallback
- **YAML-driven rules** — define any number of ingress/egress rule templates in one config file
- **Idempotent sync** — compares existing rules before authorizing; revokes stale rules with outdated IPs
- **Minimal dependencies** — only the Alibaba Cloud ECS SDK and a YAML parser

## Prerequisites

- A [RAM user](https://ram.console.aliyun.com/) in Alibaba Cloud with an AccessKey that has at least the following permissions on your security groups:

  ```json
  {
    "Version": "1",
    "Statement": [
      {
        "Effect": "Allow",
        "Action": [
          "ecs:DescribeSecurityGroupAttribute",
          "ecs:AuthorizeSecurityGroup",
          "ecs:RevokeSecurityGroup",
          "ecs:AuthorizeSecurityGroupEgress",
          "ecs:RevokeSecurityGroupEgress"
        ],
        "Resource": "*"
      }
    ]
  }
  ```

- Go 1.23+ (if building from source)

## Getting Started

### 1. Download a release

Download the latest binary from the [Releases](https://github.com/aliyun-nsg-updater/releases) page for your platform, or build from source:

```bash
git clone https://github.com/aliyun-nsg-updater.git
cd aliyun-nsg-updater
go build -o aliyun-nsg-updater .
```

### 2. Create config

Copy the example and fill in your credentials and rules:

```bash
cp config.yaml.example config.yaml
vi config.yaml
```

### 3. Run

```bash
./aliyun-nsg-updater -config config.yaml
```

The program will:

1. Load `config.yaml`
2. Detect the current public IP
3. For each rule template, query the security group for existing permissions
4. Revoke any rule matching the template but pointing to a stale IP
5. Authorize the rule with `{current-ip}/32`

## Configuration Reference

| Key | Required | Description |
|---|---|---|
| `aliyun.access_key_id` | ✅ | Alibaba Cloud AccessKey ID |
| `aliyun.access_key_secret` | ✅ | Alibaba Cloud AccessKey Secret |
| `aliyun.region_id` | ✅ | Region, e.g. `cn-hangzhou`, `cn-beijing` |
| `rules[].security_group_id` | ✅ | Security Group ID |
| `rules[].direction` | ✅ | `ingress` or `egress` |
| `rules[].protocol` | ✅ | `tcp`, `udp`, `icmp`, `gre`, `all` |
| `rules[].port_range` | ✅ | e.g. `22/22`; use `-1/-1` for ICMP |
| `rules[].priority` | | 1–100, default `1` |
| `rules[].nic_type` | | `internet` (default) or `intranet` |
| `rules[].policy` | | `accept` (default) or `drop` |
| `rules[].description` | | Human-readable description |

### Example

```yaml
aliyun:
  access_key_id: "LTAI5t..."
  access_key_secret: "your-secret"
  region_id: "cn-hangzhou"

rules:
  - security_group_id: "sg-xxxxxxxxxxxxx"
    direction: "ingress"
    protocol: "tcp"
    port_range: "22/22"
    priority: "1"
    nic_type: "internet"
    policy: "accept"
    description: "SSH from home"

  - security_group_id: "sg-xxxxxxxxxxxxx"
    direction: "ingress"
    protocol: "tcp"
    port_range: "443/443"
    priority: "1"
    nic_type: "internet"
    policy: "accept"
    description: "HTTPS from home"
```

## How It Works

```
                 ┌─────────────┐
                 │  config.yaml │
                 └──────┬──────┘
                        ▼
                 ┌──────────────┐
                 │  Load Config │
                 └──────┬───────┘
                        ▼
                 ┌──────────────┐       ┌───────────────────┐
                 │ Detect Public│──────▶│ ipify.org / etc.  │
                 │ IP           │       └───────────────────┘
                 └──────┬───────┘
                        ▼
                 ┌──────────────┐       ┌──────────────────────┐
                 │ For each rule│──────▶│ DescribeSecurityGroup │
                 │ template     │       └──────────────────────┘
                 └──────┬───────┘
                        ▼
              ┌─────────────────────┐
              │ Match existing rule │  ───  IP same? → SKIP
              │ by (proto,port,etc) │  ───  IP stale? → REVOKE + AUTHORIZE
              └─────────────────────┘  ───  No match? → AUTHORIZE
```

## Security Notes

- Keep your `config.yaml` **out of version control** (it contains secrets). The `.gitignore` already excludes `.env` files.
- Consider using environment variables or a secrets manager for production deployments (future enhancement).
- The binary only makes outbound HTTPS connections to Alibaba Cloud ECS API endpoints and public IP detection services.

## License

MIT
