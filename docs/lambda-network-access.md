# Lambda Network Access Contract

This document defines the proposed response shape for a future
`explain_lambda_network_access` tool. The tool should report network-layer
reachability inferred from Lambda VPC configuration, security groups, route
tables, NACLs, and VPC endpoints. It should not claim that function code
actually calls a destination unless a later evidence mode checks logs or flow
records.

## Response Shape

```json
{
  "resource_type": "lambda",
  "name": "dev-api",
  "arn": "arn:aws:lambda:eu-west-2:123456789012:function:dev-api",
  "region": "eu-west-2",
  "summary": {
    "network_mode": "vpc",
    "internet_access": "partial",
    "private_network_access": "yes",
    "aws_private_service_access": "yes",
    "main_risks": ["wide_ipv4_egress"]
  },
  "scope": {
    "analysis_type": "static_configuration",
    "protocols": ["tcp", "udp", "icmp", "-1"],
    "ip_families": ["ipv4", "ipv6"]
  },
  "network_context": {
    "vpc_id": "vpc-123",
    "subnet_ids": ["subnet-1"],
    "security_group_ids": ["sg-1"]
  },
  "egress": {
    "internet": {
      "verdict": "partial",
      "ipv4": "reachable",
      "ipv6": "not_configured",
      "via": ["nat-123"]
    },
    "private_networks": [],
    "aws_services": [],
    "blocked_or_unknown": []
  },
  "controls": {
    "security_groups": [],
    "route_tables": [],
    "network_acls": [],
    "endpoints": []
  },
  "paths": [],
  "warnings": [],
  "confidence": "high"
}
```

## Verdicts

Use coarse summary verdicts for quick consumption, and put detailed proof in
`paths`.

- `yes`: at least one complete path exists.
- `no`: inspected controls show no complete path.
- `partial`: mixed subnet, IP family, protocol, or port result.
- `unknown`: AWS returned incomplete data or a route target cannot be resolved.
- `not_applicable`: Lambda is not attached to a VPC or a control does not apply.

Each path should include the destination class, destination, protocol, ports,
source subnet, applied security group rules, route target chain, NACL result,
verdict, and confidence.

```json
{
  "destination_class": "internet",
  "destination": "0.0.0.0/0",
  "ip_family": "ipv4",
  "protocol": "tcp",
  "ports": [443],
  "verdict": "reachable",
  "from_subnet": "subnet-1",
  "via": ["rtb-1", "nat-1", "igw-1"],
  "allowed_by": ["sg-1 egress sgr-1"],
  "limited_by": [],
  "confidence": "high"
}
```

## Scenario Matrix

The executable contract lives in
`tests/test_lambda_network_access_contract.py`. The scenarios cover:

- non-VPC Lambda
- private subnet with NAT
- private subnet without default route
- security group allows but route blocks
- route allows but security group blocks
- mixed route tables across Lambda subnets
- multiple security groups with union egress
- NACL denial or uncertainty
- dual-stack IPv6 and egress-only internet gateway
- interface and gateway VPC endpoints
- transit gateway, VPC peering, VPN, and Direct Connect style private routes
- prefix list destinations
- security-group referenced destinations

## Boundaries

This tool should be explicit about inference. Static configuration can prove
that a packet is allowed or blocked by known AWS controls, but it cannot prove
DNS resolution, application behavior, downstream firewalls, appliance routing,
or on-premises reachability behind a transit gateway or VPN unless those systems
are also inspected.
