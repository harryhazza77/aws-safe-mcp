from typing import Any

REQUIRED_TOP_LEVEL_KEYS = {
    "resource_type",
    "name",
    "arn",
    "region",
    "summary",
    "scope",
    "network_context",
    "egress",
    "controls",
    "paths",
    "warnings",
    "confidence",
}

SUMMARY_KEYS = {
    "network_mode",
    "internet_access",
    "private_network_access",
    "aws_private_service_access",
    "main_risks",
}

EGRESS_KEYS = {"internet", "private_networks", "aws_services", "blocked_or_unknown"}
CONTROLS_KEYS = {"security_groups", "route_tables", "network_acls", "endpoints"}
CONFIDENCE_VALUES = {"high", "medium", "low"}
SUMMARY_VERDICTS = {"yes", "no", "partial", "unknown", "not_applicable"}
PATH_VERDICTS = {"reachable", "blocked", "partial", "unknown", "not_applicable"}


def _base_response(
    *,
    name: str,
    network_mode: str,
    internet_access: str,
    private_network_access: str = "no",
    aws_private_service_access: str = "no",
    main_risks: list[str] | None = None,
    vpc_id: str | None = "vpc-123",
    subnet_ids: list[str] | None = None,
    security_group_ids: list[str] | None = None,
    internet: dict[str, Any] | None = None,
    private_networks: list[dict[str, Any]] | None = None,
    aws_services: list[dict[str, Any]] | None = None,
    blocked_or_unknown: list[dict[str, Any]] | None = None,
    paths: list[dict[str, Any]] | None = None,
    warnings: list[str] | None = None,
    confidence: str = "high",
) -> dict[str, Any]:
    return {
        "resource_type": "lambda",
        "name": name,
        "arn": f"arn:aws:lambda:eu-west-2:123456789012:function:{name}",
        "region": "eu-west-2",
        "summary": {
            "network_mode": network_mode,
            "internet_access": internet_access,
            "private_network_access": private_network_access,
            "aws_private_service_access": aws_private_service_access,
            "main_risks": main_risks or [],
        },
        "scope": {
            "analysis_type": "static_configuration",
            "protocols": ["tcp", "udp", "icmp", "-1"],
            "ip_families": ["ipv4", "ipv6"],
        },
        "network_context": {
            "vpc_id": vpc_id,
            "subnet_ids": subnet_ids or [],
            "security_group_ids": security_group_ids or [],
        },
        "egress": {
            "internet": internet
            or {"verdict": internet_access, "ipv4": internet_access, "ipv6": "not_configured"},
            "private_networks": private_networks or [],
            "aws_services": aws_services or [],
            "blocked_or_unknown": blocked_or_unknown or [],
        },
        "controls": {
            "security_groups": [],
            "route_tables": [],
            "network_acls": [],
            "endpoints": [],
        },
        "paths": paths or [],
        "warnings": warnings or [],
        "confidence": confidence,
    }


def _path(
    *,
    destination_class: str,
    destination: str,
    verdict: str,
    from_subnet: str,
    protocol: str = "tcp",
    ports: list[int] | str | None = None,
    ip_family: str = "ipv4",
    via: list[str] | None = None,
    allowed_by: list[str] | None = None,
    limited_by: list[str] | None = None,
    confidence: str = "high",
) -> dict[str, Any]:
    return {
        "destination_class": destination_class,
        "destination": destination,
        "ip_family": ip_family,
        "protocol": protocol,
        "ports": ports or [443],
        "verdict": verdict,
        "from_subnet": from_subnet,
        "via": via or [],
        "allowed_by": allowed_by or [],
        "limited_by": limited_by or [],
        "confidence": confidence,
    }


SCENARIOS: list[dict[str, Any]] = [
    _base_response(
        name="public-runtime",
        network_mode="aws_managed",
        internet_access="yes",
        private_network_access="not_applicable",
        vpc_id=None,
        internet={"verdict": "yes", "ipv4": "reachable", "ipv6": "unknown", "via": []},
        warnings=["Lambda is not VPC-attached; security groups and subnet routes do not apply."],
        confidence="medium",
    ),
    _base_response(
        name="private-nat",
        network_mode="vpc",
        internet_access="yes",
        subnet_ids=["subnet-private-a"],
        security_group_ids=["sg-web-egress"],
        internet={
            "verdict": "yes",
            "ipv4": "reachable",
            "ipv6": "not_configured",
            "via": ["nat-1"],
        },
        paths=[
            _path(
                destination_class="internet",
                destination="0.0.0.0/0",
                verdict="reachable",
                from_subnet="subnet-private-a",
                via=["rtb-private-a", "nat-1", "igw-1"],
                allowed_by=["sg-web-egress tcp/443 0.0.0.0/0"],
            )
        ],
    ),
    _base_response(
        name="isolated-private",
        network_mode="vpc",
        internet_access="no",
        subnet_ids=["subnet-isolated-a"],
        security_group_ids=["sg-open"],
        internet={"verdict": "no", "ipv4": "blocked", "ipv6": "not_configured", "via": []},
        blocked_or_unknown=[{"destination": "0.0.0.0/0", "reason": "no_default_route"}],
        paths=[
            _path(
                destination_class="internet",
                destination="0.0.0.0/0",
                verdict="blocked",
                from_subnet="subnet-isolated-a",
                allowed_by=["sg-open -1 0.0.0.0/0"],
                limited_by=["rtb-isolated-a has no default route"],
            )
        ],
    ),
    _base_response(
        name="sg-allows-route-blocks",
        network_mode="vpc",
        internet_access="no",
        subnet_ids=["subnet-a"],
        security_group_ids=["sg-open"],
        main_risks=["security_group_wide_egress_but_no_route"],
        paths=[
            _path(
                destination_class="internet",
                destination="0.0.0.0/0",
                verdict="blocked",
                from_subnet="subnet-a",
                allowed_by=["sg-open -1 0.0.0.0/0"],
                limited_by=["rtb-a has no default route"],
            )
        ],
    ),
    _base_response(
        name="route-allows-sg-blocks",
        network_mode="vpc",
        internet_access="no",
        subnet_ids=["subnet-a"],
        security_group_ids=["sg-private-only"],
        paths=[
            _path(
                destination_class="internet",
                destination="0.0.0.0/0",
                verdict="blocked",
                from_subnet="subnet-a",
                via=["rtb-a", "nat-1", "igw-1"],
                limited_by=["sg-private-only has no matching egress rule"],
            )
        ],
    ),
    _base_response(
        name="mixed-subnets",
        network_mode="vpc",
        internet_access="partial",
        subnet_ids=["subnet-with-nat", "subnet-isolated"],
        security_group_ids=["sg-https"],
        main_risks=["subnet_route_mismatch"],
        internet={
            "verdict": "partial",
            "ipv4": "partial",
            "ipv6": "not_configured",
            "via": ["nat-1"],
        },
        paths=[
            _path(
                destination_class="internet",
                destination="0.0.0.0/0",
                verdict="reachable",
                from_subnet="subnet-with-nat",
                via=["rtb-nat", "nat-1", "igw-1"],
                allowed_by=["sg-https tcp/443 0.0.0.0/0"],
            ),
            _path(
                destination_class="internet",
                destination="0.0.0.0/0",
                verdict="blocked",
                from_subnet="subnet-isolated",
                allowed_by=["sg-https tcp/443 0.0.0.0/0"],
                limited_by=["rtb-isolated has no default route"],
            ),
        ],
    ),
    _base_response(
        name="multiple-security-groups",
        network_mode="vpc",
        internet_access="yes",
        subnet_ids=["subnet-a"],
        security_group_ids=["sg-locked-down", "sg-open-egress"],
        main_risks=["wide_ipv4_egress"],
        paths=[
            _path(
                destination_class="internet",
                destination="0.0.0.0/0",
                verdict="reachable",
                from_subnet="subnet-a",
                via=["rtb-a", "nat-1", "igw-1"],
                allowed_by=["sg-open-egress -1 0.0.0.0/0"],
            )
        ],
    ),
    _base_response(
        name="nacl-deny",
        network_mode="vpc",
        internet_access="no",
        subnet_ids=["subnet-a"],
        security_group_ids=["sg-https"],
        paths=[
            _path(
                destination_class="internet",
                destination="0.0.0.0/0",
                verdict="blocked",
                from_subnet="subnet-a",
                via=["rtb-a", "nat-1", "igw-1"],
                allowed_by=["sg-https tcp/443 0.0.0.0/0"],
                limited_by=["acl-1 denies outbound tcp/443"],
            )
        ],
    ),
    _base_response(
        name="dual-stack-egress-only",
        network_mode="vpc",
        internet_access="partial",
        subnet_ids=["subnet-dual"],
        security_group_ids=["sg-ipv6"],
        internet={
            "verdict": "partial",
            "ipv4": "blocked",
            "ipv6": "reachable",
            "via": ["eigw-1"],
        },
        paths=[
            _path(
                destination_class="internet",
                destination="::/0",
                verdict="reachable",
                from_subnet="subnet-dual",
                ip_family="ipv6",
                via=["rtb-dual", "eigw-1"],
                allowed_by=["sg-ipv6 tcp/443 ::/0"],
            )
        ],
    ),
    _base_response(
        name="vpc-endpoints-only",
        network_mode="vpc",
        internet_access="no",
        aws_private_service_access="yes",
        subnet_ids=["subnet-isolated-a"],
        security_group_ids=["sg-https"],
        aws_services=[
            {"service": "s3", "endpoint_type": "gateway", "via": "vpce-s3", "verdict": "reachable"},
            {
                "service": "secretsmanager",
                "endpoint_type": "interface",
                "via": "vpce-secrets",
                "verdict": "reachable",
            },
        ],
        paths=[
            _path(
                destination_class="aws_service",
                destination="com.amazonaws.eu-west-2.secretsmanager",
                verdict="reachable",
                from_subnet="subnet-isolated-a",
                via=["vpce-secrets"],
                allowed_by=["sg-https tcp/443 sg-vpce"],
            )
        ],
    ),
    _base_response(
        name="transit-gateway-private",
        network_mode="vpc",
        internet_access="no",
        private_network_access="yes",
        subnet_ids=["subnet-a"],
        security_group_ids=["sg-private"],
        private_networks=[
            {"cidr": "10.40.0.0/16", "via": "tgw-1", "verdict": "reachable", "confidence": "medium"}
        ],
        paths=[
            _path(
                destination_class="private_network",
                destination="10.40.0.0/16",
                verdict="reachable",
                from_subnet="subnet-a",
                via=["rtb-a", "tgw-1"],
                allowed_by=["sg-private tcp/443 10.0.0.0/8"],
                confidence="medium",
            )
        ],
        confidence="medium",
    ),
    _base_response(
        name="vpc-peering-private",
        network_mode="vpc",
        internet_access="no",
        private_network_access="yes",
        subnet_ids=["subnet-a"],
        security_group_ids=["sg-private"],
        private_networks=[
            {"cidr": "172.16.0.0/16", "via": "pcx-1", "verdict": "reachable", "confidence": "high"}
        ],
        paths=[
            _path(
                destination_class="private_network",
                destination="172.16.0.0/16",
                verdict="reachable",
                from_subnet="subnet-a",
                via=["rtb-a", "pcx-1"],
                allowed_by=["sg-private tcp/443 172.16.0.0/16"],
            )
        ],
    ),
    _base_response(
        name="vpn-private-unknown-beyond-edge",
        network_mode="vpc",
        internet_access="no",
        private_network_access="unknown",
        subnet_ids=["subnet-a"],
        security_group_ids=["sg-private"],
        private_networks=[
            {"cidr": "192.168.0.0/16", "via": "vgw-1", "verdict": "unknown", "confidence": "low"}
        ],
        paths=[
            _path(
                destination_class="private_network",
                destination="192.168.0.0/16",
                verdict="unknown",
                from_subnet="subnet-a",
                via=["rtb-a", "vgw-1"],
                allowed_by=["sg-private tcp/443 192.168.0.0/16"],
                limited_by=["downstream VPN or on-prem firewall not inspected"],
                confidence="low",
            )
        ],
        confidence="low",
    ),
    _base_response(
        name="prefix-list-egress",
        network_mode="vpc",
        internet_access="no",
        aws_private_service_access="yes",
        subnet_ids=["subnet-a"],
        security_group_ids=["sg-prefix"],
        aws_services=[
            {
                "service": "dynamodb",
                "endpoint_type": "gateway",
                "prefix_list_id": "pl-dynamodb",
                "verdict": "reachable",
            }
        ],
        paths=[
            _path(
                destination_class="aws_service",
                destination="pl-dynamodb",
                verdict="reachable",
                from_subnet="subnet-a",
                via=["rtb-a", "vpce-dynamodb"],
                allowed_by=["sg-prefix tcp/443 pl-dynamodb"],
            )
        ],
    ),
    _base_response(
        name="security-group-reference",
        network_mode="vpc",
        internet_access="no",
        private_network_access="yes",
        subnet_ids=["subnet-a"],
        security_group_ids=["sg-lambda"],
        private_networks=[
            {
                "destination_security_group_id": "sg-database",
                "verdict": "reachable",
                "confidence": "medium",
            }
        ],
        paths=[
            _path(
                destination_class="security_group",
                destination="sg-database",
                verdict="reachable",
                from_subnet="subnet-a",
                via=["local-vpc"],
                allowed_by=["sg-lambda tcp/5432 sg-database"],
                confidence="medium",
            )
        ],
        confidence="medium",
    ),
]


def test_lambda_network_access_scenarios_cover_expected_aws_shapes() -> None:
    names = {scenario["name"] for scenario in SCENARIOS}

    assert names == {
        "public-runtime",
        "private-nat",
        "isolated-private",
        "sg-allows-route-blocks",
        "route-allows-sg-blocks",
        "mixed-subnets",
        "multiple-security-groups",
        "nacl-deny",
        "dual-stack-egress-only",
        "vpc-endpoints-only",
        "transit-gateway-private",
        "vpc-peering-private",
        "vpn-private-unknown-beyond-edge",
        "prefix-list-egress",
        "security-group-reference",
    }


def test_lambda_network_access_contract_has_stable_top_level_shape() -> None:
    for scenario in SCENARIOS:
        assert set(scenario) == REQUIRED_TOP_LEVEL_KEYS
        assert scenario["resource_type"] == "lambda"
        assert scenario["arn"].endswith(f":function:{scenario['name']}")
        assert scenario["region"] == "eu-west-2"
        assert scenario["confidence"] in CONFIDENCE_VALUES

        assert set(scenario["summary"]) == SUMMARY_KEYS
        assert scenario["summary"]["internet_access"] in SUMMARY_VERDICTS
        assert scenario["summary"]["private_network_access"] in SUMMARY_VERDICTS
        assert scenario["summary"]["aws_private_service_access"] in SUMMARY_VERDICTS
        assert isinstance(scenario["summary"]["main_risks"], list)

        assert set(scenario["egress"]) == EGRESS_KEYS
        assert set(scenario["controls"]) == CONTROLS_KEYS
        assert isinstance(scenario["warnings"], list)


def test_lambda_network_access_contract_puts_complexity_in_paths() -> None:
    for scenario in SCENARIOS:
        for path in scenario["paths"]:
            assert set(path) == {
                "destination_class",
                "destination",
                "ip_family",
                "protocol",
                "ports",
                "verdict",
                "from_subnet",
                "via",
                "allowed_by",
                "limited_by",
                "confidence",
            }
            assert path["verdict"] in PATH_VERDICTS
            assert path["confidence"] in CONFIDENCE_VALUES
            assert path["ip_family"] in {"ipv4", "ipv6"}
            assert path["protocol"] in {"tcp", "udp", "icmp", "-1"}
            assert isinstance(path["via"], list)
            assert isinstance(path["allowed_by"], list)
            assert isinstance(path["limited_by"], list)


def test_summary_verdicts_match_representative_paths() -> None:
    by_name = {scenario["name"]: scenario for scenario in SCENARIOS}

    assert by_name["private-nat"]["paths"][0]["verdict"] == "reachable"
    assert by_name["isolated-private"]["paths"][0]["limited_by"] == [
        "rtb-isolated-a has no default route"
    ]
    assert {path["verdict"] for path in by_name["mixed-subnets"]["paths"]} == {
        "reachable",
        "blocked",
    }
    assert by_name["vpn-private-unknown-beyond-edge"]["confidence"] == "low"
    assert by_name["security-group-reference"]["paths"][0]["destination_class"] == (
        "security_group"
    )
