import pytest

from detections import sg_open


def perm(proto="tcp", from_port=22, to_port=22, v4=(), v6=()):
    """One ipPermissions item, shaped the way CloudTrail logs it."""
    p = {"ipProtocol": proto, "groups": {}, "prefixListIds": {},
         "ipRanges": {"items": [{"cidrIp": c} for c in v4]},
         "ipv6Ranges": {"items": [{"cidrIpv6": c} for c in v6]}}
    if from_port is not None:
        p["fromPort"], p["toPort"] = from_port, to_port
    return p


def request(*perms, group_id="sg-0abc"):
    return {"groupId": group_id, "ipPermissions": {"items": list(perms)}}


def rule(rule_id, proto="tcp", from_port=22, to_port=22, v4=None, v6=None, egress=False):
    r = {"groupId": "sg-0abc", "securityGroupRuleId": rule_id, "isEgress": egress,
         "ipProtocol": proto, "fromPort": from_port, "toPort": to_port}
    if v4:
        r["cidrIpv4"] = v4
    if v6:
        r["cidrIpv6"] = v6
    return r


def response(*rules):
    return {"_return": True, "securityGroupRuleSet": {"items": list(rules)}}


class FakeEC2:
    def __init__(self, tags=None, ret=True):
        self.tags = tags or {}
        self.ret = ret
        self.calls = []

    def revoke_security_group_ingress(self, **kwargs):
        self.calls.append(kwargs)
        return {"Return": self.ret}

    def describe_security_groups(self, GroupIds):
        return {"SecurityGroups": [{"GroupId": GroupIds[0],
                                    "Tags": [{"Key": k, "Value": v} for k, v in self.tags.items()]}]}


def factory(ec2):
    return lambda name, region=None: ec2


# ---------- what gets flagged ----------

def test_ssh_open_to_world_is_flagged(make_ec2_event):
    detail = make_ec2_event(request(perm(v4=["0.0.0.0/0"])),
                            response(rule("sgr-1", v4="0.0.0.0/0")))
    result = sg_open.evaluate(detail)
    assert result["rule_ids"] == ["sgr-1"]
    assert "SSH (22)" in result["reason"]
    assert result["resource"].endswith(":security-group/sg-0abc")


def test_rdp_open_to_ipv6_world_is_flagged(make_ec2_event):
    detail = make_ec2_event(request(perm(from_port=3389, to_port=3389, v6=["::/0"])))
    assert "RDP (3389)" in sg_open.evaluate(detail)["reason"]


def test_all_traffic_rule_is_flagged(make_ec2_event):
    detail = make_ec2_event(request(perm(proto="-1", from_port=None, v4=["0.0.0.0/0"])))
    reason = sg_open.evaluate(detail)["reason"]
    assert "SSH (22)" in reason and "RDP (3389)" in reason


def test_wide_port_range_covering_ssh_is_flagged(make_ec2_event):
    assert sg_open.evaluate(make_ec2_event(request(perm(from_port=0, to_port=65535, v4=["0.0.0.0/0"]))))


# ---------- what doesn't ----------

def test_https_open_to_world_is_benign(make_ec2_event):
    assert sg_open.evaluate(make_ec2_event(request(perm(from_port=443, to_port=443, v4=["0.0.0.0/0"])))) is None


def test_ssh_from_private_range_is_benign(make_ec2_event):
    assert sg_open.evaluate(make_ec2_event(request(perm(v4=["10.0.0.0/8"])))) is None


def test_udp_22_is_benign(make_ec2_event):
    assert sg_open.evaluate(make_ec2_event(request(perm(proto="udp", v4=["0.0.0.0/0"])))) is None


# ---------- precision ----------

def test_only_the_risky_rule_is_targeted_in_a_mixed_request(make_ec2_event):
    detail = make_ec2_event(
        request(perm(v4=["0.0.0.0/0"]), perm(from_port=443, to_port=443, v4=["0.0.0.0/0"])),
        response(rule("sgr-ssh", v4="0.0.0.0/0"), rule("sgr-https", from_port=443, to_port=443, v4="0.0.0.0/0")),
    )
    assert sg_open.evaluate(detail)["rule_ids"] == ["sgr-ssh"]


def test_remediation_revokes_by_rule_id(make_ec2_event):
    ec2 = FakeEC2()
    detail = make_ec2_event(request(perm(v4=["0.0.0.0/0"])), response(rule("sgr-1", v4="0.0.0.0/0")))
    sg_open.remediate(sg_open.evaluate(detail), factory(ec2))
    assert ec2.calls == [{"GroupId": "sg-0abc", "SecurityGroupRuleIds": ["sgr-1"]}]


def test_remediation_falls_back_to_permission_match(make_ec2_event):
    ec2 = FakeEC2()
    detail = make_ec2_event(request(perm(from_port=3389, to_port=3389, v4=["0.0.0.0/0"], v6=["::/0"])))
    sg_open.remediate(sg_open.evaluate(detail), factory(ec2))
    assert ec2.calls == [{"GroupId": "sg-0abc", "IpPermissions": [{
        "IpProtocol": "tcp", "FromPort": 3389, "ToPort": 3389,
        "IpRanges": [{"CidrIp": "0.0.0.0/0"}], "Ipv6Ranges": [{"CidrIpv6": "::/0"}]}]}]


def test_revoke_that_matches_nothing_is_a_failure(make_ec2_event):
    detail = make_ec2_event(request(perm(v4=["0.0.0.0/0"])), response(rule("sgr-1", v4="0.0.0.0/0")))
    with pytest.raises(RuntimeError):
        sg_open.remediate(sg_open.evaluate(detail), factory(FakeEC2(ret=False)))


# ---------- allowlist ----------

def test_tagged_group_is_allowlisted(make_ec2_event):
    result = sg_open.evaluate(make_ec2_event(request(perm(v4=["0.0.0.0/0"]))))
    assert sg_open.is_allowlisted(result, factory(FakeEC2(tags={"detlab:allow-public-ingress": "true"})))
    assert not sg_open.is_allowlisted(result, factory(FakeEC2()))
