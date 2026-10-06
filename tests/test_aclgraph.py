"""ACL kısa-yol motoru (aclgraph) — saf mantık testleri."""

from adscan import aclgraph
from adscan.aclgraph import Edge


def _e(src, dst, dn, kind, hv):
    return Edge(src=src, dst=dst, dst_dn=dn, kind=kind, highvalue=hv)


# --- classify ---

def test_classify_addmember():
    assert aclgraph.classify("CN=Domain Admins,CN=Users,DC=c,DC=h", {"member"}) == "addmember"


def test_classify_dcsync_only_at_domain_root():
    assert aclgraph.classify("DC=c,DC=h", {"dacl"}) == "dcsync"
    # aynı hak ama kullanıcıda -> control_user (DCSync değil)
    assert aclgraph.classify("CN=Bob,OU=x,DC=c,DC=h", {"dacl"}) == "control_user"


def test_classify_control_user_and_reanimate_and_rbcd_shadow():
    assert aclgraph.classify("CN=Bob,OU=x,DC=c,DC=h", {"serviceprincipalname"}) == "control_user"
    assert aclgraph.classify("CN=X\\0ADEL:y,CN=Deleted Objects,DC=c,DC=h", {"dacl"}) == "reanimate"
    assert aclgraph.classify("CN=PC1,DC=c,DC=h",
                             {"msds-allowedtoactonbehalfofotheridentity"}) == "rbcd"
    assert aclgraph.classify("CN=Bob,DC=c,DC=h", {"msds-keycredentiallink"}) == "shadow"


def test_is_highvalue_and_node():
    assert aclgraph.is_highvalue("CN=Domain Admins,CN=Users,DC=c,DC=h")
    assert aclgraph.is_highvalue("DC=c,DC=h")
    assert not aclgraph.is_highvalue("CN=Bob,OU=x,DC=c,DC=h")
    assert aclgraph._node("CN=Mark Davies,OU=Employees,DC=c,DC=h") == "mark davies"
    assert aclgraph._node("DC=c,DC=h") == "domain"


# --- shortest_path (BFS) ---

def test_path_direct_addmember_win():
    g = {"alex": [_e("alex", "domain admins", "CN=Domain Admins,DC=c,DC=h", "addmember", True)]}
    path = aclgraph.shortest_path(g, {"alex"}, set())
    assert path and path[-1].kind == "addmember"


def test_path_dcsync_win():
    g = {"alex": [_e("alex", "domain", "DC=c,DC=h", "dcsync", True)]}
    assert aclgraph.shortest_path(g, {"alex"}, set())[-1].kind == "dcsync"


def test_path_two_hop_control_then_addmember():
    g = {
        "alex": [_e("alex", "bob", "CN=Bob,DC=c,DC=h", "control_user", False)],
        "bob": [_e("bob", "domain admins", "CN=Domain Admins,DC=c,DC=h", "addmember", True)],
    }
    path = aclgraph.shortest_path(g, {"alex"}, set())
    assert len(path) == 2 and path[0].dst == "bob" and path[1].kind == "addmember"


def test_path_control_highvalue_user_wins():
    g = {"alex": [_e("alex", "max.palmer", "CN=Max Palmer,DC=c,DC=h", "control_user", False)]}
    path = aclgraph.shortest_path(g, {"alex"}, {"max.palmer"})
    assert path and path[-1].dst == "max.palmer"


def test_path_none_when_dead_end():
    g = {"alex": [_e("alex", "bob", "CN=Bob,DC=c,DC=h", "control_user", False)]}
    assert aclgraph.shortest_path(g, {"alex"}, set()) is None
