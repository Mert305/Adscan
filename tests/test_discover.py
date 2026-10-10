"""Subnet keşfi (discover.py) saf-fonksiyon testleri.

Gerçek nmap/nxc çalıştırılmaz; XML/metin örnekleriyle ayrıştırma test edilir.
"""

from adscan import discover

# --- looks_like_range ------------------------------------------------------

def test_cidr_is_range():
    assert discover.looks_like_range("10.10.10.0/24")
    assert discover.looks_like_range("192.168.1.0/16")


def test_dash_range_is_range():
    assert discover.looks_like_range("10.0.0.1-50")


def test_comma_multi_is_range():
    assert discover.looks_like_range("10.0.0.5,10.0.0.6")


def test_single_host_not_range():
    assert not discover.looks_like_range("10.10.10.5")
    assert not discover.looks_like_range("dc01.corp.local")
    assert not discover.looks_like_range("")


# --- parse_hosts_ports -----------------------------------------------------

_XML = """<?xml version="1.0"?>
<nmaprun>
  <host><status state="up"/><address addr="10.10.10.10" addrtype="ipv4"/>
    <ports>
      <port protocol="tcp" portid="88"><state state="open"/></port>
      <port protocol="tcp" portid="389"><state state="open"/></port>
      <port protocol="tcp" portid="445"><state state="open"/></port>
      <port protocol="tcp" portid="3268"><state state="open"/></port>
    </ports>
  </host>
  <host><status state="up"/><address addr="10.10.10.20" addrtype="ipv4"/>
    <ports>
      <port protocol="tcp" portid="445"><state state="open"/></port>
      <port protocol="tcp" portid="3389"><state state="open"/></port>
    </ports>
  </host>
  <host><status state="down"/><address addr="10.10.10.30" addrtype="ipv4"/></host>
</nmaprun>"""


def test_parse_hosts_ports_extracts_up_hosts():
    hp = discover.parse_hosts_ports(_XML)
    assert set(hp.keys()) == {"10.10.10.10", "10.10.10.20"}  # down host hariç
    assert hp["10.10.10.10"] == {"88", "389", "445", "3268"}
    assert hp["10.10.10.20"] == {"445", "3389"}


def test_parse_hosts_ports_bad_xml():
    assert discover.parse_hosts_ports("not xml <<") == {}


# --- pick_dcs --------------------------------------------------------------

def test_pick_dcs_identifies_kerberos_ldap_host():
    hp = discover.parse_hosts_ports(_XML)
    dcs = discover.pick_dcs(hp)
    assert dcs == ["10.10.10.10"]  # yalnız 88+389 olan


def test_pick_dcs_ranks_gc_first():
    hp = {
        "10.0.0.1": {"88", "389"},            # DC ama GC yok
        "10.0.0.2": {"88", "389", "3268"},    # GC (global catalog) -> önce
    }
    assert discover.pick_dcs(hp)[0] == "10.0.0.2"


def test_pick_dcs_empty_when_no_dc():
    hp = {"10.0.0.5": {"445", "3389"}}
    assert discover.pick_dcs(hp) == []


# --- domain_from_nxc -------------------------------------------------------

def test_domain_from_nxc_parses_name_and_domain():
    out = ("SMB 10.10.10.10 445 DC01 [*] Windows Server 2019 "
           "(name:DC01) (domain:corp.local) (signing:True) (SMBv1:False)")
    dc_name, domain = discover.domain_from_nxc(out)
    assert dc_name == "DC01"
    assert domain == "corp.local"


def test_domain_from_nxc_ignores_workgroup():
    out = "SMB 10.0.0.9 445 WS01 [*] Windows 10 (name:WS01) (domain:WORKGROUP)"
    dc_name, domain = discover.domain_from_nxc(out)
    assert dc_name == "WS01"
    assert domain == ""  # nokta yok -> gerçek AD domaini değil


def test_domain_from_nxc_no_match():
    assert discover.domain_from_nxc("hicbir sey yok") == ("", "")
