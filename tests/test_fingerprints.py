import hashlib
import pytest
from eps_probe import fingerprints as fp

def test_patch_window_sha256_matches():
    raw = bytes.fromhex(fp.PATCH_FINGERPRINT["bytes"])
    assert len(raw) == 64
    assert hashlib.sha256(raw).hexdigest() == fp.PATCH_FINGERPRINT["sha256"]

def test_egg_is_subset_of_window_at_expected_offset():
    raw = bytes.fromhex(fp.PATCH_FINGERPRINT["bytes"])
    off = fp.PATCH_FINGERPRINT["patch_offset"]
    assert raw[off] == fp.PATCH_POINT["original"]
    assert raw[off - 1:off - 1 + len(fp.EGG_SIGNATURE)] == fp.EGG_SIGNATURE

def test_register_table_unique():
    names = [n for n, _, _ in fp.REGISTER_READS]
    addrs = [a for _, a, _ in fp.REGISTER_READS]
    assert len(names) == len(set(names)) == 25
    assert len(addrs) == len(set(addrs))

def test_register_addresses_use_manual_names():
    by_addr = {a: n for n, a, _ in fp.REGISTER_READS}
    # 旧 payload 的错误别名必须不存在
    assert by_addr[0xFFA10084] == "FENTRYR"   # 旧称 FPCKAR
    assert by_addr[0xFFA10088] == "FPROTR"    # 旧称 FENTRYR
    assert by_addr[0xFFA10080] == "FSTATR"    # 旧称 FASTAT
    assert by_addr[0xFFA10010] == "FASTAT"    # 旧称 FAESTAT
    assert by_addr[0xFFA10020] == "FAREASELC" # 旧称 FREQR
    assert by_addr[0xFFF8A430] == "FHVE15"    # 旧称 FLWL
    assert by_addr[0xFFF82410] == "FHVE3"     # 旧称 FLWE
