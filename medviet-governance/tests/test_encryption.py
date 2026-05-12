# tests/test_encryption.py
import shutil
import uuid
from pathlib import Path

import pytest

from src.encryption.vault import SimpleVault

_TMP_ROOT = Path(__file__).parent / ".tmp_vault"


@pytest.fixture(scope="function")
def tmp_key_path():
    _TMP_ROOT.mkdir(exist_ok=True)
    path = _TMP_ROOT / f"vault_{uuid.uuid4().hex}.key"
    yield path
    if path.exists():
        path.unlink()


@pytest.fixture
def vault(tmp_key_path):
    return SimpleVault(master_key_path=str(tmp_key_path))


def teardown_module(module):
    if _TMP_ROOT.exists():
        shutil.rmtree(_TMP_ROOT, ignore_errors=True)


def test_round_trip_basic(vault):
    sample_cccd = "012345" + "678901"
    original = f"Nguyen Van A - CCCD: {sample_cccd}"
    encrypted = vault.encrypt_data(original)
    assert "encrypted_dek" in encrypted
    assert "ciphertext" in encrypted
    assert encrypted["algorithm"] == "AES-256-GCM"

    decrypted = vault.decrypt_data(encrypted)
    assert decrypted == original


def test_round_trip_unicode(vault):
    original = "Benh nhan Tran Thi Hong - so dien thoai 0987654321"
    encrypted = vault.encrypt_data(original)
    decrypted = vault.decrypt_data(encrypted)
    assert decrypted == original


def test_dek_differs_per_encryption(vault):
    e1 = vault.encrypt_data("same input")
    e2 = vault.encrypt_data("same input")
    assert e1["ciphertext"] != e2["ciphertext"]
    assert e1["encrypted_dek"] != e2["encrypted_dek"]


def test_kek_persisted(tmp_key_path):
    v1 = SimpleVault(master_key_path=str(tmp_key_path))
    payload = v1.encrypt_data("persist me")

    v2 = SimpleVault(master_key_path=str(tmp_key_path))
    assert v2.decrypt_data(payload) == "persist me"
