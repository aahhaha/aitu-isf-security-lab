import json
import pytest
from cryptography.exceptions import InvalidTag
from security_lab import *
def test_password_verification_and_unique_salts():
    a=password_record('Synthetic-password-2026');b=password_record('Synthetic-password-2026')
    assert a['salt']!=b['salt'];assert verify_password('Synthetic-password-2026',a);assert not verify_password('incorrect',a)
def test_password_not_retained():assert 'Synthetic-password-2026' not in json.dumps(password_record('Synthetic-password-2026'))
def test_authenticated_encryption_roundtrip_and_fresh_nonce():
    key=AESGCM.generate_key(bit_length=256);a=seal(b'synthetic data',key);b=seal(b'synthetic data',key)
    assert a!=b;assert unseal(a,key)==b'synthetic data'
def test_ciphertext_tampering_fails_closed():
    key=AESGCM.generate_key(bit_length=256);blob=bytearray(seal(b'synthetic data',key));blob[-1]^=1
    with pytest.raises(InvalidTag):unseal(bytes(blob),key)
def test_wrong_context_rejected():
    key=AESGCM.generate_key(bit_length=256)
    with pytest.raises(InvalidTag):unseal(seal(b'data',key),key,b'wrong-context')
def test_redaction_removes_identifiers():
    out=redact([{'email':'example@example.invalid','name':'Synthetic person','age':21,'region':'Region X','score':80}]);assert 'email' not in out[0] and 'name' not in out[0];assert out[0]['age_band']=='20-29'
def test_pseudonyms_are_keyed_and_stable():
    assert pseudonymize('A@EXAMPLE.INVALID',b'a')==pseudonymize('a@example.invalid',b'a');assert pseudonymize('a@example.invalid',b'a')!=pseudonymize('a@example.invalid',b'b')
def test_forensic_integrity_detects_edit(tmp_path):
    f=tmp_path/'events.json';f.write_text('original synthetic log');before=manifest(tmp_path);f.write_text('modified');assert manifest(tmp_path)!=before
def test_authentication_alert_threshold():
    events=[{'event':'login_failed','source':'192.0.2.10'}]*7;assert len(detect(events))==1;assert detect(events[:4])==[]
@pytest.mark.parametrize('src,dst,port,expected',[('students','web',443,'allow'),('students','database',5432,'deny'),('students','web',22,'deny'),('admins','web',22,'allow'),('web','database',5432,'allow'),('unknown','web',443,'deny')])
def test_segmentation_policy(src,dst,port,expected):assert policy(src,dst,port)==expected
def test_risk_prioritization():assert risk(4,5)['band']=='high';assert risk(1,2)['band']=='low'
