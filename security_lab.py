"""Local defensive exercises using synthetic records and ephemeral keys."""
from dataclasses import dataclass,asdict
from pathlib import Path
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
import base64,hashlib,hmac,json,os,secrets

def password_record(password,salt=None):
    if len(password)<12:raise ValueError('Use at least 12 characters')
    salt=salt or secrets.token_bytes(16)
    digest=hashlib.pbkdf2_hmac('sha256',password.encode(),salt,600000)
    return {'algorithm':'pbkdf2-sha256','iterations':600000,'salt':salt.hex(),'digest':digest.hex()}
def verify_password(password,record):
    digest=hashlib.pbkdf2_hmac('sha256',password.encode(),bytes.fromhex(record['salt']),record['iterations'])
    return hmac.compare_digest(digest.hex(),record['digest'])
def seal(data,key,context=b'course-lab-v1'):
    nonce=secrets.token_bytes(12);return nonce+AESGCM(key).encrypt(nonce,data,context)
def unseal(blob,key,context=b'course-lab-v1'):return AESGCM(key).decrypt(blob[:12],blob[12:],context)
def redact(records):
    """Remove direct identifiers; this alone cannot guarantee anonymity."""
    return [{'age_band':f'{int(r["age"])//10*10}-{int(r["age"])//10*10+9}','city_region':r['region'],'score':r['score']} for r in records]
def pseudonymize(email,key):return hmac.new(key,email.strip().lower().encode(),'sha256').hexdigest()[:24]
def manifest(folder):
    return {str(p.relative_to(folder)).replace('\\','/'):hashlib.sha256(p.read_bytes()).hexdigest() for p in sorted(Path(folder).rglob('*')) if p.is_file()}
def detect(log):
    failures={};alerts=[]
    for event in log:
        if event['event']=='login_failed':
            source=event['source'];failures[source]=failures.get(source,0)+1
            if failures[source]==5:alerts.append({'rule':'AUTH-05','source':source,'severity':'medium'})
    return alerts
def policy(source,destination,port):
    allowed={('students','web',443),('admins','web',22),('web','database',5432),('students','dns',53)}
    return 'allow' if (source,destination,port) in allowed else 'deny'
def risk(likelihood,impact):
    if not 1<=likelihood<=5 or not 1<=impact<=5:raise ValueError('Scores must be 1-5')
    score=likelihood*impact;return {'score':score,'band':'high' if score>=15 else 'medium' if score>=6 else 'low'}
if __name__=='__main__':
    key=AESGCM.generate_key(bit_length=256);sample=b'synthetic classroom record';blob=seal(sample,key)
    print(json.dumps({'encryption_roundtrip':unseal(blob,key)==sample,'student_database_access':policy('students','database',5432),'risk_example':risk(4,5)},indent=2))
