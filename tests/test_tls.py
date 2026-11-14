from datetime import datetime,timedelta,timezone
from ipaddress import ip_address
from http.server import BaseHTTPRequestHandler,ThreadingHTTPServer
import ssl,threading,urllib.request,urllib.error
import pytest
from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes,serialization
from cryptography.hazmat.primitives.asymmetric import rsa

def test_tls_trust_and_untrusted_rejection(tmp_path):
    key=rsa.generate_private_key(public_exponent=65537,key_size=2048)
    subject=x509.Name([x509.NameAttribute(NameOID.COMMON_NAME,'localhost')]);now=datetime.now(timezone.utc)
    cert=(x509.CertificateBuilder().subject_name(subject).issuer_name(subject).public_key(key.public_key())
          .serial_number(x509.random_serial_number()).not_valid_before(now-timedelta(minutes=1)).not_valid_after(now+timedelta(days=1))
          .add_extension(x509.SubjectAlternativeName([x509.DNSName('localhost'),x509.IPAddress(ip_address('127.0.0.1'))]),critical=False)
          .sign(key,hashes.SHA256()))
    certfile=tmp_path/'certificate.pem';keyfile=tmp_path/'private.pem'
    certfile.write_bytes(cert.public_bytes(serialization.Encoding.PEM))
    keyfile.write_bytes(key.private_bytes(serialization.Encoding.PEM,serialization.PrivateFormat.PKCS8,serialization.NoEncryption()))
    class H(BaseHTTPRequestHandler):
        def do_GET(self):self.send_response(200);self.end_headers();self.wfile.write(b'synthetic TLS record')
        def log_message(self,*args):pass
    s=ThreadingHTTPServer(('127.0.0.1',0),H);ctx=ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER);ctx.minimum_version=ssl.TLSVersion.TLSv1_2;ctx.load_cert_chain(certfile,keyfile);s.socket=ctx.wrap_socket(s.socket,server_side=True)
    t=threading.Thread(target=s.serve_forever,daemon=True);t.start();url=f'https://127.0.0.1:{s.server_port}/'
    try:
        trusted=ssl.create_default_context(cafile=str(certfile))
        with urllib.request.urlopen(url,context=trusted,timeout=5) as r:assert r.read()==b'synthetic TLS record'
        with pytest.raises(urllib.error.URLError):urllib.request.urlopen(url,context=ssl.create_default_context(),timeout=5)
    finally:s.shutdown();s.server_close();t.join()
