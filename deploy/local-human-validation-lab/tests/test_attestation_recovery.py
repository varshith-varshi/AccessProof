"""Synthetic restart evidence tests, no customer data or Microsoft credentials."""
import base64, hashlib, json, os, sqlite3, tempfile, time, unittest
from contextlib import closing
from pathlib import Path
from unittest.mock import patch
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives import serialization
from app.attestation_health import inspect_index

class SignedRecoveryTest(unittest.TestCase):
    def setUp(self):
        self.key=Ed25519PrivateKey.generate()
        raw=self.key.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
        kid=base64.urlsafe_b64encode(raw).rstrip(b"=").decode()
        self.ctx=patch.dict(os.environ,{"LAB_SOURCE_PUBLIC_KEYS_JSON":json.dumps({"test-key":kid}),
             "LAB_TENANT_ID":"tenant-1","LAB_APPLICATION_ID":"app-1","LAB_SOURCE_ID":"source-1"})
        self.ctx.start();self.now=int(time.time());self.t=tempfile.TemporaryDirectory()
        self.path=str(Path(self.t.name)/"index.db")
        self.text="An example document with synthetic financial canary content."
    def tearDown(self):
        self.ctx.stop();self.t.cleanup()
    def signature(self,expires_in=1800,source="source-1"):
        claims={"v":1,"kid":"test-key","tenant":"tenant-1","app":"app-1","source":source,
            "resource":"doc-1","chunk":"doc-1:c0","revision":"v1",
            "sha256":hashlib.sha256(self.text.encode()).hexdigest(),"iat":self.now-10,
            "exp":self.now+expires_in}
        blob=json.dumps(claims,sort_keys=True,separators=(",",":"),ensure_ascii=True).encode()
        enc=lambda x:base64.urlsafe_b64encode(x).rstrip(b"=").decode()
        return enc(blob)+"."+enc(self.key.sign(blob))
    def index(self,expires_in=1800,source="source-1",content=None,sync_age=10):
        with closing(sqlite3.connect(self.path)) as db, db:
            db.execute("CREATE TABLE metadata(key TEXT PRIMARY KEY,value TEXT)")
            db.execute("CREATE TABLE chunks(doc_id TEXT,chunk_id TEXT,text TEXT,version TEXT,attestation TEXT)")
            db.execute("INSERT INTO metadata VALUES ('last_sync',?)",(str(self.now-sync_age),))
            db.execute("INSERT INTO chunks VALUES (?,?,?,?,?)",("doc-1","doc-1:c0",
                self.text if content is None else content,"v1",self.signature(expires_in,source)))
    def ready(self):
        return inspect_index(self.path,now=self.now)
    def test_fresh_signed_index(self):
        self.index();x=self.ready();self.assertTrue(x["signed_index_ready"]);self.assertEqual(x["signed_chunks_valid"],1)
    def test_expired_index_fails_closed(self):
        self.index(expires_in=-1);self.assertFalse(self.ready()["signed_index_ready"])
    def test_near_expiry_fails_closed(self):
        self.index(expires_in=60);self.assertEqual(self.ready()["reason_code"],"ATTESTATION_EXPIRED_OR_NEAR_EXPIRY")
    def test_cross_source_rejected(self):
        self.index(source="wrong-source");self.assertEqual(self.ready()["reason_code"],"SIGNED_SOURCE_BINDING_MISMATCH")
    def test_content_tampering_rejected(self):
        self.index(content=self.text+" tampered");self.assertEqual(self.ready()["reason_code"],"SIGNED_CONTENT_DIGEST_MISMATCH")
    def test_stale_sync_rejected(self):
        self.index(sync_age=4000);self.assertEqual(self.ready()["reason_code"],"SOURCE_SYNC_STALE")
    def test_missing_key_rejected(self):
        self.index();os.environ.pop("LAB_SOURCE_PUBLIC_KEYS_JSON");self.assertFalse(self.ready()["signed_index_ready"])
    def test_missing_index_rejected(self):
        self.assertFalse(self.ready()["signed_index_ready"])
    def test_bad_signature_rejected(self):
        self.index()
        with closing(sqlite3.connect(self.path)) as db, db:
            db.execute("UPDATE chunks SET attestation=substr(attestation,1,length(attestation)-2)||'__'")
        self.assertFalse(self.ready()["signed_index_ready"])
if __name__=="__main__":unittest.main()
