"""Production Cloud KMS adapters. Keys are named configuration, never files."""
from __future__ import annotations
from dataclasses import dataclass
from .crypto import MacRecord

@dataclass
class GoogleKmsHmacKey:
    key_resource: str
    key_version: str
    retired_versions: dict[tuple[str,str],str]
    def __post_init__(self):
        from google.cloud import kms
        self.client=kms.KeyManagementServiceClient()
    def sign(self,data:bytes)->MacRecord:
        response=self.client.mac_sign(request={"name":self.key_version,"data":data})
        return MacRecord(self.key_resource,self.key_version,response.mac)
    def verify(self,record:MacRecord,data:bytes)->bool:
        name=self.key_version if (record.key_resource,record.key_version)==(self.key_resource,self.key_version) else self.retired_versions.get((record.key_resource,record.key_version))
        if not name:return False
        return bool(self.client.mac_verify(request={"name":name,"data":data,"mac":record.mac}).success)

@dataclass
class GoogleKmsDataKeyWrapper:
    key_name: str
    def __post_init__(self):
        from google.cloud import kms
        self.client=kms.KeyManagementServiceClient()
    def wrap(self,data_key:bytes)->bytes:
        return self.client.encrypt(request={"name":self.key_name,"plaintext":data_key}).ciphertext
    def unwrap(self,wrapped:bytes)->bytes:
        return self.client.decrypt(request={"name":self.key_name,"ciphertext":wrapped}).plaintext
