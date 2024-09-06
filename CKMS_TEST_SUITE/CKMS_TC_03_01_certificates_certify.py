import CKMS_general
import CKMS_keys
import CKMS_certificates

CKMS_general.start_kms_server()

def rsa_key(key_name):
    issuer_key = CKMS_keys.generate_rsa_key(size_in_bits = 4096, tags = [key_name])
    print(issuer_key[1]) 
    
rsa_key("cert_issuer_key")   
rsa_key("key_for_cert")  