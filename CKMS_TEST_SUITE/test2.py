import CKMS_keys

# Example usage of import_key function

# CKMS_keys.revoke_key(key_type = "sym", revocation_reason="Testing",tags=["test-cert"])
# CKMS_keys.destroy_key(key_type = "sym", tags=["test-cert"])

CKMS_keys.export_key(key_type = "rsa", key_file = "cert_key_exported.pem", key_format = "pkcs1-pem", tags = ["key_for_cert", "_pk"])

def test_import_key():
    # Test Case 1: Basic key import without specifying key_id
    result = CKMS_keys.import_key(
        key_file="cert_key.pem",
        key_type = "rsa",
        key_format = "pem",
        tags=["cert-key"],
    )
    print(result)
    assert result == "pass", "Test Case 1: Basic key import failed"

    # # Test Case 2: Import with a specific key_id and replace existing key
    # result = CKMS_sym.import_key(
    #     key_file="path/to/keyfile.json",
    #     key_format="json-ttlv",
    #     key_id="specific-key-id",
    #     replace_existing="true",
    #     tags=["replace-tag"],
    #     key_usage=["sign", "verify"]
    # )
    # assert result == "pass", "Test Case 2: Key import with key_id failed"

    # # Test Case 3: Import a wrapped key
    # result = CKMS_sym.import_key(
    #     key_file="path/to/wrapped-keyfile.json",
    #     key_format="json-ttlv",
    #     unwrap="true",
    #     tags=["wrapped-key"]
    # )
    # assert result == "pass", "Test Case 3: Wrapped key import failed"

    # # Test Case 4: Import with public_key_id and private_key_id
    # result = CKMS_sym.import_key(
    #     key_file="path/to/keyfile.pem",
    #     key_format="pem",
    #     public_key_id="public-key-id",
    #     private_key_id="private-key-id",
    #     tags=["keypair-tag"]
    # )
    # assert result == "pass", "Test Case 4: Import with public and private key ids failed"

    print("All test cases passed successfully.")


# if __name__ == "__main__":
#     test_import_key()
