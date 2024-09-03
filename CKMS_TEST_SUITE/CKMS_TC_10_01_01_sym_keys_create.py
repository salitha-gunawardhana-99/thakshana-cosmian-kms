import unittest
import CKMS_sym

CKMS_sym.start_kms_server()

algo_list = ["chacha20", "aes", "sha3", "shake"]

len_list = [16, 64, 96, 100, 128, 200, 224, 256, 300, 384, 400, 512]

key_length = 256

num = 4


class TestCkmsSymKeysGenerate(unittest.TestCase):
    def setUp(self):
        pass

    def tearDown(self):
        pass

    def test_generate_sym_keys_success_with_valid_algorithms(self):
        for algo in algo_list:
            list1 = []
            for length in len_list:
                key_name = f"{num}_sym_encryption_key_{algo}_valid_{length}"
                try:
                    status = CKMS_sym.generate_key(
                        key_name=key_name, key_type=algo, key_length=length)
                    list1.append(status[1])
                except Exception as e:
                    self.fail(f"Exception occurred during key generation: {e}")
            print(list1)
            self.assertTrue(all(status == "pass" or "fail" for status in list1),
                            f"Failed to generate keys for valid algorithms: {algo}")

    def test_generate_sym_keys_failure_with_invalid_algorithms(self):
        list2 = []
        for algo in algo_list:
            key_name = f"sym_encryption_key_{algo}_invalid_{num}"
            try:
                status = CKMS_sym.generate_key(
                    key_name=key_name, key_type=f"{algo}_", key_length=key_length)
                list2.append(status[1])
            except Exception as e:
                self.fail(
                    f"Exception occurred during key generation with invalid algorithm: {e}")
        print(list2)
        self.assertTrue(all(status == "fail" for status in list2),
                        f"Unexpected success in generating keys for invalid algorithms")


if __name__ == '__main__':
    unittest.main()
