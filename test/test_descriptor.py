#! /usr/bin/env python3

from hwilib.descriptor import Descriptor
import unittest

class TestDescriptor(unittest.TestCase):
    def test_parse_descriptor_with_origin(self):
        desc = Descriptor.parse("wpkh([00000001/84'/1'/0']***REMOVED***/0/0)", True)
        self.assertIsNotNone(desc)
        self.assertEqual(desc.wpkh, True)
        self.assertEqual(desc.sh_wpkh, None)
        self.assertEqual(desc.origin_fingerprint, "00000001")
        self.assertEqual(desc.origin_path, "/84'/1'/0'")
        self.assertEqual(desc.base_key, "***REMOVED***")
        self.assertEqual(desc.path_suffix, "/0/0")
        self.assertEqual(desc.testnet, True)
        self.assertEqual(desc.m_path, "m/84'/1'/0'/0/0")

    def test_parse_descriptor_without_origin(self):
        desc = Descriptor.parse("wpkh(***REMOVED***/0/0)", True)
        self.assertIsNotNone(desc)
        self.assertEqual(desc.wpkh, True)
        self.assertEqual(desc.sh_wpkh, None)
        self.assertEqual(desc.origin_fingerprint, None)
        self.assertEqual(desc.origin_path, None)
        self.assertEqual(desc.base_key, "***REMOVED***")
        self.assertEqual(desc.path_suffix, "/0/0")
        self.assertEqual(desc.testnet, True)
        self.assertEqual(desc.m_path, None)

    def test_parse_descriptor_with_key_at_end_with_origin(self):
        desc = Descriptor.parse("wpkh([00000001/84'/1'/0'/0/0]***REMOVED***)", True)
        self.assertIsNotNone(desc)
        self.assertEqual(desc.wpkh, True)
        self.assertEqual(desc.sh_wpkh, None)
        self.assertEqual(desc.origin_fingerprint, "00000001")
        self.assertEqual(desc.origin_path, "/84'/1'/0'/0/0")
        self.assertEqual(desc.base_key, "***REMOVED***")
        self.assertEqual(desc.path_suffix, None)
        self.assertEqual(desc.testnet, True)
        self.assertEqual(desc.m_path, "m/84'/1'/0'/0/0")

    def test_parse_descriptor_with_key_at_end_without_origin(self):
        desc = Descriptor.parse("wpkh(***REMOVED***)", True)
        self.assertIsNotNone(desc)
        self.assertEqual(desc.wpkh, True)
        self.assertEqual(desc.sh_wpkh, None)
        self.assertEqual(desc.origin_fingerprint, None)
        self.assertEqual(desc.origin_path, None)
        self.assertEqual(desc.base_key, "***REMOVED***")
        self.assertEqual(desc.path_suffix, None)
        self.assertEqual(desc.testnet, True)
        self.assertEqual(desc.m_path, None)

    def test_parse_empty_descriptor(self):
        desc = Descriptor.parse("", True)
        self.assertIsNone(desc)

    def test_parse_descriptor_replace_h(self):
        desc = Descriptor.parse("wpkh([00000001/84h/1h/0']***REMOVED***/0/0)", True)
        self.assertIsNotNone(desc)
        self.assertEqual(desc.origin_path, "/84'/1'/0'")

    def test_serialize_descriptor_with_origin(self):
        descriptor = "wpkh([00000001/84'/1'/0']***REMOVED***/0/0)"
        desc = Descriptor.parse(descriptor, True)
        self.assertEqual(desc.serialize(), descriptor)

    def test_serialize_descriptor_without_origin(self):
        descriptor = "wpkh(***REMOVED***/0/0)"
        desc = Descriptor.parse(descriptor, True)
        self.assertEqual(desc.serialize(), descriptor)

    def test_serialize_descriptor_with_key_at_end_with_origin(self):
        descriptor = "wpkh([00000001/84'/1'/0'/0/0]***REMOVED***)"
        desc = Descriptor.parse(descriptor, True)
        self.assertEqual(desc.serialize(), descriptor)

if __name__ == "__main__":
    unittest.main()
