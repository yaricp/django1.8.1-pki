from django.test import TestCase
from pki.models import Certificate, CertificateAuthority

class CertificateAuthorityTestCase(TestCase):
    def setUp(self):
        CertificateAuthority.objects.create(name="main1", sound="roar")
        CertificateAuthority.objects.create(name="main2", sound="meow")

    def test_ca_rebuild_ca_metadata(self):
        """Animals that can speak are correctly identified"""
        main1 = CertificateAuthority.objects.get(name="main1")
        main2 = CertificateAuthority.objects.get(name="main2")
        main1.rebuild_ca_metadata(self, True, 'append', skip_list=[])
        self.assertEqual(main1.name, 'main1')
        self.assertEqual(main2.name, 'main2')