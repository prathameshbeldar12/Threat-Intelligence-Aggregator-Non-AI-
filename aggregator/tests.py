import json
from django.test import TestCase
from django.contrib.auth.models import User
from django.utils import timezone
from rest_framework.test import APITestCase
from django.urls import reverse

from aggregator.models import Feed, IOC, IOCSource, CorrelationResult, Blocklist, ActivityLog
from aggregator.services.validator import (
    validate_ip, validate_domain, validate_url, validate_hash, validate_email
)
from aggregator.services.normalizer import (
    normalize_ip, normalize_domain, normalize_url, normalize_hash, normalize_email
)
from aggregator.services.ioc_parser import detect_ioc_type, extract_iocs_from_text
from aggregator.services.feed_parser import parse_feed_content
from aggregator.services.risk_engine import calculate_risk_and_severity
from aggregator.services.correlation import run_correlation_engine
from aggregator.services.blocklist import generate_blocklist_file
from aggregator.services.reporting import get_report_statistics


class ValidatorServiceTest(TestCase):
    def test_ip_validation(self):
        self.assertTrue(validate_ip("192.168.1.1"))
        self.assertTrue(validate_ip("8.8.8.8"))
        self.assertFalse(validate_ip("256.0.0.1"))
        self.assertFalse(validate_ip("invalid-ip"))
        self.assertFalse(validate_ip("2001:db8::1")) # IPv6 not supported in our IPv4 system

    def test_domain_validation(self):
        self.assertTrue(validate_domain("google.com"))
        self.assertTrue(validate_domain("sub.domain-name.co.uk"))
        self.assertFalse(validate_domain("invalid_domain"))
        self.assertFalse(validate_domain("google..com"))
        self.assertFalse(validate_domain("-domain.com"))

    def test_url_validation(self):
        self.assertTrue(validate_url("http://example.com/path"))
        self.assertTrue(validate_url("https://1.1.1.1:443/api"))
        self.assertFalse(validate_url("ftp://"))
        self.assertFalse(validate_url("example.com/no-scheme"))

    def test_hash_validation(self):
        # MD5
        self.assertTrue(validate_hash("098f6bcd4621d373cade4e832627b4f6"))
        # SHA1
        self.assertTrue(validate_hash("a9993e364706816aba3e25717850c26c9cd0d89d"))
        # SHA256
        self.assertTrue(validate_hash("e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"))
        # Invalid length/hex
        self.assertFalse(validate_hash("098f6bcd4621d373cade4e832627b4f6z"))
        self.assertFalse(validate_hash("not-a-hash"))

    def test_email_validation(self):
        self.assertTrue(validate_email("test@example.com"))
        self.assertTrue(validate_email("user.name+label@sub.domain.org"))
        self.assertFalse(validate_email("no-domain@"))
        self.assertFalse(validate_email("no-at.domain.com"))


class NormalizerServiceTest(TestCase):
    def test_whitespace_and_lowercase(self):
        self.assertEqual(normalize_domain("  Example.COM  "), "example.com")
        self.assertEqual(normalize_hash("  A9993E364706816ABA3E25717850C26C9CD0D89D  "), "a9993e364706816aba3e25717850c26c9cd0d89d")
        self.assertEqual(normalize_email("  Analyst@ThreatShield.LOCAL  "), "analyst@threatshield.local")

    def test_url_canonicalization(self):
        self.assertEqual(normalize_url("HTTP://Example.com:80/path//double-slash"), "http://example.com/path/double-slash")
        self.assertEqual(normalize_url("HTTPS://SECURE-API.NET:443/"), "https://secure-api.net/")


class ParserServiceTest(TestCase):
    def test_freeform_text_extraction(self):
        text = "Check IP 192.0.2.1 and host bad-domain.net and hash 098f6bcd4621d373cade4e832627b4f6"
        extracted = extract_iocs_from_text(text)
        values = [item['value'] for item in extracted]
        self.assertIn("192.0.2.1", values)
        self.assertIn("bad-domain.net", values)
        self.assertIn("098f6bcd4621d373cade4e832627b4f6", values)

    def test_csv_feed_parsing(self):
        csv_content = "indicator,type,source\n192.0.2.1,ip,feedA\nEXAMPLE.com,domain,feedA\ninvalid_ip,ip,feedA"
        successful, rejected = parse_feed_content(csv_content, "CSV")
        self.assertEqual(len(successful), 2)
        self.assertEqual(len(rejected), 1)
        self.assertEqual(successful[0]['normalized_value'], "192.0.2.1")
        self.assertEqual(successful[1]['normalized_value'], "example.com")

    def test_json_feed_parsing(self):
        json_list = [
            {"indicator": "198.51.100.1", "type": "ip"},
            {"indicator": "http://malicious.org/payload", "type": "url"},
            {"indicator": "invalid_item"}
        ]
        successful, rejected = parse_feed_content(json.dumps(json_list), "JSON")
        self.assertEqual(len(successful), 2)
        self.assertEqual(len(rejected), 1)

    def test_stix_feed_parsing(self):
        stix_bundle = {
            "type": "bundle",
            "objects": [
                {
                    "type": "indicator",
                    "pattern": "[ipv4-addr:value = '198.51.100.22']"
                },
                {
                    "type": "indicator",
                    "pattern": "[domain-name:value = 'malware-tld.biz']"
                }
            ]
        }
        successful, rejected = parse_feed_content(json.dumps(stix_bundle), "JSON")
        self.assertEqual(len(successful), 2)
        self.assertEqual(successful[0]['normalized_value'], "198.51.100.22")
        self.assertEqual(successful[1]['normalized_value'], "malware-tld.biz")


class RiskEngineTest(TestCase):
    def test_rule_based_risk_score(self):
        # 1 feed overlap
        score, severity, reason = calculate_risk_and_severity(source_count=1, occurrence_count=2, ioc_type="IPv4")
        self.assertEqual(score, 20 + 4 + 2) # Base 20 + 4 (occurrence*2) + 2 (IP type weight) = 26 (Medium)
        self.assertEqual(severity, "Medium")

        # 3 feed overlap
        score, severity, reason = calculate_risk_and_severity(source_count=3, occurrence_count=5, ioc_type="Hash")
        self.assertEqual(score, 60 + 10 + 5) # Base 60 + 10 (occurrence*2 bonus) + 5 (Hash specificity) = 75 (Critical)
        self.assertEqual(severity, "Critical")

        # Cap check
        score, severity, reason = calculate_risk_and_severity(source_count=5, occurrence_count=20, ioc_type="Hash")
        self.assertEqual(score, 100) # Capped at 100


class CorrelationAndBlocklistTest(TestCase):
    def setUp(self):
        self.user = User.objects.create_user(username="test_analyst", password="Password123")
        self.feed_a = Feed.objects.create(name="Feed A", source="URL", feed_type="TXT", category="IPs")
        self.feed_b = Feed.objects.create(name="Feed B", source="URL", feed_type="TXT", category="IPs")
        
        # Overlapping IP
        self.ioc = IOC.objects.create(value="198.51.100.5", normalized_value="198.51.100.5", ioc_type="IPv4")
        IOCSource.objects.create(ioc=self.ioc, feed=self.feed_a, occurrence_count=1)
        IOCSource.objects.create(ioc=self.ioc, feed=self.feed_b, occurrence_count=2)

    def test_correlation_cycle(self):
        stats = run_correlation_engine(user=self.user)
        self.assertEqual(stats['total_iocs'], 1)
        
        # Verify db update
        self.ioc.refresh_from_db()
        self.assertEqual(self.ioc.risk_score, 40 + 6 + 2 + 10) # Base 40 + 6 (occurrences sum=3*2) + 2 (IP weight) + 10 (recency) = 58 (High)
        self.assertEqual(self.ioc.severity, "High")
        
        # CorrelationResult created
        corr = CorrelationResult.objects.get(ioc=self.ioc)
        self.assertEqual(corr.source_count, 2)
        self.assertEqual(corr.risk_score, 58)

    def test_blocklist_generation(self):
        run_correlation_engine(user=self.user)
        content, filename, count = generate_blocklist_file(
            ioc_type="IP",
            min_severity="Low",
            min_risk_score=20,
            file_format="TXT",
            user=self.user
        )
        self.assertEqual(count, 1)
        self.assertEqual(content.strip(), "198.51.100.5")
        
        # Export log verify
        self.assertEqual(Blocklist.objects.count(), 1)


class APITest(APITestCase):
    def setUp(self):
        self.user = User.objects.create_user(username="api_analyst", password="Password123!")
        self.client.login(username="api_analyst", password="Password123!")
        
        # Create Feed
        self.feed = Feed.objects.create(
            name="AlienVault API Feed", 
            source="URL", 
            feed_type="JSON", 
            category="Malware"
        )
        
    def test_feed_api_endpoints(self):
        response = self.client.get(reverse('api-feed-list'))
        self.assertEqual(response.status_code, 200)
        self.assertEqual(len(response.data), 1)

    def test_unauthenticated_blocked(self):
        self.client.logout()
        response = self.client.get(reverse('api-feed-list'))
        self.assertEqual(response.status_code, 403) # Forbidden for anonymous users
