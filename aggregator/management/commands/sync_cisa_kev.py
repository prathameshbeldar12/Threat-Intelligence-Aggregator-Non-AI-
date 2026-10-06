from datetime import datetime

import requests

from django.core.management.base import BaseCommand

from aggregator.models import Vulnerability, ActivityLog


CISA_KEV_URL = (
    "https://www.cisa.gov/sites/default/files/feeds/"
    "known_exploited_vulnerabilities.json"
)

CISA_KEV_FALLBACK = (
    "https://raw.githubusercontent.com/cisagov/kev-data/"
    "main/known_exploited_vulnerabilities.json"
)


class Command(BaseCommand):
    help = "Synchronize the CISA Known Exploited Vulnerabilities catalog."

    def fetch_catalog(self):
        headers = {
            "User-Agent": (
                "ThreatShield-Intelligence-Aggregator/1.0 "
                "(defensive-security-project)"
            ),
            "Accept": "application/json",
        }

        urls = [
            CISA_KEV_URL,
            CISA_KEV_FALLBACK,
        ]

        last_error = None

        for url in urls:
            try:
                response = requests.get(
                    url,
                    headers=headers,
                    timeout=30
                )

                response.raise_for_status()

                data = response.json()

                if "vulnerabilities" not in data:
                    raise ValueError(
                        "Invalid CISA KEV response."
                    )

                return data

            except Exception as exc:
                last_error = exc

        raise RuntimeError(
            f"Unable to fetch CISA KEV catalog: {last_error}"
        )

    def parse_date(self, value):
        if not value:
            return None

        try:
            return datetime.strptime(
                value,
                "%Y-%m-%d"
            ).date()
        except ValueError:
            return None

    def handle(self, *args, **options):
        self.stdout.write(
            "Downloading CISA KEV catalog..."
        )

        try:
            catalog = self.fetch_catalog()
        except Exception as exc:
            ActivityLog.objects.create(
                user=None,
                action="CISA KEV Sync",
                module="vulnerability",
                status="Error",
                description=str(exc)
            )

            raise

        vulnerabilities = catalog.get(
            "vulnerabilities",
            []
        )

        created_count = 0
        updated_count = 0

        for item in vulnerabilities:
            cve_id = item.get("cveID")

            if not cve_id:
                continue

            defaults = {
                "vendor": item.get(
                    "vendorProject",
                    ""
                ),
                "product": item.get(
                    "product",
                    ""
                ),
                "name": item.get(
                    "vulnerabilityName",
                    ""
                ),
                "description": item.get(
                    "shortDescription",
                    ""
                ),
                "date_added": self.parse_date(
                    item.get("dateAdded")
                ),
                "due_date": self.parse_date(
                    item.get("dueDate")
                ),
                "known_ransomware_use": item.get(
                    "knownRansomwareCampaignUse",
                    ""
                ),
                "source_url": (
                    "https://www.cisa.gov/known-exploited-"
                    "vulnerabilities-catalog"
                ),
            }

            vulnerability, created = (
                Vulnerability.objects.update_or_create(
                    cve_id=cve_id,
                    defaults=defaults
                )
            )

            if created:
                created_count += 1
            else:
                updated_count += 1

        ActivityLog.objects.create(
            user=None,
            action="CISA KEV Sync",
            module="vulnerability",
            status="Success",
            description=(
                f"CISA KEV sync completed. "
                f"Created={created_count}, "
                f"Updated={updated_count}, "
                f"Catalog count={len(vulnerabilities)}."
            )
        )

        self.stdout.write(
            self.style.SUCCESS(
                "CISA KEV SYNC COMPLETE"
            )
        )

        self.stdout.write(
            f"Created: {created_count}"
        )

        self.stdout.write(
            f"Updated: {updated_count}"
        )

        self.stdout.write(
            f"Total catalog records: {len(vulnerabilities)}"
        )