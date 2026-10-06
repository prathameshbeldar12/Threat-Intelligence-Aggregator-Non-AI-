from django.core.management.base import BaseCommand

from aggregator.models import Feed, ActivityLog
from aggregator.services.feed_fetcher import fetch_remote_feed
from aggregator.services.feed_parser import parse_feed_content
from aggregator.services.correlation import run_correlation_engine

from aggregator.views import process_parsed_iocs


class Command(BaseCommand):
    help = "Fetch and process all active remote threat-intelligence feeds."

    def add_arguments(self, parser):
        parser.add_argument(
            "--feed-id",
            type=int,
            default=None,
            help="Process only one feed ID."
        )

    def handle(self, *args, **options):
        feed_id = options.get("feed_id")

        feeds = Feed.objects.filter(
            is_active=True,
            source=Feed.SOURCE_URL
        )

        if feed_id:
            feeds = feeds.filter(id=feed_id)

        total_success = 0
        total_rejected = 0
        failed = 0

        if not feeds.exists():
            self.stdout.write(
                self.style.WARNING(
                    "No active remote feeds found."
                )
            )
            return

        for feed in feeds:
            self.stdout.write(
                f"Processing: {feed.name}"
            )

            try:
                content = fetch_remote_feed(feed.url)

                successful, rejected = parse_feed_content(
                    content,
                    feed.feed_type
                )

                process_parsed_iocs(
                    feed,
                    successful,
                    rejected,
                    user=None
                )

                total_success += len(successful)
                total_rejected += len(rejected)

                self.stdout.write(
                    self.style.SUCCESS(
                        f"  Imported: {len(successful)} | "
                        f"Rejected: {len(rejected)}"
                    )
                )

            except Exception as exc:
                failed += 1

                ActivityLog.objects.create(
                    user=None,
                    action="Automatic Feed Sync",
                    module="feed",
                    status="Error",
                    description=(
                        f"Automatic processing failed for "
                        f"'{feed.name}': {exc}"
                    )
                )

                self.stderr.write(
                    self.style.ERROR(
                        f"  FAILED: {exc}"
                    )
                )

        # Recalculate risk/correlation after feed processing.
        try:
            correlation_stats = run_correlation_engine(user=None)

            self.stdout.write(
                self.style.SUCCESS(
                    "Correlation completed: "
                    f"{correlation_stats['total_iocs']} IOCs evaluated, "
                    f"{correlation_stats['correlated_count']} overlaps."
                )
            )

        except Exception as exc:
            failed += 1

            ActivityLog.objects.create(
                user=None,
                action="Automatic Correlation",
                module="correlation",
                status="Error",
                description=str(exc)
            )

            self.stderr.write(
                self.style.ERROR(
                    f"Correlation failed: {exc}"
                )
            )

        self.stdout.write("")
        self.stdout.write(
            self.style.SUCCESS(
                f"SYNC COMPLETE | "
                f"Imported={total_success} | "
                f"Rejected={total_rejected} | "
                f"Failures={failed}"
            )
        )