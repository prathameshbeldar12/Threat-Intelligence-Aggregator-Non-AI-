import csv
import json
from io import StringIO

from django.utils import timezone

from aggregator.models import IOC, Blocklist, ActivityLog


SEVERITY_ORDER = {
    "Low": 1,
    "Medium": 2,
    "High": 3,
    "Critical": 4,
}

ALLOWED_TYPES = {
    "IP",
    "IPv4",
    "Domain",
    "URL",
    "Hash",
}

ALLOWED_SEVERITIES = {
    "Low",
    "Medium",
    "High",
    "Critical",
}

ALLOWED_FORMATS = {
    "TXT",
    "CSV",
    "JSON",
}


def generate_blocklist_file(
    ioc_type,
    min_severity="Low",
    min_risk_score=0,
    file_format="TXT",
    user=None,
):
    """
    Filter active IOCs and generate a blocklist export.

    Returns:
        tuple: (file_content, filename, indicator_count)
    """

    # --------------------------------------------------
    # 1. Validate IOC type
    # --------------------------------------------------

    if ioc_type not in ALLOWED_TYPES:
        raise ValueError("Unsupported IOC type.")

    # --------------------------------------------------
    # 2. Validate severity
    # --------------------------------------------------

    if min_severity not in ALLOWED_SEVERITIES:
        raise ValueError("Unsupported severity.")

    # --------------------------------------------------
    # 3. Validate risk score
    # --------------------------------------------------

    try:
        min_risk_score = int(min_risk_score)
    except (TypeError, ValueError):
        raise ValueError("Risk score must be a number.")

    if not 0 <= min_risk_score <= 100:
        raise ValueError(
            "Risk score must be between 0 and 100."
        )

    # --------------------------------------------------
    # 4. Validate output format
    # --------------------------------------------------

    file_format = str(file_format).upper()

    if file_format not in ALLOWED_FORMATS:
        raise ValueError("Unsupported output format.")

    # --------------------------------------------------
    # 5. Normalize IOC type
    # --------------------------------------------------

    query_type = ioc_type

    if ioc_type.upper() == "IP":
        query_type = "IPv4"

    # --------------------------------------------------
    # 6. Get active IOCs
    # --------------------------------------------------

    iocs = IOC.objects.filter(
        status="Active",
        ioc_type=query_type,
    ).order_by("-risk_score", "-last_seen")

    # --------------------------------------------------
    # 7. Apply minimum risk score
    # --------------------------------------------------

    if min_risk_score > 0:
        iocs = iocs.filter(
            risk_score__gte=min_risk_score
        )

    # --------------------------------------------------
    # 8. Apply minimum severity
    # --------------------------------------------------

    min_severity_value = SEVERITY_ORDER[min_severity]

    allowed_severities = [
        severity
        for severity, value in SEVERITY_ORDER.items()
        if value >= min_severity_value
    ]

    iocs = iocs.filter(
        severity__in=allowed_severities
    )

    # --------------------------------------------------
    # 9. Count indicators
    # --------------------------------------------------

    indicator_count = iocs.count()

    # --------------------------------------------------
    # 10. Generate filename
    # --------------------------------------------------

    timestamp = timezone.localtime().strftime(
        "%Y%m%d%H%M%S"
    )

    filename = (
        f"blocklist_{ioc_type.lower()}_{timestamp}"
    )

    # --------------------------------------------------
    # 11. Generate TXT
    # --------------------------------------------------

    if file_format == "TXT":

        content = "\n".join(
            ioc.normalized_value
            for ioc in iocs
        )

        filename += ".txt"

    # --------------------------------------------------
    # 12. Generate CSV
    # --------------------------------------------------

    elif file_format == "CSV":

        output = StringIO()

        writer = csv.writer(output)

        writer.writerow([
            "indicator",
            "type",
            "severity",
            "risk_score",
            "last_seen",
        ])

        for ioc in iocs:

            last_seen = ""

            if ioc.last_seen:
                last_seen = timezone.localtime(
                    ioc.last_seen
                ).strftime(
                    "%Y-%m-%dT%H:%M:%S%z"
                )

            writer.writerow([
                ioc.normalized_value,
                ioc.ioc_type,
                ioc.severity,
                ioc.risk_score,
                last_seen,
            ])

        content = output.getvalue()

        filename += ".csv"

    # --------------------------------------------------
    # 13. Generate JSON
    # --------------------------------------------------

    elif file_format == "JSON":

        data_list = []

        for ioc in iocs:

            last_seen = None

            if ioc.last_seen:
                last_seen = timezone.localtime(
                    ioc.last_seen
                ).isoformat()

            data_list.append({
                "indicator": ioc.normalized_value,
                "type": ioc.ioc_type,
                "severity": ioc.severity,
                "risk_score": ioc.risk_score,
                "last_seen": last_seen,
            })

        content = json.dumps(
            data_list,
            indent=2,
        )

        filename += ".json"

    # --------------------------------------------------
    # 14. Save blocklist history
    # --------------------------------------------------

    Blocklist.objects.create(
        name=(
            f"Blocklist {ioc_type} "
            f"(Risk >= {min_risk_score})"
        ),
        blocklist_type=ioc_type,
        severity_filter=f"{min_severity}+",
        indicator_count=indicator_count,
        file_format=file_format,
    )

    # --------------------------------------------------
    # 15. Activity log
    # --------------------------------------------------

    ActivityLog.objects.create(
        user=user,
        action="Generate Blocklist",
        module="blocklist",
        status="Success",
        description=(
            f"Generated {file_format} blocklist "
            f"of {ioc_type}. "
            f"Count: {indicator_count}, "
            f"Min Severity: {min_severity}, "
            f"Min Risk: {min_risk_score}"
        ),
    )

    # --------------------------------------------------
    # 16. Return generated file
    # --------------------------------------------------

    return content, filename, indicator_count