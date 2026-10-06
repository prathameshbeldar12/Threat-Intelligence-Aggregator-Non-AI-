from django.contrib.auth.models import User
from django.core.validators import MaxValueValidator, MinValueValidator
from django.db import models


class Feed(models.Model):
    SOURCE_URL = "URL"
    SOURCE_FILE = "File Upload"

    SOURCE_CHOICES = [
        (SOURCE_URL, "URL"),
        (SOURCE_FILE, "File Upload"),
    ]

    FORMAT_CSV = "CSV"
    FORMAT_TXT = "TXT"
    FORMAT_JSON = "JSON"

    FORMAT_CHOICES = [
        (FORMAT_CSV, "CSV"),
        (FORMAT_TXT, "TXT"),
        (FORMAT_JSON, "JSON"),
    ]

    name = models.CharField(max_length=255)
    source = models.CharField(
        max_length=100,
        choices=SOURCE_CHOICES,
        default=SOURCE_URL,
    )
    feed_type = models.CharField(
        max_length=50,
        choices=FORMAT_CHOICES,
        default=FORMAT_TXT,
    )
    category = models.CharField(
        max_length=100,
        db_index=True,
    )
    description = models.TextField(blank=True)
    url = models.URLField(blank=True, null=True)
    raw_content = models.TextField(blank=True, default="")
    is_active = models.BooleanField(default=True, db_index=True)

    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    last_processed_at = models.DateTimeField(
        null=True,
        blank=True,
    )

    class Meta:
        ordering = ["-created_at"]
        indexes = [
            models.Index(fields=["is_active", "category"]),
            models.Index(fields=["source", "feed_type"]),
        ]

    def __str__(self):
        return f"{self.name} ({self.category})"


class IOC(models.Model):
    TYPE_IPV4 = "IPv4"
    TYPE_IPV6 = "IPv6"
    TYPE_DOMAIN = "Domain"
    TYPE_URL = "URL"
    TYPE_HASH = "Hash"
    TYPE_EMAIL = "Email"

    IOC_TYPE_CHOICES = [
        (TYPE_IPV4, "IPv4"),
        (TYPE_IPV6, "IPv6"),
        (TYPE_DOMAIN, "Domain"),
        (TYPE_URL, "URL"),
        (TYPE_HASH, "Hash"),
        (TYPE_EMAIL, "Email"),
        ]


    SEVERITY_LOW = "Low"
    SEVERITY_MEDIUM = "Medium"
    SEVERITY_HIGH = "High"
    SEVERITY_CRITICAL = "Critical"

    SEVERITY_CHOICES = [
        (SEVERITY_LOW, "Low"),
        (SEVERITY_MEDIUM, "Medium"),
        (SEVERITY_HIGH, "High"),
        (SEVERITY_CRITICAL, "Critical"),
    ]

    STATUS_ACTIVE = "Active"
    STATUS_FALSE_POSITIVE = "FalsePositive"
    STATUS_REVOKED = "Revoked"

    STATUS_CHOICES = [
        (STATUS_ACTIVE, "Active"),
        (STATUS_FALSE_POSITIVE, "False Positive"),
        (STATUS_REVOKED, "Revoked"),
    ]

    value = models.TextField()

    normalized_value = models.TextField(
        unique=True,
        db_index=True,
    )

    ioc_type = models.CharField(
        max_length=50,
        choices=IOC_TYPE_CHOICES,
        db_index=True,
    )

    first_seen = models.DateTimeField(auto_now_add=True)
    last_seen = models.DateTimeField(auto_now=True)

    severity = models.CharField(
        max_length=50,
        choices=SEVERITY_CHOICES,
        default=SEVERITY_LOW,
        db_index=True,
    )

    risk_score = models.IntegerField(
        default=0,
        validators=[
            MinValueValidator(0),
            MaxValueValidator(100),
        ],
        db_index=True,
    )

    status = models.CharField(
        max_length=50,
        choices=STATUS_CHOICES,
        default=STATUS_ACTIVE,
        db_index=True,
    )

    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        ordering = ["-last_seen"]
        indexes = [
            models.Index(fields=["ioc_type", "severity"]),
            models.Index(fields=["status", "risk_score"]),
        ]

    def __str__(self):
        return (
            f"{self.ioc_type}: "
            f"{self.normalized_value} "
            f"({self.severity})"
        )


class IOCSource(models.Model):
    ioc = models.ForeignKey(
        IOC,
        on_delete=models.CASCADE,
        related_name="sources",
    )

    feed = models.ForeignKey(
        Feed,
        on_delete=models.CASCADE,
        related_name="iocs",
    )

    first_seen = models.DateTimeField(auto_now_add=True)
    last_seen = models.DateTimeField(auto_now=True)

    occurrence_count = models.PositiveIntegerField(default=1)

    class Meta:
        constraints = [
            models.UniqueConstraint(
                fields=["ioc", "feed"],
                name="unique_ioc_feed_source",
            )
        ]

        ordering = ["-last_seen"]

    def __str__(self):
        return (
            f"{self.ioc.normalized_value} "
            f"in {self.feed.name}"
        )


class CorrelationResult(models.Model):
    ioc = models.OneToOneField(
        IOC,
        on_delete=models.CASCADE,
        related_name="correlation_result",
    )

    source_count = models.PositiveIntegerField(default=0)
    occurrence_count = models.PositiveIntegerField(default=0)

    risk_score = models.IntegerField(
        default=0,
        validators=[
            MinValueValidator(0),
            MaxValueValidator(100),
        ],
    )

    severity = models.CharField(
        max_length=50,
        choices=IOC.SEVERITY_CHOICES,
        default=IOC.SEVERITY_LOW,
    )

    reason = models.TextField(blank=True)

    correlated_at = models.DateTimeField(auto_now=True)

    class Meta:
        ordering = ["-correlated_at"]

    def __str__(self):
        return (
            f"Correlation for "
            f"{self.ioc.normalized_value}: "
            f"Sources={self.source_count}, "
            f"Score={self.risk_score}"
        )


class Blocklist(models.Model):
    TYPE_IP = "IP"
    TYPE_DOMAIN = "Domain"
    TYPE_URL = "URL"
    TYPE_HASH = "Hash"

    BLOCKLIST_TYPE_CHOICES = [
        (TYPE_IP, "IP"),
        (TYPE_DOMAIN, "Domain"),
        (TYPE_URL, "URL"),
        (TYPE_HASH, "Hash"),
    ]

    FORMAT_TXT = "TXT"
    FORMAT_CSV = "CSV"
    FORMAT_JSON = "JSON"

    FILE_FORMAT_CHOICES = [
        (FORMAT_TXT, "TXT"),
        (FORMAT_CSV, "CSV"),
        (FORMAT_JSON, "JSON"),
    ]

    name = models.CharField(max_length=255)

    blocklist_type = models.CharField(
        max_length=50,
        choices=BLOCKLIST_TYPE_CHOICES,
    )

    severity_filter = models.CharField(
        max_length=50,
        default="Low+",
    )

    generated_at = models.DateTimeField(auto_now_add=True)

    indicator_count = models.PositiveIntegerField(default=0)

    file_format = models.CharField(
        max_length=50,
        choices=FILE_FORMAT_CHOICES,
        default=FORMAT_TXT,
    )

    class Meta:
        ordering = ["-generated_at"]

    def __str__(self):
        return (
            f"Blocklist {self.name} "
            f"({self.blocklist_type} - {self.file_format})"
        )


class Vulnerability(models.Model):
    cve_id = models.CharField(
        max_length=30,
        unique=True,
        db_index=True,
    )

    vendor = models.CharField(
        max_length=255,
        blank=True,
    )

    product = models.CharField(
        max_length=255,
        blank=True,
    )

    name = models.CharField(
        max_length=500,
        blank=True,
    )

    description = models.TextField(blank=True)

    date_added = models.DateField(
        null=True,
        blank=True,
    )

    due_date = models.DateField(
        null=True,
        blank=True,
    )

    known_ransomware_use = models.CharField(
        max_length=50,
        blank=True,
    )

    source_url = models.URLField(blank=True)

    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        ordering = ["-date_added", "-created_at"]
        indexes = [
            models.Index(fields=["vendor", "product"]),
            models.Index(fields=["date_added"]),
        ]

    def __str__(self):
        return self.cve_id


class ActivityLog(models.Model):
    STATUS_SUCCESS = "Success"
    STATUS_ERROR = "Error"
    STATUS_WARNING = "Warning"
    STATUS_INFO = "Info"

    STATUS_CHOICES = [
        (STATUS_SUCCESS, "Success"),
        (STATUS_ERROR, "Error"),
        (STATUS_WARNING, "Warning"),
        (STATUS_INFO, "Info"),
    ]

    user = models.ForeignKey(
        User,
        null=True,
        blank=True,
        on_delete=models.SET_NULL,
        related_name="activity_logs",
    )

    action = models.CharField(max_length=100)
    module = models.CharField(max_length=100)

    status = models.CharField(
        max_length=50,
        choices=STATUS_CHOICES,
    )

    description = models.TextField()

    timestamp = models.DateTimeField(
        auto_now_add=True,
        db_index=True,
    )

    class Meta:
        ordering = ["-timestamp"]

    def __str__(self):
        return (
            f"[{self.timestamp.strftime('%Y-%m-%d %H:%M:%S')}] "
            f"{self.action} - {self.status}"
        )