import ipaddress
import socket
from urllib.parse import urlparse

import requests


USER_AGENT = (
    "ThreatShield-Intelligence-Aggregator/1.0 "
    "(defensive-threat-intelligence)"
)


def _is_public_hostname(hostname):
    """
    Reject localhost/private/reserved/link-local destinations.
    """

    if not hostname:
        return False

    hostname = hostname.strip().lower()

    blocked_names = {
        "localhost",
        "localhost.localdomain",
    }

    if hostname in blocked_names:
        return False

    try:
        ip = ipaddress.ip_address(hostname)

        return not (
            ip.is_private
            or ip.is_loopback
            or ip.is_link_local
            or ip.is_reserved
            or ip.is_multicast
            or ip.is_unspecified
        )

    except ValueError:
        pass

    try:
        addresses = socket.getaddrinfo(
            hostname,
            None,
            type=socket.SOCK_STREAM
        )

        for address in addresses:
            resolved_ip = address[4][0]

            try:
                ip = ipaddress.ip_address(resolved_ip)

                if (
                    ip.is_private
                    or ip.is_loopback
                    or ip.is_link_local
                    or ip.is_reserved
                    or ip.is_multicast
                    or ip.is_unspecified
                ):
                    return False

            except ValueError:
                return False

    except socket.gaierror:
        return False

    return True


def validate_remote_feed_url(url):
    parsed = urlparse(url)

    if parsed.scheme.lower() not in {"http", "https"}:
        raise ValueError(
            "Only HTTP and HTTPS feed URLs are supported."
        )

    if not parsed.hostname:
        raise ValueError("Feed URL must contain a valid hostname.")

    if not _is_public_hostname(parsed.hostname):
        raise ValueError(
            "Private, localhost or reserved network destinations are not allowed."
        )

    return True


def fetch_remote_feed(url, timeout=30):
    """
    Fetch remote threat-intelligence feed safely.
    """

    validate_remote_feed_url(url)

    headers = {
        "User-Agent": USER_AGENT,
        "Accept": "*/*",
    }

    try:
        response = requests.get(
            url,
            headers=headers,
            timeout=(10, timeout),
            allow_redirects=False,
        )

        if response.status_code in {301, 302, 303, 307, 308}:
            raise ValueError(
                "Redirected feed URLs are disabled for security. "
                "Use the final HTTPS feed URL directly."
            )

        response.raise_for_status()

        content_length = response.headers.get("Content-Length")

        if content_length:
            if int(content_length) > 25 * 1024 * 1024:
                raise ValueError(
                    "Remote feed is larger than the 25 MB safety limit."
                )

        if not response.content:
            raise ValueError("Remote feed returned an empty response.")

        if len(response.content) > 25 * 1024 * 1024:
            raise ValueError(
                "Remote feed exceeded the 25 MB safety limit."
            )

        return response.content.decode(
            response.encoding or "utf-8",
            errors="replace"
        )

    except requests.exceptions.Timeout as exc:
        raise RuntimeError(
            f"Connection timeout while fetching feed: {exc}"
        ) from exc

    except requests.exceptions.HTTPError as exc:
        raise RuntimeError(
            f"HTTP {response.status_code} while fetching feed."
        ) from exc

    except requests.exceptions.RequestException as exc:
        raise RuntimeError(
            f"Network error while contacting feed: {exc}"
        ) from exc