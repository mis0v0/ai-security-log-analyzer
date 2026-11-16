from datetime import datetime, timezone
from ipaddress import ip_address


def normalize_to_utc(timestamp):
    if timestamp.tzinfo is None:
        raise ValueError(
            "Timestamp must be timezone-aware"
        )

    return timestamp.astimezone(timezone.utc)


def normalize_source_ip(value):
    """Canonical spelling of an observed literal, never an actor/host lookup.

    Admission is unchanged. Preserve absent/invalid values and scoped addresses
    whose zone semantics require source context; do not merge address families.
    """
    if type(value) is not str:
        return value
    try:
        address = ip_address(value)
    except ValueError:
        return value
    if getattr(address, "scope_id", None) is not None:
        return value
    return str(address)
