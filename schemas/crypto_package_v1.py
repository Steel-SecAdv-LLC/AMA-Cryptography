#!/usr/bin/env python3
# Copyright 2025-2026 Steel Security Advisors LLC
# Licensed under the Apache License, Version 2.0

"""
AMA Cryptography - CryptoPackage Schema v1
=============================================

Formal versioned schema for CryptoPackage serialization.
Replaces ad-hoc JSON with a structured, version-tagged format.

Supports JSON serialization with a schema_version field for forward compatibility.
CBOR support can be added by installing the 'cbor2' package.

Organization: Steel Security Advisors LLC
Author/Inventor: Andrew E. A.
"""

import hashlib
import json
import time
from dataclasses import asdict, dataclass, field
from typing import Any, Dict, List, Optional


SCHEMA_VERSION = "1.0"


@dataclass
class CryptoPackageSchemaV1:
    """
    Versioned schema for CryptoPackage.

    Fields:
        schema_version: Schema version string (always "1.0" for this version)
        package_id: Unique package identifier
        content_hash: SHA3-256 hash of the canonical content
        hmac: HMAC-SHA3-256 of the content
        classical_signature: Ed25519 signature (base64)
        pqc_signature: ML-DSA-65 signature (base64)
        timestamp: RFC 3161 timestamp (optional)
        algorithm: Signing algorithm identifier
        signer_id: Signer identifier
        created_at: Creation timestamp (Unix epoch)
        metadata: Additional package metadata
        codes: List of Omni-Code identifiers included
    """

    schema_version: str = SCHEMA_VERSION
    package_id: str = ""
    content_hash: str = ""
    hmac: str = ""
    classical_signature: str = ""
    pqc_signature: str = ""
    timestamp: Optional[str] = None
    algorithm: str = ""
    signer_id: str = ""
    created_at: float = field(default_factory=time.time)
    metadata: Dict[str, Any] = field(default_factory=dict)
    codes: List[str] = field(default_factory=list)

    def to_json(self) -> str:
        """Serialize to JSON string."""
        return json.dumps(asdict(self), indent=2, sort_keys=True)

    @classmethod
    def from_json(cls, data: str) -> "CryptoPackageSchemaV1":
        """Deserialize from JSON string."""
        d = json.loads(data)
        version = d.get("schema_version", "")
        if version != SCHEMA_VERSION:
            raise ValueError(
                f"Unsupported schema version: {version}. Expected {SCHEMA_VERSION}"
            )
        return cls(**{k: v for k, v in d.items() if k in cls.__dataclass_fields__})

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary."""
        return asdict(self)

    @classmethod
    def from_dict(cls, d: Dict[str, Any]) -> "CryptoPackageSchemaV1":
        """Create from dictionary."""
        return cls(**{k: v for k, v in d.items() if k in cls.__dataclass_fields__})

    def compute_integrity_hash(self) -> str:
        """Compute SHA3-256 over canonical serialization for integrity checking."""
        canonical = json.dumps(
            {k: v for k, v in sorted(asdict(self).items()) if k != "schema_version"},
            sort_keys=True,
            separators=(",", ":"),
        )
        return hashlib.sha3_256(canonical.encode("utf-8")).hexdigest()
