#!/usr/bin/env python3
# Copyright 2025-2026 Steel Security Advisors LLC
# Licensed under the Apache License, Version 2.0

"""
AMA Cryptography Flask Integration Example
=========================================

Demonstrates integrating AMA Cryptography cryptographic protection into a Flask
web application for secure API endpoints.

Features:
- Signed API responses with Ed25519/ML-DSA-65
- Request authentication via HMAC
- Protected data endpoints
- Key rotation support

Usage:
    pip install flask cryptography
    # Optional: build native C library for quantum-resistant signatures
    python flask_integration.py

Then visit:
    http://localhost:5000/api/health
    http://localhost:5000/api/sign
    http://localhost:5000/api/protected-data
"""

import json
import sys
from datetime import datetime
from functools import wraps
from pathlib import Path

# Add project root to path
sys.path.insert(0, str(Path(__file__).parent.parent.parent))

try:
    from flask import Flask, jsonify, request
except ImportError:
    print("Flask not installed. Run: pip install flask")
    print("This example demonstrates Flask integration patterns.")
    sys.exit(1)

from ama_cryptography.crypto_api import (  # noqa: E402
    AlgorithmType,
    AmaCryptography,
    get_pqc_capabilities,
)
from ama_cryptography.legacy_compat import (  # noqa: E402
    create_crypto_package,
    generate_key_management_system,
)

# Initialize Flask app
app = Flask(__name__)

# Initialize AMA Cryptography cryptographic system
# In production, load keys from secure storage (HSM, Vault, etc.)
KMS = generate_key_management_system("Flask API Server")
CRYPTO = AmaCryptography(algorithm=AlgorithmType.ED25519)
KEYPAIR = CRYPTO.generate_keypair()


def sign_response(f):
    """
    Decorator to sign API responses with Ed25519.

    Adds X-Signature header to responses for client verification.
    """

    @wraps(f)
    def decorated_function(*args, **kwargs):
        response = f(*args, **kwargs)

        # Get response data
        if hasattr(response, "get_json"):
            data = response.get_json()
        else:
            data = response

        # Sign the response
        message = json.dumps(data, sort_keys=True).encode()
        signature = CRYPTO.sign(message, KEYPAIR.secret_key)

        # Create Flask response with signature header
        resp = jsonify(data)
        resp.headers["X-Signature"] = signature.signature.hex()
        resp.headers["X-Public-Key"] = KEYPAIR.public_key.hex()
        resp.headers["X-Algorithm"] = "Ed25519"

        return resp

    return decorated_function


def require_hmac_auth(f):
    """
    Decorator to require HMAC authentication on requests.

    Expects X-HMAC-Signature header with HMAC of request body.
    """

    @wraps(f)
    def decorated_function(*args, **kwargs):
        from ama_cryptography.legacy_compat import hmac_authenticate
        from ama_cryptography.secure_memory import constant_time_compare

        # Get signature from header
        provided_sig = request.headers.get("X-HMAC-Signature")
        if not provided_sig:
            return jsonify({"error": "Missing X-HMAC-Signature header"}), 401

        # Calculate expected signature (INVARIANT-1: no stdlib hmac)
        body = request.get_data()
        expected_sig = hmac_authenticate(body, KMS.hmac_key).hex()

        # Constant-time comparison
        if not constant_time_compare(provided_sig.encode(), expected_sig.encode()):
            return jsonify({"error": "Invalid HMAC signature"}), 401

        return f(*args, **kwargs)

    return decorated_function


@app.route("/api/health")
@sign_response
def health_check():
    """Health check endpoint with signed response."""
    capabilities = get_pqc_capabilities()

    return {
        "status": "healthy",
        "service": "AMA Cryptography Flask API",
        "timestamp": datetime.utcnow().isoformat(),
        "pqc_available": capabilities.get("dilithium_available", False),
        "algorithms": (
            ["Ed25519", "ML-DSA-65"] if capabilities.get("dilithium_available") else ["Ed25519"]
        ),
    }


@app.route("/api/sign", methods=["POST"])
@sign_response
def sign_data():
    """
    Sign arbitrary data with AMA Cryptography.

    Request body:
        {"data": "your data to sign"}

    Response:
        {"signature": "...", "public_key": "...", "algorithm": "..."}
    """
    data = request.get_json()
    if not data or "data" not in data:
        return jsonify({"error": 'Missing "data" field'}), 400

    message = data["data"].encode() if isinstance(data["data"], str) else data["data"]

    # Sign with Ed25519
    signature = CRYPTO.sign(message, KEYPAIR.secret_key)

    return {
        "signature": signature.signature.hex(),
        "public_key": KEYPAIR.public_key.hex(),
        "algorithm": "Ed25519",
        "message_hash": signature.message_hash.hex(),
    }


@app.route("/api/verify", methods=["POST"])
def verify_signature():
    """
    Verify a signature.

    Request body:
        {
            "data": "original data",
            "signature": "hex signature",
            "public_key": "hex public key"
        }
    """
    data = request.get_json()
    required = ["data", "signature", "public_key"]

    if not all(k in data for k in required):
        return jsonify({"error": f"Missing required fields: {required}"}), 400

    try:
        message = data["data"].encode() if isinstance(data["data"], str) else data["data"]
        signature = bytes.fromhex(data["signature"])
        public_key = bytes.fromhex(data["public_key"])

        is_valid = CRYPTO.verify(message, signature, public_key)

        return jsonify(
            {
                "valid": is_valid,
                "algorithm": "Ed25519",
            }
        )
    except Exception:
        return jsonify({"error": "Verification failed", "valid": False}), 400


@app.route("/api/protected-data", methods=["GET"])
@sign_response
def get_protected_data():
    """
    Get cryptographically protected data package.

    Returns a complete AMA Cryptography crypto package with:
    - Content hash (SHA3-256)
    - HMAC authentication
    - Ed25519 signature
    - Optional ML-DSA-65 quantum signature
    """
    # Sample protected data
    sensitive_data = {
        "patient_id": "ANON-12345",
        "record_type": "medical",
        "classification": "confidential",
        "created_at": datetime.utcnow().isoformat(),
    }

    data_str = json.dumps(sensitive_data, sort_keys=True)
    helix_params = [(1.0, 2.0)]

    # Create protected package
    package = create_crypto_package(
        dna_codes=data_str,
        helix_params=helix_params,
        kms=KMS,
        author="Flask API",
        use_rfc3161=False,
    )

    return {
        "data": sensitive_data,
        "protection": {
            "content_hash": package.content_hash,
            "hmac_tag": package.hmac_tag,
            "ed25519_signature": package.ed25519_signature,
            "ed25519_pubkey": package.ed25519_pubkey,
            "timestamp": package.timestamp,
            "version": package.version,
        },
    }


@app.route("/api/protected-data", methods=["POST"])
@require_hmac_auth
@sign_response
def create_protected_data():
    """
    Create a new protected data package.

    Requires HMAC authentication.

    Request body:
        {"data": {...your data...}}
    """
    data = request.get_json()
    if not data or "data" not in data:
        return jsonify({"error": 'Missing "data" field'}), 400

    data_str = json.dumps(data["data"], sort_keys=True)
    helix_params = [(1.0, 2.0)]

    package = create_crypto_package(
        dna_codes=data_str,
        helix_params=helix_params,
        kms=KMS,
        author="Flask API Client",
        use_rfc3161=False,
    )

    return {
        "status": "created",
        "content_hash": package.content_hash,
        "timestamp": package.timestamp,
    }


@app.route("/api/keys/public")
def get_public_keys():
    """Get server's public keys for client-side verification."""
    return jsonify(
        {
            "ed25519_public_key": KEYPAIR.public_key.hex(),
            "algorithm": "Ed25519",
            "key_id": "flask-api-server-v1",
        }
    )


@app.errorhandler(500)
def handle_error(error):
    """Handle internal errors securely."""
    return (
        jsonify(
            {
                "error": "Internal server error",
                "message": "An error occurred processing your request",
            }
        ),
        500,
    )


def main():
    """Run the Flask development server."""
    print("=" * 60)
    print("AMA CRYPTOGRAPHY - FLASK INTEGRATION EXAMPLE")
    print("=" * 60)
    print()
    print("Starting Flask server with AMA Cryptography cryptographic protection...")
    print()
    print("Available endpoints:")
    print("  GET  /api/health          - Health check (signed)")
    print("  POST /api/sign            - Sign data")
    print("  POST /api/verify          - Verify signature")
    print("  GET  /api/protected-data  - Get protected data package")
    print("  POST /api/protected-data  - Create protected data (HMAC auth)")
    print("  GET  /api/keys/public     - Get public keys")
    print()
    print("Server public key:", KEYPAIR.public_key.hex()[:32] + "...")
    print()

    # Run development server
    app.run(host="127.0.0.1", port=5000, debug=False)


if __name__ == "__main__":
    main()
