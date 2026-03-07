#!/usr/bin/env python3
# Copyright 2025-2026 Steel Security Advisors LLC
# Licensed under the Apache License, Version 2.0

"""
AMA Cryptography FastAPI Integration Example
==========================================

Demonstrates integrating AMA Cryptography cryptographic protection into a FastAPI
application with async support for high-performance APIs.

Features:
- Async cryptographic operations
- Signed API responses with Ed25519/ML-DSA-65
- Request authentication via HMAC
- Protected data endpoints with Pydantic models
- OpenAPI documentation integration
- Key rotation support

Usage:
    pip install fastapi uvicorn cryptography
    # Optional: build native C library for quantum-resistant signatures
    python fastapi_integration.py

Then visit:
    http://localhost:8000/docs - Interactive API documentation
    http://localhost:8000/api/health
    http://localhost:8000/api/sign
"""

import asyncio
import hashlib
import hmac
import json
import sys
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, Optional

# Add project root to path
sys.path.insert(0, str(Path(__file__).parent.parent.parent))

try:
    from fastapi import Depends, FastAPI, Header, HTTPException, Request
    from fastapi.middleware.cors import CORSMiddleware
    from fastapi.responses import JSONResponse
    from pydantic import BaseModel, Field
except ImportError:
    print("FastAPI not installed. Run: pip install fastapi uvicorn")
    print("This example demonstrates FastAPI integration patterns.")
    sys.exit(1)

from ama_cryptography.crypto_api import (  # noqa: E402
    AlgorithmType,
    AmaCryptography,
    get_pqc_capabilities,
)
from code_guardian_secure import (  # noqa: E402
    create_crypto_package,
    generate_key_management_system,
)


# Pydantic models for request/response validation
class SignRequest(BaseModel):
    """Request model for signing data."""

    data: str = Field(..., description="Data to sign")
    algorithm: str = Field(default="Ed25519", description="Signing algorithm")


class SignResponse(BaseModel):
    """Response model for signed data."""

    signature: str = Field(..., description="Hex-encoded signature")
    public_key: str = Field(..., description="Hex-encoded public key")
    algorithm: str = Field(..., description="Algorithm used")
    message_hash: str = Field(..., description="SHA3-256 hash of message")


class VerifyRequest(BaseModel):
    """Request model for signature verification."""

    data: str = Field(..., description="Original data")
    signature: str = Field(..., description="Hex-encoded signature")
    public_key: str = Field(..., description="Hex-encoded public key")


class VerifyResponse(BaseModel):
    """Response model for verification result."""

    valid: bool = Field(..., description="Whether signature is valid")
    algorithm: str = Field(..., description="Algorithm used")


class ProtectedDataRequest(BaseModel):
    """Request model for creating protected data."""

    data: Dict[str, Any] = Field(..., description="Data to protect")
    author: str = Field(default="API Client", description="Author name")


class ProtectedDataResponse(BaseModel):
    """Response model for protected data package."""

    data: Dict[str, Any]
    protection: Dict[str, str]


class HealthResponse(BaseModel):
    """Response model for health check."""

    status: str
    service: str
    timestamp: str
    pqc_available: bool
    algorithms: list


# Initialize FastAPI app
app = FastAPI(
    title="AMA Cryptography API",
    description="Quantum-resistant cryptographic protection API",
    version="2.0",
    docs_url="/docs",
    redoc_url="/redoc",
)

# Add CORS middleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # Configure appropriately for production
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Initialize AMA Cryptography cryptographic system
# In production, load keys from secure storage (HSM, Vault, etc.)
KMS = generate_key_management_system("FastAPI Server")
CRYPTO = AmaCryptography(algorithm=AlgorithmType.ED25519)
KEYPAIR = CRYPTO.generate_keypair()


class SignedResponse(JSONResponse):
    """Custom response class that adds cryptographic signature headers."""

    def __init__(self, content: Any, **kwargs):
        super().__init__(content, **kwargs)

        # Sign the response content
        message = json.dumps(content, sort_keys=True).encode()
        signature = CRYPTO.sign(message, KEYPAIR.secret_key)

        # Add signature headers
        self.headers["X-Signature"] = signature.signature.hex()
        self.headers["X-Public-Key"] = KEYPAIR.public_key.hex()
        self.headers["X-Algorithm"] = "Ed25519"


async def verify_hmac_auth(
    request: Request,
    x_hmac_signature: Optional[str] = Header(None),
) -> bool:
    """Dependency to verify HMAC authentication."""
    if not x_hmac_signature:
        raise HTTPException(
            status_code=401,
            detail="Missing X-HMAC-Signature header",
        )

    body = await request.body()
    expected_sig = hmac.new(
        KMS.hmac_key,
        body,
        hashlib.sha3_256,
    ).hexdigest()

    if not hmac.compare_digest(x_hmac_signature, expected_sig):
        raise HTTPException(
            status_code=401,
            detail="Invalid HMAC signature",
        )

    return True


@app.get("/api/health", response_model=HealthResponse, tags=["Health"])
async def health_check():
    """
    Health check endpoint with cryptographic capabilities.

    Returns server status and available cryptographic algorithms.
    Response is signed with Ed25519.
    """
    capabilities = get_pqc_capabilities()

    response_data = {
        "status": "healthy",
        "service": "AMA Cryptography FastAPI",
        "timestamp": datetime.utcnow().isoformat(),
        "pqc_available": capabilities.get("dilithium_available", False),
        "algorithms": (
            ["Ed25519", "ML-DSA-65"] if capabilities.get("dilithium_available") else ["Ed25519"]
        ),
    }

    return SignedResponse(response_data)


@app.post("/api/sign", response_model=SignResponse, tags=["Cryptography"])
async def sign_data(request: SignRequest):
    """
    Sign data with AMA Cryptography cryptographic system.

    Supports Ed25519 (classical) and ML-DSA-65 (quantum-resistant).
    """
    message = request.data.encode()

    # Select algorithm
    if request.algorithm.upper() == "ML-DSA-65":
        capabilities = get_pqc_capabilities()
        if not capabilities.get("dilithium_available"):
            raise HTTPException(
                status_code=400,
                detail="ML-DSA-65 not available. Build native C library.",
            )
        crypto = AmaCryptography(algorithm=AlgorithmType.ML_DSA_65)
        keypair = crypto.generate_keypair()
    else:
        crypto = CRYPTO
        keypair = KEYPAIR

    # Sign the message
    signature = crypto.sign(message, keypair.secret_key)

    return SignedResponse(
        {
            "signature": signature.signature.hex(),
            "public_key": keypair.public_key.hex(),
            "algorithm": request.algorithm,
            "message_hash": signature.message_hash.hex(),
        }
    )


@app.post("/api/verify", response_model=VerifyResponse, tags=["Cryptography"])
async def verify_signature(request: VerifyRequest):
    """
    Verify a cryptographic signature.

    Returns whether the signature is valid for the given data and public key.
    """
    try:
        message = request.data.encode()
        signature = bytes.fromhex(request.signature)
        public_key = bytes.fromhex(request.public_key)

        is_valid = CRYPTO.verify(message, signature, public_key)

        return {"valid": is_valid, "algorithm": "Ed25519"}
    except Exception as e:
        raise HTTPException(status_code=400, detail=str(e))


@app.get("/api/protected-data", response_model=ProtectedDataResponse, tags=["Data Protection"])
async def get_protected_data():
    """
    Get a cryptographically protected data package.

    Returns sample data with complete AMA Cryptography protection:
    - SHA3-256 content hash
    - HMAC-SHA3-256 authentication
    - Ed25519 digital signature
    - Optional ML-DSA-65 quantum signature
    """
    sensitive_data = {
        "patient_id": "ANON-12345",
        "record_type": "medical",
        "classification": "confidential",
        "created_at": datetime.utcnow().isoformat(),
    }

    data_str = json.dumps(sensitive_data, sort_keys=True)
    helix_params = [(1.0, 2.0)]

    # Create protected package (run in thread pool for CPU-bound work)
    loop = asyncio.get_event_loop()
    package = await loop.run_in_executor(
        None,
        lambda: create_crypto_package(
            dna_codes=data_str,
            helix_params=helix_params,
            kms=KMS,
            author="FastAPI Server",
            use_rfc3161=False,
        ),
    )

    return SignedResponse(
        {
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
    )


@app.post(
    "/api/protected-data",
    response_model=Dict[str, Any],
    tags=["Data Protection"],
    dependencies=[Depends(verify_hmac_auth)],
)
async def create_protected_data(request: ProtectedDataRequest):
    """
    Create a new protected data package.

    Requires HMAC authentication via X-HMAC-Signature header.
    """
    data_str = json.dumps(request.data, sort_keys=True)
    helix_params = [(1.0, 2.0)]

    loop = asyncio.get_event_loop()
    package = await loop.run_in_executor(
        None,
        lambda: create_crypto_package(
            dna_codes=data_str,
            helix_params=helix_params,
            kms=KMS,
            author=request.author,
            use_rfc3161=False,
        ),
    )

    return SignedResponse(
        {
            "status": "created",
            "content_hash": package.content_hash,
            "timestamp": package.timestamp,
        }
    )


@app.get("/api/keys/public", tags=["Keys"])
async def get_public_keys():
    """Get server's public keys for client-side verification."""
    return {
        "ed25519_public_key": KEYPAIR.public_key.hex(),
        "algorithm": "Ed25519",
        "key_id": "fastapi-server-v1",
    }


@app.get("/api/capabilities", tags=["Info"])
async def get_capabilities():
    """Get detailed cryptographic capabilities."""
    caps = get_pqc_capabilities()

    return {
        "classical": {
            "ed25519": True,
            "hmac_sha3_256": True,
            "sha3_256": True,
        },
        "quantum_resistant": {
            "ml_dsa_65": caps.get("dilithium_available", False),
            "ml_kem_1024": caps.get("kyber_available", False),
            "slh_dsa": caps.get("sphincs_available", False),
        },
        "hybrid_modes": {
            "hybrid_signature": caps.get("dilithium_available", False),
            "hybrid_kem": caps.get("kyber_available", False),
        },
    }


@app.exception_handler(Exception)
async def global_exception_handler(request: Request, exc: Exception):
    """Handle all unhandled exceptions securely."""
    return JSONResponse(
        status_code=500,
        content={
            "error": "Internal server error",
            "message": "An error occurred processing your request",
        },
    )


def main():
    """Run the FastAPI server with uvicorn."""
    print("=" * 60)
    print("AMA CRYPTOGRAPHY - FASTAPI INTEGRATION EXAMPLE")
    print("=" * 60)
    print()
    print("Starting FastAPI server with AMA Cryptography cryptographic protection...")
    print()
    print("Available endpoints:")
    print("  GET  /api/health          - Health check (signed)")
    print("  POST /api/sign            - Sign data")
    print("  POST /api/verify          - Verify signature")
    print("  GET  /api/protected-data  - Get protected data package")
    print("  POST /api/protected-data  - Create protected data (HMAC auth)")
    print("  GET  /api/keys/public     - Get public keys")
    print("  GET  /api/capabilities    - Get crypto capabilities")
    print()
    print("Interactive docs: http://localhost:8000/docs")
    print()
    print("Server public key:", KEYPAIR.public_key.hex()[:32] + "...")
    print()

    try:
        import uvicorn

        uvicorn.run(app, host="127.0.0.1", port=8000)
    except ImportError:
        print("uvicorn not installed. Run: pip install uvicorn")
        print("Or run with: uvicorn fastapi_integration:app --reload")


if __name__ == "__main__":
    main()
