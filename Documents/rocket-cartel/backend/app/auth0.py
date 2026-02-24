"""
Auth0 integration service.
Handles Management API calls (user provisioning), JWKS key fetching,
JWT token validation, and OAuth authorization code exchange.
"""
import os
import time
import logging
from typing import Optional
from datetime import datetime

import httpx
from jose import jwt, JWTError

logger = logging.getLogger(__name__)

# Configuration from environment
AUTH0_DOMAIN = os.getenv("AUTH0_DOMAIN", "")
AUTH0_CLIENT_ID = os.getenv("AUTH0_CLIENT_ID", "")
AUTH0_CLIENT_SECRET = os.getenv("AUTH0_CLIENT_SECRET", "")
AUTH0_AUDIENCE = os.getenv("AUTH0_AUDIENCE", "")
AUTH0_CALLBACK_URL = os.getenv("AUTH0_CALLBACK_URL", "")
AUTH0_MGMT_CLIENT_ID = os.getenv("AUTH0_MGMT_CLIENT_ID", "")
AUTH0_MGMT_CLIENT_SECRET = os.getenv("AUTH0_MGMT_CLIENT_SECRET", "")

# Module-level caches
_jwks_cache: dict = {"keys": [], "fetched_at": 0}
_mgmt_token_cache: dict = {"token": "", "expires_at": 0}

JWKS_CACHE_TTL = 3600  # 1 hour


class Auth0Service:
    """Stateless service for all Auth0 operations."""

    @staticmethod
    def _get_mgmt_token() -> str:
        """
        Obtain a Management API access token via client_credentials grant.
        Token is cached until 60 seconds before expiry.
        """
        now = time.time()
        if _mgmt_token_cache["token"] and _mgmt_token_cache["expires_at"] > now + 60:
            return _mgmt_token_cache["token"]

        url = f"https://{AUTH0_DOMAIN}/oauth/token"
        payload = {
            "grant_type": "client_credentials",
            "client_id": AUTH0_MGMT_CLIENT_ID,
            "client_secret": AUTH0_MGMT_CLIENT_SECRET,
            "audience": f"https://{AUTH0_DOMAIN}/api/v2/",
        }

        with httpx.Client() as client:
            resp = client.post(url, json=payload)
            resp.raise_for_status()
            data = resp.json()

        _mgmt_token_cache["token"] = data["access_token"]
        _mgmt_token_cache["expires_at"] = now + data.get("expires_in", 86400)
        return _mgmt_token_cache["token"]

    @staticmethod
    def create_or_update_user(
        email: str,
        patreon_tier: str,
        expires_at: Optional[datetime] = None,
    ) -> str:
        """
        Create or update an Auth0 user via the Management API.
        Uses email as the unique lookup key.

        Returns the Auth0 user_id (sub), e.g. 'auth0|abc123'.
        """
        token = Auth0Service._get_mgmt_token()
        headers = {"Authorization": f"Bearer {token}"}
        base_url = f"https://{AUTH0_DOMAIN}/api/v2"

        app_metadata = {
            "patreon_subscriber_tier": patreon_tier,
            "subscription_expires_at": expires_at.isoformat() if expires_at else None,
        }

        with httpx.Client() as client:
            # Search for existing user by email
            search_resp = client.get(
                f"{base_url}/users-by-email",
                params={"email": email},
                headers=headers,
            )
            search_resp.raise_for_status()
            users = search_resp.json()

            if users:
                user_id = users[0]["user_id"]
                update_resp = client.patch(
                    f"{base_url}/users/{user_id}",
                    json={"app_metadata": app_metadata},
                    headers=headers,
                )
                update_resp.raise_for_status()
                logger.info(f"Updated Auth0 user {user_id} for {email}")
                return user_id
            else:
                create_resp = client.post(
                    f"{base_url}/users",
                    json={
                        "email": email,
                        "connection": "email",
                        "email_verified": True,
                        "app_metadata": app_metadata,
                    },
                    headers=headers,
                )
                create_resp.raise_for_status()
                user_id = create_resp.json()["user_id"]
                logger.info(f"Created Auth0 user {user_id} for {email}")
                return user_id

    @staticmethod
    def get_jwks() -> list:
        """Fetch and cache Auth0 JWKS public keys (1hr TTL)."""
        now = time.time()
        if _jwks_cache["keys"] and (_jwks_cache["fetched_at"] + JWKS_CACHE_TTL) > now:
            return _jwks_cache["keys"]

        url = f"https://{AUTH0_DOMAIN}/.well-known/jwks.json"
        with httpx.Client() as client:
            resp = client.get(url)
            resp.raise_for_status()
            data = resp.json()

        _jwks_cache["keys"] = data.get("keys", [])
        _jwks_cache["fetched_at"] = now
        logger.info("JWKS cache refreshed")
        return _jwks_cache["keys"]

    @staticmethod
    def validate_token(token: str) -> dict:
        """
        Validate a JWT using Auth0's JWKS public keys.

        Returns the decoded payload on success.
        Raises ValueError if the token is invalid, expired, or unverifiable.
        """
        try:
            unverified_header = jwt.get_unverified_header(token)
        except JWTError:
            raise ValueError("Unable to parse token header")

        kid = unverified_header.get("kid")
        if not kid:
            raise ValueError("Token header missing 'kid'")

        jwks = Auth0Service.get_jwks()
        rsa_key = None
        for key in jwks:
            if key["kid"] == kid:
                rsa_key = {
                    "kty": key["kty"],
                    "kid": key["kid"],
                    "use": key["use"],
                    "n": key["n"],
                    "e": key["e"],
                }
                break

        if not rsa_key:
            raise ValueError(f"No matching key found for kid={kid}")

        payload = jwt.decode(
            token,
            rsa_key,
            algorithms=["RS256"],
            audience=AUTH0_AUDIENCE,
            issuer=f"https://{AUTH0_DOMAIN}/",
        )
        return payload

    @staticmethod
    def exchange_code_for_tokens(code: str) -> dict:
        """
        Exchange an OAuth authorization code for tokens.
        Returns dict with access_token, id_token, token_type, expires_in.
        """
        url = f"https://{AUTH0_DOMAIN}/oauth/token"
        payload = {
            "grant_type": "authorization_code",
            "client_id": AUTH0_CLIENT_ID,
            "client_secret": AUTH0_CLIENT_SECRET,
            "code": code,
            "redirect_uri": AUTH0_CALLBACK_URL,
        }

        with httpx.Client() as client:
            resp = client.post(url, json=payload)
            resp.raise_for_status()
            return resp.json()

    @staticmethod
    def get_login_url(state: str) -> str:
        """Build the Auth0 /authorize URL for user login redirect."""
        return (
            f"https://{AUTH0_DOMAIN}/authorize"
            f"?response_type=code"
            f"&client_id={AUTH0_CLIENT_ID}"
            f"&redirect_uri={AUTH0_CALLBACK_URL}"
            f"&audience={AUTH0_AUDIENCE}"
            f"&scope=openid profile email"
            f"&state={state}"
        )
