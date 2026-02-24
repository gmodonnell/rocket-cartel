"""
FastAPI application for Auth0-based Minecraft whitelist system.

Endpoints:
    GET  /health                - Health check
    POST /api/patreon-webhook   - Patreon subscription event handler
    GET  /api/auth-callback     - Auth0 OAuth callback (code exchange)
    GET  /api/login-url         - Get Auth0 login redirect URL
    POST /api/map-username      - Map Minecraft username (JWT-protected)
    GET  /api/whitelist         - Active subscription whitelist
    GET  /api/me                - Current user info (JWT-protected)
"""
import os
import uuid
import logging
from datetime import datetime, timedelta
from typing import Optional

from fastapi import FastAPI, Depends, HTTPException, status
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import RedirectResponse
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from sqlalchemy.orm import Session
from pydantic import BaseModel, Field

from app.database import get_db, init_db
from app.models import Auth0User, UsernameMapping
from app.auth0 import Auth0Service, AUTH0_DOMAIN, AUTH0_CLIENT_ID, AUTH0_CALLBACK_URL
from app.scheduler import start_scheduler

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

app = FastAPI(title="Whitelist API", version="2.0.0")

# CORS -- restricted to frontend origin
app.add_middleware(
    CORSMiddleware,
    allow_origins=[
        os.getenv("FRONTEND_URL", "http://localhost:8080"),
    ],
    allow_credentials=True,
    allow_methods=["GET", "POST"],
    allow_headers=["Authorization", "Content-Type"],
)

security = HTTPBearer()


# --- Pydantic Models ---

class PatreonWebhookPayload(BaseModel):
    """Payload from Patreon webhook on members:create or members:update."""
    patreon_email: str
    patreon_tier: str = "default"
    subscription_months: int = 1


class UsernameMapRequest(BaseModel):
    """Map a Minecraft username to the authenticated user."""
    minecraft_username: str = Field(
        ..., min_length=3, max_length=16, pattern=r"^[a-zA-Z0-9_]+$"
    )


class WhitelistEntry(BaseModel):
    minecraft_username: str


class UserInfoResponse(BaseModel):
    auth0_sub: str
    email: str
    minecraft_username: Optional[str] = None
    patreon_subscriber_tier: Optional[str] = None
    subscription_expires_at: Optional[datetime] = None


# --- Dependencies ---

def get_current_user_sub(
    credentials: HTTPAuthorizationCredentials = Depends(security),
) -> str:
    """
    Extract and validate the JWT from Authorization: Bearer <token>.
    Returns the Auth0 'sub' claim. Raises 401 if invalid.
    """
    try:
        payload = Auth0Service.validate_token(credentials.credentials)
        sub = payload.get("sub")
        if not sub:
            raise ValueError("Token missing 'sub' claim")
        return sub
    except ValueError as e:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail=str(e),
            headers={"WWW-Authenticate": "Bearer"},
        )


# --- Lifecycle ---

@app.on_event("startup")
async def startup_event():
    init_db()
    logger.info("Database initialized")
    start_scheduler()
    logger.info("Scheduler started")


# --- Endpoints ---

@app.get("/health")
async def health_check():
    return {"status": "healthy", "version": "2.0.0"}


@app.post("/api/patreon-webhook")
async def patreon_webhook(
    payload: PatreonWebhookPayload,
    db: Session = Depends(get_db),
):
    """
    Phase 1: Patreon webhook handler.
    Creates/updates Auth0 user and stores subscription metadata locally.

    TODO: Validate X-Patreon-Signature header in production.
    """
    try:
        expires_at = datetime.utcnow() + timedelta(days=30 * payload.subscription_months)

        # Create or update user in Auth0
        auth0_sub = Auth0Service.create_or_update_user(
            email=payload.patreon_email,
            patreon_tier=payload.patreon_tier,
            expires_at=expires_at,
        )

        # Upsert in local database
        existing = db.query(Auth0User).filter(
            Auth0User.auth0_sub == auth0_sub
        ).first()

        if existing:
            existing.email = payload.patreon_email
            existing.patreon_subscriber_tier = payload.patreon_tier
            existing.subscription_expires_at = expires_at
            existing.updated_at = datetime.utcnow()
            logger.info(f"Updated DB record for {auth0_sub}")
        else:
            new_user = Auth0User(
                auth0_sub=auth0_sub,
                email=payload.patreon_email,
                patreon_subscriber_tier=payload.patreon_tier,
                subscription_expires_at=expires_at,
            )
            db.add(new_user)
            logger.info(f"Created DB record for {auth0_sub}")

        db.commit()
        return {"status": "processed", "auth0_sub": auth0_sub}

    except Exception as e:
        db.rollback()
        logger.error(f"Patreon webhook error: {e}")
        raise HTTPException(status_code=500, detail="Webhook processing failed")


@app.get("/api/auth-callback")
async def auth_callback(
    code: str,
    state: str,
    db: Session = Depends(get_db),
):
    """
    Phase 2: Auth0 OAuth callback.
    Exchanges authorization code for tokens, ensures local DB record exists,
    then redirects to the SPA with the access token in a URL fragment.
    """
    try:
        token_data = Auth0Service.exchange_code_for_tokens(code)
        access_token = token_data["access_token"]

        # Validate token and extract user identity
        payload = Auth0Service.validate_token(access_token)
        auth0_sub = payload["sub"]

        # Ensure user exists in local DB
        existing = db.query(Auth0User).filter(
            Auth0User.auth0_sub == auth0_sub
        ).first()

        if not existing:
            email = payload.get("email", "")
            new_user = Auth0User(
                auth0_sub=auth0_sub,
                email=email,
            )
            db.add(new_user)
            db.commit()
            logger.info(f"Created DB record for {auth0_sub} from callback")

        # Redirect to frontend with token in fragment (never sent to server)
        frontend_url = os.getenv("FRONTEND_URL", "http://localhost:8080")
        return RedirectResponse(url=f"{frontend_url}/#token={access_token}")

    except Exception as e:
        logger.error(f"Auth callback error: {e}")
        raise HTTPException(status_code=400, detail="Authentication failed")


@app.get("/api/login-url")
async def get_login_url():
    """Returns the Auth0 authorization URL for the frontend to redirect to."""
    state = str(uuid.uuid4())
    url = Auth0Service.get_login_url(state=state)
    return {"login_url": url, "state": state}


@app.post("/api/map-username")
async def map_username(
    req: UsernameMapRequest,
    auth0_sub: str = Depends(get_current_user_sub),
    db: Session = Depends(get_db),
):
    """
    Phase 2 (cont): Map a Minecraft username to the authenticated user.
    JWT-protected. Users can update their username.
    """
    try:
        user = db.query(Auth0User).filter(
            Auth0User.auth0_sub == auth0_sub
        ).first()

        if not user:
            raise HTTPException(status_code=404, detail="User not found")

        # Check if username is taken by another user
        existing_mapping = db.query(UsernameMapping).filter(
            UsernameMapping.minecraft_username == req.minecraft_username
        ).first()

        if existing_mapping and existing_mapping.auth0_user_id != user.id:
            raise HTTPException(
                status_code=status.HTTP_409_CONFLICT,
                detail="Minecraft username already registered by another user",
            )

        if user.username_mapping:
            user.username_mapping.minecraft_username = req.minecraft_username
            user.username_mapping.updated_at = datetime.utcnow()
            logger.info(f"Updated username for {auth0_sub}: {req.minecraft_username}")
        else:
            mapping = UsernameMapping(
                auth0_user_id=user.id,
                minecraft_username=req.minecraft_username,
            )
            db.add(mapping)
            logger.info(f"Mapped username for {auth0_sub}: {req.minecraft_username}")

        db.commit()
        return {"status": "success", "minecraft_username": req.minecraft_username}

    except HTTPException:
        raise
    except Exception as e:
        db.rollback()
        logger.error(f"Username mapping error: {e}")
        raise HTTPException(status_code=500, detail="Username mapping failed")


@app.get("/api/whitelist")
async def get_whitelist(db: Session = Depends(get_db)):
    """
    Phase 3: Returns list of Minecraft usernames with active subscriptions.
    Called by the GTNH server to update its whitelist.
    """
    try:
        now = datetime.utcnow()
        active_mappings = (
            db.query(UsernameMapping)
            .join(Auth0User, UsernameMapping.auth0_user_id == Auth0User.id)
            .filter(
                Auth0User.subscription_expires_at.isnot(None),
                Auth0User.subscription_expires_at > now,
            )
            .all()
        )

        return [
            WhitelistEntry(minecraft_username=m.minecraft_username)
            for m in active_mappings
        ]

    except Exception as e:
        logger.error(f"Whitelist error: {e}")
        raise HTTPException(status_code=500, detail="Failed to fetch whitelist")


@app.get("/api/me")
async def get_current_user(
    auth0_sub: str = Depends(get_current_user_sub),
    db: Session = Depends(get_db),
):
    """
    Phase 4: Returns current user profile info.
    JWT-protected. Used by frontend to display user state.
    """
    user = db.query(Auth0User).filter(Auth0User.auth0_sub == auth0_sub).first()
    if not user:
        raise HTTPException(status_code=404, detail="User not found")

    return UserInfoResponse(
        auth0_sub=user.auth0_sub,
        email=user.email,
        minecraft_username=(
            user.username_mapping.minecraft_username
            if user.username_mapping else None
        ),
        patreon_subscriber_tier=user.patreon_subscriber_tier,
        subscription_expires_at=user.subscription_expires_at,
    )
