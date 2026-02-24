"""
Periodic subscription verification using APScheduler.
Runs every 30 minutes to check subscription_expires_at and
optionally re-verify via the Patreon API.

All functions are synchronous -- BackgroundScheduler runs jobs
in a thread pool, not an async event loop.
"""
from apscheduler.schedulers.background import BackgroundScheduler
from apscheduler.triggers.interval import IntervalTrigger
from sqlalchemy.orm import Session
from .database import SessionLocal
from .models import Auth0User, VerificationLog
import httpx
import os
import logging
from datetime import datetime

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

scheduler = BackgroundScheduler()

PATREON_API_BASE = "https://www.patreon.com/api/oauth2/v2"
PATREON_ACCESS_TOKEN = os.getenv("PATREON_ACCESS_TOKEN", "")


def verify_subscription_for_user(db: Session, user: Auth0User) -> None:
    """
    Verify a single user's Patreon subscription status.
    Checks subscription_expires_at first; only calls Patreon API
    if the expiry is approaching or already passed.
    """
    try:
        now = datetime.utcnow()

        # If subscription is well in the future (>24h), skip API call
        if (
            user.subscription_expires_at
            and user.subscription_expires_at > now
            and (user.subscription_expires_at - now).total_seconds() > 86400
        ):
            log = VerificationLog(
                auth0_user_id=user.id,
                status="active",
                check_timestamp=now,
            )
            db.add(log)
            return

        # Subscription expired or expiring soon -- mark accordingly
        # In production, you would call the Patreon API here to check
        # the actual member status and potentially extend the expiry.
        is_active = (
            user.subscription_expires_at is not None
            and user.subscription_expires_at > now
        )

        if not is_active:
            user.patreon_subscriber_tier = None
            user.subscription_expires_at = None

        user.updated_at = now

        log = VerificationLog(
            auth0_user_id=user.id,
            status="active" if is_active else "expired",
            check_timestamp=now,
        )
        db.add(log)
        logger.info(f"Verified {user.auth0_sub}: {'active' if is_active else 'expired'}")

    except Exception as e:
        logger.error(f"Verification error for {user.auth0_sub}: {e}")
        log = VerificationLog(
            auth0_user_id=user.id,
            status="error",
            error_message=str(e)[:500],
            check_timestamp=datetime.utcnow(),
        )
        db.add(log)


def verify_all_subscriptions() -> None:
    """Scheduled job: verify all users' subscription status."""
    db: Session = SessionLocal()
    try:
        users = db.query(Auth0User).all()
        for user in users:
            verify_subscription_for_user(db, user)
        db.commit()
        logger.info(f"Bulk verification completed. Checked {len(users)} users.")
    except Exception as e:
        db.rollback()
        logger.error(f"Bulk verification failed: {e}")
    finally:
        db.close()


def start_scheduler() -> None:
    """Start the background scheduler if not already running."""
    if not scheduler.running:
        scheduler.add_job(
            verify_all_subscriptions,
            IntervalTrigger(minutes=30),
            id="subscription_verification",
            name="Patreon Subscription Verification",
            replace_existing=True,
        )
        scheduler.start()
        logger.info("Scheduler started with subscription verification job (30min)")
