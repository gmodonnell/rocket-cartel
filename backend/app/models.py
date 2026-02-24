"""
Database models for the Auth0-based whitelist system.
Auth0User stores identity + Patreon subscription data.
UsernameMapping links Auth0 users to Minecraft usernames.
VerificationLog tracks periodic subscription checks.
"""
from sqlalchemy import Column, String, Boolean, DateTime, Integer, ForeignKey
from sqlalchemy.orm import declarative_base, relationship
from datetime import datetime

Base = declarative_base()


class Auth0User(Base):
    """
    Auth0-authenticated user with Patreon subscription metadata.
    auth0_sub is the unique identifier from Auth0 (e.g. 'auth0|abc123').
    """
    __tablename__ = "auth0_users"

    id = Column(Integer, primary_key=True, index=True)
    auth0_sub = Column(String(255), unique=True, nullable=False, index=True)
    email = Column(String(255), nullable=False, index=True)
    patreon_subscriber_tier = Column(String(50), nullable=True)
    subscription_expires_at = Column(DateTime, nullable=True)
    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

    username_mapping = relationship(
        "UsernameMapping", back_populates="auth0_user", uselist=False,
        cascade="all, delete-orphan"
    )
    verification_logs = relationship(
        "VerificationLog", back_populates="auth0_user", cascade="all, delete-orphan"
    )


class UsernameMapping(Base):
    """
    Maps an Auth0 user to their Minecraft username.
    One-to-one with Auth0User.
    """
    __tablename__ = "username_mappings"

    id = Column(Integer, primary_key=True, index=True)
    auth0_user_id = Column(
        Integer, ForeignKey("auth0_users.id"), unique=True, nullable=False
    )
    minecraft_username = Column(String(16), unique=True, nullable=False, index=True)
    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

    auth0_user = relationship("Auth0User", back_populates="username_mapping")


class VerificationLog(Base):
    """Logs periodic Patreon subscription verification checks."""
    __tablename__ = "verification_logs"

    id = Column(Integer, primary_key=True, index=True)
    auth0_user_id = Column(Integer, ForeignKey("auth0_users.id"), nullable=False)
    check_timestamp = Column(DateTime, default=datetime.utcnow)
    status = Column(String(50))  # 'active', 'expired', 'error'
    error_message = Column(String(500), nullable=True)

    auth0_user = relationship("Auth0User", back_populates="verification_logs")
