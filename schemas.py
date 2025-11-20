"""
Database Schemas for Discord-based Musical Events Booking System

Each Pydantic model corresponds to a MongoDB collection (lowercased name).
"""
from __future__ import annotations
from pydantic import BaseModel, Field, EmailStr, HttpUrl
from typing import Optional, List, Literal
from datetime import datetime

# ============== AUTH & USERS ==================
class Profile(BaseModel):
    display_name: Optional[str] = None
    avatar_url: Optional[HttpUrl] = None
    bio: Optional[str] = None
    links: List[HttpUrl] = []

class User(BaseModel):
    email: EmailStr
    password_hash: Optional[str] = Field(None, description="Hashed password (bcrypt)")
    oauth_provider: Optional[str] = None
    oauth_id: Optional[str] = None
    profile: Profile = Field(default_factory=Profile)
    role: Literal["user", "artist", "host", "pending"] = "pending"
    verified: bool = False
    is_admin: bool = False
    status: Literal["active", "suspended"] = "active"

class VerificationRequest(BaseModel):
    user_id: str
    role: Literal["artist", "host"]
    demo_video_url: HttpUrl
    description: Optional[str] = None
    links: List[HttpUrl] = []
    status: Literal["pending", "approved", "rejected"] = "pending"
    reviewed_by: Optional[str] = None
    reviewed_at: Optional[datetime] = None
    feedback: Optional[str] = None

# ============== AVAILABILITY & BOOKINGS ==================
class AvailabilitySlot(BaseModel):
    user_id: str
    start_iso: str  # ISO datetime string UTC
    end_iso: str    # ISO datetime string UTC
    is_booked: bool = False

class Booking(BaseModel):
    requester_id: str
    target_id: str  # artist or host id
    slot_id: str
    status: Literal["pending", "confirmed", "cancelled"] = "pending"
    notes: Optional[str] = None

# ============== NOTIFICATIONS ==================
class Notification(BaseModel):
    user_id: str
    title: str
    message: str
    type: Literal["info", "success", "warning", "error"] = "info"
    is_read: bool = False

# ============== SETTINGS ==================
class SiteSetting(BaseModel):
    key: str
    value: dict
