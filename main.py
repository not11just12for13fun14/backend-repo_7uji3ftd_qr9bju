import os
from datetime import datetime, timedelta, timezone
from typing import Optional, List, Literal

from fastapi import FastAPI, HTTPException, Depends, status, Body
from fastapi.middleware.cors import CORSMiddleware
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from pydantic import BaseModel, EmailStr
from jose import jwt, JWTError
from passlib.context import CryptContext
from bson import ObjectId

from database import db, create_document, get_documents

# ===================== App & Security =====================
app = FastAPI(title="Discord Musical Events Booking API")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

SECRET_KEY = os.getenv("SECRET_KEY", "dev-secret-key-change")
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 60 * 24

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="/auth/login")

# ===================== Utility =====================
class Token(BaseModel):
    access_token: str
    token_type: str = "bearer"

class SignUpPayload(BaseModel):
    email: EmailStr
    password: str
    display_name: Optional[str] = None

class RoleSelectionPayload(BaseModel):
    role: Literal["user", "artist", "host"]
    demo_video_url: Optional[str] = None
    description: Optional[str] = None

class AvailabilityPayload(BaseModel):
    start_iso: str
    end_iso: str

class BookingPayload(BaseModel):
    target_id: str
    slot_id: str
    notes: Optional[str] = None


def hash_password(password: str) -> str:
    return pwd_context.hash(password)


def verify_password(plain: str, hashed: str) -> bool:
    return pwd_context.verify(plain, hashed)


def create_access_token(data: dict, expires_delta: Optional[timedelta] = None):
    to_encode = data.copy()
    expire = datetime.now(timezone.utc) + (expires_delta or timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES))
    to_encode.update({"exp": expire})
    return jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)


def get_user_by_email(email: str):
    users = db.user.find_one({"email": email}) if db else None
    return users


def get_user_by_id(user_id: str):
    return db.user.find_one({"_id": ObjectId(user_id)}) if db else None


async def get_current_user(token: str = Depends(oauth2_scheme)):
    credentials_exception = HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Could not validate credentials")
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        user_id: str = payload.get("sub")
        if user_id is None:
            raise credentials_exception
    except JWTError:
        raise credentials_exception
    user = get_user_by_id(user_id)
    if user is None:
        raise credentials_exception
    return user


def require_admin(user = Depends(get_current_user)):
    if not user.get("is_admin"):
        raise HTTPException(status_code=403, detail="Admin access required")
    return user

# ===================== Public & Health =====================
@app.get("/")
def root():
    return {"message": "Musical Booking API running"}

@app.get("/test")
def test_database():
    response = {
        "backend": "✅ Running",
        "database": "❌ Not Available",
        "database_url": "✅ Set" if os.getenv("DATABASE_URL") else "❌ Not Set",
        "database_name": "✅ Set" if os.getenv("DATABASE_NAME") else "❌ Not Set",
        "collections": []
    }
    try:
        if db is not None:
            response["database"] = "✅ Connected"
            response["collections"] = db.list_collection_names()[:10]
    except Exception as e:
        response["database"] = f"⚠️ {str(e)[:80]}"
    return response

# ===================== Auth =====================
@app.post("/auth/signup", response_model=Token)
def signup(payload: SignUpPayload):
    if db.user.find_one({"email": payload.email}):
        raise HTTPException(400, "Email already registered")
    user_doc = {
        "email": payload.email,
        "password_hash": hash_password(payload.password),
        "oauth_provider": None,
        "oauth_id": None,
        "profile": {
            "display_name": payload.display_name or payload.email.split("@")[0],
            "avatar_url": None,
            "bio": None,
            "links": []
        },
        "role": "pending",
        "verified": False,
        "is_admin": False,
        "status": "active",
        "created_at": datetime.now(timezone.utc),
        "updated_at": datetime.now(timezone.utc)
    }
    res = db.user.insert_one(user_doc)
    token = create_access_token({"sub": str(res.inserted_id)})
    return Token(access_token=token)


@app.post("/auth/login", response_model=Token)
def login(form_data: OAuth2PasswordRequestForm = Depends()):
    user = get_user_by_email(form_data.username)
    if not user or not verify_password(form_data.password, user.get("password_hash", "")):
        raise HTTPException(400, "Invalid credentials")
    token = create_access_token({"sub": str(user["_id"])})
    return Token(access_token=token)


@app.get("/me")
def me(current = Depends(get_current_user)):
    user = current.copy()
    user["_id"] = str(user["_id"])
    return user

# ===================== Roles & Verification =====================
@app.post("/roles/select")
def select_role(payload: RoleSelectionPayload, current = Depends(get_current_user)):
    user_id = current["_id"]
    if payload.role == "user":
        db.user.update_one({"_id": user_id}, {"$set": {"role": "user", "verified": True, "updated_at": datetime.now(timezone.utc)}})
        return {"message": "Role set to Normal User", "requires_verification": False}
    # artist/host require verification
    if not payload.demo_video_url:
        raise HTTPException(400, "demo_video_url is required for artist/host")
    ver = {
        "user_id": str(user_id),
        "role": payload.role,
        "demo_video_url": payload.demo_video_url,
        "description": payload.description,
        "links": [],
        "status": "pending",
        "reviewed_by": None,
        "reviewed_at": None,
        "feedback": None,
        "created_at": datetime.now(timezone.utc),
        "updated_at": datetime.now(timezone.utc)
    }
    create_document("verificationrequest", ver)
    db.user.update_one({"_id": user_id}, {"$set": {"role": "pending", "verified": False, "updated_at": datetime.now(timezone.utc)}})
    return {"message": "Verification submitted", "requires_verification": True}

@app.get("/directory")
def public_directory(role: Literal["artist", "host"]):
    users = list(db.user.find({"role": role, "verified": True, "status": "active"}, {"password_hash": 0}))
    for u in users:
        u["_id"] = str(u["_id"])
    return users

# ===================== Admin =====================
@app.get("/admin/verification-requests")
def list_ver_requests(admin = Depends(require_admin)):
    docs = list(db.verificationrequest.find({}, { }))
    for d in docs:
        d["_id"] = str(d["_id"]) 
    return docs

@app.post("/admin/verification/{req_id}/approve")
def approve_verification(req_id: str, admin = Depends(require_admin)):
    vr = db.verificationrequest.find_one({"_id": ObjectId(req_id)})
    if not vr:
        raise HTTPException(404, "Request not found")
    user_oid = ObjectId(vr["user_id"])
    db.user.update_one({"_id": user_oid}, {"$set": {"role": vr["role"], "verified": True, "updated_at": datetime.now(timezone.utc)}})
    db.verificationrequest.update_one({"_id": ObjectId(req_id)}, {"$set": {"status": "approved", "reviewed_by": str(admin["_id"]), "reviewed_at": datetime.now(timezone.utc)}})
    create_document("notification", {"user_id": vr["user_id"], "title": "Verification Approved", "message": f"You are now a verified {vr['role']}.", "type": "success"})
    return {"message": "Approved"}

@app.post("/admin/verification/{req_id}/reject")
def reject_verification(req_id: str, feedback: Optional[str] = Body(default=None), admin = Depends(require_admin)):
    vr = db.verificationrequest.find_one({"_id": ObjectId(req_id)})
    if not vr:
        raise HTTPException(404, "Request not found")
    db.user.update_one({"_id": ObjectId(vr["user_id"])}, {"$set": {"role": "pending", "verified": False, "updated_at": datetime.now(timezone.utc)}})
    db.verificationrequest.update_one({"_id": ObjectId(req_id)}, {"$set": {"status": "rejected", "reviewed_by": str(admin["_id"]), "reviewed_at": datetime.now(timezone.utc), "feedback": feedback}})
    create_document("notification", {"user_id": vr["user_id"], "title": "Verification Rejected", "message": feedback or "Your verification was rejected.", "type": "warning"})
    return {"message": "Rejected"}

@app.get("/admin/users")
def admin_users(admin = Depends(require_admin)):
    users = list(db.user.find({}, {"password_hash": 0}))
    for u in users:
        u["_id"] = str(u["_id"]) 
    return users

# ===================== Availability =====================
@app.post("/availability")
def add_availability(payload: AvailabilityPayload, current = Depends(get_current_user)):
    if current.get("role") not in ("artist", "host") or not current.get("verified"):
        raise HTTPException(403, "Only verified artists/hosts can add availability")
    slot = {
        "user_id": str(current["_id"]),
        "start_iso": payload.start_iso,
        "end_iso": payload.end_iso,
        "is_booked": False,
        "created_at": datetime.now(timezone.utc),
        "updated_at": datetime.now(timezone.utc)
    }
    slot_id = create_document("availabilityslot", slot)
    return {"slot_id": slot_id}

@app.get("/availability/{user_id}")
def get_availability(user_id: str):
    slots = list(db.availabilityslot.find({"user_id": user_id, "is_booked": False}))
    for s in slots:
        s["_id"] = str(s["_id"]) 
    return slots

# ===================== Bookings =====================
@app.post("/bookings")
def create_booking(payload: BookingPayload, current = Depends(get_current_user)):
    slot = db.availabilityslot.find_one({"_id": ObjectId(payload.slot_id), "user_id": payload.target_id})
    if not slot or slot.get("is_booked"):
        raise HTTPException(400, "Slot not available")
    booking = {
        "requester_id": str(current["_id"]),
        "target_id": payload.target_id,
        "slot_id": payload.slot_id,
        "status": "pending",
        "notes": payload.notes,
        "created_at": datetime.now(timezone.utc),
        "updated_at": datetime.now(timezone.utc)
    }
    booking_id = create_document("booking", booking)
    db.availabilityslot.update_one({"_id": ObjectId(payload.slot_id)}, {"$set": {"is_booked": True, "updated_at": datetime.now(timezone.utc)}})
    # Notify target
    create_document("notification", {"user_id": payload.target_id, "title": "New Booking Request", "message": "You have a new booking request.", "type": "info"})
    return {"booking_id": booking_id}

@app.get("/bookings/mine")
def my_bookings(current = Depends(get_current_user)):
    uid = str(current["_id"]) 
    bookings = list(db.booking.find({"$or": [{"requester_id": uid}, {"target_id": uid}]}))
    for b in bookings:
        b["_id"] = str(b["_id"]) 
    return bookings

# ===================== Notifications =====================
@app.get("/notifications")
def my_notifications(current = Depends(get_current_user)):
    docs = list(db.notification.find({"user_id": str(current["_id"])}, sort=[("created_at", -1)]))
    for d in docs:
        d["_id"] = str(d["_id"]) 
    return docs


if __name__ == "__main__":
    import uvicorn
    port = int(os.getenv("PORT", 8000))
    uvicorn.run(app, host="0.0.0.0", port=port)
