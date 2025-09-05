"""
FastAPI PoC: Auth0 Organizations — org-first secure bootstrap

Two flows supported (via env BOOTSTRAP_MODE):
  1) INVITE (recommended): create org ➜ create invite (no email) ➜ 302 to invite URL
  2) JIT (membership-on-auth guarded): create org ➜ enable DB connection with
     assign_membership_on_login=true ➜ 302 to /authorize?organization=...

What you need in Auth0 (tenant config):
  - Enable Organizations.
  - A DB connection (Username-Password-Authentication) and its CONNECTION_ID.
  - A Regular Web App (WEB_CLIENT_ID) with callback: http://localhost:8000/callback
  - A Machine-to-Machine app authorized for Management API (MGMT_CLIENT_ID/SECRET).
  - An API (AUDIENCE) your Access Tokens are minted for.

Run locally:
  1) Create .env (see README.md for example)
  2) pip install -e . (or pip install -e ".[dev]" for development)
  3) uvicorn app:app --reload
  4) Open http://localhost:8000 and try the demo form

Security notes:
  - Default is INVITE bootstrap which prevents unauthorized users from joining a new org.
  - This PoC exchanges the OAuth code on the server and verifies tokens via JWKS.
  - For brevity we use SQLite and simple role seeding; map to Postgres + RLS in production.
"""
from __future__ import annotations

import base64
import json
import re
import time
import uuid
from datetime import datetime, timezone
from typing import Any

import httpx
from fastapi import Depends, FastAPI, Form, HTTPException, Request
from fastapi.responses import FileResponse, PlainTextResponse, RedirectResponse
from jose import jwt
from pydantic import BaseModel
from pydantic_settings import BaseSettings
from sqlalchemy import (
    DateTime,
    ForeignKey,
    String,
    UniqueConstraint,
    create_engine,
    func,
    select,
)
from sqlalchemy.orm import DeclarativeBase, Mapped, Session, mapped_column, relationship, sessionmaker

# ----------------------------------------------------------------------------
# Settings
# ----------------------------------------------------------------------------

class Settings(BaseSettings):
    AUTH0_DOMAIN: str
    AUTH0_MGMT_CLIENT_ID: str
    AUTH0_MGMT_CLIENT_SECRET: str
    AUTH0_WEB_CLIENT_ID: str
    AUTH0_WEB_CLIENT_SECRET: str | None = None  # client secret for Regular Web App
    AUTH0_DB_CONNECTION_ID: str
    AUTH0_AUDIENCE: str
    CALLBACK_URL: str = "http://localhost:8000/callback"
    DATABASE_URL: str = "sqlite:///./app.db"
    BOOTSTRAP_MODE: str = "invite"  # "invite" or "jit"
    ORG_OWNER_ROLE_ID: str | None = None  # optional Auth0 role id for org owner

    class Config:
        env_file = ".env"

settings = Settings()  # type: ignore[call-arg]

# ----------------------------------------------------------------------------
# DB setup (SQLAlchemy)
# ----------------------------------------------------------------------------

engine = create_engine(settings.DATABASE_URL, echo=False, future=True)
SessionLocal = sessionmaker(bind=engine, expire_on_commit=False, future=True)

class Base(DeclarativeBase):
    pass

class Organization(Base):
    __tablename__ = "organizations"
    id: Mapped[str] = mapped_column(String, primary_key=True, default=lambda: str(uuid.uuid4()))
    auth0_org_id: Mapped[str] = mapped_column(String, unique=True, nullable=False)
    slug: Mapped[str] = mapped_column(String, unique=True, nullable=False)
    name: Mapped[str] = mapped_column(String, nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc))
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc))

    members: Mapped[list[OrganizationMembership]] = relationship(back_populates="org")

class User(Base):
    __tablename__ = "users"
    id: Mapped[str] = mapped_column(String, primary_key=True, default=lambda: str(uuid.uuid4()))
    auth0_user_id: Mapped[str] = mapped_column(String, unique=True, nullable=False)
    email: Mapped[str] = mapped_column(String, nullable=False)
    name: Mapped[str | None] = mapped_column(String, nullable=True)
    picture_url: Mapped[str | None] = mapped_column(String, nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc))
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc))

    memberships: Mapped[list[OrganizationMembership]] = relationship(back_populates="user")

class Role(Base):
    __tablename__ = "roles"
    id: Mapped[str] = mapped_column(String, primary_key=True, default=lambda: str(uuid.uuid4()))
    key: Mapped[str] = mapped_column(String, unique=True, nullable=False)
    scope: Mapped[str] = mapped_column(String, nullable=False)  # 'org' | 'project'
    description: Mapped[str | None] = mapped_column(String, nullable=True)
    auth0_role_id: Mapped[str | None] = mapped_column(String, nullable=True)

class OrganizationMembership(Base):
    __tablename__ = "organization_memberships"
    id: Mapped[str] = mapped_column(String, primary_key=True, default=lambda: str(uuid.uuid4()))
    org_id: Mapped[str] = mapped_column(String, ForeignKey("organizations.id"), nullable=False)
    user_id: Mapped[str] = mapped_column(String, ForeignKey("users.id"), nullable=False)
    role_id: Mapped[str] = mapped_column(String, ForeignKey("roles.id"), nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc))

    org: Mapped[Organization] = relationship(back_populates="members")
    user: Mapped[User] = relationship(back_populates="memberships")
    role: Mapped[Role] = relationship()

    __table_args__ = (
        UniqueConstraint("org_id", "user_id", name="uq_org_user"),
    )

Base.metadata.create_all(engine)

# Seed minimal roles
with SessionLocal() as s:
    if not s.scalar(select(Role).where(Role.key == "org_owner")):
        s.add_all([
            Role(key="org_owner", scope="org", description="Full control over org"),
            Role(key="org_admin", scope="org", description="Manage members, billing, settings"),
            Role(key="org_member", scope="org", description="Standard member"),
        ])
        s.commit()

# ----------------------------------------------------------------------------
# Utilities: slugify, sessions, and JWT verification
# ----------------------------------------------------------------------------

_slug_rx = re.compile(r"[^a-z0-9]+")

def slugify(name: str) -> str:
    s = name.strip().lower()
    s = _slug_rx.sub("-", s)
    return s.strip("-")[:50]

def should_include_audience() -> bool:
    """Check if audience parameter should be included in Auth0 requests"""
    return bool(settings.AUTH0_AUDIENCE and settings.AUTH0_AUDIENCE != "https://api.yourapp.com")

def build_auth0_authorize_url(**params) -> str:
    """Build Auth0 authorize URL with common parameters"""
    base_params = {
        "client_id": settings.AUTH0_WEB_CLIENT_ID,
        "response_type": "code",
        "redirect_uri": settings.CALLBACK_URL,
        "scope": "openid profile email offline_access",
    }
    base_params.update(params)

    # Only add audience if configured
    if should_include_audience():
        base_params["audience"] = settings.AUTH0_AUDIENCE

    q = "&".join(f"{k}={httpx.QueryParams({k:v})[k]}" for k, v in base_params.items())
    return f"https://{settings.AUTH0_DOMAIN}/authorize?{q}"

# JWKS cache (very lightweight)
_jwks_cache: dict[str, dict] = {}
_jwks_expiry: dict[str, float] = {}

async def get_jwks(domain: str) -> dict[str, Any]:
    now = time.time()
    if domain in _jwks_cache and _jwks_expiry.get(domain, 0) > now:
        return _jwks_cache[domain]
    url = f"https://{domain}/.well-known/jwks.json"
    async with httpx.AsyncClient(timeout=10) as client:
        r = await client.get(url)
        r.raise_for_status()
        jwks = r.json()
    _jwks_cache[domain] = jwks
    _jwks_expiry[domain] = now + 60 * 60  # 1h
    return jwks  # type: ignore[no-any-return]

async def verify_jwt(token: str, *, audience: str, domain: str) -> dict[str, Any]:
    jwks = await get_jwks(domain)
    headers = jwt.get_unverified_header(token)
    kid = headers.get("kid")
    key = None
    for k in jwks.get("keys", []):
        if k.get("kid") == kid:
            key = k
            break
    if not key:
        raise HTTPException(401, "Invalid token (kid)")

    try:
        claims = jwt.decode(
            token,
            key,
            algorithms=["RS256"],
            audience=audience,
            issuer=f"https://{domain}/",
        )
        return claims  # type: ignore[no-any-return]
    except Exception as e:
        raise HTTPException(401, f"Token verification failed: {e}") from e

# ----------------------------------------------------------------------------
# Auth0 Management API helpers
# ----------------------------------------------------------------------------

_mgmt_token: dict | None = None  # {access_token, expires_at}

async def get_mgmt_token() -> str:
    global _mgmt_token
    if _mgmt_token and _mgmt_token["expires_at"] > time.time() + 60:
        return _mgmt_token["access_token"]  # type: ignore[no-any-return]

    token_url = f"https://{settings.AUTH0_DOMAIN}/oauth/token"
    payload = {
        "grant_type": "client_credentials",
        "client_id": settings.AUTH0_MGMT_CLIENT_ID,
        "client_secret": settings.AUTH0_MGMT_CLIENT_SECRET,
        "audience": f"https://{settings.AUTH0_DOMAIN}/api/v2/",
    }
    async with httpx.AsyncClient(timeout=15) as client:
        r = await client.post(token_url, json=payload)
        r.raise_for_status()
        data = r.json()
    _mgmt_token = {
        "access_token": data["access_token"],
        "expires_at": time.time() + data.get("expires_in", 3600),
    }
    return _mgmt_token["access_token"]  # type: ignore[no-any-return]

async def auth0_create_org(slug: str, display_name: str) -> dict[str, Any]:
    token = await get_mgmt_token()
    url = f"https://{settings.AUTH0_DOMAIN}/api/v2/organizations"
    body = {"name": slug, "display_name": display_name}
    async with httpx.AsyncClient(timeout=20) as client:
        r = await client.post(url, json=body, headers={"Authorization": f"Bearer {token}"})
        r.raise_for_status()
        return r.json()  # type: ignore[no-any-return]

async def auth0_enable_db_connection(org_id: str, assign_membership_on_login: bool) -> None:
    token = await get_mgmt_token()
    url = f"https://{settings.AUTH0_DOMAIN}/api/v2/organizations/{org_id}/enabled_connections"
    body = {
        "connection_id": settings.AUTH0_DB_CONNECTION_ID,
        "assign_membership_on_login": assign_membership_on_login,
    }
    async with httpx.AsyncClient(timeout=20) as client:
        r = await client.post(url, json=body, headers={"Authorization": f"Bearer {token}"})
        r.raise_for_status()

async def auth0_create_invitation(org_id: str, email: str) -> dict[str, Any]:
    token = await get_mgmt_token()
    url = f"https://{settings.AUTH0_DOMAIN}/api/v2/organizations/{org_id}/invitations"
    body = {
        "inviter": {"name": "Your App"},
        "invitee": {"email": email},
        "client_id": settings.AUTH0_WEB_CLIENT_ID,
        "connection_id": settings.AUTH0_DB_CONNECTION_ID,
        "ttl_sec": 604800,  # 7 days in seconds
        "send_invitation_email": True,
        # optionally attach roles (Auth0 org member roles) if you created them
        **({"roles": [settings.ORG_OWNER_ROLE_ID]} if settings.ORG_OWNER_ROLE_ID else {}),
    }
    async with httpx.AsyncClient(timeout=20) as client:
        r = await client.post(url, json=body, headers={"Authorization": f"Bearer {token}"})
        r.raise_for_status()
        return r.json()  # type: ignore[no-any-return]

# ----------------------------------------------------------------------------
# FastAPI app
# ----------------------------------------------------------------------------

app = FastAPI(title="Auth0 Org-First PoC")

# Dependency to get DB session

def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

# ----------------------------------------------------------------------------
# Demo index
# ----------------------------------------------------------------------------

@app.get("/", response_class=FileResponse)
async def index():
    return FileResponse("templates/index.html", media_type="text/html")

class InitBody(BaseModel):
    company_name: str
    email: str

# ----------------------------------------------------------------------------
# Slug-based login endpoint
# ----------------------------------------------------------------------------

@app.get("/org/{slug}/login")
async def login_by_slug(
    slug: str,
    login_hint: str | None = None,
    db: Session = Depends(get_db)
):
    """Login to an organization by its slug"""

    # Find organization by slug
    org = db.scalar(select(Organization).where(Organization.slug == slug))

    if not org:
        # For security, redirect to generic login instead of revealing org doesn't exist
        return RedirectResponse("/", status_code=302)

    # Redirect to standard login with org ID
    params = {
        "organization": org.auth0_org_id
    }
    if login_hint:
        params["login_hint"] = login_hint

    query = "&".join(f"{k}={httpx.QueryParams({k:v})[k]}" for k, v in params.items())
    return RedirectResponse(f"/login?{query}", status_code=302)

# ----------------------------------------------------------------------------
# Login endpoint for existing users
# ----------------------------------------------------------------------------

@app.get("/login")
async def login(
    organization: str,
    login_hint: str | None = None,
):
    """Redirect to Auth0 login for a specific organization"""

    if not organization:
        raise HTTPException(400, "Organization is required")

    # Build Auth0 authorize URL
    params = {"organization": organization}
    if login_hint:
        params["login_hint"] = login_hint

    auth_url = build_auth0_authorize_url(**params)
    return RedirectResponse(auth_url, status_code=302)

# ----------------------------------------------------------------------------
# Org bootstrap endpoint (form or JSON)
# ----------------------------------------------------------------------------

@app.post("/onboard/init")
async def onboard_init(
    request: Request,
    company_name: str | None = Form(default=None),
    email: str | None = Form(default=None),
    body: InitBody | None = None,
    db: Session = Depends(get_db),
):
    # Accept either form or JSON
    if body:
        company = body.company_name
        user_email = body.email
    else:
        if not company_name or not email:
            raise HTTPException(400, "company_name and email required")
        company = company_name
        user_email = email

    slug = slugify(company)

    # Create Org in Auth0
    org = await auth0_create_org(slug, company)
    org_id = org["id"]  # e.g., org_abc123

    # Persist org in local DB
    with db.begin():
        db_org = Organization(auth0_org_id=org_id, slug=slug, name=company)
        db.add(db_org)

    if settings.BOOTSTRAP_MODE.lower() == "invite":
        # Secure pattern: first enable the DB connection on the Org (NO auto-membership)
        # Without this, Auth0 will 400 because the connection isn't enabled for the org.
        await auth0_enable_db_connection(org_id, assign_membership_on_login=False)
        # Create an invitation and 302 to invitation_url
        invite = await auth0_create_invitation(org_id, user_email)
        invitation_url = invite.get("invitation_url")
        if not invitation_url:
            raise HTTPException(500, "Auth0 did not return invitation_url")
        return RedirectResponse(invitation_url, status_code=302)
    else:
        # JIT pattern: enable auto-membership and redirect to authorize (signup)
        await auth0_enable_db_connection(org_id, assign_membership_on_login=True)
        auth_url = build_auth0_authorize_url(
            organization=org_id,
            screen_hint="signup",
            login_hint=user_email
        )
        return RedirectResponse(auth_url, status_code=302)

# ----------------------------------------------------------------------------
# OAuth callback helper functions
# ----------------------------------------------------------------------------

async def exchange_code_for_tokens(code: str) -> dict[str, Any]:
    """Exchange authorization code for tokens"""
    token_url = f"https://{settings.AUTH0_DOMAIN}/oauth/token"
    payload = {
        "grant_type": "authorization_code",
        "client_id": settings.AUTH0_WEB_CLIENT_ID,
        "code": code,
        "redirect_uri": settings.CALLBACK_URL,
    }
    # Add client secret if configured (for Regular Web Apps)
    if settings.AUTH0_WEB_CLIENT_SECRET:
        payload["client_secret"] = settings.AUTH0_WEB_CLIENT_SECRET

    async with httpx.AsyncClient(timeout=20) as client:
        r = await client.post(token_url, json=payload)
        try:
            r.raise_for_status()
        except httpx.HTTPStatusError as e:
            raise HTTPException(500, f"Token exchange failed: {e.response.text}") from e
        return r.json()  # type: ignore[no-any-return]

def validate_token_claims(id_claims: dict[str, Any]) -> tuple[str, str, str]:
    """Validate and extract required claims from ID token"""
    auth0_user_id = id_claims.get("sub")
    email = id_claims.get("email")
    org_id = id_claims.get("org_id")

    if not auth0_user_id or not email:
        raise HTTPException(400, "ID token missing sub/email")
    if not org_id:
        # This means authorize did not include organization=... (user-first flow)
        raise HTTPException(400, "No org context on token; expected org-first flow.")

    return auth0_user_id, email, org_id

async def upsert_user(
    db: Session,
    auth0_user_id: str,
    email: str,
    name: str | None,
    picture_url: str | None
) -> User:
    """Create or update user in database"""
    db_user = db.scalar(select(User).where(User.auth0_user_id == auth0_user_id))
    if not db_user:
        db_user = User(
            auth0_user_id=auth0_user_id,
            email=email,
            name=name,
            picture_url=picture_url
        )
        db.add(db_user)
    else:
        db_user.email = email  # keep latest
        db_user.name = name
        db_user.picture_url = picture_url
    return db_user

async def upsert_organization(
    db: Session,
    org_id: str,
    org_name: str | None
) -> Organization:
    """Create or get organization in database"""
    db_org = db.scalar(select(Organization).where(Organization.auth0_org_id == org_id))
    if not db_org:
        # In case callback happens before DB write (rare), create it now
        db_org = Organization(
            auth0_org_id=org_id,
            slug=f"org-{org_id[-6:]}",
            name=org_name or "New Org"
        )
        db.add(db_org)
    return db_org

async def ensure_organization_membership(
    db: Session,
    db_org: Organization,
    db_user: User
) -> None:
    """Ensure user is a member of the organization with appropriate role"""
    existing = db.scalar(select(OrganizationMembership).where(
        OrganizationMembership.org_id == db_org.id,
        OrganizationMembership.user_id == db_user.id,
    ))
    if not existing:
        # Count existing members using SQLAlchemy 2.x syntax with func.count()
        member_count = db.scalar(
            select(func.count()).select_from(OrganizationMembership).where(
                OrganizationMembership.org_id == db_org.id
            )
        )
        role_key = "org_owner" if member_count == 0 else "org_member"
        role = db.scalar(select(Role).where(Role.key == role_key))
        if not role:
            raise HTTPException(500, f"Role {role_key} not found")
        db.add(OrganizationMembership(
            org_id=db_org.id,
            user_id=db_user.id,
            role_id=role.id
        ))

async def assign_auth0_org_role(
    org_id: str,
    auth0_user_id: str
) -> None:
    """Optionally assign Auth0 org member role to the user"""
    if not settings.ORG_OWNER_ROLE_ID:
        return

    try:
        token = await get_mgmt_token()
        url = f"https://{settings.AUTH0_DOMAIN}/api/v2/organizations/{org_id}/members/{auth0_user_id}/roles"
        async with httpx.AsyncClient(timeout=15) as client:
            await client.post(
                url,
                json={"roles": [settings.ORG_OWNER_ROLE_ID]},
                headers={"Authorization": f"Bearer {token}"}
            )
    except Exception:
        pass  # Optional operation, continue on failure

def create_auth_response(
    id_token: str,
    email: str,
    org_name: str | None,
    org_id: str
) -> RedirectResponse:
    """Create response with authentication cookies"""
    response = RedirectResponse("/dashboard", status_code=302)

    # Set secure HTTP-only cookies
    # In production, use secure=True for HTTPS
    is_https = settings.CALLBACK_URL.startswith("https://")

    # Use ID token for authentication (guaranteed to be a JWT)
    response.set_cookie(
        key="auth_token",
        value=id_token,
        max_age=86400,  # 1 day
        httponly=True,
        samesite="lax",
        secure=is_https
    )

    # Also set a non-httponly cookie with basic info for the UI
    # Use base64 encoding to avoid JSON parsing issues with special characters
    user_info = {
        "email": email,
        "org_name": org_name or 'Unknown',
        "org_id": org_id
    }
    # Encode to base64 to handle special characters safely
    user_info_encoded = base64.b64encode(json.dumps(user_info).encode()).decode()
    response.set_cookie(
        key="user_info",
        value=user_info_encoded,
        max_age=86400,
        samesite="lax",
        secure=is_https
    )

    return response

# ----------------------------------------------------------------------------
# OAuth callback — exchange code, upsert user + membership, show result
# ----------------------------------------------------------------------------

@app.get("/callback")
async def oauth_callback(
    code: str | None = None,
    state: str | None = None,
    invitation: str | None = None,
    organization: str | None = None,
    organization_name: str | None = None,
    db: Session = Depends(get_db)
):
    """
    Handle OAuth callback from Auth0.

    This endpoint handles two flows:
    1. Invitation acceptance - redirects to Auth0 with invitation token
    2. Post-authentication - exchanges code for tokens and sets up user session

    The callback performs these steps:
    1. Exchange authorization code for tokens
    2. Verify and validate the ID token
    3. Upsert user and organization in database
    4. Ensure organization membership with appropriate role
    5. Optionally assign Auth0 organization roles
    6. Set authentication cookies and redirect to dashboard
    """

    # Handle invitation acceptance flow
    if invitation and organization and not code:
        # User is accepting an invitation, redirect to Auth0 authorize endpoint
        auth_url = build_auth0_authorize_url(
            organization=organization,
            invitation=invitation
        )
        return RedirectResponse(auth_url, status_code=302)

    if not code:
        return PlainTextResponse("Missing code", status_code=400)

    # Step 1: Exchange code for tokens
    tokens = await exchange_code_for_tokens(code)

    id_token = tokens.get("id_token")
    if not id_token:
        return PlainTextResponse("ID token missing from response", status_code=500)

    # Step 2: Verify and extract claims from ID token
    id_claims = await verify_jwt(
        id_token,
        audience=settings.AUTH0_WEB_CLIENT_ID,
        domain=settings.AUTH0_DOMAIN
    )

    # Step 3: Validate token claims
    auth0_user_id, email, org_id = validate_token_claims(id_claims)

    # Step 4: Update database with user and organization data
    with db.begin():
        db_user = await upsert_user(
            db,
            auth0_user_id,
            email,
            id_claims.get("name"),
            id_claims.get("picture")
        )

        db_org = await upsert_organization(
            db,
            org_id,
            id_claims.get("org_name")
        )

        await ensure_organization_membership(db, db_org, db_user)

    # Step 5: Optionally assign Auth0 org role
    await assign_auth0_org_role(org_id, auth0_user_id)

    # Step 6: Create response with authentication cookies
    return create_auth_response(
        id_token,
        email,
        id_claims.get('org_name'),
        org_id
    )

# ----------------------------------------------------------------------------
# Auth dependencies
# ----------------------------------------------------------------------------

class AuthContext:
    """Context from verified JWT token"""
    def __init__(self, user: User, org: Organization, membership: OrganizationMembership, role: Role, token_claims: dict):
        self.user = user
        self.org = org
        self.membership = membership
        self.role = role
        self.token_claims = token_claims

async def get_current_user(
    request: Request,
    authorization: str | None = None,
    db: Session = Depends(get_db)
) -> AuthContext:
    """Dependency to get current authenticated user with org context"""
    # Try to get token from Authorization header first
    auth = authorization or request.headers.get("authorization")
    token = None

    if auth and auth.lower().startswith("bearer "):
        token = auth.split()[1]
    else:
        # Fall back to cookie
        token = request.cookies.get("auth_token")

    if not token:
        raise HTTPException(401, "Missing authentication token")

    # Since we're using ID tokens for auth (no API audience configured),
    # always verify as ID token
    try:
        claims = await verify_jwt(token, audience=settings.AUTH0_WEB_CLIENT_ID, domain=settings.AUTH0_DOMAIN)
    except Exception as e:
        raise HTTPException(401, f"Invalid token: {str(e)}") from e

    sub = claims.get("sub")
    org_id = claims.get("org_id")
    if not org_id:
        raise HTTPException(403, "Token is not in an organization context")

    with db.begin():
        db_user = db.scalar(select(User).where(User.auth0_user_id == sub))
        db_org = db.scalar(select(Organization).where(Organization.auth0_org_id == org_id))
        if not (db_user and db_org):
            raise HTTPException(404, "User or Org not found locally")

        membership = db.scalar(select(OrganizationMembership).where(
            OrganizationMembership.org_id == db_org.id,
            OrganizationMembership.user_id == db_user.id,
        ))
        if not membership:
            raise HTTPException(403, "User is not a member of this organization")

        role = db.get(Role, membership.role_id)
        if not role:
            raise HTTPException(500, "Role not found")

    return AuthContext(
        user=db_user,
        org=db_org,
        membership=membership,
        role=role,
        token_claims=claims
    )

def require_role(*allowed_roles: str):
    """Dependency factory to require specific roles"""
    async def check_role(auth: AuthContext = Depends(get_current_user)):
        if auth.role.key not in allowed_roles:
            raise HTTPException(403, f"Insufficient permissions. Required role: {', '.join(allowed_roles)}")
        return auth
    return check_role

# ----------------------------------------------------------------------------
# Example protected API (expects org-scoped Access Token)
# ----------------------------------------------------------------------------

@app.get("/me")
async def me(auth: AuthContext = Depends(get_current_user)):
    """Get current user information"""
    return {
        "user": {
            "id": auth.user.id,
            "email": auth.user.email,
            "auth0_user_id": auth.user.auth0_user_id,
            "name": auth.user.name
        },
        "org": {
            "id": auth.org.id,
            "name": auth.org.name,
            "auth0_org_id": auth.org.auth0_org_id
        },
        "role": auth.role.key,
    }

# ----------------------------------------------------------------------------
# Organization management endpoints
# ----------------------------------------------------------------------------

class InviteUserRequest(BaseModel):
    email: str
    role_key: str | None = "org_member"

@app.post("/org/invite")
async def invite_user_to_org(
    invite: InviteUserRequest,
    auth: AuthContext = Depends(require_role("org_owner", "org_admin")),
    db: Session = Depends(get_db)
):
    """Invite a new user to the organization. Requires org_owner or org_admin role."""

    # Verify the role exists
    role = db.scalar(select(Role).where(Role.key == invite.role_key))
    if not role:
        raise HTTPException(400, f"Invalid role: {invite.role_key}")

    # Don't allow inviting users as org_owner unless you are org_owner
    if invite.role_key == "org_owner" and auth.role.key != "org_owner":
        raise HTTPException(403, "Only org owners can invite other org owners")

    # Check if user is already a member
    existing_user = db.scalar(select(User).where(User.email == invite.email))
    if existing_user:
        existing_membership = db.scalar(select(OrganizationMembership).where(
            OrganizationMembership.org_id == auth.org.id,
            OrganizationMembership.user_id == existing_user.id
        ))
        if existing_membership:
            raise HTTPException(400, "User is already a member of this organization")

    # Create Auth0 invitation
    try:
        invitation = await auth0_create_invitation(auth.org.auth0_org_id, invite.email)
    except httpx.HTTPStatusError as e:
        if e.response.status_code == 400:
            raise HTTPException(400, f"Failed to create invitation: {e.response.text}") from e
        raise HTTPException(500, "Failed to create invitation") from e

    return {
        "message": f"Invitation sent to {invite.email}",
        "invitation_url": invitation.get("invitation_url"),
        "invitation_id": invitation.get("id"),
        "role": invite.role_key
    }

@app.get("/org/members")
async def list_org_members(
    auth: AuthContext = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """List all members of the current organization"""

    # Query all memberships for this org
    memberships = db.scalars(
        select(OrganizationMembership)
        .where(OrganizationMembership.org_id == auth.org.id)
        .order_by(OrganizationMembership.created_at)
    ).all()

    members = []
    for membership in memberships:
        user = db.get(User, membership.user_id)
        role = db.get(Role, membership.role_id)
        if not user or not role:
            continue  # Skip if user or role not found
        members.append({
            "user": {
                "id": user.id,
                "email": user.email,
                "name": user.name,
                "auth0_user_id": user.auth0_user_id
            },
            "role": role.key,
            "joined_at": membership.created_at.isoformat(),
            "is_current_user": user.id == auth.user.id
        })

    return {
        "organization": {
            "id": auth.org.id,
            "name": auth.org.name,
            "auth0_org_id": auth.org.auth0_org_id
        },
        "members": members,
        "total_count": len(members),
        "current_user_role": auth.role.key,
        "can_invite": auth.role.key in ["org_owner", "org_admin"]
    }

@app.delete("/org/members/{user_id}")
async def remove_org_member(
    user_id: str,
    auth: AuthContext = Depends(require_role("org_owner", "org_admin")),
    db: Session = Depends(get_db)
):
    """Remove a member from the organization. Requires org_owner or org_admin role."""

    # Prevent removing yourself
    if user_id == auth.user.id:
        raise HTTPException(400, "Cannot remove yourself from the organization")

    # Find the membership
    membership = db.scalar(select(OrganizationMembership).where(
        OrganizationMembership.org_id == auth.org.id,
        OrganizationMembership.user_id == user_id
    ))

    if not membership:
        raise HTTPException(404, "Member not found in organization")

    # Check if trying to remove an org_owner (only org_owners can do this)
    member_role = db.get(Role, membership.role_id)
    if not member_role:
        raise HTTPException(500, "Member role not found")
    if member_role.key == "org_owner" and auth.role.key != "org_owner":
        raise HTTPException(403, "Only org owners can remove other org owners")

    # Remove from Auth0 organization
    user = db.get(User, user_id)
    if not user:
        raise HTTPException(404, "User not found")

    try:
        token = await get_mgmt_token()
        url = f"https://{settings.AUTH0_DOMAIN}/api/v2/organizations/{auth.org.auth0_org_id}/members"
        async with httpx.AsyncClient(timeout=15) as client:
            # First, get the Auth0 user ID format for the API call
            delete_url = f"{url}/{user.auth0_user_id}"
            r = await client.delete(delete_url, headers={"Authorization": f"Bearer {token}"})
            if r.status_code not in [204, 404]:  # 404 is OK if already removed
                r.raise_for_status()
    except Exception:
        pass  # Continue even if Auth0 removal fails - still remove from local DB

    # Remove from local database
    with db.begin():
        db.delete(membership)

    return {"message": f"Successfully removed user {user.email} from organization"}

@app.put("/org/members/{user_id}/role")
async def update_member_role(
    user_id: str,
    role_update: dict,  # {"role_key": "org_admin"}
    auth: AuthContext = Depends(require_role("org_owner")),
    db: Session = Depends(get_db)
):
    """Update a member's role. Requires org_owner role."""

    new_role_key = role_update.get("role_key")
    if not new_role_key:
        raise HTTPException(400, "role_key is required")

    # Verify the role exists
    new_role = db.scalar(select(Role).where(Role.key == new_role_key))
    if not new_role:
        raise HTTPException(400, f"Invalid role: {new_role_key}")

    # Find the membership
    membership = db.scalar(select(OrganizationMembership).where(
        OrganizationMembership.org_id == auth.org.id,
        OrganizationMembership.user_id == user_id
    ))

    if not membership:
        raise HTTPException(404, "Member not found in organization")

    # Prevent changing your own role
    if user_id == auth.user.id:
        raise HTTPException(400, "Cannot change your own role")

    # Update the role
    with db.begin():
        membership.role_id = new_role.id

    user = db.get(User, user_id)
    if not user:
        raise HTTPException(404, "User not found")
    return {
        "message": f"Successfully updated role for {user.email} to {new_role_key}",
        "user_id": user_id,
        "new_role": new_role_key
    }

# ----------------------------------------------------------------------------
# Logout endpoint
# ----------------------------------------------------------------------------

@app.get("/logout")
async def logout():
    """Clear cookies and redirect to home"""
    response = RedirectResponse("/", status_code=302)
    response.delete_cookie("auth_token")
    response.delete_cookie("user_info")
    return response

# ----------------------------------------------------------------------------
# Simple dashboard UI
# ----------------------------------------------------------------------------

@app.get("/dashboard", response_class=FileResponse)
async def dashboard():
    """Simple dashboard UI for testing member management"""
    return FileResponse("templates/dashboard.html", media_type="text/html")
