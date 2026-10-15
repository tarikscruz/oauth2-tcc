import json, re
from datetime import datetime, timezone, timedelta
from urllib.parse import urlencode
from cryptography.fernet import InvalidToken
from fastapi import FastAPI, Depends, Form, HTTPException, Request
from fastapi.responses import HTMLResponse, JSONResponse, RedirectResponse
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from fastapi.templating import Jinja2Templates
from sqlalchemy import select
from sqlalchemy.orm import Session
from app.config import get_settings
from app.database import Base, engine, get_db
from app.models import User, OAuthClient, AuthorizationCode, OAuthToken, AuditEvent
from app.security import (
    hash_password,
    verify_password,
    hash_secret,
    pkce_s256,
    random_urlsafe,
    encode_ticket,
    decode_ticket,
)

settings = get_settings()
app = FastAPI(title="OAuth2 Manual TCC")
templates = Jinja2Templates(directory="app/templates")
bearer = HTTPBearer(auto_error=False)
Base.metadata.create_all(bind=engine)
VERIFIER_RE = re.compile(r"^[A-Za-z0-9\-._~]{43,128}$")


def now():
    return datetime.now(timezone.utc)


def scopes(v):
    return {x for x in v.split() if x}


def client(db, cid):
    return db.scalar(
        select(OAuthClient).where(
            OAuthClient.client_id == cid, OAuthClient.active.is_(True)
        )
    )


def audit(db, event, ok, cid=None, uid=None, details=None):
    db.add(
        AuditEvent(
            event_type=event,
            success=ok,
            client_id=cid,
            user_id=uid,
            details=json.dumps(details or {}),
        )
    )


def error(name, desc, code=400):
    return JSONResponse(
        {"error": name, "error_description": desc},
        status_code=code,
        headers={"Cache-Control": "no-store", "Pragma": "no-cache"},
    )


def validate(db, response_type, client_id, redirect_uri, scope, challenge, method):
    c = client(db, client_id)
    if not c:
        raise HTTPException(400, "Cliente invalido")
    if redirect_uri not in json.loads(c.redirect_uris):
        raise HTTPException(400, "redirect_uri nao cadastrada")
    if response_type != "code":
        raise HTTPException(400, "Somente response_type=code")
    if method != "S256" or len(challenge) < 43:
        raise HTTPException(400, "PKCE S256 obrigatorio")
    requested = scopes(scope)
    if not requested or not requested.issubset(scopes(c.allowed_scopes)):
        raise HTTPException(400, "Scope invalido")
    return c, " ".join(sorted(requested))


@app.get("/health")
def health():
    return {"status": "ok"}


@app.get("/register", response_class=HTMLResponse)
def register_page(request: Request):
    return templates.TemplateResponse(
        request=request, name="register.html", context={"error": None}
    )


@app.post("/register", response_class=HTMLResponse)
def register(
    request: Request,
    username: str = Form(...),
    password: str = Form(...),
    db: Session = Depends(get_db),
):
    username = username.strip().lower()
    if len(username) < 3 or len(password) < 12:
        return templates.TemplateResponse(
            request=request,
            name="register.html",
            context={"error": "Usuario >= 3 e senha >= 12 caracteres."},
            status_code=400,
        )
    if db.scalar(select(User).where(User.username == username)):
        return templates.TemplateResponse(
            request=request,
            name="register.html",
            context={"error": "Usuario ja existe."},
            status_code=409,
        )
    u = User(username=username, password_hash=hash_password(password))
    db.add(u)
    db.commit()
    return HTMLResponse(
        "<h1>Usuario cadastrado</h1><p>Inicie o fluxo OAuth.</p>", status_code=201
    )


@app.get("/oauth/authorize", response_class=HTMLResponse)
def authorize_page(
    request: Request,
    response_type: str,
    client_id: str,
    redirect_uri: str,
    scope: str,
    code_challenge: str,
    code_challenge_method: str,
    state: str | None = None,
    db: Session = Depends(get_db),
):
    c, canonical = validate(
        db,
        response_type,
        client_id,
        redirect_uri,
        scope,
        code_challenge,
        code_challenge_method,
    )
    ticket = encode_ticket(
        {
            "response_type": response_type,
            "client_id": client_id,
            "redirect_uri": redirect_uri,
            "scope": canonical,
            "code_challenge": code_challenge,
            "code_challenge_method": code_challenge_method,
            "state": state,
        }
    )
    return templates.TemplateResponse(
        request=request,
        name="authorize.html",
        context={
            "client_name": c.name,
            "scope": canonical,
            "ticket": ticket,
            "error": None,
        },
    )


@app.post("/oauth/authorize")
def authorize(
    request: Request,
    ticket: str = Form(...),
    username: str = Form(""),
    password: str = Form(""),
    decision: str = Form(...),
    db: Session = Depends(get_db),
):
    try:
        ar = decode_ticket(ticket)
    except InvalidToken:
        raise HTTPException(400, "Solicitacao expirada ou adulterada")
    c, canonical = validate(
        db,
        ar["response_type"],
        ar["client_id"],
        ar["redirect_uri"],
        ar["scope"],
        ar["code_challenge"],
        ar["code_challenge_method"],
    )
    params = {"state": ar.get("state")} if ar.get("state") else {}
    if decision != "approve":
        params.update({"error": "access_denied"})
        return RedirectResponse(ar["redirect_uri"] + "?" + urlencode(params), 303)
    u = db.scalar(
        select(User).where(
            User.username == username.strip().lower(), User.active.is_(True)
        )
    )
    if not u or not verify_password(u.password_hash, password):
        return templates.TemplateResponse(
            request=request,
            name="authorize.html",
            context={
                "client_name": c.name,
                "scope": canonical,
                "ticket": ticket,
                "error": "Credenciais invalidas.",
            },
            status_code=401,
        )
    plain = random_urlsafe(48)
    db.add(
        AuthorizationCode(
            code_hash=hash_secret(plain),
            client_id=c.client_id,
            user_id=u.id,
            redirect_uri=ar["redirect_uri"],
            scope=canonical,
            code_challenge=ar["code_challenge"],
            code_challenge_method="S256",
            expires_at=now() + timedelta(seconds=settings.auth_code_seconds),
        )
    )
    audit(db, "authorization_code_issued", True, c.client_id, u.id)
    db.commit()
    params.update({"code": plain})
    return RedirectResponse(ar["redirect_uri"] + "?" + urlencode(params), 303)

def issue(db, cid, uid, scope):
    access = random_urlsafe(48)
    refresh = random_urlsafe(64)
    db.add(
        OAuthToken(
            access_token_hash=hash_secret(access),
            refresh_token_hash=hash_secret(refresh),
            client_id=cid,
            user_id=uid,
            scope=scope,
            access_expires_at=now() + timedelta(minutes=settings.access_token_minutes),
            refresh_expires_at=now() + timedelta(days=settings.refresh_token_days),
        )
    )
    return {
        "access_token": access,
        "token_type": "Bearer",
        "expires_in": settings.access_token_minutes * 60,
        "refresh_token": refresh,
        "scope": scope,
    }

@app.post("/oauth/token")
def token(
    grant_type: str = Form(...),
    client_id: str = Form(...),
    code: str | None = Form(None),
    redirect_uri: str | None = Form(None),
    code_verifier: str | None = Form(None),
    refresh_token: str | None = Form(None),
    scope: str | None = Form(None),
    db: Session = Depends(get_db),
):
    c = client(db, client_id)
    if not c:
        return error("invalid_client", "Cliente invalido", 401)
    if grant_type == "authorization_code":
        if (
            not code
            or not redirect_uri
            or not code_verifier
            or not VERIFIER_RE.fullmatch(code_verifier)
        ):
            return error(
                "invalid_request", "Parametros do authorization code invalidos"
            )
        rec = db.scalar(
            select(AuthorizationCode)
            .where(AuthorizationCode.code_hash == hash_secret(code))
            .with_for_update()
        )
        if (
            not rec
            or rec.client_id != client_id
            or rec.redirect_uri != redirect_uri
            or rec.consumed_at
            or rec.expires_at <= now()
            or not hmac_compare(pkce_s256(code_verifier), rec.code_challenge)
        ):
            return error("invalid_grant", "Codigo ou PKCE invalido")
        rec.consumed_at = now()
        body = issue(db, client_id, rec.user_id, rec.scope)
        audit(db, "tokens_issued", True, client_id, rec.user_id)
        db.commit()
        return JSONResponse(
            body, headers={"Cache-Control": "no-store", "Pragma": "no-cache"}
        )
    if grant_type == "refresh_token":
        if not refresh_token:
            return error("invalid_request", "refresh_token obrigatorio")
        old = db.scalar(
            select(OAuthToken)
            .where(OAuthToken.refresh_token_hash == hash_secret(refresh_token))
            .with_for_update()
        )
        if (
            not old
            or old.client_id != client_id
            or old.revoked_at
            or not old.refresh_expires_at
            or old.refresh_expires_at <= now()
        ):
            return error("invalid_grant", "Refresh token invalido")
        requested = scopes(scope) if scope else scopes(old.scope)
        if not requested.issubset(scopes(old.scope)):
            return error("invalid_scope", "Refresh nao amplia scopes")
        old.revoked_at = now()
        body = issue(db, client_id, old.user_id, " ".join(sorted(requested)))
        db.commit()
        return JSONResponse(
            body, headers={"Cache-Control": "no-store", "Pragma": "no-cache"}
        )
    return error("unsupported_grant_type", "Grant nao suportado")

def hmac_compare(a, b):
    import hmac

    return hmac.compare_digest(a, b)

def require(required):
    def dep(
        credentials: HTTPAuthorizationCredentials | None = Depends(bearer),
        db: Session = Depends(get_db),
    ):
        if not credentials:
            raise HTTPException(
                401, "Bearer ausente", headers={"WWW-Authenticate": "Bearer"}
            )
        t = db.scalar(
            select(OAuthToken).where(
                OAuthToken.access_token_hash == hash_secret(credentials.credentials)
            )
        )
        if not t or t.revoked_at or t.access_expires_at <= now():
            raise HTTPException(401, "Token invalido")
        if required not in scopes(t.scope):
            raise HTTPException(403, "Scope insuficiente")
        return db.get(User, t.user_id), t

    return dep

@app.get("/api/profile")
def profile(auth=Depends(require("profile:read"))):
    u, t = auth
    return {"sub": str(u.id), "username": u.username, "scope": t.scope}


@app.get("/api/admin")
def admin(auth=Depends(require("admin:read"))):
    u, t = auth
    return {"username": u.username, "scope": t.scope}


@app.get("/api/users")
def list_users(auth=Depends(require("users:read")), db: Session = Depends(get_db)):
    u, t = auth
    users = db.scalars(select(User)).all()
    return [
        {
            "id": str(u.id),
            "username": u.username,
            "active": u.active,
            "created_at": u.created_at.isoformat() if u.created_at else None,
        }
        for u in users
    ]





