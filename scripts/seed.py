import json
from sqlalchemy import select
from app.database import Base, SessionLocal, engine
from app.models import OAuthClient

Base.metadata.create_all(bind=engine)
with SessionLocal() as db:
    cid = "client_id_tcc_uspesalq"
    if not db.scalar(select(OAuthClient).where(OAuthClient.client_id == cid)):
        db.add(
            OAuthClient(
                client_id=cid,
                name="TCC Esalq",
                redirect_uris=json.dumps(
                    [
                        "https://oauth.pstmn.io/v1/callback",
                        "http://localhost:8000/callback",
                        "http://localhost:8000/postman/callback",
                    ]
                ),
                allowed_scopes="profile:read admin:read offline_access users:read",
                active=True,
            )
        )
        db.commit()
        print("Cliente criado")
    else:
        print("Cliente ja existe")
