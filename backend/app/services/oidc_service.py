from authlib.integrations.starlette_client import OAuth
from app.config import settings
oauth = OAuth()
if settings.OIDC_CLIENT_ID:
    oauth.register(name="company", client_id=settings.OIDC_CLIENT_ID, client_secret=settings.OIDC_CLIENT_SECRET, server_metadata_url=settings.OIDC_DISCOVERY_URL, client_kwargs={"scope": "openid email profile", "code_challenge_method": "S256"})
