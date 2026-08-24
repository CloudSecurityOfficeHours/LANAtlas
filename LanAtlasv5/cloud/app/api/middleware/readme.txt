What api/middleware/auth.py Does With Social OAuth
Even though Gmail, iCloud, etc. handle the actual credential verification, auth.py still has real work to do — OAuth doesn't eliminate the need for this file, it changes what's inside it.
1. OAuth Callback Handling
When a user logs in with Google, Google redirects back to your API with an authorization code. auth.py exchanges that code for user info:
python# simplified flow
def handle_oauth_callback(provider: str, code: str):
    token = exchange_code_for_token(provider, code)      # calls Google/Apple
    user_info = fetch_user_info(provider, token)          # gets email, sub claim
    user = find_or_create_user(user_info)                 # repositories/users.py
    session_token = create_session(user)                  # repositories/sessions.py
    return issue_jwt(user, session_token)
2. Verifying LAN Atlas's Own JWT on Every Request
After login, every subsequent API call carries LAN Atlas's own JWT (not Google's token). auth.py verifies that JWT and extracts the user identity:
pythondef verify_jwt(token: str) -> UserContext:
    payload = decode_jwt(token, SECRET_KEY)
    session = repositories.sessions.get_active(payload["session_id"])
    if session is None or session.revoked_at is not None:
        raise AuthenticationError("Session revoked or expired")
    return UserContext(
        user_id=payload["user_id"],
        organization_id=payload["organization_id"],
        role=payload["role"]
    )
This is the piece that makes sessions.revoked_at meaningful — Google doesn't know or care if you revoked a LAN Atlas session. Your own auth.py is what enforces that.
3. Injecting organization_id Into Every Request
This is the most security-critical job. Once the JWT is verified, auth.py attaches the authenticated user's organization_id to the request context so every downstream service and repository call is automatically tenant-scoped:
python# FastAPI dependency example
async def get_current_user(token: str = Depends(oauth2_scheme)) -> UserContext:
    user_context = verify_jwt(token)
    return user_context  # injected into every route that needs it
Every route handler then receives current_user.organization_id and passes it down. This is the single enforcement point for Broken Access Control (A01) — without it, a compromised or malformed request could query any tenant's data.
4. Rejecting Expired or Malformed Tokens
pythondef verify_jwt(token: str) -> UserContext:
    try:
        payload = decode_jwt(token, SECRET_KEY)
    except ExpiredSignatureError:
        raise AuthenticationError("Token expired — refresh required")
    except InvalidTokenError:
        raise AuthenticationError("Malformed token")

Summary — What Changes With Social OAuth vs Traditional Auth
ResponsibilityTraditional (username/password)Social OAuthVerify passwordauth.py checks hashGoogle/Apple does this — not your codeIssue your own sessionauth.pyauth.py — unchangedVerify JWT on each requestauth.pyauth.py — unchangedTrack failed loginsauth.py increments failed_login_countMostly N/A — provider handles lockoutHandle provider callbackN/Aauth.py — new responsibilityMap provider identity to userN/Aauth.py — oauth_provider + oauth_subject lookup
auth.py doesn't disappear with OAuth — its job shifts from "verify a password" to "verify a provider's claim and manage your own session on top of it." It's still the single most important file in api/middleware/ for enforcing Least Privilege and Centralized Enforcement.