from slowapi import Limiter
from slowapi.util import get_remote_address

# Per-IP by default (get_remote_address reads request.client.host). In-memory
# storage - fine for one dev process; swap for a Redis storage backend before
# running multiple workers, same caveat as the WebAuthn challenge store.
limiter = Limiter(key_func=get_remote_address)
