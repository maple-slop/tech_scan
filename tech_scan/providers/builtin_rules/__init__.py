from __future__ import annotations

from . import backend, frontend, implied, server


RULES = [
    *server.RULES,
    *frontend.RULES,
    *backend.RULES,
]

IMPLIED_BACKENDS = implied.BACKENDS
IMPLIED_FRONTENDS = implied.FRONTENDS
