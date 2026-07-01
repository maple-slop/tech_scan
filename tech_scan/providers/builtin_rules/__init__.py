from __future__ import annotations

from . import backend, cms, frontend, implied, server


RULES = [
    *server.RULES,
    *frontend.RULES,
    *backend.RULES,
    *cms.RULES,
]

IMPLIED_BACKENDS = implied.BACKENDS
IMPLIED_FRONTENDS = implied.FRONTENDS
