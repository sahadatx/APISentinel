"""Shared SQL predicates for owner and role-scoped client access."""
from sqlalchemy import exists, or_, select

from .models import Client, ClientMembership

ALL_CLIENT_ROLES = ("viewer", "analyst", "reviewer")


def client_access_filter(analyst_id: int, roles: tuple[str, ...] = ALL_CLIENT_ROLES):
    membership = exists(select(1).where(
        ClientMembership.client_id == Client.id,
        ClientMembership.analyst_id == analyst_id,
        ClientMembership.role.in_(roles),
    ))
    return or_(Client.owner_user_id == analyst_id, membership)
