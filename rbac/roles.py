from dataclasses import dataclass


@dataclass(frozen=True)
class Role:
    name: str
    can_read: bool
    can_write: bool
    allowed_namespaces: frozenset[str]
    rate_limit_rpm: int


ROLES: dict[str, Role] = {
    "admin": Role(
        name="admin",
        can_read=True,
        can_write=True,
        allowed_namespaces=frozenset({"general", "hr", "finance", "legal", "audit"}),
        rate_limit_rpm=500,
    ),
    "analyst": Role(
        name="analyst",
        can_read=True,
        can_write=False,
        allowed_namespaces=frozenset({"general", "legal"}),
        rate_limit_rpm=120,
    ),
    "auditor": Role(
        name="auditor",
        can_read=True,
        can_write=False,
        allowed_namespaces=frozenset({"audit"}),
        rate_limit_rpm=60,
    ),
    "readonly": Role(
        name="readonly",
        can_read=True,
        can_write=False,
        allowed_namespaces=frozenset({"general"}),
        rate_limit_rpm=30,
    ),
}


def get_role(role_name: str) -> Role:
    role = ROLES.get(role_name)
    if role is None:
        raise ValueError(f"Unknown role: {role_name!r}. Valid roles: {list(ROLES)}")
    return role


def can_access_namespace(role_name: str, namespace: str) -> bool:
    role = get_role(role_name)
    return namespace in role.allowed_namespaces


def assert_write_access(role_name: str) -> None:
    role = get_role(role_name)
    if not role.can_write:
        raise PermissionError(f"Role {role_name!r} does not have write access")
