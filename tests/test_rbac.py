import pytest
from rbac.roles import get_role, can_access_namespace, assert_write_access, Role

def test_get_role_valid():
    admin = get_role("admin")
    assert admin.name == "admin"
    assert admin.can_write is True
    
    analyst = get_role("analyst")
    assert analyst.name == "analyst"
    assert analyst.can_write is False

def test_get_role_invalid():
    with pytest.raises(ValueError, match="Unknown role"):
        get_role("hacker")

def test_can_access_namespace():
    # Admin can access all
    assert can_access_namespace("admin", "hr") is True
    assert can_access_namespace("admin", "finance") is True
    
    # Analyst can access general and legal but not hr
    assert can_access_namespace("analyst", "general") is True
    assert can_access_namespace("analyst", "legal") is True
    assert can_access_namespace("analyst", "hr") is False
    
    # Auditor can access audit only
    assert can_access_namespace("auditor", "audit") is True
    assert can_access_namespace("auditor", "general") is False
    
    # Readonly can access general only
    assert can_access_namespace("readonly", "general") is True
    assert can_access_namespace("readonly", "audit") is False

def test_assert_write_access():
    # Admin should not raise
    assert_write_access("admin")
    
    # Others should raise PermissionError
    with pytest.raises(PermissionError, match="does not have write access"):
        assert_write_access("analyst")
    with pytest.raises(PermissionError, match="does not have write access"):
        assert_write_access("auditor")
    with pytest.raises(PermissionError, match="does not have write access"):
        assert_write_access("readonly")
