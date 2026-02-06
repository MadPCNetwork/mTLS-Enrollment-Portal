# Backend Tests

## Overview

Comprehensive test suite for the mTLS PKI Portal backend, covering authentication, authorization, certificate lifecycle, and security controls.

## Test Structure

```
backend/tests/
├── test_crl_format.py      # CRL generation tests
├── test_security.py        # Security controls and audit logging
├── test_api.py             # API endpoint integration tests
└── README.md               # This file
```

## Test Categories

### Unit Tests (`-m unit`)
Fast tests with no external dependencies:
- Authentication logic
- Authorization checks
- Model properties
- Cryptographic functions
- Configuration parsing

### Integration Tests (`-m integration`)
Tests requiring database and external services:
- Full API endpoint testing
- Database operations
- Rate limiting enforcement
- Complete certificate lifecycle

### Security Tests (`-m security`)
Security-focused tests:
- Audit logging
- Input validation
- Authorization enforcement
- Rate limiting
- Security headers

## Running Tests

### All Tests
```bash
cd backend
pip install -r requirements.txt
pytest tests/ -v
```

### Unit Tests Only (Fast)
```bash
pytest tests/ -v -m "not integration"
```

### Integration Tests
```bash
# Start PostgreSQL first
docker run -d --name test-postgres \
  -e POSTGRES_DB=test_pki \
  -e POSTGRES_USER=test_pki \
  -e POSTGRES_PASSWORD=test_password \
  -p 5432:5432 \
  postgres:16-alpine

# Set environment variables
export POSTGRES_HOST=localhost
export POSTGRES_PORT=5432
export POSTGRES_USER=test_pki
export POSTGRES_PASSWORD=test_password
export POSTGRES_DB=test_pki

# Run tests
pytest tests/ -v -m integration

# Cleanup
docker stop test-postgres && docker rm test-postgres
```

### Security Tests Only
```bash
pytest tests/test_security.py -v
```

### With Coverage
```bash
pytest tests/ -v --cov=app --cov-report=html --cov-report=term
# Open htmlcov/index.html to view coverage report
```

### Specific Test File
```bash
pytest tests/test_security.py -v
pytest tests/test_api.py -v
pytest tests/test_crl_format.py -v
```

### Specific Test Function
```bash
pytest tests/test_security.py::TestAuthentication::test_validate_token_success -v
```

## Test Configuration

Configuration is in `pytest.ini`:

```ini
[tool:pytest]
python_files = test_*.py
python_classes = Test*
python_functions = test_*
asyncio_mode = auto

markers =
    unit: Unit tests (fast, no external dependencies)
    integration: Integration tests (require database, slower)
    security: Security-focused tests
    slow: Slow running tests
```

## Writing New Tests

### Test File Template

```python
"""
Description of what this test file covers.
"""

import pytest
from app.models import YourModel


class TestYourFeature:
    """Test your feature."""
    
    def test_something(self):
        """Test description."""
        # Arrange
        expected = "value"
        
        # Act
        result = your_function()
        
        # Assert
        assert result == expected
    
    @pytest.mark.asyncio
    async def test_async_function(self):
        """Test async function."""
        result = await your_async_function()
        assert result is not None
```

### Fixtures

Create reusable fixtures in `conftest.py`:

```python
# backend/tests/conftest.py
import pytest

@pytest.fixture
def mock_user():
    """Mock authenticated user."""
    from app.auth import UserClaims
    return UserClaims(
        sub="test-user",
        email="test@example.com",
        groups=["staff"],
        raw_claims={}
    )
```

### Async Tests

Use `@pytest.mark.asyncio` for async functions:

```python
@pytest.mark.asyncio
async def test_async_endpoint(client):
    response = await client.get("/api/v1/endpoint")
    assert response.status_code == 200
```

### Mocking

Use `unittest.mock` or `pytest-mock`:

```python
from unittest.mock import patch, MagicMock

def test_with_mock():
    with patch('app.auth.validate_token') as mock_validate:
        mock_validate.return_value = mock_user
        # Test code here
```

## Coverage Goals

**Target Coverage:** 80%+

**Current Coverage by Module:**
- `app/auth.py` - 60% (needs more tests)
- `app/crypto.py` - 40% (needs more tests)
- `app/routes/requests.py` - 30% (needs more tests)
- `app/models.py` - 80% (good)
- `app/config.py` - 50% (needs more tests)
- `app/audit.py` - 70% (good)

**Priority Areas:**
1. API endpoint tests (routes/requests.py)
2. Cryptographic operations (crypto.py)
3. Authentication flows (auth.py)

## Test Data

### Mock Users

```python
# Regular user
mock_user = UserClaims(
    sub="user123",
    email="user@example.com",
    name="Test User",
    groups=["staff"],
    raw_claims={}
)

# Admin user
mock_admin = UserClaims(
    sub="admin123",
    email="admin@example.com",
    name="Admin User",
    groups=["ROOT"],
    raw_claims={}
)

# Approver user
mock_approver = UserClaims(
    sub="approver123",
    email="approver@example.com",
    name="Approver User",
    groups=["security"],
    raw_claims={}
)
```

### Mock Certificates

```python
from datetime import datetime, timedelta

mock_cert = Certificate(
    request_id=1,
    serial_number="abc123def456",
    subject="CN=Test User,O=Acme Corp",
    certificate_pem="-----BEGIN CERTIFICATE-----\n...",
    not_before=datetime.utcnow(),
    not_after=datetime.utcnow() + timedelta(days=30),
    revoked_at=None,
)
```

## Continuous Improvement

### Adding New Tests

When adding new features:

1. **Write tests first** (TDD approach)
2. **Add unit tests** for business logic
3. **Add integration tests** for API endpoints
4. **Add security tests** for security-critical code
5. **Update coverage goals**

### Test Review Checklist

- [ ] Tests are independent (no shared state)
- [ ] Tests are deterministic (no random failures)
- [ ] Tests have clear descriptions
- [ ] Tests follow AAA pattern (Arrange, Act, Assert)
- [ ] Async tests use `@pytest.mark.asyncio`
- [ ] Integration tests are marked with `@pytest.mark.integration`
- [ ] Security tests are marked with `@pytest.mark.security`
- [ ] Tests clean up after themselves
- [ ] Tests don't rely on external services (use mocks)

## Troubleshooting

### "No tests found"

**Cause:** Test files don't match discovery pattern

**Solution:**
- Ensure files start with `test_`
- Ensure test functions start with `test_`
- Check pytest.ini configuration

### "Database connection failed"

**Cause:** PostgreSQL not running or wrong credentials

**Solution:**
```bash
# Check PostgreSQL is running
docker ps | grep postgres

# Verify environment variables
echo $POSTGRES_HOST
echo $POSTGRES_PORT
```

### "Import errors"

**Cause:** Missing dependencies

**Solution:**
```bash
pip install -r requirements.txt
pip install pytest pytest-asyncio pytest-cov
```

### "Async tests not running"

**Cause:** Missing pytest-asyncio or wrong configuration

**Solution:**
```bash
pip install pytest-asyncio

# Ensure pytest.ini has:
# asyncio_mode = auto
```

## CI/CD Integration

Tests run automatically in GitLab CI:

- **On Merge Requests:** All tests run
- **On Default Branch:** All tests + security scans
- **On Tags:** Full pipeline + deployment

View results:
- Project → CI/CD → Pipelines
- Click on pipeline → View test results
- Download coverage report from artifacts

## References

- [pytest Documentation](https://docs.pytest.org/)
- [pytest-asyncio](https://pytest-asyncio.readthedocs.io/)
- [FastAPI Testing](https://fastapi.tiangolo.com/tutorial/testing/)
- [SQLAlchemy Testing](https://docs.sqlalchemy.org/en/20/orm/session_transaction.html#joining-a-session-into-an-external-transaction-such-as-for-test-suites)
