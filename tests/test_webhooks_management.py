"""
Comprehensive test suite for webhooks_management.py with 100% coverage.

Tests all webhook endpoints including:
- Create, list, get, update, delete webhooks
- Test webhook delivery
- Get delivery history
- Authorization and error handling
"""

import pytest
import pytest_asyncio
import json
from datetime import datetime
from unittest.mock import Mock, AsyncMock, patch, MagicMock
from fastapi import FastAPI
from httpx import AsyncClient, ASGITransport
import uuid

from app.routes.webhooks_management import router, WebhookCreate, WebhookUpdate
from app.auth import TokenData


# =============================================================================
# FIXTURES
# =============================================================================

@pytest_asyncio.fixture
async def test_app(redis_client):
    """Create test FastAPI app with webhooks router"""
    app = FastAPI()
    app.state.redis = redis_client
    app.include_router(router)
    yield app


@pytest_asyncio.fixture
async def authenticated_client(test_app):
    """Create async client with mocked authentication"""
    
    # Mock the get_current_client dependency
    async def mock_get_current_client():
        return TokenData(
            sub="test_user_123", 
            email="test@example.com",
            exp=1735689600,  # Future timestamp
            jti="test_jti_1234567890123456",
            iss="test_issuer",
            aud="test_audience"
        )
    
    # Override the dependency
    from app.routes.webhooks_management import get_current_client
    test_app.dependency_overrides[get_current_client] = mock_get_current_client
    
    async with AsyncClient(
        transport=ASGITransport(app=test_app),
        base_url="http://test"
    ) as client:
        yield client


@pytest_asyncio.fixture
async def sample_webhook(redis_client):
    """Create a sample webhook in Redis for testing"""
    webhook_id = str(uuid.uuid4())
    webhook_data = {
        "id": webhook_id,
        "user_id": "test_user_123",
        "url": "https://example.com/webhook",
        "events": ["validation.completed"],
        "secret": "test_secret_12345678",
        "status": "active",
        "description": "Test webhook",
        "created_at": datetime.utcnow().isoformat(),
        "deliveries": {
            "total": 0,
            "successful": 0,
            "failed": 0
        }
    }
    
    from app.json_utils import dumps
    await redis_client.set(f"webhook:{webhook_id}", dumps(webhook_data))
    await redis_client.sadd("user:test_user_123:webhooks", webhook_id)
    
    return webhook_data


# =============================================================================
# TEST CREATE WEBHOOK
# =============================================================================

@pytest.mark.asyncio
class TestCreateWebhook:
    """Test webhook creation endpoint"""
    
    async def test_create_webhook_success(self, authenticated_client, redis_client):
        """Test successful webhook creation"""
        payload = {
            "url": "https://example.com/webhook",
            "events": ["validation.completed", "batch.completed"],
            "description": "My webhook"
        }
        
        response = await authenticated_client.post("/webhooks/", json=payload)
        
        assert response.status_code == 200
        data = response.json()
        
        # Verify response structure
        assert "id" in data
        assert data["url"] == payload["url"]
        assert data["events"] == payload["events"]
        assert data["description"] == payload["description"]
        assert data["status"] == "active"
        assert data["user_id"] == "test_user_123"
        
        # Secret should be masked
        assert data["secret"].endswith("...")
        assert len(data["secret"]) < 32
        
        # Verify stored in Redis
        from app.json_utils import loads
        webhook_data = await redis_client.get(f"webhook:{data['id']}")
        assert webhook_data is not None
        
        stored = loads(webhook_data)
        assert stored["url"] == payload["url"]
        assert len(stored["secret"]) > 20  # Full secret stored
        
        # Verify added to user's webhook list
        user_webhooks = await redis_client.smembers("user:test_user_123:webhooks")
        assert data["id"].encode() in user_webhooks
    
    async def test_create_webhook_with_custom_secret(self, authenticated_client, redis_client):
        """Test webhook creation with custom secret"""
        custom_secret = "my_custom_secret_key_12345678"
        payload = {
            "url": "https://example.com/webhook",
            "events": ["validation.completed"],
            "secret": custom_secret
        }
        
        response = await authenticated_client.post("/webhooks/", json=payload)
        
        assert response.status_code == 200
        data = response.json()
        
        # Verify custom secret is used (masked in response)
        assert data["secret"].startswith(custom_secret[:8])
        
        # Verify full secret stored in Redis
        from app.json_utils import loads
        webhook_data = await redis_client.get(f"webhook:{data['id']}")
        stored = loads(webhook_data)
        assert stored["secret"] == custom_secret
    
    async def test_create_webhook_redis_error(self, authenticated_client, redis_client):
        """Test webhook creation with Redis error"""
        payload = {
            "url": "https://example.com/webhook",
            "events": ["validation.completed"]
        }
        
        # Mock Redis to raise an exception
        with patch.object(redis_client, 'set', side_effect=Exception("Redis error")):
            response = await authenticated_client.post("/webhooks/", json=payload)
            
            assert response.status_code == 500
            assert "Failed to create webhook" in response.json()["detail"]
    
    async def test_create_webhook_default_events(self, authenticated_client):
        """Test webhook creation uses default events"""
        payload = {
            "url": "https://example.com/webhook"
            # No events specified
        }
        
        response = await authenticated_client.post("/webhooks/", json=payload)
        
        assert response.status_code == 200
        data = response.json()
        assert "validation.completed" in data["events"]
        assert "batch.completed" in data["events"]


# =============================================================================
# TEST LIST WEBHOOKS
# =============================================================================

@pytest.mark.asyncio
class TestListWebhooks:
    """Test listing webhooks endpoint"""
    
    async def test_list_webhooks_empty(self, authenticated_client):
        """Test listing webhooks when none exist"""
        response = await authenticated_client.get("/webhooks/")
        
        assert response.status_code == 200
        data = response.json()
        assert data["webhooks"] == []
        assert data["count"] == 0
    
    async def test_list_webhooks_multiple(self, authenticated_client, redis_client):
        """Test listing multiple webhooks"""
        from app.json_utils import dumps
        
        # Create multiple webhooks
        webhooks = []
        for i in range(3):
            webhook_id = str(uuid.uuid4())
            webhook_data = {
                "id": webhook_id,
                "user_id": "test_user_123",
                "url": f"https://example.com/webhook{i}",
                "events": ["validation.completed"],
                "secret": f"secret_{i}_12345678",
                "status": "active",
                "deliveries": {"total": 0, "successful": 0, "failed": 0}
            }
            webhooks.append(webhook_data)
            await redis_client.set(f"webhook:{webhook_id}", dumps(webhook_data))
            await redis_client.sadd("user:test_user_123:webhooks", webhook_id)
        
        response = await authenticated_client.get("/webhooks/")
        
        assert response.status_code == 200
        data = response.json()
        assert data["count"] == 3
        assert len(data["webhooks"]) == 3
    
    async def test_list_webhooks_masks_secrets(self, authenticated_client, sample_webhook):
        """Test that listing webhooks masks secrets"""
        response = await authenticated_client.get("/webhooks/")
        
        assert response.status_code == 200
        data = response.json()
        assert len(data["webhooks"]) == 1
        
        webhook = data["webhooks"][0]
        # Secret should be masked
        assert webhook["secret"].endswith("...")
        assert len(webhook["secret"]) < len(sample_webhook["secret"])
    
    async def test_list_webhooks_redis_error(self, authenticated_client, redis_client):
        """Test listing webhooks with Redis error"""
        with patch.object(redis_client, 'smembers', side_effect=Exception("Redis error")):
            response = await authenticated_client.get("/webhooks/")
            
            assert response.status_code == 500
            assert "Failed to list webhooks" in response.json()["detail"]


# =============================================================================
# TEST GET WEBHOOK
# =============================================================================

@pytest.mark.asyncio
class TestGetWebhook:
    """Test getting single webhook endpoint"""
    
    async def test_get_webhook_success(self, authenticated_client, sample_webhook):
        """Test successfully getting a webhook"""
        webhook_id = sample_webhook["id"]
        
        response = await authenticated_client.get(f"/webhooks/{webhook_id}")
        
        assert response.status_code == 200
        data = response.json()
        
        assert data["id"] == webhook_id
        assert data["url"] == sample_webhook["url"]
        assert data["user_id"] == sample_webhook["user_id"]
        # Secret should be masked
        assert data["secret"].endswith("...")
    
    async def test_get_webhook_not_found(self, authenticated_client):
        """Test getting non-existent webhook"""
        fake_id = str(uuid.uuid4())
        
        response = await authenticated_client.get(f"/webhooks/{fake_id}")
        
        assert response.status_code == 404
        assert "Webhook not found" in response.json()["detail"]
    
    async def test_get_webhook_unauthorized(self, authenticated_client, redis_client):
        """Test getting webhook owned by another user"""
        from app.json_utils import dumps
        
        # Create webhook owned by different user
        webhook_id = str(uuid.uuid4())
        webhook_data = {
            "id": webhook_id,
            "user_id": "different_user",  # Different user
            "url": "https://example.com/webhook",
            "events": ["validation.completed"],
            "secret": "secret_12345678",
            "status": "active",
            "deliveries": {"total": 0, "successful": 0, "failed": 0}
        }
        await redis_client.set(f"webhook:{webhook_id}", dumps(webhook_data))
        
        response = await authenticated_client.get(f"/webhooks/{webhook_id}")
        
        assert response.status_code == 403
        assert "Not authorized" in response.json()["detail"]
    
    async def test_get_webhook_redis_error(self, authenticated_client, redis_client):
        """Test getting webhook with Redis error"""
        webhook_id = str(uuid.uuid4())
        
        with patch.object(redis_client, 'get', side_effect=Exception("Redis error")):
            response = await authenticated_client.get(f"/webhooks/{webhook_id}")
            
            assert response.status_code == 500
            assert "Failed to get webhook" in response.json()["detail"]


# =============================================================================
# TEST UPDATE WEBHOOK
# =============================================================================

@pytest.mark.asyncio
class TestUpdateWebhook:
    """Test updating webhook endpoint"""
    
    async def test_update_webhook_url(self, authenticated_client, sample_webhook):
        """Test updating webhook URL"""
        webhook_id = sample_webhook["id"]
        new_url = "https://newdomain.com/webhook"
        
        response = await authenticated_client.patch(
            f"/webhooks/{webhook_id}",
            json={"url": new_url}
        )
        
        assert response.status_code == 200
        data = response.json()
        assert data["url"] == new_url
        assert "updated_at" in data
    
    async def test_update_webhook_events(self, authenticated_client, sample_webhook):
        """Test updating webhook events"""
        webhook_id = sample_webhook["id"]
        new_events = ["batch.completed", "usage.limit_reached"]
        
        response = await authenticated_client.patch(
            f"/webhooks/{webhook_id}",
            json={"events": new_events}
        )
        
        assert response.status_code == 200
        data = response.json()
        assert data["events"] == new_events
    
    async def test_update_webhook_status(self, authenticated_client, sample_webhook):
        """Test updating webhook status"""
        webhook_id = sample_webhook["id"]
        
        response = await authenticated_client.patch(
            f"/webhooks/{webhook_id}",
            json={"status": "paused"}
        )
        
        assert response.status_code == 200
        data = response.json()
        assert data["status"] == "paused"
    
    async def test_update_webhook_description(self, authenticated_client, sample_webhook):
        """Test updating webhook description (including empty string)"""
        webhook_id = sample_webhook["id"]
        
        # Update to new description
        response = await authenticated_client.patch(
            f"/webhooks/{webhook_id}",
            json={"description": "Updated description"}
        )
        assert response.status_code == 200
        assert response.json()["description"] == "Updated description"
        
        # Update to empty string (should work because we check 'is not None')
        response = await authenticated_client.patch(
            f"/webhooks/{webhook_id}",
            json={"description": ""}
        )
        assert response.status_code == 200
        assert response.json()["description"] == ""
    
    async def test_update_webhook_not_found(self, authenticated_client):
        """Test updating non-existent webhook"""
        fake_id = str(uuid.uuid4())
        
        response = await authenticated_client.patch(
            f"/webhooks/{fake_id}",
            json={"status": "paused"}
        )
        
        assert response.status_code == 404
        assert "Webhook not found" in response.json()["detail"]
    
    async def test_update_webhook_unauthorized(self, authenticated_client, redis_client):
        """Test updating webhook owned by another user"""
        from app.json_utils import dumps
        
        # Create webhook owned by different user
        webhook_id = str(uuid.uuid4())
        webhook_data = {
            "id": webhook_id,
            "user_id": "different_user",
            "url": "https://example.com/webhook",
            "events": ["validation.completed"],
            "secret": "secret_12345678",
            "status": "active",
            "deliveries": {"total": 0, "successful": 0, "failed": 0}
        }
        await redis_client.set(f"webhook:{webhook_id}", dumps(webhook_data))
        
        response = await authenticated_client.patch(
            f"/webhooks/{webhook_id}",
            json={"status": "paused"}
        )
        
        assert response.status_code == 403
        assert "Not authorized" in response.json()["detail"]
    
    async def test_update_webhook_redis_error(self, authenticated_client, sample_webhook, test_app):
        """Test updating webhook with Redis error"""
        webhook_id = sample_webhook["id"]
        
        with patch.object(test_app.state.redis, 'set', side_effect=Exception("Redis error")):
            response = await authenticated_client.patch(
                f"/webhooks/{webhook_id}",
                json={"status": "paused"}
            )
            
            assert response.status_code == 500
            assert "Failed to update webhook" in response.json()["detail"]


# =============================================================================
# TEST DELETE WEBHOOK
# =============================================================================

@pytest.mark.asyncio
class TestDeleteWebhook:
    """Test deleting webhook endpoint"""
    
    async def test_delete_webhook_success(self, authenticated_client, sample_webhook, redis_client):
        """Test successfully deleting a webhook"""
        webhook_id = sample_webhook["id"]
        
        response = await authenticated_client.delete(f"/webhooks/{webhook_id}")
        
        assert response.status_code == 200
        data = response.json()
        assert data["deleted"] is True
        assert data["webhook_id"] == webhook_id
        
        # Verify webhook deleted from Redis
        webhook_data = await redis_client.get(f"webhook:{webhook_id}")
        assert webhook_data is None
        
        # Verify removed from user's webhook list
        user_webhooks = await redis_client.smembers("user:test_user_123:webhooks")
        assert webhook_id.encode() not in user_webhooks
    
    async def test_delete_webhook_not_found(self, authenticated_client):
        """Test deleting non-existent webhook"""
        fake_id = str(uuid.uuid4())
        
        response = await authenticated_client.delete(f"/webhooks/{fake_id}")
        
        assert response.status_code == 404
        assert "Webhook not found" in response.json()["detail"]
    
    async def test_delete_webhook_unauthorized(self, authenticated_client, redis_client):
        """Test deleting webhook owned by another user"""
        from app.json_utils import dumps
        
        # Create webhook owned by different user
        webhook_id = str(uuid.uuid4())
        webhook_data = {
            "id": webhook_id,
            "user_id": "different_user",
            "url": "https://example.com/webhook",
            "events": ["validation.completed"],
            "secret": "secret_12345678",
            "status": "active",
            "deliveries": {"total": 0, "successful": 0, "failed": 0}
        }
        await redis_client.set(f"webhook:{webhook_id}", dumps(webhook_data))
        
        response = await authenticated_client.delete(f"/webhooks/{webhook_id}")
        
        assert response.status_code == 403
        assert "Not authorized" in response.json()["detail"]
    
    async def test_delete_webhook_redis_error(self, authenticated_client, sample_webhook, test_app):
        """Test deleting webhook with Redis error"""
        webhook_id = sample_webhook["id"]
        
        with patch.object(test_app.state.redis, 'delete', side_effect=Exception("Redis error")):
            response = await authenticated_client.delete(f"/webhooks/{webhook_id}")
            
            assert response.status_code == 500
            assert "Failed to delete webhook" in response.json()["detail"]


# =============================================================================
# TEST WEBHOOK TEST ENDPOINT
# =============================================================================

@pytest.mark.asyncio
class TestTestWebhook:
    """Test webhook testing endpoint"""
    
    async def test_test_webhook_success(self, authenticated_client, sample_webhook):
        """Test sending test webhook successfully"""
        webhook_id = sample_webhook["id"]
        
        # Mock the send_webhook function where it is defined, as it is imported inside the function
        with patch('app.jobs.webhooks.send_webhook', new_callable=AsyncMock) as mock_send:
            mock_send.return_value = None  # Successful send
            
            response = await authenticated_client.post(f"/webhooks/{webhook_id}/test")
            
            assert response.status_code == 200
            data = response.json()
            assert data["status"] == "test_sent"
            assert "Test webhook delivered" in data["message"]
            
            # Verify send_webhook was called with correct parameters
            mock_send.assert_called_once()
            args = mock_send.call_args[0]
            assert args[0] == sample_webhook["url"]
            assert args[2] == sample_webhook["secret"]
            # Payload should contain test event
            payload = args[1]
            assert payload["event"] == "test.webhook"
            assert payload["data"]["webhook_id"] == webhook_id
    
    async def test_test_webhook_send_failure(self, authenticated_client, sample_webhook):
        """Test webhook test when sending fails"""
        webhook_id = sample_webhook["id"]
        
        # Mock send_webhook to raise an exception
        with patch('app.jobs.webhooks.send_webhook', new_callable=AsyncMock) as mock_send:
            mock_send.side_effect = Exception("Connection timeout")
            
            response = await authenticated_client.post(f"/webhooks/{webhook_id}/test")
            
            assert response.status_code == 200  # Still returns 200
            data = response.json()
            assert data["status"] == "test_failed"
            assert "Connection timeout" in data["error"]
    
    async def test_test_webhook_not_found(self, authenticated_client):
        """Test testing non-existent webhook"""
        fake_id = str(uuid.uuid4())
        
        response = await authenticated_client.post(f"/webhooks/{fake_id}/test")
        
        assert response.status_code == 404
        assert "Webhook not found" in response.json()["detail"]
    
    async def test_test_webhook_unauthorized(self, authenticated_client, redis_client):
        """Test testing webhook owned by another user"""
        from app.json_utils import dumps
        
        # Create webhook owned by different user
        webhook_id = str(uuid.uuid4())
        webhook_data = {
            "id": webhook_id,
            "user_id": "different_user",
            "url": "https://example.com/webhook",
            "events": ["validation.completed"],
            "secret": "secret_12345678",
            "status": "active",
            "deliveries": {"total": 0, "successful": 0, "failed": 0}
        }
        await redis_client.set(f"webhook:{webhook_id}", dumps(webhook_data))
        
        response = await authenticated_client.post(f"/webhooks/{webhook_id}/test")
        
        assert response.status_code == 403
        assert "Not authorized" in response.json()["detail"]


# =============================================================================
# TEST GET DELIVERIES
# =============================================================================

@pytest.mark.asyncio
class TestGetDeliveries:
    """Test webhook deliveries endpoint"""
    
    async def test_get_deliveries_empty(self, authenticated_client, sample_webhook):
        """Test getting deliveries when none exist"""
        webhook_id = sample_webhook["id"]
        
        response = await authenticated_client.get(f"/webhooks/{webhook_id}/deliveries")
        
        assert response.status_code == 200
        data = response.json()
        assert data["deliveries"] == []
        assert data["count"] == 0
    
    async def test_get_deliveries_with_data(self, authenticated_client, sample_webhook, redis_client):
        """Test getting deliveries with data"""
        from app.json_utils import dumps
        import time
        
        webhook_id = sample_webhook["id"]
        
        # Add some deliveries to Redis sorted set
        deliveries = []
        for i in range(3):
            delivery = {
                "id": f"delivery_{i}",
                "event": "validation.completed",
                "status": "success" if i % 2 == 0 else "failed",
                "response_code": 200 if i % 2 == 0 else 500
            }
            timestamp = time.time() - (i * 100)  # Different timestamps
            deliveries.append((dumps(delivery), timestamp))
        
        # Add to sorted set (score = timestamp)
        for delivery_data, timestamp in deliveries:
            await redis_client.zadd(
                f"webhook:{webhook_id}:deliveries",
                {delivery_data: timestamp}
            )
        
        response = await authenticated_client.get(f"/webhooks/{webhook_id}/deliveries")
        
        assert response.status_code == 200
        data = response.json()
        assert data["count"] == 3
        assert len(data["deliveries"]) == 3
        
        # Verify deliveries returned in reverse chronological order (most recent first)
        # First delivery should be the most recent (i=0)
        assert data["deliveries"][0]["status"] == "success"
    
    async def test_get_deliveries_limit(self, authenticated_client, sample_webhook, redis_client):
        """Test getting deliveries with limit parameter"""
        from app.json_utils import dumps
        import time
        
        webhook_id = sample_webhook["id"]
        
        # Add 10 deliveries
        for i in range(10):
            delivery = {"event": "test", "index": i}
            await redis_client.zadd(
                f"webhook:{webhook_id}:deliveries",
                {dumps(delivery): time.time() - i}
            )
        
        # Request only 5
        response = await authenticated_client.get(f"/webhooks/{webhook_id}/deliveries?limit=5")
        
        assert response.status_code == 200
        data = response.json()
        assert data["count"] == 5
        assert len(data["deliveries"]) == 5
    
    async def test_get_deliveries_not_found(self, authenticated_client):
        """Test getting deliveries for non-existent webhook"""
        fake_id = str(uuid.uuid4())
        
        response = await authenticated_client.get(f"/webhooks/{fake_id}/deliveries")
        
        assert response.status_code == 404
        assert "Webhook not found" in response.json()["detail"]
    
    async def test_get_deliveries_unauthorized(self, authenticated_client, redis_client):
        """Test getting deliveries for webhook owned by another user"""
        from app.json_utils import dumps
        
        # Create webhook owned by different user
        webhook_id = str(uuid.uuid4())
        webhook_data = {
            "id": webhook_id,
            "user_id": "different_user",
            "url": "https://example.com/webhook",
            "events": ["validation.completed"],
            "secret": "secret_12345678",
            "status": "active",
            "deliveries": {"total": 0, "successful": 0, "failed": 0}
        }
        await redis_client.set(f"webhook:{webhook_id}", dumps(webhook_data))
        
        response = await authenticated_client.get(f"/webhooks/{webhook_id}/deliveries")
        
        assert response.status_code == 403
        assert "Not authorized" in response.json()["detail"]
