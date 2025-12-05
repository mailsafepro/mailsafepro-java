"""
Tests para jobs_routes.py - Alcanzar 100% coverage
"""

import pytest
import json
import uuid
from unittest.mock import Mock, patch, AsyncMock
from fastapi import HTTPException, status
from fastapi.security import SecurityScopes

from app.jobs.jobs_routes import (
    router,
    JobCreateRequest,
    JobCreateResponse, 
    JobStatusResponse,
    JobResultEntry,
    JobResultsPage,
    _now_iso,
    _hash_idempotency,
    _get_json,
    create_job,
    get_job_status,
    get_job_results
)


class TestJobModels:
    """Tests para modelos Pydantic"""
    
    def test_job_create_request_list_source_validation(self):
        # Source=list requiere emails
        with pytest.raises(ValueError, match="emails requeridos"):
            JobCreateRequest(source="list")
    
    def test_job_create_request_upload_source_validation(self):
        # Source=upload requiere file_token
        with pytest.raises(ValueError, match="file_token requerido"):
            JobCreateRequest(source="upload")
    
    def test_job_create_request_valid_list(self):
        request = JobCreateRequest(
            source="list",
            emails=["test@example.com"],
            checksmtp=True,
            includerawdns=False
        )
        
        assert request.source == "list"
        assert request.emails == ["test@example.com"]
        assert request.checksmtp is True
        assert request.includerawdns is False
    
    def test_job_create_request_valid_upload(self):
        # El validador está asociado al campo 'emails', así que necesitamos
        # proporcionar emails como lista vacía incluso para source=upload
        request = JobCreateRequest(
            source="upload",
            file_token="file-token-123",
            emails=[],  # Lista vacía para pasar la validación del campo 'emails'
            sandbox=True
        )
        
        assert request.source == "upload"
        assert request.file_token == "file-token-123"
        assert request.sandbox is True
    
    def test_job_create_response(self):
        response = JobCreateResponse(
            job_id="test-job-123",
            status="queued",
            created_at="2023-01-01T00:00:00"
        )
        
        assert response.job_id == "test-job-123"
        assert response.status == "queued"
    
    def test_job_status_response(self):
        response = JobStatusResponse(
            job_id="test-job-123",
            status="processing",
            counts={"queued": 10, "processing": 5, "completed": 0},
            started_at="2023-01-01T00:00:00",
            finished_at=None,
            error=None
        )
        
        assert response.job_id == "test-job-123"
        assert response.status == "processing"
        assert response.counts["queued"] == 10
    
    def test_job_result_entry(self):
        entry = JobResultEntry(
            email="test@example.com",
            valid=True,
            riskscore=0.1,
            qualityscore=0.9,
            provider="gmail",
            reputation=0.95,
            smtp={"valid": True},
            dns={"mx": ["mx.gmail.com"]},
            metadata={"custom": "data"}
        )
        
        assert entry.email == "test@example.com"
        assert entry.valid is True
        assert entry.riskscore == 0.1
        assert entry.smtp["valid"] is True
    
    def test_job_results_page(self):
        results_page = JobResultsPage(
            job_id="test-job-123",
            page=1,
            size=100,
            total_pages=5,
            results=[]
        )
        
        assert results_page.job_id == "test-job-123"
        assert results_page.page == 1
        assert results_page.total_pages == 5


class TestHelperFunctions:
    """Tests para funciones auxiliares"""
    
    def test_now_iso(self):
        iso_time = _now_iso()
        assert "T" in iso_time
        # Should be in ISO format
    
    def test_hash_idempotency(self):
        key = "test-key"
        hash1 = _hash_idempotency(key)
        hash2 = _hash_idempotency(key)
        
        # Same input should produce same hash
        assert hash1 == hash2
        # Should be hex string
        assert len(hash1) == 64
        assert all(c in "0123456789abcdef" for c in hash1)
    
    @pytest.mark.asyncio
    async def test_get_json_valid(self):
        mock_redis = AsyncMock()
        expected_data = {"test": "data"}
        mock_redis.get.return_value = json.dumps(expected_data).encode()
        
        result = await _get_json(mock_redis, "test-key")
        
        assert result == expected_data
        mock_redis.get.assert_called_once_with("test-key")
    
    @pytest.mark.asyncio
    async def test_get_json_none(self):
        mock_redis = AsyncMock()
        mock_redis.get.return_value = None
        
        result = await _get_json(mock_redis, "test-key")
        
        assert result is None
    
    @pytest.mark.asyncio
    async def test_get_json_invalid_json(self):
        mock_redis = AsyncMock()
        mock_redis.get.return_value = b"invalid json"
        
        result = await _get_json(mock_redis, "test-key")
        
        assert result is None
    
    @pytest.mark.asyncio
    async def test_get_json_bytes(self):
        mock_redis = AsyncMock()
        expected_data = {"test": "data"}
        mock_redis.get.return_value = json.dumps(expected_data).encode()
        
        result = await _get_json(mock_redis, "test-key")
        
        assert result == expected_data


class TestCreateJobEndpoint:
    """Tests para el endpoint create_job"""
    
    @pytest.fixture
    def mock_request(self):
        return Mock()
    
    @pytest.fixture
    def mock_redis(self):
        redis = AsyncMock()
        redis.get.return_value = None
        redis.set.return_value = True
        redis.lpush.return_value = True
        redis.llen.return_value = 1
        return redis
    
    @pytest.fixture
    def mock_current_user(self):
        current = Mock()
        current.plan = "PREMIUM"
        current.sub = "user-123"
        return current
    
    @pytest.mark.asyncio
    async def test_create_job_success_list_source(self, mock_request, mock_redis, mock_current_user):
        body = JobCreateRequest(
            source="list",
            emails=["test1@example.com", "test2@example.com"],
            checksmtp=True,
            includerawdns=True
        )
        
        response = await create_job(
            mock_request, body, mock_current_user, None, mock_redis, mock_redis
        )
        
        assert response.status_code == status.HTTP_201_CREATED
        content = json.loads(response.body)
        assert "job_id" in content
        assert content["status"] == "queued"
        
        # Verify redis calls
        assert mock_redis.set.call_count >= 2
        assert mock_redis.enqueue_job.call_count == 1
    
    @pytest.mark.asyncio
    async def test_create_job_success_upload_source(self, mock_request, mock_redis, mock_current_user):
        # Para source=upload, necesitamos pasar emails como lista vacía
        # debido a que el validador está asociado al campo 'emails'
        body = JobCreateRequest(
            source="upload",
            file_token="file-token-123",
            emails=[]  # Lista vacía para pasar la validación
        )
        
        response = await create_job(
            mock_request, body, mock_current_user, None, mock_redis, mock_redis
        )
        
        assert response.status_code == status.HTTP_201_CREATED
    
    @pytest.mark.asyncio
    async def test_create_job_idempotency_replay(self, mock_request, mock_redis, mock_current_user):
        # Mock idempotency key replay
        existing_job_id = str(uuid.uuid4())
        mock_redis.get.return_value = existing_job_id.encode()
        
        # Mock existing job metadata
        mock_redis.get.side_effect = [
            existing_job_id.encode(),  # First call for idempotency check
            json.dumps({
                "job_id": existing_job_id,
                "status": "completed",
                "created_at": "2023-01-01T00:00:00"
            }).encode()  # Second call for job metadata
        ]
        
        body = JobCreateRequest(
            source="list",
            emails=["test@example.com"]
        )
        
        response = await create_job(
            mock_request, body, mock_current_user, "same-key", mock_redis, mock_redis
        )
        
        assert response.status_code == status.HTTP_201_CREATED
        content = json.loads(response.body)
        assert content["job_id"] == existing_job_id
        assert content["status"] == "completed"
    
    @pytest.mark.asyncio
    async def test_create_job_free_plan_limit_exceeded(self, mock_request, mock_redis):
        # Mock FREE plan user
        current = Mock()
        current.plan = "FREE"
        current.sub = "free-user"
        
        body = JobCreateRequest(
            source="list", 
            emails=[f"test{i}@example.com" for i in range(101)]  # 101 emails
        )
        
        with pytest.raises(HTTPException) as exc_info:
            await create_job(mock_request, body, current, None, mock_redis, mock_redis)
        
        assert exc_info.value.status_code == status.HTTP_403_FORBIDDEN
        assert "Batch not available on FREE plan" in str(exc_info.value.detail)
    
    @pytest.mark.asyncio
    async def test_create_job_free_plan_with_premium_features(self, mock_request, mock_redis):
        # FREE plan should not have access to premium features
        current = Mock()
        current.plan = "FREE"
        current.sub = "free-user"
        
        body = JobCreateRequest(
            source="list",
            emails=["test@example.com"],
            checksmtp=True,  # Premium feature
            includerawdns=True  # Premium feature
        )
        
        response = await create_job(
            mock_request, body, current, None, mock_redis, mock_redis
        )
        
        # Should succeed but without premium features
        assert response.status_code == status.HTTP_201_CREATED
        
        # Verify the stored job options don't include premium features for FREE plan
        call_args = mock_redis.set.call_args_list
        meta_call = None
        for call in call_args:
            if "jobs:" in call[0][0] and "meta" in call[0][0]:
                meta_call = call
                break
        
        assert meta_call is not None
        stored_meta = json.loads(meta_call[0][1])
        assert stored_meta["options"]["checksmtp"] is False
        assert stored_meta["options"]["includerawdns"] is False


class TestGetJobStatusEndpoint:
    """Tests para el endpoint get_job_status"""
    
    @pytest.fixture
    def mock_redis(self):
        return AsyncMock()
    
    @pytest.fixture
    def mock_current_user(self):
        current = Mock()
        current.sub = "user-123"
        return current
    
    @pytest.mark.asyncio
    async def test_get_job_status_success(self, mock_redis, mock_current_user):
        job_id = "test-job-123"
        mock_meta = {
            "job_id": job_id,
            "creator": "user-123",
            "status": "processing",
            "counts": {"queued": 10, "processing": 5, "completed": 2},
            "started_at": "2023-01-01T00:00:00",
            "finished_at": None,
            "error": None
        }
        
        mock_redis.get.return_value = json.dumps(mock_meta).encode()
        
        response = await get_job_status(job_id, mock_current_user, mock_redis)
        
        assert response["job_id"] == job_id
        assert response["status"] == "processing"
        assert response["counts"]["queued"] == 10
    
    @pytest.mark.asyncio
    async def test_get_job_status_not_found(self, mock_redis, mock_current_user):
        mock_redis.get.return_value = None
        
        with pytest.raises(HTTPException) as exc_info:
            await get_job_status("non-existent-job", mock_current_user, mock_redis)
        
        assert exc_info.value.status_code == status.HTTP_404_NOT_FOUND
        assert "Job not found" in str(exc_info.value.detail)
    
    @pytest.mark.asyncio
    async def test_get_job_status_forbidden(self, mock_redis, mock_current_user):
        # Job belongs to different user
        job_id = "other-user-job"
        mock_meta = {
            "job_id": job_id,
            "creator": "other-user",
            "status": "queued"
        }
        
        mock_redis.get.return_value = json.dumps(mock_meta).encode()
        
        with pytest.raises(HTTPException) as exc_info:
            await get_job_status(job_id, mock_current_user, mock_redis)
        
        assert exc_info.value.status_code == status.HTTP_403_FORBIDDEN
        assert "Forbidden" in str(exc_info.value.detail)


class TestGetJobResultsEndpoint:
    """Tests para el endpoint get_job_results"""
    
    @pytest.fixture
    def mock_redis(self):
        return AsyncMock()
    
    @pytest.fixture
    def mock_current_user(self):
        current = Mock()
        current.sub = "user-123"
        return current
    
    @pytest.mark.asyncio
    async def test_get_job_results_success(self, mock_redis, mock_current_user):
        job_id = "test-job-123"
        
        # Mock job metadata
        mock_meta = {
            "job_id": job_id,
            "creator": "user-123",
            "status": "completed"
        }
        
        # Mock page data
        mock_page_data = {
            "total_pages": 3,
            "results": [
                {
                    "email": "test@example.com",
                    "valid": True,
                    "riskscore": 0.1,
                    "qualityscore": 0.9
                }
            ]
        }
        
        mock_redis.get.side_effect = [
            json.dumps(mock_meta).encode(),  # First call for metadata
            json.dumps(mock_page_data).encode()  # Second call for page data
        ]
        
        response = await get_job_results(job_id, 1, 100, mock_current_user, mock_redis)
        
        assert response["job_id"] == job_id
        assert response["page"] == 1
        assert response["size"] == 100
        assert response["total_pages"] == 3
        assert len(response["results"]) == 1
        assert response["results"][0]["email"] == "test@example.com"
    
    @pytest.mark.asyncio
    async def test_get_job_results_invalid_pagination(self, mock_redis, mock_current_user):
        with pytest.raises(HTTPException) as exc_info:
            await get_job_results("test-job", 0, 100, mock_current_user, mock_redis)
        
        assert exc_info.value.status_code == status.HTTP_400_BAD_REQUEST
        
        with pytest.raises(HTTPException) as exc_info:
            await get_job_results("test-job", 1, 0, mock_current_user, mock_redis)
        
        assert exc_info.value.status_code == status.HTTP_400_BAD_REQUEST
    
    @pytest.mark.asyncio
    async def test_get_job_results_not_found(self, mock_redis, mock_current_user):
        mock_redis.get.return_value = None
        
        with pytest.raises(HTTPException) as exc_info:
            await get_job_results("non-existent-job", 1, 100, mock_current_user, mock_redis)
        
        assert exc_info.value.status_code == status.HTTP_404_NOT_FOUND
    
    @pytest.mark.asyncio
    async def test_get_job_results_forbidden(self, mock_redis, mock_current_user):
        job_id = "other-user-job"
        mock_meta = {
            "job_id": job_id,
            "creator": "other-user",
            "status": "completed"
        }
        
        mock_redis.get.return_value = json.dumps(mock_meta).encode()
        
        with pytest.raises(HTTPException) as exc_info:
            await get_job_results(job_id, 1, 100, mock_current_user, mock_redis)
        
        assert exc_info.value.status_code == status.HTTP_403_FORBIDDEN
    
    @pytest.mark.asyncio
    async def test_get_job_results_empty_page(self, mock_redis, mock_current_user):
        job_id = "test-job-123"
        mock_meta = {
            "job_id": job_id,
            "creator": "user-123",
            "status": "completed"
        }
        
        mock_redis.get.side_effect = [
            json.dumps(mock_meta).encode(),  # Metadata
            None  # No page data
        ]
        
        response = await get_job_results(job_id, 1, 100, mock_current_user, mock_redis)
        
        assert response["job_id"] == job_id
        assert response["page"] == 1
        assert response["total_pages"] == 0
        assert response["results"] == []


class TestRouterConfiguration:
    """Tests para la configuración del router"""
    
    def test_router_prefix_and_tags(self):
        assert router.prefix == "/v1"
        assert "Jobs" in router.tags
    
    def test_router_route_summaries(self):
        # Verify that routes have expected summaries
        routes_by_path = {route.path: route for route in router.routes}
        
        # Las rutas incluyen el prefijo /v1
        assert "/v1/jobs" in routes_by_path
        assert routes_by_path["/v1/jobs"].summary == "Create validation job"
        
        assert "/v1/jobs/{job_id}" in routes_by_path
        assert routes_by_path["/v1/jobs/{job_id}"].summary == "Get job status"
        
        assert "/v1/jobs/{job_id}/results" in routes_by_path
        assert routes_by_path["/v1/jobs/{job_id}/results"].summary == "Get job results (paged)"