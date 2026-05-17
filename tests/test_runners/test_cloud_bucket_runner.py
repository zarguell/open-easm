from __future__ import annotations

import uuid
from unittest.mock import AsyncMock, MagicMock, patch

import httpx
import pytest

from easm.runners.cloud_bucket_runner import CloudBucketRunner


@pytest.mark.asyncio
async def test_cloud_bucket_runner_class_attributes():
    assert CloudBucketRunner.source_name == "cloud_enum"
    assert CloudBucketRunner.supports_schedule is True
    assert CloudBucketRunner.supports_manual_trigger is True
    assert CloudBucketRunner.is_continuous is False
    assert CloudBucketRunner.is_api_runner is True


def test_bucket_name_prefixes_from_domain():
    from easm.runners.cloud_bucket_runner import _derive_bucket_prefixes
    prefixes = _derive_bucket_prefixes("example.com")
    assert "example" in prefixes
    assert "example-com" in prefixes
    assert "example.com" in prefixes


def test_bucket_name_prefixes_from_long_domain():
    from easm.runners.cloud_bucket_runner import _derive_bucket_prefixes
    prefixes = _derive_bucket_prefixes("sub.domain.co.uk")
    assert "sub" in prefixes
    assert "sub-domain" in prefixes


def test_provider_checks_s3():
    from easm.runners.cloud_bucket_runner import _provider_check_urls
    urls = _provider_check_urls("mybucket", "aws_s3")
    assert len(urls) == 1
    assert urls[0][0] == "https://mybucket.s3.amazonaws.com"
    assert urls[0][1] == "aws_s3"


def test_provider_checks_gcs():
    from easm.runners.cloud_bucket_runner import _provider_check_urls
    urls = _provider_check_urls("mybucket", "gcs")
    assert len(urls) == 1
    assert urls[0][0] == "https://storage.googleapis.com/mybucket"
    assert urls[0][1] == "gcs"


def test_provider_checks_azure():
    from easm.runners.cloud_bucket_runner import _provider_check_urls
    urls = _provider_check_urls("mybucket", "azure_blob")
    assert len(urls) == 1
    assert urls[0][0] == "https://mybucket.blob.core.windows.net"
    assert urls[0][1] == "azure_blob"


def test_all_providers_are_checked():
    from easm.runners.cloud_bucket_runner import CLOUD_PROVIDERS
    assert "aws_s3" in CLOUD_PROVIDERS
    assert "gcs" in CLOUD_PROVIDERS
    assert "azure_blob" in CLOUD_PROVIDERS


@pytest.mark.asyncio
async def test_cloud_bucket_runner_run_once_returns_counts():
    mock_store = MagicMock()
    mock_store.pool = AsyncMock()
    mock_store.pool.execute = AsyncMock(return_value="INSERT 0 1")

    mock_target = MagicMock()
    mock_target.id = "test-target"
    mock_target.org_id = "default"
    mock_target.match_rules.domains = ["example.com"]

    mock_http = AsyncMock(spec=httpx.AsyncClient)
    mock_head_response = MagicMock(spec=httpx.Response)
    mock_head_response.status_code = 200
    mock_head_response.headers = {}
    mock_head_response.request = MagicMock()
    mock_head_response.request.url = httpx.URL("https://example-backup.s3.amazonaws.com")
    mock_http.head = AsyncMock(return_value=mock_head_response)

    runner = CloudBucketRunner(store=mock_store, http_client=mock_http)
    inserted, deduped, errors = await runner.run_once(
        mock_target, "manual", uuid.uuid4()
    )
    assert isinstance(inserted, int)
    assert isinstance(deduped, int)
    assert isinstance(errors, int)
