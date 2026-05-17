import pytest
from easm.parse.cloud_bucket_parser import CloudBucketParser


@pytest.mark.asyncio
async def test_cloud_bucket_parser_extracts_s3_entity():
    parser = CloudBucketParser()
    event = {
        "raw": {
            "bucket_url": "myorg-backup.s3.amazonaws.com",
            "provider": "aws_s3",
            "bucket_name": "myorg-backup",
            "public_access": True,
            "public_list": False,
            "status_code": 200,
        }
    }
    result = await parser.parse(event)
    assert not result.unparseable
    assert len(result.entities) == 1
    assert result.entities[0].entity_type == "domain"
    assert result.entities[0].value == "myorg-backup.s3.amazonaws.com"
    attrs = result.entities[0].attributes
    assert attrs["source"] == "cloud_enum"
    assert attrs["cloud_provider"] == "aws_s3"
    assert attrs["public_access"] is True
    assert attrs["public_list"] is False
    assert attrs["bucket_name"] == "myorg-backup"


@pytest.mark.asyncio
async def test_cloud_bucket_parser_extracts_gcs_entity():
    parser = CloudBucketParser()
    event = {
        "raw": {
            "bucket_url": "storage.googleapis.com/myorg-backup",
            "provider": "gcs",
            "bucket_name": "myorg-backup",
            "public_access": True,
            "public_list": True,
            "status_code": 200,
        }
    }
    result = await parser.parse(event)
    assert not result.unparseable
    assert result.entities[0].value == "storage.googleapis.com"
    assert result.entities[0].attributes["cloud_provider"] == "gcs"
    assert result.entities[0].attributes["bucket_name"] == "myorg-backup"


@pytest.mark.asyncio
async def test_cloud_bucket_parser_handles_no_access():
    parser = CloudBucketParser()
    event = {
        "raw": {
            "bucket_url": "myorg-restricted.s3.amazonaws.com",
            "provider": "aws_s3",
            "bucket_name": "myorg-restricted",
            "public_access": False,
            "public_list": False,
            "status_code": 403,
        }
    }
    result = await parser.parse(event)
    assert not result.unparseable
    assert result.entities[0].attributes["public_access"] is False


@pytest.mark.asyncio
async def test_cloud_bucket_parser_missing_bucket_url():
    parser = CloudBucketParser()
    event = {"raw": {"provider": "aws_s3"}}
    result = await parser.parse(event)
    assert result.unparseable is True


@pytest.mark.asyncio
async def test_cloud_bucket_parser_missing_provider():
    parser = CloudBucketParser()
    event = {"raw": {"bucket_url": "test.s3.amazonaws.com"}}
    result = await parser.parse(event)
    assert result.unparseable is True


@pytest.mark.asyncio
async def test_cloud_bucket_parser_empty_raw():
    parser = CloudBucketParser()
    event = {"raw": {}}
    result = await parser.parse(event)
    assert result.unparseable is True


@pytest.mark.asyncio
async def test_cloud_bucket_parser_class_attributes():
    assert CloudBucketParser.source_name == "cloud_enum"
    assert CloudBucketParser.current_version == 1
