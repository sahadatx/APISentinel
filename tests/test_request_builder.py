from types import SimpleNamespace

import pytest

from apisentinel.request_builder import RequestBuildError, build_request


def endpoint():
    return SimpleNamespace(
        method="GET", path="/v1/users/{user_id}", server_base_path="/api",
        parameters=[
            {"name": "user_id", "in": "path", "required": True, "schema": {"type": "string"}},
            {"name": "tag", "in": "query", "required": False, "schema": {"type": "string"}},
            {"name": "ids", "in": "query", "required": False,
             "schema": {"type": "array", "items": {"type": "integer"}}},
            {"name": "X-Trace", "in": "header", "required": False, "schema": {"type": "string"}},
        ],
    )


def test_build_request_encodes_path_query_and_declared_headers_without_network():
    url, headers = build_request(endpoint(), "https://api.example.test/api/v1/users/{user_id}",
                                 path_parameters={"user_id": "a b?"},
                                 query_parameters={"tag": ["blue sky", "x&y"], "ids": [2, 3]},
                                 header_parameters={"X-Trace": "trace-value"})
    assert url == "https://api.example.test/api/v1/users/a%20b%3F?tag=blue+sky&tag=x%26y&ids=2&ids=3"
    assert headers == {"X-Trace": "trace-value"}


@pytest.mark.parametrize("arguments", [
    {"query_parameters": {"unlisted": "x"}},
    {"path_parameters": {"user_id": "../secret"}},
    {"header_parameters": {"X-Trace": "safe\r\nHost: evil.test"}},
    {"header_parameters": {"Authorization": "attacker token"}},
])
def test_build_request_rejects_undeclared_unsafe_or_injected_values(arguments):
    supplied = {"path_parameters": {"user_id": "valid"}, **arguments}
    with pytest.raises(RequestBuildError):
        build_request(endpoint(), "https://api.example.test/api/v1/users/{user_id}", **supplied)


def test_build_request_rejects_missing_required_parameters_and_unsafe_methods():
    with pytest.raises(RequestBuildError, match="Path parameters"):
        build_request(endpoint(), "https://api.example.test/api/v1/users/{user_id}")
    item = endpoint()
    item.method = "DELETE"
    with pytest.raises(RequestBuildError, match="Only GET"):
        build_request(item, "https://api.example.test/api/v1/users/{user_id}",
                      path_parameters={"user_id": "valid"})
