"""Keep test behavior isolated from a developer's local APISentinel .env file."""

import os

_TEST_SETTINGS = {
    "APISENTINEL_ENVIRONMENT": "test",
    "APISENTINEL_DATABASE_URL": "sqlite:////tmp/apisentinel-test-suite.sqlite",
    "APISENTINEL_ALLOW_ACTIVE_TESTS": "false",
    "APISENTINEL_ALLOW_LOCAL_LAB": "false",
    "APISENTINEL_RUNNER_LAB_ALLOW_HTTP": "false",
    "APISENTINEL_RUNNER_LAB_ALLOWED_PORTS": "",
    "APISENTINEL_RUNNER_EGRESS_ALLOWED_CIDRS": "",
    "APISENTINEL_ENABLED_SECURITY_TESTS": "response.header.content_type_options,response.header.strict_transport_security",
}

os.environ.update(_TEST_SETTINGS)
