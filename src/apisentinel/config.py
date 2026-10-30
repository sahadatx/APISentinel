import ipaddress
from urllib.parse import urlsplit

from cryptography.fernet import Fernet
from pydantic import Field, model_validator
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_prefix="APISENTINEL_", env_file=".env", extra="ignore")
    database_url: str = "sqlite:///./apisentinel.db"
    api_prefix: str = "/api/v1"
    max_requests_per_minute: int = Field(default=30, ge=1, le=1000)
    request_timeout_seconds: float = Field(default=5, gt=0, le=30)
    runner_connect_timeout_seconds: float = Field(default=3, gt=0, le=10)
    runner_read_timeout_seconds: float = Field(default=5, gt=0, le=30)
    runner_write_timeout_seconds: float = Field(default=5, gt=0, le=30)
    runner_pool_timeout_seconds: float = Field(default=2, gt=0, le=10)
    runner_total_timeout_seconds: float = Field(default=90, gt=0, le=300)
    runner_max_response_bytes: int = Field(default=1_000_000, ge=1024, le=5_000_000)
    openapi_max_document_bytes: int = Field(default=1_000_000, ge=1024, le=5_000_000)
    enabled_security_tests: str = ("response.header.content_type_options,response.header.strict_transport_security,"
                                   "authentication.unauthenticated_access,authorization.sensitive_property_observation,"
                                   "resource.rate_limit_observation,authorization.bola.synthetic_pair,"
                                   "authorization.function_role_pair")
    runner_max_concurrency: int = Field(default=2, ge=1, le=4)
    runner_max_redirects: int = Field(default=3, ge=0, le=3)
    runner_lab_allowed_ports: str = ""
    runner_egress_allowed_cidrs: str = ""
    apk_parser_url: str = ""
    allow_active_tests: bool = False
    allow_local_lab: bool = False
    runner_lab_allow_http: bool = False
    environment: str = "development"
    session_cookie_name: str = "apisentinel_session"
    csrf_cookie_name: str = "apisentinel_csrf"
    session_ttl_minutes: int = Field(default=480, ge=5, le=1440)
    cookie_secure: bool = False
    cors_origins: str = "http://127.0.0.1:5173,http://127.0.0.1:5174"
    credential_encryption_key: str = ""
    credential_encryption_key_next: str = ""
    credential_encryption_provider: str = "fernet"
    credential_kms_key_id: str = ""
    credential_kms_key_id_next: str = ""
    credential_kms_region: str = ""

    @property
    def allowed_origins(self) -> list[str]:
        return [origin.strip().rstrip("/") for origin in self.cors_origins.split(",") if origin.strip()]

    @property
    def lab_allowed_ports(self) -> frozenset[int]:
        try:
            ports = frozenset(int(port.strip()) for port in self.runner_lab_allowed_ports.split(",") if port.strip())
        except ValueError:
            raise ValueError("APISENTINEL_RUNNER_LAB_ALLOWED_PORTS must be comma-separated port numbers") from None
        if any(port < 1 or port > 65535 for port in ports):
            raise ValueError("Lab ports must be between 1 and 65535")
        return ports

    @property
    def egress_allowed_networks(self) -> tuple[ipaddress.IPv4Network | ipaddress.IPv6Network, ...]:
        values = [value.strip() for value in self.runner_egress_allowed_cidrs.split(",") if value.strip()]
        try:
            networks = tuple(ipaddress.ip_network(value, strict=True) for value in values)
            if any(network.prefixlen == 0 for network in networks):
                raise ValueError
            return networks
        except ValueError:
            raise ValueError("APISENTINEL_RUNNER_EGRESS_ALLOWED_CIDRS must be comma-separated canonical CIDRs") from None

    @model_validator(mode="after")
    def production_cookie_security(self):
        if self.environment.lower() not in {"development", "test", "lab", "staging", "production"}:
            raise ValueError("APISENTINEL_ENVIRONMENT must be development, test, lab, staging, or production")
        production_like = self.environment.lower() in {"staging", "production"}
        if production_like and not self.runner_egress_allowed_cidrs.strip():
            raise ValueError("APISENTINEL_RUNNER_EGRESS_ALLOWED_CIDRS is required in staging and production")
        if production_like and not self.apk_parser_url:
            raise ValueError("APISENTINEL_APK_PARSER_URL is required in staging and production")
        if production_like and not self.database_url.startswith(("postgresql://", "postgresql+psycopg://")):
            raise ValueError("PostgreSQL is required in staging and production")
        if self.apk_parser_url:
            parsed_parser = urlsplit(self.apk_parser_url)
            parser_host_allowed = parsed_parser.hostname == "apk-parser"
            if self.environment.lower() in {"development", "test", "lab"}:
                parser_host_allowed = parser_host_allowed or parsed_parser.hostname in {
                    "127.0.0.1", "localhost", "172.24.0.2"
                }
            if (parsed_parser.scheme != "http" or not parser_host_allowed or
                    parsed_parser.port != 8090 or parsed_parser.path not in {"", "/"} or
                    parsed_parser.username or parsed_parser.password or parsed_parser.query or parsed_parser.fragment):
                raise ValueError("APISENTINEL_APK_PARSER_URL must use the private apk-parser service endpoint")
        if self.credential_encryption_provider not in {"fernet", "aws_kms"}:
            raise ValueError("APISENTINEL_CREDENTIAL_ENCRYPTION_PROVIDER must be fernet or aws_kms")
        if not self.api_prefix.startswith("/") or self.api_prefix.startswith("//"):
            raise ValueError("APISENTINEL_API_PREFIX must be an absolute path")
        if "*" in self.allowed_origins:
            raise ValueError("APISENTINEL_CORS_ORIGINS must use explicit origins, not a wildcard")
        for origin in self.allowed_origins:
            try:
                parsed_origin = urlsplit(origin)
                valid_origin = (parsed_origin.scheme in {"http", "https"} and bool(parsed_origin.hostname)
                                and parsed_origin.username is None and parsed_origin.password is None
                                and parsed_origin.path in {"", "/"} and not parsed_origin.query
                                and not parsed_origin.fragment)
                _ = parsed_origin.port
            except ValueError:
                valid_origin = False
            if not valid_origin:
                raise ValueError("APISENTINEL_CORS_ORIGINS must contain only explicit origin URLs")
        if production_like and not self.cookie_secure:
            raise ValueError("APISENTINEL_COOKIE_SECURE must be true in staging and production")
        if production_like and any(not origin.startswith("https://") for origin in self.allowed_origins):
            raise ValueError("Staging and production CORS origins must use HTTPS")
        if production_like and self.allow_local_lab:
            raise ValueError("APISENTINEL_ALLOW_LOCAL_LAB must be false in staging and production")
        if production_like and self.runner_lab_allow_http:
            raise ValueError("APISENTINEL_RUNNER_LAB_ALLOW_HTTP must be false in staging and production")
        if production_like and self.credential_encryption_provider == "fernet":
            raise ValueError("Managed KMS encryption is required in staging and production")
        if production_like and self.credential_encryption_provider == "aws_kms" and not (self.credential_kms_key_id and self.credential_kms_region):
            raise ValueError("AWS KMS key ID and region are required in staging and production")
        if self.credential_encryption_key:
            try:
                Fernet(self.credential_encryption_key.encode("ascii"))
            except (ValueError, UnicodeEncodeError, TypeError):
                raise ValueError("APISENTINEL_CREDENTIAL_ENCRYPTION_KEY must be a valid Fernet key") from None
        if self.credential_encryption_key_next:
            try:
                Fernet(self.credential_encryption_key_next.encode("ascii"))
            except (ValueError, UnicodeEncodeError, TypeError):
                raise ValueError("APISENTINEL_CREDENTIAL_ENCRYPTION_KEY_NEXT must be a valid Fernet key") from None
        _ = self.lab_allowed_ports
        _ = self.egress_allowed_networks
        return self


settings = Settings()
