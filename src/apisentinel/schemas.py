from datetime import date, datetime
from typing import Literal
from urllib.parse import urlsplit

from pydantic import (
    BaseModel,
    ConfigDict,
    Field,
    SecretStr,
    StrictInt,
    field_serializer,
    field_validator,
    model_validator,
)

from .authorization import parse_testing_window


class ReadModel(BaseModel):
    model_config = ConfigDict(from_attributes=True)


class AuditEventRead(BaseModel):
    id: int
    actor_id: int | None
    client_id: int | None
    assessment_id: int | None
    test_run_id: int | None
    finding_id: int | None
    event_type: str
    outcome: str
    metadata: dict
    created_at: datetime


class AuditEventPage(BaseModel):
    items: list[AuditEventRead]
    total: int
    limit: int
    offset: int
    time_range: dict


class DashboardRead(BaseModel):
    time_range: dict
    clients: int
    assessments: int
    assessment_status: dict[str, int]
    assessment_type: dict[str, int]
    endpoints: int
    approved_endpoint_count: int
    execution_approved_endpoint_count: int = 0
    endpoint_review_state: dict[str, int]
    findings: int
    finding_severity: dict[str, int]
    finding_validation_state: dict[str, int]
    finding_triage_status: dict[str, int]
    finding_open_count: int
    finding_resolved_count: int
    finding_validated_count: int
    finding_unvalidated_count: int
    finding_rejected_count: int
    finding_accepted_risk_count: int
    remediation_status: dict[str, int]
    remediation_overdue_count: int
    retest_outcome: dict[str, int]
    execution_status: dict[str, int]
    security_outcome: dict[str, int]
    reports: int
    report_status: dict[str, int]
    recent_assessments: list[dict]
    recent_findings: list[dict]
    recent_activity: list[AuditEventRead]


class ClientCreate(BaseModel):
    name: str = Field(min_length=1, max_length=200)
    organization: str = Field(default="", max_length=200)
    contact_person: str = Field(default="", max_length=200)
    contact_email: str = Field(default="", max_length=320)
    source: Literal["UNKNOWN", "UPWORK", "FIVERR", "DIRECT", "REFERRAL", "OTHER"] = "UNKNOWN"
    source_url: str = Field(default="", max_length=2048)
    engagement_notes: str = Field(default="", max_length=4000)

    @field_validator("name", "organization", "contact_person", "contact_email", "source_url", "engagement_notes")
    @classmethod
    def trim_client_fields(cls, value: str) -> str:
        return value.strip()

    @field_validator("name")
    @classmethod
    def require_client_name(cls, value: str) -> str:
        if not value:
            raise ValueError("Client name is required")
        return value
    @field_validator("source_url")
    @classmethod
    def validate_client_source_url(cls, value: str) -> str:
        if value:
            parsed = urlsplit(value)
            if parsed.scheme not in {"http", "https"} or not parsed.hostname or parsed.username or parsed.password:
                raise ValueError("Source link must be a valid HTTP or HTTPS URL")
        return value


class ClientStatusUpdate(BaseModel):
    status: Literal["Active", "Inactive", "Prospect / Unverified", "Archived"]
    expected_status: Literal["Active", "Inactive", "Prospect / Unverified", "Archived"]


class ClientMembershipCreate(BaseModel):
    login: str = Field(min_length=1, max_length=320)
    role: Literal["viewer", "analyst", "reviewer"]


class ClientRead(ReadModel):
    id: int
    name: str
    organization: str
    contact_person: str
    contact_email: str
    source: str
    source_url: str
    engagement_notes: str
    status: str
    assessment_count: int
    created_at: datetime
    access_role: Literal["owner", "viewer", "analyst", "reviewer"] = "viewer"


class AssessmentMilestone(BaseModel):
    model_config = ConfigDict(extra="forbid")
    name: str = Field(min_length=1, max_length=120)
    due_date: date | None = None

    @field_validator("name")
    @classmethod
    def trim_milestone_name(cls, value: str) -> str:
        value = value.strip()
        if not value:
            raise ValueError("Milestone name must not be blank")
        return value


class AssessmentEngagementDetails(BaseModel):
    model_config = ConfigDict(extra="forbid")
    marketplace: Literal["UNKNOWN", "UPWORK", "FIVERR", "DIRECT", "REFERRAL", "OTHER"] = "UNKNOWN"
    contract_reference: str = Field(default="", max_length=200)
    project_url: str = Field(default="", max_length=2048)
    work_objectives: str = Field(default="", max_length=4000)
    out_of_scope: str = Field(default="", max_length=3000)
    deliverables: list[Literal["TECHNICAL_REPORT", "EXECUTIVE_SUMMARY", "RETEST", "REMEDIATION_SUPPORT"]] = Field(default_factory=list, max_length=4)
    planned_start_date: date | None = None
    due_date: date | None = None
    milestones: list[AssessmentMilestone] = Field(default_factory=list, max_length=20)
    assigned_analyst_id: int | None = None
    reviewer_id: int | None = None

    @field_validator("contract_reference", "project_url", "work_objectives", "out_of_scope")
    @classmethod
    def trim_engagement_values(cls, value: str) -> str:
        return value.strip()

    @field_validator("project_url")
    @classmethod
    def validate_project_url(cls, value: str) -> str:
        if not value:
            return value
        parsed = urlsplit(value)
        if parsed.scheme not in {"https", "http"} or not parsed.hostname or parsed.username or parsed.password:
            raise ValueError("Project link must be a valid HTTP(S) URL without embedded credentials")
        return value

    @model_validator(mode="after")
    def validate_schedule(self):
        if self.planned_start_date and self.due_date and self.due_date < self.planned_start_date:
            raise ValueError("Due date cannot be earlier than the planned start date")
        if self.deliverables and len(set(self.deliverables)) != len(self.deliverables):
            raise ValueError("Deliverables must not contain duplicates")
        return self


class AssessmentCreate(BaseModel):
    model_config = ConfigDict(extra="forbid")
    client_id: int
    name: str = Field(min_length=1, max_length=200)
    description: str = Field(default="", max_length=4000)
    assessment_type: Literal["WEB_API", "ANDROID_API", "BOTH"] = "WEB_API"
    environment: Literal["development", "staging", "production", "lab"] = "staging"
    target_configs: dict = Field(default_factory=dict)
    engagement_details: AssessmentEngagementDetails = Field(default_factory=AssessmentEngagementDetails)
    authorization_reference: str = ""
    authorization_confirmed: bool = False
    allowed_hosts: list[str] = Field(default_factory=list)
    allowed_paths: list[str] = Field(default_factory=list)
    excluded_paths: list[str] = Field(default_factory=list)
    max_requests_per_minute: int = Field(default=30, ge=1, le=600)
    testing_window_start: str = ""
    testing_window_end: str = ""

    @field_validator("name")
    @classmethod
    def trim_name(cls, value: str) -> str:
        value = value.strip()
        if not value:
            raise ValueError("Assessment name must not be blank")
        return value

    @field_validator("target_configs")
    @classmethod
    def validate_target_configs(cls, value: dict) -> dict:
        if set(value) - {"web_api", "android_api"}:
            raise ValueError("Target configuration supports only web_api and android_api")
        for config in value.values():
            if not isinstance(config, dict) or set(config) - {"base_url", "api_version", "source_notes", "package_name", "app_version"}:
                raise ValueError("Target configuration contains unsupported fields")
            base_url = config.get("base_url", "").strip()
            if base_url:
                parsed = urlsplit(base_url)
                if (parsed.scheme not in {"https", "http"} or not parsed.hostname
                        or parsed.username or parsed.password or parsed.query or parsed.fragment):
                    raise ValueError("Target base URL must be an HTTP(S) origin/path without credentials, query, or fragment")
                config["base_url"] = base_url.rstrip("/")
            for field_name, maximum in (("api_version", 100), ("source_notes", 1000), ("package_name", 255), ("app_version", 100)):
                if field_name in config and (not isinstance(config[field_name], str) or len(config[field_name]) > maximum):
                    raise ValueError(f"{field_name} must be text of at most {maximum} characters")
        return value

    @model_validator(mode="after")
    def validate_platform_configuration(self):
        parse_testing_window(self.testing_window_start, self.testing_window_end)
        if self.assessment_type == "WEB_API" and "android_api" in self.target_configs:
            raise ValueError("WEB_API assessments cannot include android_api target configuration")
        if self.assessment_type == "ANDROID_API" and "web_api" in self.target_configs:
            raise ValueError("ANDROID_API assessments cannot include web_api target configuration")
        if self.environment == "production":
            for config in self.target_configs.values():
                base_url = config.get("base_url", "")
                if base_url and urlsplit(base_url).scheme != "https":
                    raise ValueError("Production target base URLs must use HTTPS")
        return self


class AssessmentUpdate(BaseModel):
    model_config = ConfigDict(extra="forbid")
    expected_configuration_version: int = Field(ge=1)
    name: str | None = Field(default=None, min_length=1, max_length=200)
    description: str | None = Field(default=None, max_length=4000)
    assessment_type: Literal["WEB_API", "ANDROID_API", "BOTH"] | None = None
    environment: Literal["development", "staging", "production", "lab"] | None = None
    target_configs: dict | None = None
    engagement_details: AssessmentEngagementDetails | None = None
    allowed_hosts: list[str] | None = Field(default=None, max_length=100)
    allowed_paths: list[str] | None = Field(default=None, max_length=100)
    excluded_paths: list[str] | None = Field(default=None, max_length=100)
    max_requests_per_minute: int | None = Field(default=None, ge=1, le=60)
    testing_window_start: str | None = Field(default=None, max_length=40)
    testing_window_end: str | None = Field(default=None, max_length=40)

    @field_validator("target_configs")
    @classmethod
    def validate_target_configs(cls, value):
        if value is None:
            return value
        return AssessmentCreate.validate_target_configs(value)

    @field_validator("name")
    @classmethod
    def trim_name(cls, value):
        if value is None:
            return value
        value = value.strip()
        if not value:
            raise ValueError("Assessment name must not be blank")
        return value


class AuthorizationRecordCreate(BaseModel):
    model_config = ConfigDict(extra="forbid")
    reference: str = Field(min_length=3, max_length=500)
    authorizing_party: str = Field(min_length=2, max_length=200)
    valid_from: datetime
    expires_at: datetime
    permitted_methods: list[Literal["GET", "HEAD", "OPTIONS"]] = Field(min_length=1)
    scope_acknowledged: Literal[True]
    reason: str = Field(min_length=5, max_length=2000)
    expected_version: int = Field(ge=1)

    @field_validator("valid_from", "expires_at")
    @classmethod
    def require_timezone(cls, value: datetime) -> datetime:
        if value.tzinfo is None or value.utcoffset() is None:
            raise ValueError("Authorization timestamps must include a timezone")
        return value

    @field_validator("permitted_methods")
    @classmethod
    def normalize_methods(cls, value: list[str]) -> list[str]:
        normalized = [method.upper() for method in value]
        if len(set(normalized)) != len(normalized):
            raise ValueError("Permitted methods must not contain duplicates")
        return normalized


class AuthorizationReview(BaseModel):
    model_config = ConfigDict(extra="forbid")
    expected_version: int = Field(ge=1)
    reason: str = Field(min_length=5, max_length=2000)
    scope_and_authority_reviewed: Literal[True]
    solo_operator_self_review: bool = False


class AuthorizationRevoke(BaseModel):
    model_config = ConfigDict(extra="forbid")
    expected_version: int = Field(ge=1)
    reason: str = Field(min_length=5, max_length=2000)


class AssessmentRead(ReadModel):
    id: int
    client_id: int
    name: str
    description: str = ""
    target_configs: dict = Field(default_factory=dict)
    engagement_details: AssessmentEngagementDetails = Field(default_factory=AssessmentEngagementDetails)
    configuration_version: int = 1
    created_by_id: int | None = None
    updated_at: datetime | None = None
    assessment_type: Literal["WEB_API", "ANDROID_API", "BOTH"]
    environment: str
    status: str
    authorization_reference: str
    authorization_confirmed: bool
    authorization_status: str
    authorization_scope_snapshot: dict
    authorization_methods: list[str]
    authorization_party: str
    authorization_evidence_sha256: str
    authorization_evidence_name: str
    authorization_evidence_size: int
    authorization_valid_from: datetime | None
    authorization_expires_at: datetime | None
    authorization_recorded_by_id: int | None
    authorization_recorded_at: datetime | None
    authorization_reviewed_by_id: int | None
    authorization_reviewed_at: datetime | None
    authorization_revoked_at: datetime | None
    authorization_reason: str
    authorization_version: int
    allowed_hosts: list
    allowed_paths: list
    excluded_paths: list
    max_requests_per_minute: int
    testing_window_start: str = ""
    testing_window_end: str = ""
    created_at: datetime


class AndroidApplicationCreate(BaseModel):
    model_config = ConfigDict(extra="forbid")
    package_name: str = Field(min_length=3, max_length=255, pattern=r"^[A-Za-z][A-Za-z0-9_]*(\.[A-Za-z][A-Za-z0-9_]*)+$")
    version_name: str = Field(default="", max_length=100)
    version_code: str = Field(default="", max_length=40)
    artifact_sha256: str = Field(default="", pattern=r"^(?:[0-9a-fA-F]{64})?$")
    api_level: int | None = Field(default=None, ge=1, le=1000)
    metadata: dict = Field(default_factory=dict)


class BearerCredentialCreate(BaseModel):
    model_config = ConfigDict(extra="forbid")
    token: str = Field(min_length=8, max_length=8192)

    @field_validator("token")
    @classmethod
    def validate_token(cls, value: str) -> str:
        if "\r" in value or "\n" in value or not value.strip():
            raise ValueError("Credential token is malformed")
        return value.strip()


class EndpointRead(ReadModel):
    id: int
    assessment_id: int
    method: str
    path: str
    summary: str
    operation_id: str
    parameters: list
    auth_required: bool
    source: str
    source_provenance: list = Field(default_factory=list)
    execution_approved: bool = False
    execution_approved_by: int | None = None
    execution_approved_at: datetime | None = None
    import_id: int | None = None
    definition_hash: str = ""
    inventory_current: bool = True
    review_state: str = "NEEDS_REVIEW"
    review_reason: str = ""
    tags: list = Field(default_factory=list)
    request_body: dict = Field(default_factory=dict)
    security_requirements: list = Field(default_factory=list)
    server_base_path: str = ""
    server_review_issues: list = Field(default_factory=list)
    server_origin: str = ""
    scope_status: str = "UNRESOLVED"
    scope_reason: str = ""
    api_title: str = ""
    api_version: str = ""
    description: str = ""
    deprecated: bool = False
    content_types: list = Field(default_factory=list)
    response_schemas: dict = Field(default_factory=dict)
    last_discovered_at: datetime | None = None
    last_reviewed_at: datetime | None = None


class EndpointExecutionApproval(BaseModel):
    approved: bool
    reason: str = Field(min_length=5, max_length=1000)


class EndpointScopeReview(BaseModel):
    scope_status: Literal["IN_SCOPE", "OUT_OF_SCOPE", "EXCLUDED", "UNRESOLVED"]
    reason: str = Field(min_length=5, max_length=1000)


class FindingCreate(BaseModel):
    model_config = ConfigDict(extra="forbid")
    assessment_id: int
    title: str = Field(min_length=1, max_length=300)
    severity: Literal["Critical", "High", "Medium", "Low", "Informational"] = "Medium"
    endpoint: str = ""
    description: str = ""
    impact: str = ""
    evidence: dict = Field(default_factory=dict)
    remediation: str = ""
    vulnerability_category: str = Field(default="", max_length=80)
    cvss_vector: str | None = Field(default=None, max_length=200)

    @field_validator("cvss_vector")
    @classmethod
    def validate_cvss_vector(cls, value):
        if value is None or not value.strip():
            return None
        from .cvss import calculate_cvss_v31

        calculate_cvss_v31(value)
        return value.strip()


class FindingRiskUpdate(BaseModel):
    model_config = ConfigDict(extra="forbid")
    cvss_vector: str | None = Field(default=None, max_length=200)
    reason: str = Field(min_length=10, max_length=2000)

    @field_validator("cvss_vector")
    @classmethod
    def validate_cvss_vector(cls, value):
        if value is None or not value.strip():
            return None
        from .cvss import calculate_cvss_v31

        calculate_cvss_v31(value)
        return value.strip()


class FindingRead(ReadModel):
    id: int
    assessment_id: int
    endpoint_id: int | None = None
    test_run_id: int | None = None
    title: str
    severity: str
    status: str
    endpoint: str
    description: str
    impact: str
    evidence: dict
    evidence_attachments: list[dict] = Field(default_factory=list)
    remediation: str
    vulnerability_category: str
    owasp_categories: list[str]
    taxonomy_version: str
    validation_state: Literal["PENDING_VALIDATION", "NEEDS_REVIEW", "VALIDATED", "REJECTED", "INCONCLUSIVE"]
    validation_rationale: str
    remediation_status: Literal["OPEN", "IN_PROGRESS", "PENDING_RETEST", "RESOLVED", "READY_FOR_RETEST", "FIXED_PENDING_VERIFICATION", "VERIFIED_FIXED", "REOPENED", "ACCEPTED_RISK", "CLOSED"]
    assigned_owner_id: int | None
    remediation_target_date: date | None
    remediation_notes: str
    proposed_fix: str
    linked_change_reference: str
    remediation_reviewer_notes: str
    remediation_guidance_type: Literal["CHECK_SPECIFIC", "GENERIC", "ANALYST_PROVIDED", "UNAVAILABLE"]
    confidence: Literal["LOW", "MEDIUM", "HIGH", "UNASSESSED"]
    confidence_rationale: str
    priority: Literal["P0", "P1", "P2", "P3", "P4"]
    priority_rationale: str
    risk_analysis: dict
    correlation_key: str
    first_detected_at: datetime
    last_observed_at: datetime
    history: list
    created_at: datetime

    @field_serializer("evidence", "history", "title", "endpoint", "description", "impact", "remediation", "remediation_notes", "proposed_fix", "linked_change_reference", "remediation_reviewer_notes")
    def sanitize_finding_data(self, value):
        from .safety import sanitize_evidence

        return sanitize_evidence(value)


class FindingStatusUpdate(BaseModel):
    model_config = ConfigDict(extra="forbid")
    status: Literal[
        "Needs Review", "Confirmed", "False Positive", "Accepted Risk",
        "Remediation In Progress", "Retest Required", "Resolved", "Closed",
    ]
    reason: str = Field(default="", max_length=2000)


class FindingValidationUpdate(BaseModel):
    model_config = ConfigDict(extra="forbid")
    validation_state: Literal["NEEDS_REVIEW", "VALIDATED", "REJECTED", "INCONCLUSIVE"]
    rationale: str = Field(min_length=10, max_length=2000)


class FindingRemediationUpdate(BaseModel):
    model_config = ConfigDict(extra="forbid")
    status: Literal["OPEN", "IN_PROGRESS", "READY_FOR_RETEST", "FIXED_PENDING_VERIFICATION", "VERIFIED_FIXED", "REOPENED", "ACCEPTED_RISK", "CLOSED"] | None = None
    assigned_owner_id: int | None = None
    target_date: date | None = None
    notes: str | None = Field(default=None, max_length=4000)
    proposed_fix: str | None = Field(default=None, max_length=4000)
    linked_change_reference: str | None = Field(default=None, max_length=500)
    reviewer_notes: str | None = Field(default=None, max_length=2000)
    reason: str = Field(min_length=5, max_length=2000)


class ManualSecurityReviewUpdate(BaseModel):
    model_config = ConfigDict(extra="forbid")
    status: Literal["NOT_REVIEWED", "NO_ISSUE_OBSERVED", "ISSUE_FOUND", "NOT_APPLICABLE", "BLOCKED"]
    review_notes: str = Field(default="", max_length=4000)
    evidence_refs: list[str] = Field(default_factory=list, max_length=20)
    linked_finding_id: int | None = None

    @field_validator("evidence_refs")
    @classmethod
    def validate_evidence_refs(cls, value):
        cleaned = [item.strip() for item in value]
        if any(not item or len(item) > 500 for item in cleaned):
            raise ValueError("Each evidence reference must be 1–500 characters")
        return cleaned

    @model_validator(mode="after")
    def validate_review_basis(self):
        if self.status != "NOT_REVIEWED" and len(self.review_notes.strip()) < 10:
            raise ValueError("A review note of at least 10 characters is required for a recorded status")
        if self.status == "ISSUE_FOUND" and self.linked_finding_id is None:
            raise ValueError("Link an assessment finding before recording ISSUE_FOUND")
        if self.status in {"NO_ISSUE_OBSERVED", "ISSUE_FOUND"} and not self.evidence_refs:
            raise ValueError("Add at least one evidence reference for a reviewed result")
        if self.status != "ISSUE_FOUND" and self.linked_finding_id is not None:
            raise ValueError("A linked finding is only allowed when status is ISSUE_FOUND")
        return self


class ManualSecurityReviewRead(ReadModel):
    id: int
    assessment_id: int
    framework_id: str
    control_id: str
    status: Literal["NOT_REVIEWED", "NO_ISSUE_OBSERVED", "ISSUE_FOUND", "NOT_APPLICABLE", "BLOCKED"]
    review_notes: str
    evidence_refs: list[str]
    linked_finding_id: int | None
    reviewed_by_id: int | None
    created_at: datetime
    updated_at: datetime


class ReportCreate(BaseModel):
    model_config = ConfigDict(extra="forbid")
    report_type: Literal["EXECUTIVE_SUMMARY", "TECHNICAL", "REMEDIATION", "RETEST_CLOSURE"] = "TECHNICAL"
    validation_states: list[Literal["PENDING_VALIDATION", "NEEDS_REVIEW", "VALIDATED", "REJECTED", "INCONCLUSIVE"]] = Field(default_factory=list, max_length=5)
    severities: list[Literal["Critical", "High", "Medium", "Low", "Informational"]] = Field(default_factory=list, max_length=5)
    include_evidence: bool = True


class TestRunCreate(BaseModel):
    assessment_id: int
    category: Literal["Authentication", "Authorization", "Input Validation", "Misconfiguration"] = "Misconfiguration"
    endpoint_id: int
    execution_mode: Literal["HTTP_REQUEST"] = "HTTP_REQUEST"
    test_id: str | None = Field(default=None, min_length=1, max_length=120)


class TestJobCreate(BaseModel):
    model_config = ConfigDict(extra="forbid")
    assessment_id: int
    endpoint_id: int
    test_id: str | None = Field(default=None, min_length=1, max_length=120)
    path_parameters: dict[str, str | int | float | bool] = Field(default_factory=dict, max_length=100)
    query_parameters: dict[str, str | int | float | bool | list[str | int | float | bool]] = Field(default_factory=dict, max_length=100)
    header_parameters: dict[str, str | int | float | bool] = Field(default_factory=dict, max_length=100)
    test_identity_ids: list[StrictInt] = Field(default_factory=list, max_length=2)
    synthetic_object_ids: list[str] = Field(default_factory=list, max_length=2)
    object_parameter: str | None = Field(default=None, min_length=1, max_length=200)
    expected_allowed_identity_id: StrictInt | None = None


class TestIdentityProfileCreate(BaseModel):
    model_config = ConfigDict(extra="forbid")
    label: str = Field(min_length=2, max_length=100)
    role: str = Field(min_length=1, max_length=80)
    bearer_token: SecretStr = Field(min_length=8, max_length=8192)


class RetestCreate(BaseModel):
    model_config = ConfigDict(extra="forbid")
    outcome: Literal[
        "Resolved", "Not Resolved", "Partially Resolved", "Inconclusive",
        "CONFIRMED_PERSISTENCE", "NO_ISSUE_OBSERVED", "INCONCLUSIVE",
        "EXECUTION_ERROR", "NOT_EXECUTED",
    ] | None = None
    evidence: dict = Field(default_factory=dict)
    notes: str = Field(default="", max_length=2000)
    test_run_id: int | None = None


class RetestRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    path_parameters: dict[str, str | int | float | bool] = Field(default_factory=dict, max_length=100)
    query_parameters: dict[str, str | int | float | bool | list[str | int | float | bool]] = Field(default_factory=dict, max_length=100)
    header_parameters: dict[str, str | int | float | bool] = Field(default_factory=dict, max_length=100)
    notes: str = Field(default="Explicit analyst-requested retest", min_length=5, max_length=2000)


class OpenAPIImport(BaseModel):
    assessment_id: int
    document: dict
    source: str = Field(default="inline_json", min_length=1, max_length=200)


class GraphQLSchemaImport(BaseModel):
    model_config = ConfigDict(extra="forbid")
    assessment_id: int
    document: dict

