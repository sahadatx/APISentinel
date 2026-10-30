from datetime import UTC, date, datetime
from typing import ClassVar

from sqlalchemy import (
    JSON,
    Boolean,
    CheckConstraint,
    Date,
    DateTime,
    ForeignKey,
    Index,
    Integer,
    LargeBinary,
    String,
    Text,
    UniqueConstraint,
    text,
)
from sqlalchemy.orm import Mapped, mapped_column, relationship

from .db import Base


def now():
    return datetime.now(UTC)


class Client(Base):
    __tablename__ = "clients"
    id: Mapped[int] = mapped_column(primary_key=True)
    owner_user_id: Mapped[int | None] = mapped_column(ForeignKey("analysts.id", ondelete="SET NULL"), index=True, nullable=True)
    name: Mapped[str] = mapped_column(String(200), index=True)
    organization: Mapped[str] = mapped_column(String(200), default="")
    contact_person: Mapped[str] = mapped_column(String(200), default="")
    contact_email: Mapped[str] = mapped_column(String(320), default="")
    source: Mapped[str] = mapped_column(String(20), default="UNKNOWN")
    source_url: Mapped[str] = mapped_column(String(2048), default="")
    engagement_notes: Mapped[str] = mapped_column(Text, default="")
    status: Mapped[str] = mapped_column(String(30), default="Active")
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=now)
    assessments: Mapped[list["Assessment"]] = relationship(back_populates="client", cascade="all, delete-orphan")

    @property
    def assessment_count(self) -> int:
        return len(self.assessments)


class ClientMembership(Base):
    __tablename__ = "client_memberships"
    __table_args__ = (CheckConstraint("role IN ('viewer', 'analyst', 'reviewer')", name="ck_client_membership_role"),)
    client_id: Mapped[int] = mapped_column(ForeignKey("clients.id", ondelete="CASCADE"), primary_key=True)
    analyst_id: Mapped[int] = mapped_column(ForeignKey("analysts.id", ondelete="CASCADE"), primary_key=True, index=True)
    role: Mapped[str] = mapped_column(String(20), nullable=False)
    granted_by_id: Mapped[int] = mapped_column(ForeignKey("analysts.id", ondelete="RESTRICT"), nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=now, nullable=False)


class Analyst(Base):
    __tablename__ = "analysts"
    id: Mapped[int] = mapped_column(primary_key=True)
    login_normalized: Mapped[str] = mapped_column(String(320), unique=True)
    password_hash: Mapped[str] = mapped_column(String(500))
    role: Mapped[str] = mapped_column(String(30), default="analyst")
    mfa_secret_encrypted: Mapped[str | None] = mapped_column(Text, nullable=True)
    mfa_enabled: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)
    mfa_last_counter: Mapped[int | None] = mapped_column(Integer, nullable=True)
    mfa_recovery_hashes: Mapped[list] = mapped_column(JSON, default=list, nullable=False)
    is_active: Mapped[bool] = mapped_column(Boolean, default=True)
    login_failure_count: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    login_failure_window_started_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    login_locked_until: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=now)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=now, onupdate=now)
    sessions: Mapped[list["AuthSession"]] = relationship(back_populates="analyst", cascade="all, delete-orphan")


class AuthSession(Base):
    __tablename__ = "auth_sessions"
    id: Mapped[int] = mapped_column(primary_key=True)
    analyst_id: Mapped[int] = mapped_column(ForeignKey("analysts.id", ondelete="CASCADE"), index=True)
    token_hash: Mapped[str] = mapped_column(String(64), unique=True)
    csrf_token_hash: Mapped[str] = mapped_column(String(64))
    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), index=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=now)
    analyst: Mapped[Analyst] = relationship(back_populates="sessions")


class Assessment(Base):
    __tablename__ = "assessments"
    id: Mapped[int] = mapped_column(primary_key=True)
    client_id: Mapped[int] = mapped_column(ForeignKey("clients.id", ondelete="CASCADE"), index=True)
    name: Mapped[str] = mapped_column(String(200))
    description: Mapped[str] = mapped_column(Text, default="", nullable=False)
    target_configs: Mapped[dict] = mapped_column(JSON, default=dict, nullable=False)
    engagement_details: Mapped[dict] = mapped_column(JSON, default=dict, nullable=False)
    configuration_version: Mapped[int] = mapped_column(Integer, default=1, nullable=False)
    created_by_id: Mapped[int | None] = mapped_column(ForeignKey("analysts.id", ondelete="SET NULL"), nullable=True)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=now, onupdate=now, nullable=False)
    assessment_type: Mapped[str] = mapped_column(String(20), default="WEB_API", nullable=False)
    environment: Mapped[str] = mapped_column(String(80), default="staging")
    status: Mapped[str] = mapped_column(String(40), default="Draft")
    authorization_reference: Mapped[str] = mapped_column(String(500), default="")
    authorization_confirmed: Mapped[bool] = mapped_column(Boolean, default=False)
    # Legacy confirmation/reference are retained for data compatibility, but do
    # not authorize execution. The reviewed record below is the execution gate.
    authorization_status: Mapped[str] = mapped_column(String(30), default="REVIEW_REQUIRED", nullable=False)
    authorization_scope_hash: Mapped[str] = mapped_column(String(64), default="", nullable=False)
    authorization_scope_snapshot: Mapped[dict] = mapped_column(JSON, default=dict, nullable=False)
    authorization_methods: Mapped[list] = mapped_column(JSON, default=list, nullable=False)
    authorization_valid_from: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    authorization_expires_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    authorization_party: Mapped[str] = mapped_column(String(200), default="", nullable=False)
    authorization_evidence_sha256: Mapped[str] = mapped_column(String(64), default="", nullable=False)
    authorization_evidence_name: Mapped[str] = mapped_column(String(200), default="", nullable=False)
    authorization_evidence_size: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    authorization_recorded_by_id: Mapped[int | None] = mapped_column(ForeignKey("analysts.id", ondelete="SET NULL"), nullable=True)
    authorization_recorded_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    authorization_reviewed_by_id: Mapped[int | None] = mapped_column(ForeignKey("analysts.id", ondelete="SET NULL"), nullable=True)
    authorization_reviewed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    authorization_revoked_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    authorization_reason: Mapped[str] = mapped_column(Text, default="", nullable=False)
    authorization_version: Mapped[int] = mapped_column(Integer, default=1, nullable=False)
    allowed_hosts: Mapped[list] = mapped_column(JSON, default=list)
    allowed_paths: Mapped[list] = mapped_column(JSON, default=list)
    excluded_paths: Mapped[list] = mapped_column(JSON, default=list)
    max_requests_per_minute: Mapped[int] = mapped_column(Integer, default=30)
    testing_window_start: Mapped[str] = mapped_column(String(40), default="")
    testing_window_end: Mapped[str] = mapped_column(String(40), default="")
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=now)
    client: Mapped[Client] = relationship(back_populates="assessments")
    endpoints: Mapped[list["Endpoint"]] = relationship(back_populates="assessment", cascade="all, delete-orphan")
    findings: Mapped[list["Finding"]] = relationship(back_populates="assessment", cascade="all, delete-orphan")
    reports: Mapped[list["Report"]] = relationship(back_populates="assessment", cascade="all, delete-orphan")
    android_applications: Mapped[list["AndroidApplication"]] = relationship(back_populates="assessment", cascade="all, delete-orphan")
    ios_applications: Mapped[list["IOSApplication"]] = relationship(back_populates="assessment", cascade="all, delete-orphan")

    __mapper_args__: ClassVar[dict] = {"version_id_col": authorization_version}


class Endpoint(Base):
    __tablename__ = "endpoints"
    id: Mapped[int] = mapped_column(primary_key=True)
    assessment_id: Mapped[int] = mapped_column(ForeignKey("assessments.id", ondelete="CASCADE"), index=True)
    method: Mapped[str] = mapped_column(String(12))
    path: Mapped[str] = mapped_column(String(1000))
    summary: Mapped[str] = mapped_column(String(500), default="")
    operation_id: Mapped[str] = mapped_column(String(200), default="")
    parameters: Mapped[list] = mapped_column(JSON, default=list)
    auth_required: Mapped[bool] = mapped_column(Boolean, default=False)
    source: Mapped[str] = mapped_column(String(80), default="openapi")
    source_provenance: Mapped[list] = mapped_column(JSON, default=list, nullable=False)
    import_id: Mapped[int | None] = mapped_column(ForeignKey("openapi_documents.id", ondelete="SET NULL"), index=True, nullable=True)
    definition_hash: Mapped[str] = mapped_column(String(64), default="", nullable=False, index=True)
    inventory_current: Mapped[bool] = mapped_column(Boolean, default=True, nullable=False, index=True)
    review_state: Mapped[str] = mapped_column(String(30), default="NEEDS_REVIEW", nullable=False, index=True)
    review_reason: Mapped[str] = mapped_column(Text, default="", nullable=False)
    tags: Mapped[list] = mapped_column(JSON, default=list, nullable=False)
    request_body: Mapped[dict] = mapped_column(JSON, default=dict, nullable=False)
    security_requirements: Mapped[list] = mapped_column(JSON, default=list, nullable=False)
    server_base_path: Mapped[str] = mapped_column(String(1000), default="", nullable=False)
    server_origin: Mapped[str] = mapped_column(String(1000), default="", nullable=False)
    scope_status: Mapped[str] = mapped_column(String(24), default="UNRESOLVED", nullable=False, index=True)
    scope_reason: Mapped[str] = mapped_column(Text, default="", nullable=False)
    api_title: Mapped[str] = mapped_column(String(300), default="", nullable=False)
    api_version: Mapped[str] = mapped_column(String(100), default="", nullable=False)
    description: Mapped[str] = mapped_column(Text, default="", nullable=False)
    deprecated: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)
    content_types: Mapped[list] = mapped_column(JSON, default=list, nullable=False)
    response_schemas: Mapped[dict] = mapped_column(JSON, default=dict, nullable=False)
    last_discovered_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=now, nullable=False)
    server_review_issues: Mapped[list] = mapped_column(JSON, default=list, nullable=False)
    execution_approved: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)
    execution_approved_by: Mapped[int | None] = mapped_column(ForeignKey("analysts.id", ondelete="SET NULL"), nullable=True)
    execution_approved_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    assessment: Mapped[Assessment] = relationship(back_populates="endpoints")


class OpenAPIDocument(Base):
    __tablename__ = "openapi_documents"
    id: Mapped[int] = mapped_column(primary_key=True)
    assessment_id: Mapped[int] = mapped_column(ForeignKey("assessments.id", ondelete="CASCADE"), index=True)
    imported_by: Mapped[int] = mapped_column(ForeignKey("analysts.id", ondelete="RESTRICT"), index=True)
    source: Mapped[str] = mapped_column(String(200), default="inline_json", nullable=False)
    openapi_version: Mapped[str] = mapped_column(String(40), nullable=False)
    content_hash: Mapped[str] = mapped_column(String(64), nullable=False, index=True)
    artifact_metadata: Mapped[dict] = mapped_column(JSON, default=dict, nullable=False)
    server_declarations: Mapped[list] = mapped_column(JSON, default=list, nullable=False)
    issues: Mapped[list] = mapped_column(JSON, default=list, nullable=False)
    endpoint_ids: Mapped[list] = mapped_column(JSON, default=list, nullable=False)
    change_summary: Mapped[dict] = mapped_column(JSON, default=dict, nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=now, nullable=False)


class GraphQLSchemaDocument(Base):
    """Sanitized client-supplied GraphQL schema inventory; raw introspection is discarded."""
    __tablename__ = "graphql_schema_documents"
    id: Mapped[int] = mapped_column(primary_key=True)
    assessment_id: Mapped[int] = mapped_column(ForeignKey("assessments.id", ondelete="CASCADE"), index=True)
    imported_by: Mapped[int] = mapped_column(ForeignKey("analysts.id", ondelete="RESTRICT"), index=True)
    content_hash: Mapped[str] = mapped_column(String(64), nullable=False, index=True)
    schema_summary: Mapped[dict] = mapped_column(JSON, nullable=False, default=dict)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=now, nullable=False)


class InventoryReview(Base):
    """Immutable, passive review snapshot of the assessment's imported API inventory."""
    __tablename__ = "inventory_reviews"
    id: Mapped[int] = mapped_column(primary_key=True)
    assessment_id: Mapped[int] = mapped_column(ForeignKey("assessments.id", ondelete="CASCADE"), index=True)
    analyst_id: Mapped[int | None] = mapped_column(ForeignKey("analysts.id", ondelete="SET NULL"), nullable=True)
    inventory_digest: Mapped[str] = mapped_column(String(64), nullable=False, index=True)
    result: Mapped[dict] = mapped_column(JSON, default=dict, nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=now, nullable=False, index=True)


class ManualSecurityReview(Base):
    """Analyst-entered status and evidence pointer for a versioned review control."""
    __tablename__ = "manual_security_reviews"
    __table_args__ = (
        UniqueConstraint("assessment_id", "framework_id", "control_id",
                         name="uq_manual_review_assessment_control"),
        CheckConstraint("status IN ('NOT_REVIEWED', 'NO_ISSUE_OBSERVED', 'ISSUE_FOUND', 'NOT_APPLICABLE', 'BLOCKED')",
                        name="ck_manual_security_review_status"),
    )
    id: Mapped[int] = mapped_column(primary_key=True)
    assessment_id: Mapped[int] = mapped_column(ForeignKey("assessments.id", ondelete="CASCADE"), index=True)
    framework_id: Mapped[str] = mapped_column(String(40), nullable=False)
    control_id: Mapped[str] = mapped_column(String(40), nullable=False)
    status: Mapped[str] = mapped_column(String(30), nullable=False, default="NOT_REVIEWED")
    review_notes: Mapped[str] = mapped_column(Text, nullable=False, default="")
    evidence_refs: Mapped[list] = mapped_column(JSON, nullable=False, default=list)
    linked_finding_id: Mapped[int | None] = mapped_column(
        ForeignKey("findings.id", ondelete="SET NULL"), index=True, nullable=True)
    reviewed_by_id: Mapped[int | None] = mapped_column(ForeignKey("analysts.id", ondelete="SET NULL"), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=now, nullable=False)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=now,
                                                  onupdate=now, nullable=False)


class AndroidApplication(Base):
    """Sanitized client-supplied Android metadata; APK bytes are never stored or executed."""
    __tablename__ = "android_applications"
    __table_args__ = (UniqueConstraint("assessment_id", "package_name", name="uq_android_app_assessment_package"),)
    id: Mapped[int] = mapped_column(primary_key=True)
    assessment_id: Mapped[int] = mapped_column(ForeignKey("assessments.id", ondelete="CASCADE"), index=True)
    package_name: Mapped[str] = mapped_column(String(255), nullable=False)
    version_name: Mapped[str] = mapped_column(String(100), default="", nullable=False)
    version_code: Mapped[str] = mapped_column(String(40), default="", nullable=False)
    artifact_sha256: Mapped[str] = mapped_column(String(64), default="", nullable=False)
    api_level: Mapped[int | None] = mapped_column(Integer, nullable=True)
    metadata_json: Mapped[dict] = mapped_column(JSON, default=dict, nullable=False)
    created_by: Mapped[int | None] = mapped_column(ForeignKey("analysts.id", ondelete="SET NULL"), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=now, nullable=False)
    assessment: Mapped[Assessment] = relationship(back_populates="android_applications")


class IOSApplication(Base):
    """Sanitized metadata from a client-supplied IPA; package bytes are never stored."""
    __tablename__ = "ios_applications"
    __table_args__ = (UniqueConstraint("assessment_id", "bundle_id", name="uq_ios_app_assessment_bundle"),)
    id: Mapped[int] = mapped_column(primary_key=True)
    assessment_id: Mapped[int] = mapped_column(ForeignKey("assessments.id", ondelete="CASCADE"), index=True)
    bundle_id: Mapped[str] = mapped_column(String(255), nullable=False)
    display_name: Mapped[str] = mapped_column(String(200), default="", nullable=False)
    version_name: Mapped[str] = mapped_column(String(100), default="", nullable=False)
    build_number: Mapped[str] = mapped_column(String(40), default="", nullable=False)
    minimum_os_version: Mapped[str] = mapped_column(String(40), default="", nullable=False)
    artifact_sha256: Mapped[str] = mapped_column(String(64), nullable=False)
    metadata_json: Mapped[dict] = mapped_column(JSON, default=dict, nullable=False)
    created_by: Mapped[int | None] = mapped_column(ForeignKey("analysts.id", ondelete="SET NULL"), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=now, nullable=False)
    assessment: Mapped[Assessment] = relationship(back_populates="ios_applications")


class CredentialProfile(Base):
    __tablename__ = "credential_profiles"
    id: Mapped[int] = mapped_column(primary_key=True)
    assessment_id: Mapped[int] = mapped_column(ForeignKey("assessments.id", ondelete="CASCADE"), unique=True, index=True)
    auth_type: Mapped[str] = mapped_column(String(30), nullable=False, default="BEARER")
    encrypted_secret: Mapped[str] = mapped_column(Text, nullable=False)
    active: Mapped[bool] = mapped_column(Boolean, nullable=False, default=True)
    created_by: Mapped[int | None] = mapped_column(ForeignKey("analysts.id", ondelete="SET NULL"), nullable=True)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=now, onupdate=now, nullable=False)


class TestIdentityProfile(Base):
    """Encrypted, client-provisioned disposable identity for read-only comparisons."""
    __tablename__ = "test_identity_profiles"
    __table_args__ = (UniqueConstraint("assessment_id", "label", name="uq_test_identity_assessment_label"),)
    id: Mapped[int] = mapped_column(primary_key=True)
    assessment_id: Mapped[int] = mapped_column(ForeignKey("assessments.id", ondelete="CASCADE"), index=True)
    label: Mapped[str] = mapped_column(String(100), nullable=False)
    role: Mapped[str] = mapped_column(String(80), nullable=False)
    encrypted_secret: Mapped[str] = mapped_column(Text, nullable=False)
    active: Mapped[bool] = mapped_column(Boolean, nullable=False, default=True)
    created_by: Mapped[int | None] = mapped_column(ForeignKey("analysts.id", ondelete="SET NULL"), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=now, nullable=False)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=now, onupdate=now, nullable=False)


class ExecutionLimiterState(Base):
    __tablename__ = "execution_limiter_states"
    assessment_id: Mapped[int] = mapped_column(ForeignKey("assessments.id", ondelete="CASCADE"), primary_key=True)
    touched_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=now, nullable=False)


class ExecutionReservation(Base):
    __tablename__ = "execution_reservations"
    id: Mapped[int] = mapped_column(primary_key=True)
    assessment_id: Mapped[int] = mapped_column(ForeignKey("assessments.id", ondelete="CASCADE"), index=True)
    requested_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=now, nullable=False, index=True)
    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, index=True)
    released_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)


class TestRun(Base):
    __tablename__ = "test_runs"
    __table_args__ = (
        Index("uq_test_runs_running_endpoint", "assessment_id", "endpoint_id", unique=True,
              sqlite_where=text("status = 'RUNNING' AND endpoint_id IS NOT NULL"),
              postgresql_where=text("status = 'RUNNING' AND endpoint_id IS NOT NULL")),
        Index("uq_test_runs_idempotency", "assessment_id", "analyst_id", "idempotency_key", unique=True,
              sqlite_where=text("idempotency_key IS NOT NULL"),
              postgresql_where=text("idempotency_key IS NOT NULL")),
    )
    id: Mapped[int] = mapped_column(primary_key=True)
    assessment_id: Mapped[int] = mapped_column(ForeignKey("assessments.id", ondelete="CASCADE"), index=True)
    endpoint_id: Mapped[int | None] = mapped_column(ForeignKey("endpoints.id", ondelete="SET NULL"), index=True, nullable=True)
    category: Mapped[str] = mapped_column(String(80))
    status: Mapped[str] = mapped_column(String(40), default="Queued")
    summary: Mapped[str] = mapped_column(Text, default="")
    analyst_id: Mapped[int | None] = mapped_column(ForeignKey("analysts.id", ondelete="SET NULL"), index=True, nullable=True)
    execution_mode: Mapped[str] = mapped_column(String(40), default="LEGACY", nullable=False)
    test_id: Mapped[str] = mapped_column(String(120), default="", nullable=False)
    test_version: Mapped[str] = mapped_column(String(40), default="", nullable=False)
    security_outcome: Mapped[str] = mapped_column(String(40), default="NOT_RUN", nullable=False)
    method: Mapped[str] = mapped_column(String(12), default="", nullable=False)
    started_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    completed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    execution_metadata: Mapped[dict] = mapped_column(JSON, default=dict, nullable=False)
    encrypted_request_parameters: Mapped[str | None] = mapped_column(Text, nullable=True)
    idempotency_key: Mapped[str | None] = mapped_column(String(64), nullable=True)
    worker_lease_expires_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    attempt_count: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=now)


class ExecutionAuditEvent(Base):
    __tablename__ = "execution_audit_events"
    id: Mapped[int] = mapped_column(primary_key=True)
    actor_id: Mapped[int | None] = mapped_column(ForeignKey("analysts.id", ondelete="SET NULL"), index=True, nullable=True)
    client_id: Mapped[int | None] = mapped_column(ForeignKey("clients.id", ondelete="SET NULL"), index=True, nullable=True)
    assessment_id: Mapped[int | None] = mapped_column(ForeignKey("assessments.id", ondelete="SET NULL"), index=True, nullable=True)
    test_run_id: Mapped[int | None] = mapped_column(ForeignKey("test_runs.id", ondelete="SET NULL"), index=True, nullable=True)
    finding_id: Mapped[int | None] = mapped_column(ForeignKey("findings.id", ondelete="SET NULL"), index=True, nullable=True)
    event_type: Mapped[str] = mapped_column(String(60), nullable=False)
    outcome: Mapped[str] = mapped_column(String(40), nullable=False)
    metadata_json: Mapped[dict] = mapped_column(JSON, default=dict, nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=now, nullable=False, index=True)


class Finding(Base):
    __tablename__ = "findings"
    __table_args__ = (
        Index("ix_findings_validation_state", "validation_state"),
        Index("ix_findings_confidence", "confidence"),
        Index("ix_findings_priority", "priority"),
        Index("ix_findings_correlation_key", "assessment_id", "correlation_key"),
    )
    id: Mapped[int] = mapped_column(primary_key=True)
    assessment_id: Mapped[int] = mapped_column(ForeignKey("assessments.id", ondelete="CASCADE"), index=True)
    endpoint_id: Mapped[int | None] = mapped_column(ForeignKey("endpoints.id", ondelete="SET NULL"), index=True, nullable=True)
    test_run_id: Mapped[int | None] = mapped_column(ForeignKey("test_runs.id", ondelete="SET NULL"), index=True, nullable=True)
    title: Mapped[str] = mapped_column(String(300))
    severity: Mapped[str] = mapped_column(String(30), default="Medium")
    status: Mapped[str] = mapped_column(String(40), default="Candidate")
    endpoint: Mapped[str] = mapped_column(String(1000), default="")
    description: Mapped[str] = mapped_column(Text, default="")
    impact: Mapped[str] = mapped_column(Text, default="")
    evidence: Mapped[dict] = mapped_column(JSON, default=dict)
    remediation: Mapped[str] = mapped_column(Text, default="")
    vulnerability_category: Mapped[str] = mapped_column(String(80), default="", nullable=False)
    owasp_categories: Mapped[list] = mapped_column(JSON, default=list, nullable=False)
    taxonomy_version: Mapped[str] = mapped_column(String(100), default="", nullable=False)
    validation_state: Mapped[str] = mapped_column(String(30), default="PENDING_VALIDATION", nullable=False)
    validation_rationale: Mapped[str] = mapped_column(Text, default="", nullable=False)
    remediation_status: Mapped[str] = mapped_column(String(40), default="OPEN", nullable=False)
    assigned_owner_id: Mapped[int | None] = mapped_column(ForeignKey("analysts.id", ondelete="SET NULL"), nullable=True, index=True)
    remediation_target_date: Mapped[date | None] = mapped_column(Date, nullable=True)
    remediation_notes: Mapped[str] = mapped_column(Text, default="", nullable=False)
    proposed_fix: Mapped[str] = mapped_column(Text, default="", nullable=False)
    linked_change_reference: Mapped[str] = mapped_column(String(500), default="", nullable=False)
    remediation_reviewer_notes: Mapped[str] = mapped_column(Text, default="", nullable=False)
    remediation_guidance_type: Mapped[str] = mapped_column(String(24), default="UNAVAILABLE", nullable=False)
    confidence: Mapped[str] = mapped_column(String(20), default="UNASSESSED", nullable=False)
    confidence_rationale: Mapped[str] = mapped_column(Text, default="", nullable=False)
    priority: Mapped[str] = mapped_column(String(4), default="P3", nullable=False)
    priority_rationale: Mapped[str] = mapped_column(Text, default="", nullable=False)
    risk_analysis: Mapped[dict] = mapped_column(JSON, default=dict, nullable=False)
    correlation_key: Mapped[str] = mapped_column(String(64), default="", nullable=False)
    first_detected_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=now, nullable=False)
    last_observed_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=now, nullable=False)
    history: Mapped[list] = mapped_column(JSON, default=list)
    triage_version: Mapped[int] = mapped_column(Integer, default=1, nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=now)
    evidence_attachments: Mapped[list["FindingEvidenceAttachment"]] = relationship(
        back_populates="finding", cascade="all, delete-orphan")
    assessment: Mapped[Assessment] = relationship(back_populates="findings")

    __mapper_args__: ClassVar[dict] = {"version_id_col": triage_version}


class FindingEvidenceAttachment(Base):
    """Small, sanitized immutable image evidence attached to a canonical finding."""
    __tablename__ = "finding_evidence_attachments"
    __table_args__ = (Index("ix_finding_evidence_finding_created", "finding_id", "created_at"),)
    id: Mapped[int] = mapped_column(primary_key=True)
    finding_id: Mapped[int] = mapped_column(ForeignKey("findings.id", ondelete="CASCADE"), nullable=False)
    uploaded_by_id: Mapped[int | None] = mapped_column(ForeignKey("analysts.id", ondelete="SET NULL"), nullable=True)
    filename: Mapped[str] = mapped_column(String(200), nullable=False)
    mime_type: Mapped[str] = mapped_column(String(40), nullable=False)
    caption: Mapped[str] = mapped_column(String(500), nullable=False, default="")
    sha256: Mapped[str] = mapped_column(String(64), nullable=False)
    image_bytes: Mapped[bytes] = mapped_column(LargeBinary, nullable=False)
    width: Mapped[int] = mapped_column(Integer, nullable=False)
    height: Mapped[int] = mapped_column(Integer, nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=now, nullable=False)
    finding: Mapped[Finding] = relationship(back_populates="evidence_attachments")


class Report(Base):
    __tablename__ = "reports"
    id: Mapped[int] = mapped_column(primary_key=True)
    assessment_id: Mapped[int] = mapped_column(ForeignKey("assessments.id", ondelete="CASCADE"), index=True)
    version: Mapped[int] = mapped_column(Integer, default=1)
    status: Mapped[str] = mapped_column(String(30), default="Draft")
    format: Mapped[str] = mapped_column(String(20), default="json")
    content: Mapped[dict] = mapped_column(JSON, default=dict)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=now)
    assessment: Mapped[Assessment] = relationship(back_populates="reports")


class Retest(Base):
    __tablename__ = "retests"
    __table_args__ = (Index("uq_retests_test_run_id", "test_run_id", unique=True),)
    id: Mapped[int] = mapped_column(primary_key=True)
    finding_id: Mapped[int] = mapped_column(ForeignKey("findings.id", ondelete="CASCADE"), index=True)
    # Nullable so pre-provenance retests remain honest and are not backfilled.
    assessment_id: Mapped[int | None] = mapped_column(ForeignKey("assessments.id", ondelete="SET NULL"), index=True, nullable=True)
    test_run_id: Mapped[int | None] = mapped_column(ForeignKey("test_runs.id", ondelete="SET NULL"), nullable=True)
    endpoint_id: Mapped[int | None] = mapped_column(ForeignKey("endpoints.id", ondelete="SET NULL"), nullable=True)
    analyst_id: Mapped[int | None] = mapped_column(ForeignKey("analysts.id", ondelete="SET NULL"), nullable=True)
    test_id: Mapped[str] = mapped_column(String(120), default="", nullable=False)
    test_version: Mapped[str] = mapped_column(String(40), default="", nullable=False)
    endpoint_definition_hash: Mapped[str] = mapped_column(String(64), default="", nullable=False)
    outcome: Mapped[str] = mapped_column(String(40))
    evidence: Mapped[dict] = mapped_column(JSON, default=dict)
    notes: Mapped[str] = mapped_column(Text, default="")
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=now)
