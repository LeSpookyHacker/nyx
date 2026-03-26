"""Import all models so SQLAlchemy registers them with the metadata."""
from app.models.base import Base, TimestampMixin  # noqa: F401
from app.models.repository import Repository  # noqa: F401
from app.models.scan import Scan  # noqa: F401
from app.models.finding import Finding  # noqa: F401
from app.models.remediation import Remediation  # noqa: F401
from app.models.audit_log import AuditLog  # noqa: F401
from app.models.jira_link import JiraLink  # noqa: F401
from app.models.sbom import Sbom, SbomAlert  # noqa: F401
from app.models.regression_auto_alert import RegressionAutoAlert  # noqa: F401
