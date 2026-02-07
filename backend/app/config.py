"""
Configuration management for the mTLS PKI Portal.
Loads settings from environment variables and YAML config for CA/subject mapping.
"""

import os
from pathlib import Path
from typing import Optional

import yaml
from pydantic import BaseModel, Field
from pydantic_settings import BaseSettings


class OIDCConfig(BaseModel):
    """OIDC provider configuration (from environment)."""
    issuer: str
    client_id: str
    client_secret: Optional[str] = None
    scopes: list[str] = Field(default_factory=lambda: ["openid", "profile", "email", "groups"])


class SMTPConfig(BaseModel):
    """SMTP configuration for email notifications (from environment)."""
    enabled: bool = False
    host: str = ""
    port: int = 587
    username: Optional[str] = None
    password: Optional[str] = None
    from_address: str = ""
    from_display_name: Optional[str] = None
    use_tls: bool = True
    local_hostname: Optional[str] = None
    approver_emails: list[str] = Field(default_factory=list)


class SubjectAttributesConfig(BaseModel):
    """X.509 subject attribute configuration (from YAML)."""
    static: dict[str, str] = Field(default_factory=dict)
    mapping: dict[str, str] = Field(default_factory=dict)


class CARule(BaseModel):
    """Rule for CA access control."""
    oidc_groups: list[str] = Field(default_factory=list)
    auto_approve: bool = False
    approver_groups: list[str] = Field(default_factory=list)
    max_ttl: str = "720h"  # Default 30 days
    # Quota settings
    max_active_certs: Optional[int] = None  # None = unlimited
    allow_request_over_quota: bool = True  # If false, block requests when at limit
    # Renewal grace period - how early before expiry a user can request a renewal
    # without the expiring cert counting against their quota.
    # Set to "0h" to disable (expiring certs always count). Default: no grace period.
    renewal_grace_period: str = "0h"
    
    def parse_ttl_hours(self) -> int:
        """Parse TTL string to hours."""
        return self._parse_duration(self.max_ttl)
    
    def parse_renewal_grace_period_hours(self) -> int:
        """Parse renewal grace period string to hours."""
        return self._parse_duration(self.renewal_grace_period)
    
    @staticmethod
    def _parse_duration(duration: str) -> int:
        """Parse a duration string (e.g. '720h', '30d', '4w') to hours."""
        d = duration.strip().lower()
        if d.endswith("h"):
            return int(d[:-1])
        elif d.endswith("d"):
            return int(d[:-1]) * 24
        elif d.endswith("w"):
            return int(d[:-1]) * 24 * 7
        return int(d)


class X509CAConfig(BaseModel):
    """Certificate Authority configuration (from YAML)."""
    id: str
    name: str
    cert_path: str
    key_path: str
    rules: list[CARule] = Field(default_factory=list)
    key_password_env_var: Optional[str] = None
    
    @property
    def key_password(self) -> Optional[bytes]:
        """Resolve CA key password from environment variable."""
        if self.key_password_env_var:
            pwd = os.getenv(self.key_password_env_var)
            return pwd.encode() if pwd else None
        return None


class SANMappingConfig(BaseModel):
    """Subject Alternative Name mappings (from YAML)."""
    email: Optional[str] = None
    dns: Optional[list[str]] = None
    uri: Optional[str] = None


class EnvSettings(BaseSettings):
    """Environment-based settings."""
    # App settings
    app_url: str = "http://localhost"
    
    # OIDC settings
    oidc_issuer: str = ""
    oidc_client_id: str = ""
    oidc_client_secret: Optional[str] = None
    oidc_scopes: str = "openid,profile,email,groups"
    
    # Database
    postgres_user: str = "pki"
    postgres_password: str = "pki"
    postgres_db: str = "pki"
    postgres_host: str = "db"
    postgres_port: int = 5432
    
    # Config file path (for CA/subject mapping)
    config_path: str = "/app/config.yaml"
    
    # SMTP settings
    smtp_enabled: bool = False
    smtp_host: str = ""
    smtp_port: int = 587
    smtp_username: Optional[str] = None
    smtp_password: Optional[str] = None
    smtp_from_address: str = ""
    smtp_from_display_name: Optional[str] = None
    smtp_use_tls: bool = True
    smtp_server_name: Optional[str] = None
    smtp_approver_emails: str = ""
    
    class Config:
        env_file = ".env"
        extra = "ignore"


class AppConfig(BaseModel):
    """Main application configuration (combined from env + YAML)."""
    # From environment
    app_url: str
    oidc: OIDCConfig
    database_url: str
    smtp: SMTPConfig
    
    # From YAML config file
    subject_attributes: SubjectAttributesConfig = Field(default_factory=SubjectAttributesConfig)
    san_mapping: SANMappingConfig = Field(default_factory=SANMappingConfig)
    x509_cas: list[X509CAConfig] = Field(default_factory=list)
    admin_groups: list[str] = Field(default_factory=list)  # Groups with admin access


_config: Optional[AppConfig] = None


def load_config() -> AppConfig:
    """Load configuration from environment variables and YAML file."""
    global _config
    
    if _config is not None:
        return _config
    
    # Load environment settings
    env = EnvSettings()
    
    # Build OIDC config from env
    oidc = OIDCConfig(
        issuer=env.oidc_issuer,
        client_id=env.oidc_client_id,
        client_secret=env.oidc_client_secret,
        scopes=[s.strip() for s in env.oidc_scopes.split(",") if s.strip()],
    )
    
    # Build Database URL from individual params
    database_url = f"postgresql://{env.postgres_user}:{env.postgres_password}@{env.postgres_host}:{env.postgres_port}/{env.postgres_db}"
    
    # Build SMTP config from env
    smtp = SMTPConfig(
        enabled=env.smtp_enabled,
        host=env.smtp_host,
        port=env.smtp_port,
        username=env.smtp_username,
        password=env.smtp_password,
        from_address=env.smtp_from_address,
        from_display_name=env.smtp_from_display_name,
        use_tls=env.smtp_use_tls,
        local_hostname=env.smtp_server_name,
        approver_emails=[e.strip() for e in env.smtp_approver_emails.split(",") if e.strip()],
    )
    
    # Load YAML config for CA and subject mapping
    yaml_config = {}
    config_path = Path(env.config_path)
    if config_path.exists():
        with open(config_path, "r") as f:
            yaml_config = yaml.safe_load(f) or {}
    
    # Build subject attributes from YAML
    subject_attrs_raw = yaml_config.get("subject_attributes", {})
    subject_attributes = SubjectAttributesConfig(
        static=subject_attrs_raw.get("static", {}),
        mapping=subject_attrs_raw.get("mapping", {}),
    )
    
    # Build SAN mapping from YAML
    san_raw = yaml_config.get("san_mapping", {})
    san_mapping = SANMappingConfig(**san_raw) if san_raw else SANMappingConfig()
    
    # Build CA configs from YAML
    x509_cas = []
    for ca_raw in yaml_config.get("x509_cas", []):
        rules = [CARule(**r) for r in ca_raw.get("rules", [])]
        ca = X509CAConfig(
            id=ca_raw.get("id", ""),
            name=ca_raw.get("name", ""),
            cert_path=ca_raw.get("cert_path", ""),
            key_path=ca_raw.get("key_path", ""),
            rules=rules,
            key_password_env_var=ca_raw.get("key_password_env_var"),
        )
        x509_cas.append(ca)
    
    # Load admin groups from YAML
    admin_groups = yaml_config.get("admin_groups", [])
    
    _config = AppConfig(
        app_url=env.app_url,
        oidc=oidc,
        database_url=database_url,
        smtp=smtp,
        subject_attributes=subject_attributes,
        san_mapping=san_mapping,
        x509_cas=x509_cas,
        admin_groups=admin_groups,
    )
    
    return _config


def get_config() -> AppConfig:
    """Get the loaded configuration (loads if not already loaded)."""
    global _config
    if _config is None:
        return load_config()
    return _config
