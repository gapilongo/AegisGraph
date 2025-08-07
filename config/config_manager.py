# config/config_manager.py
import json
import logging
import os
import threading
import time
from datetime import datetime
from enum import Enum
from pathlib import Path
from typing import Any, Dict, List, Optional, Union

import yaml
from pydantic import BaseModel, Field, validator
from watchdog.events import FileSystemEventHandler
from watchdog.observers import Observer

logger = logging.getLogger(__name__)


class Environment(str, Enum):
    """Supported deployment environments"""
    DEVELOPMENT = "dev"
    TEST = "test" 
    STAGING = "staging"
    PRODUCTION = "prod"


class CredentialProvider(str, Enum):
    """Supported credential management providers"""
    ENVIRONMENT = "env"
    HASHICORP_VAULT = "vault"
    AWS_SECRETS_MANAGER = "aws_secrets"
    AZURE_KEY_VAULT = "azure_kv"
    LOCAL_FILE = "file"  # For development only


class DatabaseConfig(BaseModel):
    """Database configuration model"""
    host: str = Field(default="localhost", description="Database host")
    port: int = Field(default=5432, ge=1, le=65535)
    database: str = Field(default="soc_framework", description="Database name")
    username: str = Field(default="soc_user", description="Database username")
    password: Optional[str] = Field(default=None, description="Database password")
    ssl_mode: str = Field(default="require", description="SSL mode")
    pool_size: int = Field(default=10, ge=1, le=100)
    max_overflow: int = Field(default=20, ge=0, le=100)


class RedisConfig(BaseModel):
    """Redis configuration model"""
    host: str = Field(default="localhost", description="Redis host")
    port: int = Field(default=6379, ge=1, le=65535)
    database: int = Field(default=0, ge=0, le=15)
    password: Optional[str] = Field(default=None, description="Redis password")
    ssl: bool = Field(default=False, description="Use SSL connection")


class SIEMConnectionConfig(BaseModel):
    """SIEM connection configuration model"""
    type: str = Field(..., description="SIEM type (splunk, qradar, sentinel)")
    endpoint: str = Field(..., description="SIEM API endpoint")
    auth_method: str = Field(..., description="Authentication method")
    timeout_seconds: int = Field(default=30, ge=1, le=300)
    rate_limit_rps: float = Field(default=10.0, ge=0.1, le=1000.0)
    batch_size: int = Field(default=100, ge=1, le=10000)


class SecurityConfig(BaseModel):
    """Security configuration model"""
    encryption_key_id: str = Field(default="default_key_123", description="Encryption key identifier")
    token_expiry_hours: int = Field(default=24, ge=1, le=8760)  # Max 1 year
    allowed_origins: List[str] = Field(default_factory=list)
    jwt_algorithm: str = Field(default="HS256")
    password_min_length: int = Field(default=12, ge=8, le=128)
    session_timeout_minutes: int = Field(default=30, ge=5, le=480)


class PerformanceConfig(BaseModel):
    """Performance configuration model"""
    max_concurrent_agents: int = Field(default=10, ge=1, le=100)
    agent_timeout_seconds: int = Field(default=300, ge=10, le=3600)
    state_cache_ttl_seconds: int = Field(default=3600, ge=60, le=86400)
    batch_processing_size: int = Field(default=50, ge=1, le=1000)
    memory_limit_mb: int = Field(default=1024, ge=256, le=16384)


class NotificationConfig(BaseModel):
    """Notification configuration model"""
    slack_webhook_url: Optional[str] = None
    email_smtp_host: Optional[str] = None
    email_smtp_port: int = Field(default=587, ge=1, le=65535)
    email_use_tls: bool = Field(default=True)
    pagerduty_integration_key: Optional[str] = None
    notification_rate_limit: int = Field(default=100, ge=1, le=10000)  # per hour


class SOCFrameworkConfig(BaseModel):
    """Main configuration model for SOC framework"""
    environment: Environment
    debug: bool = Field(default=False)
    log_level: str = Field(default="INFO")
    
    # Core components
    database: DatabaseConfig = Field(default_factory=DatabaseConfig)
    redis: RedisConfig = Field(default_factory=RedisConfig)
    security: SecurityConfig = Field(default_factory=SecurityConfig)
    performance: PerformanceConfig = Field(default_factory=PerformanceConfig)
    notifications: NotificationConfig = Field(default_factory=NotificationConfig)
    
    # SIEM connections
    siem_connections: Dict[str, SIEMConnectionConfig] = Field(default_factory=dict)
    
    # Feature flags
    enable_learning_agent: bool = Field(default=True)
    enable_auto_response: bool = Field(default=False)
    enable_metrics_collection: bool = Field(default=True)
    enable_state_persistence: bool = Field(default=True)
    
    # Version and metadata
    config_version: str = Field(default="1.0.0")
    last_updated: datetime = Field(default_factory=datetime.utcnow)
    
    @validator('environment')
    def validate_environment(cls, v):
        """Validate environment value"""
        if isinstance(v, str):
            return Environment(v)
        return v
    
    @validator('log_level')
    def validate_log_level(cls, v):
        """Validate log level"""
        valid_levels = ['DEBUG', 'INFO', 'WARNING', 'ERROR', 'CRITICAL']
        if v.upper() not in valid_levels:
            raise ValueError(f'log_level must be one of: {valid_levels}')
        return v.upper()
    
    class Config:
        use_enum_values = True
        validate_assignment = True
        json_encoders = {
            datetime: lambda v: v.isoformat()
        }


class ConfigFileHandler(FileSystemEventHandler):
    """File system event handler for configuration hot-reload"""
    
    def __init__(self, config_manager):
        self.config_manager = config_manager
        self.last_reload = time.time()
        self.reload_debounce_seconds = 2.0  # Prevent rapid reloads
    
    def on_modified(self, event):
        """Handle file modification events"""
        if event.is_directory:
            return
            
        current_time = time.time()
        if current_time - self.last_reload < self.reload_debounce_seconds:
            return
            
        config_files = [
            self.config_manager.config_file_path,
            self.config_manager.env_file_path
        ]
        
        if event.src_path in [str(f) for f in config_files if f and f.exists()]:
            logger.info(f"Configuration file changed: {event.src_path}")
            try:
                self.config_manager._reload_configuration()
                self.last_reload = current_time
                logger.info("Configuration successfully reloaded")
            except Exception as e:
                logger.error(f"Failed to reload configuration: {e}")


class CredentialManager:
    """Manages credential retrieval from various providers"""
    
    def __init__(self, provider: CredentialProvider, provider_config: Dict[str, Any]):
        self.provider = provider
        self.provider_config = provider_config
        self._initialize_provider()
    
    def _initialize_provider(self):
        """Initialize the credential provider"""
        if self.provider == CredentialProvider.HASHICORP_VAULT:
            self._initialize_vault()
        elif self.provider == CredentialProvider.AWS_SECRETS_MANAGER:
            self._initialize_aws_secrets()
        elif self.provider == CredentialProvider.AZURE_KEY_VAULT:
            self._initialize_azure_kv()
    
    def _initialize_vault(self):
        """Initialize HashiCorp Vault client"""
        try:
            import hvac
            self.vault_client = hvac.Client(
                url=self.provider_config.get('url'),
                token=self.provider_config.get('token')
            )
            if not self.vault_client.is_authenticated():
                raise Exception("Vault authentication failed")
            logger.info("HashiCorp Vault client initialized successfully")
        except ImportError:
            raise Exception("hvac package required for HashiCorp Vault support")
        except Exception as e:
            raise Exception(f"Failed to initialize Vault client: {e}")
    
    def _initialize_aws_secrets(self):
        """Initialize AWS Secrets Manager client"""
        try:
            import boto3
            self.secrets_client = boto3.client(
                'secretsmanager',
                region_name=self.provider_config.get('region', 'us-east-1'),
                aws_access_key_id=self.provider_config.get('access_key_id'),
                aws_secret_access_key=self.provider_config.get('secret_access_key')
            )
            logger.info("AWS Secrets Manager client initialized successfully")
        except ImportError:
            raise Exception("boto3 package required for AWS Secrets Manager support")
        except Exception as e:
            raise Exception(f"Failed to initialize AWS Secrets Manager client: {e}")
    
    def _initialize_azure_kv(self):
        """Initialize Azure Key Vault client"""
        try:
            from azure.identity import DefaultAzureCredential
            from azure.keyvault.secrets import SecretClient
            
            credential = DefaultAzureCredential()
            vault_url = self.provider_config.get('vault_url')
            self.kv_client = SecretClient(vault_url=vault_url, credential=credential)
            logger.info("Azure Key Vault client initialized successfully")
        except ImportError:
            raise Exception("azure-keyvault-secrets and azure-identity packages required for Azure Key Vault support")
        except Exception as e:
            raise Exception(f"Failed to initialize Azure Key Vault client: {e}")
    
    def get_secret(self, secret_path: str) -> str:
        """
        Retrieve secret from the configured provider
        
        Args:
            secret_path: Path to the secret in the provider's format
            
        Returns:
            str: Secret value
        """
        try:
            if self.provider == CredentialProvider.ENVIRONMENT:
                return os.environ.get(secret_path)
            elif self.provider == CredentialProvider.HASHICORP_VAULT:
                return self._get_vault_secret(secret_path)
            elif self.provider == CredentialProvider.AWS_SECRETS_MANAGER:
                return self._get_aws_secret(secret_path)
            elif self.provider == CredentialProvider.AZURE_KEY_VAULT:
                return self._get_azure_secret(secret_path)
            elif self.provider == CredentialProvider.LOCAL_FILE:
                return self._get_file_secret(secret_path)
            else:
                raise ValueError(f"Unsupported credential provider: {self.provider}")
        except Exception as e:
            logger.error(f"Failed to retrieve secret '{secret_path}': {e}")
            raise
    
    def _get_vault_secret(self, secret_path: str) -> str:
        """Retrieve secret from HashiCorp Vault"""
        response = self.vault_client.secrets.kv.v2.read_secret_version(path=secret_path)
        return response['data']['data'].get('value')
    
    def _get_aws_secret(self, secret_path: str) -> str:
        """Retrieve secret from AWS Secrets Manager"""
        response = self.secrets_client.get_secret_value(SecretId=secret_path)
        return response['SecretString']
    
    def _get_azure_secret(self, secret_path: str) -> str:
        """Retrieve secret from Azure Key Vault"""
        secret = self.kv_client.get_secret(secret_path)
        return secret.value
    
    def _get_file_secret(self, secret_path: str) -> str:
        """Retrieve secret from local file (development only)"""
        file_path = Path(self.provider_config.get('base_path', '.')) / secret_path
        if not file_path.exists():
            raise FileNotFoundError(f"Secret file not found: {file_path}")
        return file_path.read_text().strip()


class ConfigManager:
    """
    Hierarchical configuration manager with environment support and secure credentials
    
    SOC-003 Requirements:
    - Environment-based configuration (dev, test, staging, prod)
    - Support for environment variables, .env files, and configuration files
    - Secure credential management (HashiCorp Vault, AWS Secrets Manager)
    - Configuration validation at startup
    - Configuration hot-reload capability
    - Tests for all configuration scenarios
    """
    
    def __init__(self, 
                 environment: Optional[Environment] = None,
                 config_file: Optional[str] = None,
                 env_file: Optional[str] = None,
                 credential_provider: CredentialProvider = CredentialProvider.ENVIRONMENT,
                 credential_config: Optional[Dict] = None):
        """
        Initialize configuration manager
        
        Args:
            environment: Target environment (auto-detected if None)
            config_file: Path to configuration file
            env_file: Path to .env file
            credential_provider: Credential management provider
            credential_config: Provider-specific configuration
        """
        self.environment = environment or self._detect_environment()
        self.config_file_path = Path(config_file) if config_file else self._get_default_config_file()
        self.env_file_path = Path(env_file) if env_file else Path(".env")
        
        # Initialize credential manager
        self.credential_manager = None
        if credential_config:
            try:
                self.credential_manager = CredentialManager(credential_provider, credential_config)
            except Exception as e:
                logger.warning(f"Failed to initialize credential manager: {e}")
        
        # Configuration state
        self._config: Optional[SOCFrameworkConfig] = None
        self._config_lock = threading.RLock()
        self._last_loaded = None
        
        # Hot-reload setup
        self._observer = None
        self._file_handler = None
        self._hot_reload_enabled = False
        
        # Load initial configuration
        self.load_configuration()
    
    def _detect_environment(self) -> Environment:
        """Auto-detect environment from various sources"""
        # Check environment variable first
        env_var = os.environ.get('SOC_ENVIRONMENT', os.environ.get('ENVIRONMENT', ''))
        if env_var:
            try:
                return Environment(env_var.lower())
            except ValueError:
                pass
        
        # Check for common CI/CD indicators
        if os.environ.get('CI') or os.environ.get('GITHUB_ACTIONS'):
            return Environment.TEST
        
        # Check for production indicators
        if os.environ.get('PROD') or os.environ.get('PRODUCTION'):
            return Environment.PRODUCTION
        
        # Default to development
        return Environment.DEVELOPMENT
    
    def _get_default_config_file(self) -> Path:
        """Get default configuration file based on environment"""
        config_dir = Path("config")
        
        # Look for environment-specific config first
        env_config = config_dir / f"config.{self.environment.value}.yaml"
        if env_config.exists():
            return env_config
        
        # Fall back to general config
        for filename in ["config.yaml", "config.yml", "config.json"]:
            config_file = config_dir / filename
            if config_file.exists():
                return config_file
        
        # Create default path
        return config_dir / "config.yaml"
    
    def load_configuration(self) -> SOCFrameworkConfig:
        """
        Load configuration from all sources with proper precedence
        
        Precedence (highest to lowest):
        1. Environment variables
        2. .env file
        3. Configuration file
        4. Default values
        
        Returns:
            SOCFrameworkConfig: Loaded and validated configuration
        """
        with self._config_lock:
            logger.info(f"Loading configuration for environment: {self.environment.value}")
            
            # Start with defaults
            config_data = {
                "environment": self.environment.value
            }
            
            # Load from configuration file
            if self.config_file_path.exists():
                file_config = self._load_config_file()
                config_data.update(file_config)
                logger.info(f"Loaded configuration from: {self.config_file_path}")
            else:
                logger.warning(f"Configuration file not found: {self.config_file_path}")
            
            # Load from .env file
            if self.env_file_path.exists():
                self._load_env_file()
                logger.info(f"Loaded environment variables from: {self.env_file_path}")
            
            # Override with environment variables
            self._apply_environment_overrides(config_data)
            
            # Resolve secrets
            self._resolve_secrets(config_data)
            
            # Create and validate configuration
            try:
                self._config = SOCFrameworkConfig(**config_data)
                self._last_loaded = datetime.utcnow()
                
                logger.info("Configuration loaded and validated successfully")
                self._log_configuration_summary()
                
                return self._config
                
            except Exception as e:
                logger.error(f"Configuration validation failed: {e}")
                raise ValueError(f"Invalid configuration: {e}")
    
    def _load_config_file(self) -> Dict[str, Any]:
        """Load configuration from YAML or JSON file"""
        try:
            content = self.config_file_path.read_text()
            
            if self.config_file_path.suffix.lower() in ['.yaml', '.yml']:
                return yaml.safe_load(content) or {}
            elif self.config_file_path.suffix.lower() == '.json':
                return json.loads(content)
            else:
                raise ValueError(f"Unsupported config file format: {self.config_file_path.suffix}")
                
        except Exception as e:
            logger.error(f"Failed to load config file {self.config_file_path}: {e}")
            raise
    
    def _load_env_file(self):
        """Load environment variables from .env file"""
        try:
            from dotenv import load_dotenv
            load_dotenv(self.env_file_path)
        except ImportError:
            # Manual .env loading if python-dotenv is not available
            with open(self.env_file_path) as f:
                for line in f:
                    line = line.strip()
                    if line and not line.startswith('#') and '=' in line:
                        key, value = line.split('=', 1)
                        os.environ[key.strip()] = value.strip()
        except Exception as e:
            logger.error(f"Failed to load .env file {self.env_file_path}: {e}")
            raise
    
    def _apply_environment_overrides(self, config_data: Dict[str, Any]):
        """Apply environment variable overrides using hierarchical mapping"""
        env_mappings = {
            # Database settings
            'SOC_DB_HOST': ('database', 'host'),
            'SOC_DB_PORT': ('database', 'port'),
            'SOC_DB_NAME': ('database', 'database'),
            'SOC_DB_USER': ('database', 'username'),
            'SOC_DB_PASSWORD': ('database', 'password'),
            'SOC_DB_SSL_MODE': ('database', 'ssl_mode'),
            'SOC_DB_POOL_SIZE': ('database', 'pool_size'),
            
            # Redis settings
            'SOC_REDIS_HOST': ('redis', 'host'),
            'SOC_REDIS_PORT': ('redis', 'port'),
            'SOC_REDIS_DB': ('redis', 'database'),
            'SOC_REDIS_PASSWORD': ('redis', 'password'),
            'SOC_REDIS_SSL': ('redis', 'ssl'),
            
            # Security settings
            'SOC_ENCRYPTION_KEY_ID': ('security', 'encryption_key_id'),
            'SOC_TOKEN_EXPIRY_HOURS': ('security', 'token_expiry_hours'),
            'SOC_JWT_ALGORITHM': ('security', 'jwt_algorithm'),
            'SOC_SESSION_TIMEOUT': ('security', 'session_timeout_minutes'),
            
            # Performance settings
            'SOC_MAX_CONCURRENT_AGENTS': ('performance', 'max_concurrent_agents'),
            'SOC_AGENT_TIMEOUT': ('performance', 'agent_timeout_seconds'),
            'SOC_STATE_CACHE_TTL': ('performance', 'state_cache_ttl_seconds'),
            'SOC_BATCH_SIZE': ('performance', 'batch_processing_size'),
            'SOC_MEMORY_LIMIT_MB': ('performance', 'memory_limit_mb'),
            
            # Notification settings
            'SOC_SLACK_WEBHOOK': ('notifications', 'slack_webhook_url'),
            'SOC_SMTP_HOST': ('notifications', 'email_smtp_host'),
            'SOC_SMTP_PORT': ('notifications', 'email_smtp_port'),
            'SOC_PAGERDUTY_KEY': ('notifications', 'pagerduty_integration_key'),
            
            # General settings
            'SOC_DEBUG': ('debug',),
            'SOC_LOG_LEVEL': ('log_level',),
            'SOC_ENABLE_LEARNING': ('enable_learning_agent',),
            'SOC_ENABLE_AUTO_RESPONSE': ('enable_auto_response',),
            'SOC_ENABLE_METRICS': ('enable_metrics_collection',),
        }
        
        for env_var, config_path in env_mappings.items():
            value = os.environ.get(env_var)
            if value is not None:
                self._set_nested_value(config_data, config_path, self._convert_env_value(value))
    
    def _set_nested_value(self, data: Dict, path: tuple, value: Any):
        """Set nested dictionary value using path tuple"""
        current = data
        for key in path[:-1]:
            if key not in current:
                current[key] = {}
            current = current[key]
        current[path[-1]] = value
    
    def _convert_env_value(self, value: str) -> Any:
        """Convert environment variable string to appropriate type"""
        # Boolean conversion
        if value.lower() in ('true', 'yes', '1', 'on'):
            return True
        elif value.lower() in ('false', 'no', '0', 'off'):
            return False
        
        # Integer conversion
        if value.isdigit():
            return int(value)
        
        # Float conversion
        try:
            if '.' in value:
                return float(value)
        except ValueError:
            pass
        
        # List conversion (comma-separated)
        if ',' in value:
            return [item.strip() for item in value.split(',')]
        
        # Return as string
        return value
    
    def _resolve_secrets(self, config_data: Dict[str, Any]):
        """Resolve secret references in configuration"""
        if not self.credential_manager:
            return
        
        self._resolve_secrets_recursive(config_data)
    
    def _resolve_secrets_recursive(self, data: Any) -> Any:
        """Recursively resolve secrets in nested structures"""
        if isinstance(data, dict):
            for key, value in data.items():
                data[key] = self._resolve_secrets_recursive(value)
        elif isinstance(data, list):
            for i, value in enumerate(data):
                data[i] = self._resolve_secrets_recursive(value)
        elif isinstance(data, str) and data.startswith('${secret:') and data.endswith('}'):
            # Extract secret name from ${secret:name}
            secret_name = data[9:-1]
            try:
                secret_value = self.credential_manager.get_secret(secret_name)
                return secret_value if secret_value else data
            except Exception as e:
                logger.warning(f"Failed to resolve secret '{secret_name}': {e}")
                return data
        
        return data
    
    def _log_configuration_summary(self):
        """Log configuration summary (without sensitive data)"""
        summary = {
            "environment": self._config.environment.value,
            "debug": self._config.debug,
            "log_level": self._config.log_level,
            "database_host": self._config.database.host,
            "redis_host": self._config.redis.host,
            "siem_connections": list(self._config.siem_connections.keys()),
            "feature_flags": {
                "learning_agent": self._config.enable_learning_agent,
                "auto_response": self._config.enable_auto_response,
                "metrics_collection": self._config.enable_metrics_collection,
                "state_persistence": self._config.enable_state_persistence,
            }
        }
        logger.info(f"Configuration summary: {json.dumps(summary, indent=2)}")
    
    def enable_hot_reload(self):
        """Enable configuration hot-reload monitoring"""
        if self._hot_reload_enabled:
            return
        
        try:
            self._file_handler = ConfigFileHandler(self)
            self._observer = Observer()
            
            # Watch config directory
            config_dir = self.config_file_path.parent
            if config_dir.exists():
                self._observer.schedule(self._file_handler, str(config_dir), recursive=False)
            
            # Watch .env file directory if different
            env_dir = self.env_file_path.parent
            if env_dir != config_dir and env_dir.exists():
                self._observer.schedule(self._file_handler, str(env_dir), recursive=False)
            
            self._observer.start()
            self._hot_reload_enabled = True
            logger.info("Configuration hot-reload enabled")
            
        except Exception as e:
            logger.error(f"Failed to enable hot-reload: {e}")
    
    def disable_hot_reload(self):
        """Disable configuration hot-reload monitoring"""
        if not self._hot_reload_enabled:
            return
        
        try:
            if self._observer:
                self._observer.stop()
                self._observer.join()
                self._observer = None
            
            self._file_handler = None
            self._hot_reload_enabled = False
            logger.info("Configuration hot-reload disabled")
            
        except Exception as e:
            logger.error(f"Failed to disable hot-reload: {e}")
    
    def _reload_configuration(self):
        """Internal method to reload configuration (called by file watcher)"""
        try:
            old_config = self._config
            new_config = self.load_configuration()
            
            # Trigger reload callbacks if configuration changed
            if old_config != new_config:
                logger.info("Configuration changed - triggering reload callbacks")
                
        except Exception as e:
            logger.error(f"Failed to reload configuration: {e}")
    
    @property
    def config(self) -> SOCFrameworkConfig:
        """Get current configuration (thread-safe)"""
        with self._config_lock:
            if self._config is None:
                raise RuntimeError("Configuration not loaded. Call load_configuration() first.")
            return self._config
    
    def get_siem_config(self, siem_name: str) -> Optional[SIEMConnectionConfig]:
        """Get configuration for specific SIEM connection"""
        return self.config.siem_connections.get(siem_name)
    
    def validate_configuration(self) -> tuple[bool, List[str]]:
        """
        Validate current configuration and return validation results
        
        Returns:
            Tuple[bool, List[str]]: (is_valid, list_of_errors)
        """
        errors = []
        
        try:
            config = self.config
            
            # Validate database connection
            if not config.database.host:
                errors.append("Database host is required")
            if not config.database.database:
                errors.append("Database name is required")
            if not config.database.username:
                errors.append("Database username is required")
            
            # Validate required security settings
            if not config.security.encryption_key_id:
                errors.append("Encryption key ID is required")
            
            # Validate SIEM connections
            for siem_name, siem_config in config.siem_connections.items():
                if not siem_config.endpoint:
                    errors.append(f"SIEM '{siem_name}' endpoint is required")
                if not siem_config.type:
                    errors.append(f"SIEM '{siem_name}' type is required")
            
            # Validate performance settings
            if config.performance.max_concurrent_agents < 1:
                errors.append("Max concurrent agents must be at least 1")
            
            # Environment-specific validations
            if config.environment == Environment.PRODUCTION:
                if config.debug:
                    errors.append("Debug mode should not be enabled in production")
                if config.log_level == "DEBUG":
                    errors.append("Debug log level should not be used in production")
            
            return len(errors) == 0, errors
            
        except Exception as e:
            errors.append(f"Configuration validation error: {e}")
            return False, errors
    
    def export_config(self, format: str = "yaml", include_secrets: bool = False) -> str:
        """
        Export current configuration to string
        
        Args:
            format: Export format ('yaml' or 'json')
            include_secrets: Whether to include sensitive data
            
        Returns:
            str: Exported configuration
        """
        config_dict = self.config.model_dump()
        
        if not include_secrets:
            # Mask sensitive fields
            self._mask_secrets_recursive(config_dict)
        
        if format.lower() == 'yaml':
            return yaml.dump(config_dict, default_flow_style=False, indent=2)
        elif format.lower() == 'json':
            return json.dumps(config_dict, indent=2, default=str)
        else:
            raise ValueError(f"Unsupported format: {format}")
    
    def _mask_secrets_recursive(self, data: Any) -> Any:
        """Recursively mask secrets in nested structures"""
        sensitive_keys = {'password', 'token', 'key', 'secret', 'webhook'}
        
        if isinstance(data, dict):
            for key, value in data.items():
                if any(sensitive_word in key.lower() for sensitive_word in sensitive_keys):
                    data[key] = '***REDACTED***'
                else:
                    self._mask_secrets_recursive(value)
        elif isinstance(data, list):
            for item in data:
                self._mask_secrets_recursive(item)
        
        return data
    
    def __enter__(self):
        """Context manager entry"""
        return self
    
    def __exit__(self, exc_type, exc_val, exc_tb):
        """Context manager exit - cleanup resources"""
        self.disable_hot_reload()


# Global configuration manager instance
_config_manager: Optional[ConfigManager] = None
_config_lock = threading.Lock()


def get_config_manager() -> ConfigManager:
    """Get global configuration manager instance (singleton)"""
    global _config_manager
    
    if _config_manager is None:
        with _config_lock:
            if _config_manager is None:
                _config_manager = ConfigManager()
    
    return _config_manager


def init_config_manager(environment: Optional[Environment] = None,
                       config_file: Optional[str] = None,
                       env_file: Optional[str] = None,
                       credential_provider: CredentialProvider = CredentialProvider.ENVIRONMENT,
                       credential_config: Optional[Dict] = None,
                       enable_hot_reload: bool = True) -> ConfigManager:
    """
    Initialize global configuration manager
    
    Args:
        environment: Target environment
        config_file: Path to configuration file
        env_file: Path to .env file
        credential_provider: Credential management provider
        credential_config: Provider-specific configuration
        enable_hot_reload: Enable configuration hot-reload
        
    Returns:
        ConfigManager: Initialized configuration manager
    """
    global _config_manager
    
    with _config_lock:
        _config_manager = ConfigManager(
            environment=environment,
            config_file=config_file,
            env_file=env_file,
            credential_provider=credential_provider,
            credential_config=credential_config
        )
        
        if enable_hot_reload:
            _config_manager.enable_hot_reload()
    
    return _config_manager


def get_config() -> SOCFrameworkConfig:
    """Get current configuration"""
    return get_config_manager().config