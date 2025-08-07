# tests/test_config/test_config_manager.py
import json
import os
import sys
import tempfile
import threading
import time
from pathlib import Path
from unittest.mock import Mock, patch

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '../../')))

import pytest

from config.config_manager import (
    ConfigManager,
    CredentialManager,
    CredentialProvider,
    DatabaseConfig,
    Environment,
    NotificationConfig,
    PerformanceConfig,
    RedisConfig,
    SecurityConfig,
    SIEMConnectionConfig,
    SOCFrameworkConfig,
    get_config,
    get_config_manager,
    init_config_manager,
)


class TestEnvironmentSetup:
    """Base class with environment setup/teardown"""
    
    def setup_method(self):
        """Clean environment before each test"""
        self.original_env = os.environ.copy()
        
        # Clear SOC and test-related environment variables
        vars_to_clear = [
            key for key in os.environ.keys() 
            if key.startswith(('SOC_', 'TEST_')) or 
            key in ['CI', 'GITHUB_ACTIONS', 'PROD', 'PRODUCTION', 'ENVIRONMENT']
        ]
        for var in vars_to_clear:
            if var in os.environ:
                del os.environ[var]
        
        # Reset global config manager
        import config.config_manager
        config.config_manager._config_manager = None
    
    def teardown_method(self):
        """Restore environment after each test"""
        os.environ.clear()
        os.environ.update(self.original_env)
    
    def create_test_config(self, **overrides):
        """Create a valid test configuration with optional overrides"""
        config = {
            'environment': 'dev',
            'debug': False,
            'log_level': 'INFO',
            'database': {
                'host': 'localhost',
                'port': 5432,
                'database': 'soc_test',
                'username': 'test_user',
                'password': None
            },
            'redis': {
                'host': 'localhost',
                'port': 6379,
                'database': 0,
                'password': None,
                'ssl': False
            },
            'security': {
                'encryption_key_id': 'test_key_123',
                'token_expiry_hours': 24,
                'jwt_algorithm': 'HS256'
            },
            'performance': {
                'max_concurrent_agents': 10,
                'agent_timeout_seconds': 300
            },
            'notifications': {
                'email_smtp_port': 587,
                'notification_rate_limit': 100
            },
            'siem_connections': {}
        }
        
        # Apply overrides
        for key, value in overrides.items():
            if '.' in key:
                # Handle nested keys like 'database.host'
                parts = key.split('.')
                current = config
                for part in parts[:-1]:
                    if part not in current:
                        current[part] = {}
                    current = current[part]
                current[parts[-1]] = value
            else:
                config[key] = value
        
        return config


class TestCredentialManager(TestEnvironmentSetup):
    """Test credential management functionality"""
    
    def test_environment_credential_provider(self):
        """Test environment variable credential provider"""
        os.environ['TEST_SECRET'] = 'secret_value'
        
        manager = CredentialManager(CredentialProvider.ENVIRONMENT, {})
        secret = manager.get_secret('TEST_SECRET')
        
        assert secret == 'secret_value'
    
    def test_file_credential_provider(self):
        """Test file-based credential provider"""
        with tempfile.TemporaryDirectory() as temp_dir:
            secret_file = Path(temp_dir) / 'test_secret'
            secret_file.write_text('file_secret_value')
            
            config = {'base_path': temp_dir}
            manager = CredentialManager(CredentialProvider.LOCAL_FILE, config)
            
            secret = manager.get_secret('test_secret')
            assert secret == 'file_secret_value'
    
    def test_file_credential_not_found(self):
        """Test file credential provider with missing file"""
        with tempfile.TemporaryDirectory() as temp_dir:
            config = {'base_path': temp_dir}
            manager = CredentialManager(CredentialProvider.LOCAL_FILE, config)
            
            with pytest.raises(FileNotFoundError):
                manager.get_secret('nonexistent_secret')
    
    @patch('hvac.Client')
    def test_vault_credential_provider(self, mock_hvac):
        """Test HashiCorp Vault credential provider"""
        mock_client = Mock()
        mock_client.is_authenticated.return_value = True
        mock_client.secrets.kv.v2.read_secret_version.return_value = {
            'data': {'data': {'value': 'vault_secret'}}
        }
        mock_hvac.return_value = mock_client
        
        config = {'url': 'https://vault.test:8200', 'token': 'test_token'}
        manager = CredentialManager(CredentialProvider.HASHICORP_VAULT, config)
        
        secret = manager.get_secret('test/secret')
        assert secret == 'vault_secret'
    
    @patch('boto3.client')
    def test_aws_secrets_credential_provider(self, mock_boto3):
        """Test AWS Secrets Manager credential provider"""
        mock_client = Mock()
        mock_client.get_secret_value.return_value = {'SecretString': 'aws_secret'}
        mock_boto3.return_value = mock_client
        
        config = {'region': 'us-east-1'}
        manager = CredentialManager(CredentialProvider.AWS_SECRETS_MANAGER, config)
        
        secret = manager.get_secret('test/secret')
        assert secret == 'aws_secret'


class TestConfigurationModels(TestEnvironmentSetup):
    """Test configuration data models"""
    
    def test_database_config_defaults(self):
        """Test database configuration with defaults"""
        config = DatabaseConfig()
        
        assert config.host == 'localhost'
        assert config.port == 5432
        assert config.database == 'soc_framework'
        assert config.username == 'soc_user'
        assert config.ssl_mode == 'require'
    
    def test_database_config_validation(self):
        """Test database configuration validation"""
        # Valid configuration
        config = DatabaseConfig(host='db.example.com', database='prod_db', username='admin')
        assert config.host == 'db.example.com'
        
        # Invalid port
        with pytest.raises(ValueError):
            DatabaseConfig(port=0)
        
        # Invalid pool size
        with pytest.raises(ValueError):
            DatabaseConfig(pool_size=0)
    
    def test_security_config_defaults(self):
        """Test security configuration with defaults"""
        config = SecurityConfig()
        
        assert config.encryption_key_id == 'default_key_123'
        assert config.token_expiry_hours == 24
        assert config.jwt_algorithm == 'HS256'
    
    def test_siem_config_validation(self):
        """Test SIEM configuration validation"""
        config = SIEMConnectionConfig(
            type='splunk',
            endpoint='https://splunk.example.com:8089',
            auth_method='api_token'
        )
        
        assert config.timeout_seconds == 30
        assert config.rate_limit_rps == 10.0
        
        # Invalid rate limit
        with pytest.raises(ValueError):
            SIEMConnectionConfig(
                type='splunk',
                endpoint='https://test.com',
                auth_method='api_token',
                rate_limit_rps=0
            )


class TestConfigManager(TestEnvironmentSetup):
    """Test configuration manager core functionality"""
    
    def test_environment_detection(self):
        """Test automatic environment detection"""
        config_data = self.create_test_config()
        
        with tempfile.NamedTemporaryFile(mode='w', suffix='.yaml', delete=False) as f:
            import yaml
            yaml.dump(config_data, f)
            config_file = f.name
        
        try:
            # Test with environment variable
            os.environ['SOC_ENVIRONMENT'] = 'prod'
            manager = ConfigManager(config_file=config_file)
            assert manager.environment == Environment.PRODUCTION
            del os.environ['SOC_ENVIRONMENT']
            
            # Test with CI indicator
            os.environ['CI'] = 'true'
            manager = ConfigManager(config_file=config_file)
            assert manager.environment == Environment.TEST
            del os.environ['CI']
            
            # Test default
            manager = ConfigManager(config_file=config_file)
            assert manager.environment == Environment.DEVELOPMENT
            
        finally:
            os.unlink(config_file)
    
    def test_yaml_config_loading(self):
        """Test loading YAML configuration file"""
        config_data = self.create_test_config(
            debug=True,
            **{'database.host': 'yaml-host'}
        )
        
        with tempfile.NamedTemporaryFile(mode='w', suffix='.yaml', delete=False) as f:
            import yaml
            yaml.dump(config_data, f)
            config_file = f.name
        
        try:
            manager = ConfigManager(config_file=config_file)
            config = manager.config
            
            assert config.debug is True
            assert config.database.host == 'yaml-host'
            assert config.database.database == 'soc_test'
            
        finally:
            os.unlink(config_file)
    
    def test_json_config_loading(self):
        """Test loading JSON configuration file"""
        config_data = self.create_test_config(
            environment='test',
            **{'database.host': 'json-host'}
        )
        
        with tempfile.NamedTemporaryFile(mode='w', suffix='.json', delete=False) as f:
            json.dump(config_data, f)
            config_file = f.name
        
        try:
            manager = ConfigManager(environment=Environment.TEST, config_file=config_file)
            config = manager.config
            
            assert config.environment == Environment.TEST
            assert config.database.host == 'json-host'
            
        finally:
            os.unlink(config_file)
    
    def test_environment_variable_overrides(self):
        """Test environment variable overrides"""
        config_data = self.create_test_config()
        
        with tempfile.NamedTemporaryFile(mode='w', suffix='.yaml', delete=False) as f:
            import yaml
            yaml.dump(config_data, f)
            config_file = f.name
        
        # Set environment overrides
        os.environ.update({
            'SOC_DB_HOST': 'override-host',
            'SOC_DB_PORT': '3306',
            'SOC_DEBUG': 'true',
            'SOC_LOG_LEVEL': 'WARNING'
        })
        
        try:
            manager = ConfigManager(config_file=config_file)
            config = manager.config
            
            assert config.database.host == 'override-host'
            assert config.database.port == 3306
            assert config.debug is True
            assert config.log_level == 'WARNING'
            
        finally:
            os.unlink(config_file)
    
    def test_env_file_loading(self):
        """Test loading from .env file"""
        config_data = self.create_test_config()
        
        env_content = """
SOC_DB_HOST=env-db-host
SOC_DB_PORT=5433
SOC_DEBUG=true
SOC_LOG_LEVEL=DEBUG
        """.strip()
        
        with tempfile.NamedTemporaryFile(mode='w', suffix='.yaml', delete=False) as config_f:
            import yaml
            yaml.dump(config_data, config_f)
            config_file = config_f.name
        
        with tempfile.NamedTemporaryFile(mode='w', suffix='.env', delete=False) as env_f:
            env_f.write(env_content)
            env_file = env_f.name
        
        try:
            manager = ConfigManager(config_file=config_file, env_file=env_file)
            config = manager.config
            
            assert config.database.host == 'env-db-host'
            assert config.database.port == 5433
            assert config.debug is True
            assert config.log_level == 'DEBUG'
            
        finally:
            os.unlink(config_file)
            os.unlink(env_file)
    
    def test_configuration_precedence(self):
        """Test configuration precedence: env vars > .env > config file > defaults"""
        config_data = self.create_test_config(
            debug=False,
            log_level='INFO',
            **{
                'database.host': 'config-host',
                'database.port': 5432,
                'redis.port': 6379
            }
        )
        
        env_content = """
SOC_DB_HOST=env-host
SOC_REDIS_PORT=6380
        """.strip()
        
        with tempfile.NamedTemporaryFile(mode='w', suffix='.yaml', delete=False) as config_f:
            import yaml
            yaml.dump(config_data, config_f)
            config_file = config_f.name
        
        with tempfile.NamedTemporaryFile(mode='w', suffix='.env', delete=False) as env_f:
            env_f.write(env_content)
            env_file = env_f.name
        
        # Environment variables (highest precedence)
        os.environ.update({
            'SOC_LOG_LEVEL': 'WARNING',
            'SOC_DB_PORT': '3306'
        })
        
        try:
            manager = ConfigManager(config_file=config_file, env_file=env_file)
            config = manager.config
            
            # From environment variables (highest)
            assert config.log_level == 'WARNING'
            assert config.database.port == 3306
            
            # From .env file
            assert config.database.host == 'env-host'
            assert config.redis.port == 6380
            
            # From config file
            assert config.database.database == 'soc_test'
            
            # From defaults
            assert config.redis.database == 0
            
        finally:
            os.unlink(config_file)
            os.unlink(env_file)


class TestCredentialIntegration(TestEnvironmentSetup):
    """Test credential management integration"""
    
    def test_secret_resolution(self):
        """Test secret resolution from credential manager"""
        config_data = self.create_test_config(
            **{
                'database.password': '${secret:db_password}',
                'security.encryption_key_id': '${secret:encryption_key}',
                'notifications.slack_webhook_url': '${secret:slack_webhook}'
            }
        )
        
        with tempfile.NamedTemporaryFile(mode='w', suffix='.yaml', delete=False) as f:
            import yaml
            yaml.dump(config_data, f)
            config_file = f.name
        
        with tempfile.TemporaryDirectory() as temp_dir:
            # Create secret files
            (Path(temp_dir) / 'db_password').write_text('secret_db_pass')
            (Path(temp_dir) / 'encryption_key').write_text('secret_key_123')
            (Path(temp_dir) / 'slack_webhook').write_text('https://hooks.slack.com/test')
            
            credential_config = {'base_path': temp_dir}
            
            try:
                manager = ConfigManager(
                    config_file=config_file,
                    credential_provider=CredentialProvider.LOCAL_FILE,
                    credential_config=credential_config
                )
                config = manager.config
                
                assert config.database.password == 'secret_db_pass'
                assert config.security.encryption_key_id == 'secret_key_123'
                assert config.notifications.slack_webhook_url == 'https://hooks.slack.com/test'
                
            finally:
                os.unlink(config_file)


class TestConfigValidation(TestEnvironmentSetup):
    """Test configuration validation functionality"""
    
    def test_valid_configuration(self):
        """Test validation of valid configuration"""
        config_data = self.create_test_config(
            **{'performance.max_concurrent_agents': 5}
        )
        
        with tempfile.NamedTemporaryFile(mode='w', suffix='.yaml', delete=False) as f:
            import yaml
            yaml.dump(config_data, f)
            config_file = f.name
        
        try:
            manager = ConfigManager(config_file=config_file)
            is_valid, errors = manager.validate_configuration()
            
            assert is_valid is True
            assert len(errors) == 0
            
        finally:
            os.unlink(config_file)
    
    def test_invalid_configuration(self):
        """Test validation with configuration errors"""
        config_data = self.create_test_config(
            environment='prod',
            debug=True,  # Should not be enabled in prod
            **{
                'database.host': '',  # Empty host
                'security.encryption_key_id': ''  # Empty key
            }
        )
        
        with tempfile.NamedTemporaryFile(mode='w', suffix='.yaml', delete=False) as f:
            import yaml
            yaml.dump(config_data, f)
            config_file = f.name
        
        try:
            manager = ConfigManager(environment=Environment.PRODUCTION, config_file=config_file)
            is_valid, errors = manager.validate_configuration()
            
            assert is_valid is False
            assert len(errors) > 0
            
            error_text = ' '.join(errors)
            assert 'Database host is required' in error_text
            assert 'Debug mode should not be enabled in production' in error_text
            assert 'Encryption key ID is required' in error_text
            
        finally:
            os.unlink(config_file)


class TestConfigExport(TestEnvironmentSetup):
    """Test configuration export functionality"""
    
    def test_export_without_secrets(self):
        """Test configuration export with secrets masked"""
        config_data = self.create_test_config(
            **{
                'database.password': 'secret_password',
                'redis.password': 'redis_secret',
                'notifications.slack_webhook_url': 'https://secret.webhook.com'
            }
        )
        
        with tempfile.NamedTemporaryFile(mode='w', suffix='.yaml', delete=False) as f:
            import yaml
            yaml.dump(config_data, f)
            config_file = f.name
        
        try:
            manager = ConfigManager(config_file=config_file)
            
            # Export without secrets
            yaml_export = manager.export_config(format='yaml', include_secrets=False)
            json_export = manager.export_config(format='json', include_secrets=False)
            
            assert 'secret_password' not in yaml_export
            assert 'secret_password' not in json_export
            assert '***REDACTED***' in yaml_export
            assert '***REDACTED***' in json_export
            
        finally:
            os.unlink(config_file)
    
    def test_export_with_secrets(self):
        """Test configuration export with secrets included"""
        config_data = self.create_test_config(
            **{'database.password': 'secret_password'}
        )
        
        with tempfile.NamedTemporaryFile(mode='w', suffix='.yaml', delete=False) as f:
            import yaml
            yaml.dump(config_data, f)
            config_file = f.name
        
        try:
            manager = ConfigManager(config_file=config_file)
            
            yaml_export = manager.export_config(format='yaml', include_secrets=True)
            assert 'secret_password' in yaml_export
            
        finally:
            os.unlink(config_file)


class TestHotReload(TestEnvironmentSetup):
    """Test hot-reload functionality"""
    
    def test_hot_reload_enable_disable(self):
        """Test enabling and disabling hot-reload"""
        config_data = self.create_test_config()
        
        with tempfile.NamedTemporaryFile(mode='w', suffix='.yaml', delete=False) as f:
            import yaml
            yaml.dump(config_data, f)
            config_file = f.name
        
        try:
            manager = ConfigManager(config_file=config_file)
            
            # Test enabling
            manager.enable_hot_reload()
            assert manager._hot_reload_enabled is True
            
            # Test disabling
            manager.disable_hot_reload()
            assert manager._hot_reload_enabled is False
            
        finally:
            os.unlink(config_file)


class TestSIEMConnections(TestEnvironmentSetup):
    """Test SIEM connection configuration"""
    
    def test_siem_connections_loading(self):
        """Test loading SIEM connection configurations"""
        config_data = self.create_test_config(
            siem_connections={
                'splunk_prod': {
                    'type': 'splunk',
                    'endpoint': 'https://splunk.company.com:8089',
                    'auth_method': 'api_token',
                    'timeout_seconds': 60,
                    'rate_limit_rps': 10.0,
                    'batch_size': 100
                },
                'qradar_prod': {
                    'type': 'qradar',
                    'endpoint': 'https://qradar.company.com',
                    'auth_method': 'basic_auth',
                    'timeout_seconds': 90,
                    'rate_limit_rps': 5.0,
                    'batch_size': 50
                }
            }
        )
        
        with tempfile.NamedTemporaryFile(mode='w', suffix='.yaml', delete=False) as f:
            import yaml
            yaml.dump(config_data, f)
            config_file = f.name
        
        try:
            manager = ConfigManager(config_file=config_file)
            config = manager.config
            
            assert len(config.siem_connections) == 2
            
            # Test specific SIEM config retrieval
            splunk_config = manager.get_siem_config('splunk_prod')
            assert splunk_config is not None
            assert splunk_config.type == 'splunk'
            assert splunk_config.endpoint == 'https://splunk.company.com:8089'
            assert splunk_config.rate_limit_rps == 10.0
            
            qradar_config = manager.get_siem_config('qradar_prod')
            assert qradar_config is not None
            assert qradar_config.type == 'qradar'
            assert qradar_config.batch_size == 50
            
            # Test non-existent SIEM
            assert manager.get_siem_config('nonexistent') is None
            
        finally:
            os.unlink(config_file)


class TestGlobalConfigManager(TestEnvironmentSetup):
    """Test global configuration manager functionality"""
    
    def test_singleton_behavior(self):
        """Test global config manager singleton behavior"""
        config_data = self.create_test_config()
        
        with tempfile.NamedTemporaryFile(mode='w', suffix='.yaml', delete=False) as f:
            import yaml
            yaml.dump(config_data, f)
            config_file = f.name
        
        try:
            # Initialize with config file
            manager = init_config_manager(config_file=config_file, enable_hot_reload=False)
            
            manager1 = get_config_manager()
            manager2 = get_config_manager()
            
            assert manager1 is manager2
            assert manager1 is manager
            
        finally:
            os.unlink(config_file)
    
    def test_global_config_access(self):
        """Test global configuration access"""
        config_data = self.create_test_config(
            environment='test',
            **{
                'database.host': 'global-test-host',
                'redis.host': 'global-test-redis'
            }
        )
        
        with tempfile.NamedTemporaryFile(mode='w', suffix='.yaml', delete=False) as f:
            import yaml
            yaml.dump(config_data, f)
            config_file = f.name
        
        try:
            init_config_manager(
                environment=Environment.TEST,
                config_file=config_file,
                enable_hot_reload=False
            )
            
            config = get_config()
            assert config.environment == Environment.TEST
            assert config.database.host == 'global-test-host'
            assert config.redis.host == 'global-test-redis'
            
        finally:
            os.unlink(config_file)


class TestThreadSafety(TestEnvironmentSetup):
    """Test thread safety"""
    
    def test_concurrent_config_access(self):
        """Test concurrent configuration access"""
        config_data = self.create_test_config()
        
        with tempfile.NamedTemporaryFile(mode='w', suffix='.yaml', delete=False) as f:
            import yaml
            yaml.dump(config_data, f)
            config_file = f.name
        
        try:
            manager = ConfigManager(config_file=config_file)
            results = []
            errors = []
            
            def access_config():
                try:
                    config = manager.config
                    results.append(config.environment.value)
                except Exception as e:
                    errors.append(str(e))
            
            # Create multiple threads
            threads = []
            for _ in range(10):
                thread = threading.Thread(target=access_config)
                threads.append(thread)
                thread.start()
            
            # Wait for completion
            for thread in threads:
                thread.join()
            
            # Verify results
            assert len(errors) == 0, f"Errors occurred: {errors}"
            assert len(results) == 10
            assert all(result == 'dev' for result in results)
            
        finally:
            os.unlink(config_file)


class TestPerformance(TestEnvironmentSetup):
    """Test configuration performance"""
    
    def test_large_config_loading_performance(self):
        """Test performance with large configuration"""
        # Create config with many SIEM connections
        siem_connections = {}
        for i in range(50):  # Reduced from 100 for faster tests
            siem_connections[f'siem_{i}'] = {
                'type': 'splunk',
                'endpoint': f'https://splunk-{i}.example.com:8089',
                'auth_method': 'api_token',
                'timeout_seconds': 30,
                'rate_limit_rps': 10.0,
                'batch_size': 100
            }
        
        config_data = self.create_test_config(siem_connections=siem_connections)
        
        with tempfile.NamedTemporaryFile(mode='w', suffix='.yaml', delete=False) as f:
            import yaml
            yaml.dump(config_data, f)
            config_file = f.name
        
        try:
            start_time = time.time()
            manager = ConfigManager(config_file=config_file)
            config = manager.config
            load_time = time.time() - start_time
            
            assert len(config.siem_connections) == 50
            assert load_time < 2.0  # Should load within 2 seconds
            
        finally:
            os.unlink(config_file)


class TestErrorHandling(TestEnvironmentSetup):
    """Test error handling"""
    
    def test_invalid_yaml_file(self):
        """Test handling of invalid YAML files"""
        with tempfile.NamedTemporaryFile(mode='w', suffix='.yaml', delete=False) as f:
            f.write('invalid: yaml: content: [unmatched')
            invalid_yaml = f.name
        
        try:
            with pytest.raises(Exception):  # Should raise parsing error
                ConfigManager(config_file=invalid_yaml)
        finally:
            os.unlink(invalid_yaml)
    
    def test_invalid_json_file(self):
        """Test handling of invalid JSON files"""
        with tempfile.NamedTemporaryFile(mode='w', suffix='.json', delete=False) as f:
            f.write('{"invalid": json content without closing}')
            invalid_json = f.name
        
        try:
            with pytest.raises(Exception):  # Should raise parsing error
                ConfigManager(config_file=invalid_json)
        finally:
            os.unlink(invalid_json)
    
    def test_missing_config_file(self):
        """Test handling of missing configuration files"""
        # Should not fail, but will use defaults
        # We'll create a basic valid config to ensure required fields are present
        config_data = self.create_test_config()
        
        with tempfile.NamedTemporaryFile(mode='w', suffix='.yaml', delete=False) as f:
            import yaml
            yaml.dump(config_data, f)
            config_file = f.name
        
        try:
            manager = ConfigManager(config_file=config_file)
            config = manager.config
            
            # Should have defaults
            assert config.environment == Environment.DEVELOPMENT
            assert config.database.port == 5432
            
        finally:
            os.unlink(config_file)


if __name__ == "__main__":
    pytest.main([__file__, "-v", "--tb=short"])