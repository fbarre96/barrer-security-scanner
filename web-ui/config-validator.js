/**
 * Configuration Validator
 * Validates security configuration on startup
 */

const crypto = require('crypto');

class ConfigValidator {
    constructor() {
        this.errors = [];
        this.warnings = [];
        this.passed = true;
    }

    /**
     * Validate all configuration
     */
    validate() {
        console.log('\n🔍 Validating Security Configuration...\n');

        this.validateEnvironment();
        this.validateSecrets();
        this.validateSecurity();
        this.validatePorts();
        this.validateSSL();
        this.validateRateLimits();
        this.validateOAuth();
        this.validateBackup();
        this.validateOllama();

        this.printResults();

        return {
            passed: this.passed,
            errors: this.errors,
            warnings: this.warnings
        };
    }

    /**
     * Validate environment
     */
    validateEnvironment() {
        // Check NODE_ENV
        if (!process.env.NODE_ENV) {
            this.addWarning('NODE_ENV not set, defaulting to development');
        } else if (process.env.NODE_ENV === 'production') {
            this.addSuccess('NODE_ENV set to production');
        }

        // Check required variables
        const required = ['PORT', 'SESSION_SECRET', 'MFA_ENCRYPTION_KEY'];
        for (const key of required) {
            if (!process.env[key]) {
                this.addError(`Required environment variable missing: ${key}`);
            }
        }
    }

    /**
     * Validate secrets
     */
    validateSecrets() {
        const secrets = {
            SESSION_SECRET: process.env.SESSION_SECRET,
            MFA_ENCRYPTION_KEY: process.env.MFA_ENCRYPTION_KEY,
            CSRF_SECRET: process.env.CSRF_SECRET
        };

        for (const [key, value] of Object.entries(secrets)) {
            if (!value) {
                continue; // Already checked in validateEnvironment
            }

            // Check if default/weak value
            const weakValues = [
                'change-this-in-production',
                'default',
                'secret',
                'password',
                '12345',
                'test'
            ];

            if (weakValues.some(weak => value.toLowerCase().includes(weak))) {
                this.addError(`${key} appears to be a default/weak value`);
                continue;
            }

            // Check length
            if (value.length < 32) {
                this.addWarning(`${key} is shorter than recommended (32+ chars)`);
            } else {
                this.addSuccess(`${key} meets length requirements`);
            }

            // Check entropy
            if (!this.hasGoodEntropy(value)) {
                this.addWarning(`${key} may have low entropy`);
            }
        }
    }

    /**
     * Validate security settings
     */
    validateSecurity() {
        // Check rate limiting
        const authLimit = parseInt(process.env.AUTH_RATE_LIMIT_MAX || '5');
        if (authLimit > 10) {
            this.addWarning('AUTH_RATE_LIMIT_MAX is high, consider lowering for production');
        } else {
            this.addSuccess('Authentication rate limiting properly configured');
        }

        // Check log level
        const logLevel = process.env.LOG_LEVEL || 'info';
        if (logLevel === 'debug' && process.env.NODE_ENV === 'production') {
            this.addWarning('LOG_LEVEL set to debug in production (verbose logs)');
        }

        // Check HTTPS enforcement
        if (process.env.NODE_ENV === 'production') {
            if (!process.env.SSL_CERT_PATH || !process.env.SSL_KEY_PATH) {
                this.addWarning('SSL certificates not configured for production');
            } else {
                this.addSuccess('SSL/TLS certificates configured');
            }

            if (process.env.FORCE_HTTPS !== 'true') {
                this.addWarning('FORCE_HTTPS not enabled for production');
            }
        }
    }

    /**
     * Validate ports
     */
    validatePorts() {
        const port = parseInt(process.env.PORT || '3000');

        if (port < 1024 && process.platform !== 'win32') {
            this.addWarning('Port < 1024 requires elevated privileges on Unix systems');
        }

        if (port === 3000 && process.env.NODE_ENV === 'production') {
            this.addWarning('Using default port 3000 in production');
        }

        if (port < 1 || port > 65535) {
            this.addError(`Invalid port number: ${port}`);
        } else {
            this.addSuccess(`Port ${port} is valid`);
        }
    }

    /**
     * Validate SSL configuration
     */
    validateSSL() {
        const fs = require('fs');

        if (process.env.SSL_CERT_PATH) {
            try {
                fs.accessSync(process.env.SSL_CERT_PATH, fs.constants.R_OK);
                this.addSuccess('SSL certificate file accessible');
            } catch (error) {
                this.addError(`SSL certificate file not accessible: ${process.env.SSL_CERT_PATH}`);
            }
        }

        if (process.env.SSL_KEY_PATH) {
            try {
                fs.accessSync(process.env.SSL_KEY_PATH, fs.constants.R_OK);
                this.addSuccess('SSL key file accessible');
            } catch (error) {
                this.addError(`SSL key file not accessible: ${process.env.SSL_KEY_PATH}`);
            }
        }
    }

    /**
     * Validate rate limits
     */
    validateRateLimits() {
        const limits = {
            AUTH_RATE_LIMIT_MAX: { default: 5, recommended: 5, max: 10 },
            API_RATE_LIMIT_MAX: { default: 100, recommended: 100, max: 500 },
            SCAN_RATE_LIMIT_MAX: { default: 10, recommended: 10, max: 50 }
        };

        for (const [key, config] of Object.entries(limits)) {
            const value = parseInt(process.env[key] || config.default);
            
            if (value > config.max) {
                this.addWarning(`${key} is very high (${value}), may allow abuse`);
            } else if (value === config.recommended) {
                this.addSuccess(`${key} set to recommended value`);
            }
        }
    }

    /**
     * Validate OAuth configuration
     */
    validateOAuth() {
        // Google OAuth
        if (process.env.GOOGLE_CLIENT_ID || process.env.GOOGLE_CLIENT_SECRET) {
            if (!process.env.GOOGLE_CLIENT_ID || !process.env.GOOGLE_CLIENT_SECRET) {
                this.addWarning('Google OAuth partially configured (missing ID or secret)');
            } else {
                this.addSuccess('Google OAuth configured');
                
                if (!process.env.GOOGLE_CALLBACK_URL) {
                    this.addWarning('Google OAuth callback URL not set');
                }
            }
        }

        // Microsoft OAuth
        if (process.env.MICROSOFT_CLIENT_ID || process.env.MICROSOFT_CLIENT_SECRET) {
            if (!process.env.MICROSOFT_CLIENT_ID || !process.env.MICROSOFT_CLIENT_SECRET) {
                this.addWarning('Microsoft OAuth partially configured (missing ID or secret)');
            } else {
                this.addSuccess('Microsoft OAuth configured');
                
                if (!process.env.MICROSOFT_CALLBACK_URL) {
                    this.addWarning('Microsoft OAuth callback URL not set');
                }
            }
        }
    }

    /**
     * Validate Ollama AI configuration
     */
    validateOllama() {
        const host = process.env.OLLAMA_HOST || 'http://localhost:11434';
        const model = process.env.OLLAMA_MODEL || 'llama3.1:8b';

        try {
            const url = new URL(host);
            if (!['http:', 'https:'].includes(url.protocol)) {
                this.addError(`OLLAMA_HOST has unsupported protocol: ${url.protocol}`);
            } else if (host === 'http://localhost:11434') {
                this.addSuccess(`Ollama host: ${host} (local default)`);
            } else {
                this.addSuccess(`Ollama host configured: ${host}`);
            }
        } catch {
            this.addError(`OLLAMA_HOST is not a valid URL: "${host}"`);
        }

        this.addSuccess(`Ollama model: ${model}`);
    }

    /**
     * Validate backup configuration
     */
    validateBackup() {
        if (process.env.AUTO_BACKUP_ENABLED === 'true') {
            this.addSuccess('Automated backups enabled');
            
            const retention = parseInt(process.env.BACKUP_RETENTION_DAYS || '30');
            if (retention < 7) {
                this.addWarning('Backup retention < 7 days (very short)');
            } else if (retention > 365) {
                this.addWarning('Backup retention > 365 days (very long, check disk space)');
            }
        } else {
            this.addWarning('Automated backups not enabled');
        }
    }

    /**
     * Check entropy of a string
     */
    hasGoodEntropy(str) {
        const charCounts = {};
        for (const char of str) {
            charCounts[char] = (charCounts[char] || 0) + 1;
        }

        let entropy = 0;
        const len = str.length;

        for (const count of Object.values(charCounts)) {
            const p = count / len;
            entropy -= p * Math.log2(p);
        }

        // Good entropy is typically > 3.5 for hex strings
        return entropy > 3.5;
    }

    /**
     * Add error
     */
    addError(message) {
        this.errors.push(message);
        this.passed = false;
        console.log(`❌ ERROR: ${message}`);
    }

    /**
     * Add warning
     */
    addWarning(message) {
        this.warnings.push(message);
        console.log(`⚠️  WARNING: ${message}`);
    }

    /**
     * Add success
     */
    addSuccess(message) {
        console.log(`✅ ${message}`);
    }

    /**
     * Print results summary
     */
    printResults() {
        console.log('\n' + '='.repeat(60));
        console.log('Configuration Validation Results');
        console.log('='.repeat(60));
        console.log(`Errors:   ${this.errors.length}`);
        console.log(`Warnings: ${this.warnings.length}`);
        console.log(`Status:   ${this.passed ? '✅ PASSED' : '❌ FAILED'}`);
        console.log('='.repeat(60) + '\n');

        if (this.errors.length > 0) {
            console.log('⚠️  Critical errors found! Please fix before running in production.\n');
        } else if (this.warnings.length > 0) {
            console.log('⚠️  Warnings found. Review recommendations for production deployment.\n');
        } else {
            console.log('🎉 All security checks passed!\n');
        }
    }

    /**
     * Validate and optionally exit on failure
     */
    validateOrExit(exitOnFailure = false) {
        const result = this.validate();

        if (exitOnFailure && !result.passed) {
            console.error('\n❌ Configuration validation failed. Exiting...\n');
            process.exit(1);
        }

        return result;
    }
}

module.exports = new ConfigValidator();
