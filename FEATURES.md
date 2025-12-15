# FEATURES – MailSafePro Email Validation API

## Project Infrastructure & Development Setup

### Docker Configuration
- **Dockerfile**:
  - Multi-stage build for optimized image size
  - Python 3.11 slim base image
  - Build stage with build dependencies
  - Production stage with minimal footprint
  - Non-root user security
  - Health check endpoint
  - Proper file permissions
  - Optimized layer caching

- **Docker Compose**:
  - **Core Services**:
    - Redis with persistence
    - API service with hot-reload
    - Background worker service
    - Health checks
    - Resource limits
    - Network isolation

  - **Development Configuration**:
    - Volume mounts for live code reload
    - Environment variable management
    - DNS configuration
    - Service dependencies
    - Health monitoring

### Development Tools
- **Makefile**:
  - **Code Quality**:
    - Linting (Black, isort, Flake8)
    - Type checking (mypy)
    - Security scanning (Bandit, Safety)
    - Code formatting

  - **Testing**:
    - Unit and integration tests
    - Coverage reporting
    - Watch mode
    - Test isolation

  - **Build & Run**:
    - Docker image building
    - Container management
    - Environment setup
    - Dependency installation

### Dependency Management
- **Python Dependencies**:
  - **Core**:
    - FastAPI framework
    - Pydantic validation
    - Async support
    - Environment management

  - **Databases & Caching**:
    - Redis client
    - Async Redis support
    - Connection pooling
    - Cache management

  - **Security**:
    - JWT authentication
    - Password hashing
    - Input validation
    - Rate limiting

  - **Networking**:
    - Async HTTP client
    - DNS resolution
    - SMTP handling
    - WebSocket support

  - **Monitoring**:
    - Prometheus metrics
    - Logging integration
    - Performance tracking
    - Health checks

### Deployment Configuration
- **Kubernetes Manifests**:
  - Deployment configurations
  - Service definitions
  - Ingress rules
  - Resource quotas
  - Auto-scaling
  - Secrets management

- **Render Configuration**:
  - Service definitions
  - Environment variables
  - Health checks
  - Scaling rules
  - Custom domains

### Documentation
- **Technical Documentation**:
  - API references
  - Architecture decisions
  - Deployment guides
  - Development setup
  - Troubleshooting
  - Best practices

- **Runbooks**:
  - Incident response
  - Maintenance procedures
  - Backup/restore
  - Performance tuning
  - Security updates

### Development Workflow
- **Version Control**:
  - Git branching strategy
  - Commit conventions
  - PR templates
  - Code review guidelines
  - Release process

- **CI/CD**:
  - Automated testing
  - Code quality gates
  - Security scanning
  - Deployment pipelines
  - Environment promotion

- `dashboard/`: front-end (Vite/React) para panel.

## app/ (núcleo FastAPI)
- `main.py`:
  - **Application Initialization**:
    - FastAPI application setup with async lifecycle management
    - Environment-based configuration (development, staging, production)
    - Structured logging configuration with Loguru
    - OpenTelemetry tracing setup
    - Prometheus metrics instrumentation

  - **Core Infrastructure**:
    - Redis connection pooling with retry logic and circuit breakers
    - ARQ background task queue with Redis backend
    - Connection warm-up for reduced cold-start latency
    - Graceful shutdown handling
    - Health check endpoints (liveness, readiness, startup)

  - **Security Features**:
    - Global rate limiting with IP-based throttling
    - CORS middleware with configurable origins
    - Request/response compression with GZip
    - Payload size limits
    - Security headers middleware
    - Proxy support with IP validation

  - **API Documentation**:
    - Custom OpenAPI schema generation
    - Interactive ReDoc documentation
    - API versioning support
    - Request/response models documentation

  - **Monitoring & Observability**:
    - Prometheus metrics endpoint (/metrics)
    - Structured JSON logging
    - Request/response logging with PII masking
    - Performance metrics collection
    - Error tracking and reporting

  - **Performance Optimizations**:
    - Connection pooling for Redis and database
    - Async/await support throughout
    - Background task processing
    - DNS pre-fetching and connection warm-up
    - Response caching headers

  - **Dependency Management**:
    - Environment variable validation
    - Configuration management with Pydantic
    - Dependency injection
    - Service initialization with retries

  - **API Endpoints**:
    - Health checks (/health, /ready, /live)
    - Service status (/status)
    - Circuit breaker status (/circuit-breakers)
    - API documentation (/docs, /redoc)

  - **Error Handling**:
    - Global exception handlers
    - Custom error responses
    - Request validation
    - Rate limit exceeded responses

  - **Background Services**:
    - Async task queue (ARQ)
    - Scheduled jobs
    - Cache warming
    - Maintenance tasks
- `auth.py`:
  - **Authentication & Authorization**:
    - JWT-based authentication (access & refresh tokens)
    - API Key authentication with Redis storage
    - Role-based access control (RBAC) with scopes
    - Plan-based permission system (FREE/PREMIUM/ENTERPRISE)
    - Token blacklisting and revocation
    - Password strength validation with zxcvbn

  - **Security Features**:
    - Timing attack protection
    - Rate limiting for authentication endpoints
    - Secure password hashing with bcrypt
    - Automatic session invalidation on password change
    - Token rotation and refresh token handling
    - PII protection in logs

  - **User Management**:
    - User registration with email validation
    - Password reset flow
    - Account deletion with data cleanup
    - Email verification
    - Concurrent session management

  - **API Key Management**:
    - Key generation with secure hashing
    - Key rotation with grace period
    - Scoped API keys
    - Key revocation
    - Usage tracking per key

  - **Token Management**:
    - Access token generation with configurable expiration
    - Refresh token implementation
    - Token blacklisting
    - Automatic token refresh
    - Token validation with proper error handling

  - **Security Middleware**:
    - Request validation
    - Rate limiting middleware
    - CORS and security headers
    - Input sanitization
    - Protection against common web vulnerabilities

  - **Integration Points**:
    - Redis for session storage
    - JWT for stateless authentication
    - SMTP for email notifications
    - Prometheus for metrics
    - Structured logging with PII protection
- `validation.py`: 
  - **Core Validation Engine**: Comprehensive email validation with multiple verification layers
  - **DNS/MX Validation**: 
    - Asynchronous DNS resolution with configurable timeouts and retries
    - MX record lookup with caching (memory + Redis)
    - Support for custom DNS nameservers with fallback to public DNS
  - **SMTP Verification**:
    - Asynchronous SMTP connection testing with STARTTLS support
    - Mailbox existence checking with RCPT TO verification
    - Circuit breaker pattern to handle SMTP server failures
    - Rate limiting per SMTP host to prevent blacklisting
  - **Domain Analysis**:
    - TLD extraction and validation
    - Disposable email domain detection
    - Catch-all domain detection
    - Abuse domain detection
    - Domain format validation (IDNA, length, character set)
  - **Caching Layer**:
    - Multi-level caching with AsyncTTLCache (L1) and Redis (L2)
    - Configurable TTLs for different cache types (MX, domain, SMTP)
    - Cache invalidation and management utilities
  - **Resilience Features**:
    - Automatic retries with exponential backoff and jitter
    - Timeout handling for all network operations
    - Graceful degradation when external services fail
  - **Security**:
    - PII protection in logs
    - Input validation and sanitization
    - Protection against DNS-based attacks
  - **Performance**:
    - Asynchronous I/O for all network operations
    - Connection pooling for SMTP and DNS
    - Efficient data structures for high-throughput processing
  - **Monitoring & Metrics**:
    - Integration with Prometheus metrics (when available)
    - Detailed error reporting and logging
    - Circuit breaker status monitoring
  - **Configuration**:
    - Centralized configuration via `ValidationConfig`
    - Environment variable overrides
    - Sensible defaults with production-hardened values
- `providers.py`: 
  - **Provider Analysis Engine**: 
    - Comprehensive email provider identification and analysis
    - MX record resolution and validation
    - ASN (Autonomous System Number) lookup and classification
    - DNS-based authentication checks (SPF, DKIM, DMARC)
  - **Reputation System**:
    - Initial reputation scoring based on security features
    - Dynamic reputation updates based on validation results
    - Caching of reputation data with configurable TTL
  - **Email Validation Features**:
    - Disposable email detection
    - Role-based email detection (admin, support, etc.)
    - Typo detection and suggestions
    - Spam trap detection
  - **Security Protocols**:
    - SPF (Sender Policy Framework) validation
    - DKIM (DomainKeys Identified Mail) verification
    - DMARC (Domain-based Message Authentication) checking
  - **Provider Classification**:
    - Built-in patterns for major email providers (Gmail, Outlook, etc.)
    - Custom provider fingerprinting
    - Support for external provider feed (JSON)
  - **Performance & Caching**:
    - Multi-level caching (memory + Redis)
    - Configurable TTLs for different cache types
    - Async/await support for non-blocking I/O
  - **Resilience Features**:
    - Circuit breaker for WHOIS lookups
    - Automatic retries with exponential backoff
    - Graceful degradation on service failures
  - **Integration Capabilities**:
    - HaveIBeenPwned API integration for breach checking
    - Custom DNS resolver with fallback support
    - Extensible architecture for additional validations
  - **Monitoring & Metrics**:
    - Prometheus metrics integration
    - Detailed logging with structured data
    - Cache statistics and hit/miss tracking
- `routes/validation_routes.py`:
  - **Core Validation Endpoints**:
    - `POST /validate/email`: Single email validation with comprehensive checks
    - `POST /validate/batch`: Batch email validation (up to 1000 emails per request)
    - `POST /validate/batch/upload`: File-based batch validation (CSV/TXT/ZIP)
  
  - **Validation Pipeline**:
    - Multi-stage validation process with early termination on critical failures
    - Email normalization and typo detection with suggestions
    - Disposable email detection
    - Spam trap detection with confidence scoring
    - HaveIBeenPwned breach checking (for PREMIUM/ENTERPRISE plans)
    - Provider analysis (MX, SPF, DKIM, DMARC)
    - SMTP verification with circuit breakers
  
  - **Security & Rate Limiting**:
    - JWT and API key authentication
    - Per-plan rate limiting with Redis backend
    - Request validation and sanitization
    - PII protection in logs and responses
    - Concurrency limits per user/plan
  
  - **Batch Processing**:
    - Support for CSV, TXT, and ZIP file uploads
    - Configurable email column selection for CSV files
    - Progress tracking and result aggregation
    - Comprehensive error handling for malformed inputs
  
  - **Response Formatting**:
    - Consistent JSON response structure
    - Detailed error messages with error types
    - Suggested fixes for common issues (e.g., typos)
    - Risk scoring and quality indicators
    - Provider reputation information
  
  - **Performance Optimizations**:
    - Async/await for I/O-bound operations
    - Caching of validation results
    - Connection pooling for external services
    - Timeout management with fallbacks
  
  - **Monitoring & Observability**:
    - Structured logging with request IDs
    - Prometheus metrics integration
    - Cache hit/miss statistics
    - Processing time tracking
  
  - **Plan-based Features**:
    - Different validation tiers (BASIC, STANDARD, PREMIUM)
    - Variable timeout limits based on plan
    - Customizable validation depth
    - Raw DNS record inclusion for advanced users
- `routes/billing_routes.py`:
  - **Core Billing & Subscription Management**:
    - Integration with Stripe for payment processing
    - Subscription lifecycle management (create, update, cancel)
    - Webhook handling for Stripe events
    - Customer and subscription mapping
    - Plan upgrades and downgrades

  - **Security & Validation**:
    - Webhook signature verification
    - Request validation with Pydantic models
    - Rate limiting for billing endpoints
    - PII protection in logs and responses
    - Secure storage of payment information (handled by Stripe)

  - **User & Plan Management**:
    - User subscription status tracking
    - Plan feature enforcement
    - Usage limits and quotas
    - Billing cycle management
    - Trial period handling

  - **Payment Processing**:
    - Secure checkout sessions
    - Payment method management
    - Invoice generation and retrieval
    - Receipt handling
    - Refund processing

  - **Webhook Processing**:
    - Asynchronous event handling
    - Idempotency handling
    - Event deduplication
    - Error handling and retries
    - Background task processing

  - **Error Handling & Resilience**:
    - Circuit breakers for external services
    - Retry mechanisms with exponential backoff
    - Graceful degradation
    - Comprehensive error logging
    - Transaction management

  - **Monitoring & Observability**:
    - Structured logging
    - Metrics collection
    - Audit trails
    - Performance monitoring
    - Alerting on critical events

  - **API Endpoints**:
    - Create checkout session
    - Get subscription status
    - Handle webhook events
    - Update subscription
    - Cancel subscription

  - **Data Management**:
    - Secure storage of billing data
    - Data retention policies
    - Backup and recovery
    - Data export capabilities

  - **Compliance**:
    - PCI DSS compliance (via Stripe)
    - Tax calculation
    - Invoice customization
    - Legal document management
- `routes/logs_routes.py`:
  - **Request Logging**:
    - Structured logging of API requests
    - User-specific log isolation
    - 30-day log retention
    - Filtering by status code, endpoint, and HTTP method
    - Timestamp-based querying
    - Pagination support
    - Admin-only access controls
    - Log rotation and cleanup

- `routes/webhooks_management.py`:
  - **Webhook Management**:
    - Create, read, update, delete webhooks
    - Event subscriptions (validation.completed, batch.completed, usage.limit_reached)
    - HMAC signature verification
    - Delivery tracking and retries
    - Webhook testing endpoint
    - Delivery history with status tracking
    - Secret key rotation
    - Rate limiting per webhook
    - Payload validation
    - Webhook status monitoring (active/paused)

- `jobs/` (jobs_routes.py + jobs_worker.py + tasks.py):
  - **Asynchronous Job Processing**:
    - Batch email validation jobs
    - File-based job processing
    - Real-time progress tracking
    - Idempotent job creation
    - Job status polling
    - Result pagination
    - Automatic cleanup (TTL-based)
    - Plan-based rate limiting
    - Webhook notifications
    - Job metadata and tagging
    - Error handling and retries
    - ARQ-based task queue
    - Redis-backed storage
    - Progress tracking
    - Resource usage monitoring
    - Job prioritization
    - Batch processing optimizations
    - Result caching
    - Job cancellation support
- `health_checks.py`:
  - **Health Monitoring System**:
    - Kubernetes-compatible liveness/readiness probes
    - Component-level health checks (Redis, DNS, disk, memory)
    - Graceful degradation support
    - Response time tracking
    - Cache for health check results
    - Uptime monitoring
    - Custom health check registration
    - Environment-aware health states
    - Detailed error reporting
    - Metrics integration

- `metrics.py`:
  - **Observability & Monitoring**:
    - Prometheus metrics integration
    - HTTP request/response metrics
    - Business metrics (validations, SMTP checks)
    - Cache performance tracking
    - System resource monitoring
    - Error tracking and classification
    - Custom metric decorators
    - Label normalization for high-cardinality data
    - Multi-process metrics support
    - Performance monitoring utilities

- `exceptions.py`:
  - **Error Handling Framework**:
    - RFC 7807 Problem Details for HTTP APIs
    - Structured error responses
    - Automatic error metrics recording
    - Correlation ID support
    - Validation error formatting
    - Custom exception hierarchy
    - Client plan detection
    - Error logging with context
    - Rate limiting responses
    - Service availability tracking
- **Logging System** (`logger.py` + `structured_logging.py` + `request_logging.py`):
  - **Core Logging Features**:
    - Structured JSON logging with Loguru and structlog
    - Environment-aware configuration (development/production)
    - Automatic log rotation and retention
    - Multi-destination logging (file + console)
    - Async-safe logging with queue
    - Request ID correlation
    - Performance-optimized logging
    - Environment-specific log levels

  - **Structured Logging**:
    - JSON-formatted logs for ELK/Grafana/Loki
    - Contextual logging with bound loggers
    - Automatic timestamp and log level inclusion
    - Correlation ID propagation
    - Sensitive data redaction (PII, API keys, tokens)
    - Custom log processors
    - Performance-optimized for production

  - **Request Logging**:
    - HTTP request/response logging
    - Request timing and performance metrics
    - Response status and size tracking
    - User/agent information
    - Error and exception logging
    - Custom request context
    - Rate limit tracking

  - **Security Features**:
    - PII masking (emails, phone numbers, API keys)
    - Sensitive data redaction
    - Authentication/authorization logging
    - Security event tracking
    - Audit logging for sensitive operations
    - IP address logging with privacy controls
    - Secure error handling

  - **Performance Monitoring**:
    - Request duration tracking
    - Database query timing
    - Cache hit/miss metrics
    - Background job performance
    - External service call timing
    - Memory usage monitoring
    - Custom performance markers

  - **Business Context**:
    - User/tenant context in logs
    - API key/plan information
    - Feature usage tracking
    - Business event logging
    - Custom metrics and KPIs
    - Operational intelligence
- **Security System** (`security/`):
  - **Abuse Detection**:
    - Behavioral pattern analysis
    - Rate limiting and threshold monitoring
    - Honeypot detection
    - Suspicious activity tracking
    - Automated threat response
    - User reputation scoring

  - **Input Validation**:
    - Strict email format validation (RFC 5321)
    - Dangerous character filtering
    - Input length restrictions
    - Batch validation safety
    - Type and format enforcement
    - Custom validation rules

  - **Payload Limits**:
    - Endpoint-specific size limits
    - Request size validation
    - Memory protection
    - Bandwidth control
    - Granular configuration
    - 413 Payload Too Large responses

  - **Data Sanitization**:
    - Redis key sanitization
    - Lua script escaping
    - NoSQL injection prevention
    - Safe string handling
    - Key normalization
    - Cache key building

  - **Secrets Management**:
    - Secure API key generation
    - Secret rotation policies
    - Cryptographic hashing
    - JWT secret handling
    - Webhook security
    - Key versioning

- **Rate Limiting System** (`rate_limiting/advanced_rate_limiting.py`):
  - **Core Features**:
    - Sliding window algorithm
    - Tiered rate limits (Free/Premium/Enterprise)
    - Endpoint-specific rules
    - Request cost accounting
    - Distributed with Redis
    - Fail-closed fallback
    - Circuit breaker integration

  - **Security**:
    - Request fingerprinting
    - IP-based limiting
    - User/API key limits
    - Cost-based accounting
    - Ban evasion detection
    - Secure defaults

  - **Resilience**:
    - Local fallback (10% of limits)
    - Graceful degradation
    - Automatic recovery
    - Health monitoring
    - Circuit breaker pattern
    - Fail-safe defaults

  - **Monitoring**:
    - Real-time statistics
    - Usage tracking
    - Abuse alerting
    - Performance metrics
    - Success/failure rates
    - Circuit state
- **Resilience System** (`resilience/`):
  - **Circuit Breakers**:
    - Automatic failure detection
    - Configurable thresholds
    - Half-open state handling
    - Automatic recovery
    - Multiple failure policies
    - Monitoring hooks

  - **Fallback Mechanisms**:
    - Graceful degradation
    - Local fallback caches
    - Stale-while-revalidate
    - Request queuing
    - Timeout handling
    - Retry strategies

- **Caching System** (`cache/` + `unified_cache`):
  - **Core Features**:
    - Unified Redis + in-memory cache
    - TTL management
    - Cache invalidation
    - Namespacing
    - Compression
    - Statistics

  - **Performance**:
    - Connection pooling
    - Pipelining
    - Background refresh
    - Batch operations
    - Memory optimization
    - Cache warming

- **Core Utilities**:
  - **Redis Helpers** (`redis_utils.py`, `connection_pooling.py`):
    - Connection management
    - Pool optimization
    - Error handling
    - Serialization
    - Atomic operations
    - Lua scripting

  - **PII Protection** (`pii_mask.py`):
    - Email obfuscation
    - Phone number masking
    - Secure string redaction
    - Log sanitization
    - Data export safety
    - Audit trail protection

  - **General Utilities** (`utils.py`):
    - Usage and quota tracking
    - Data normalization
    - Validation helpers
    - Async utilities
    - Performance timers
    - Error handling
- `models.py`:
  - **Base Models**:
    - `BaseAPIModel`: Base class with common configuration for all API models
    - `PriorityEnum`: Priority levels (low/standard/high)
    - `PlanEnum`: Subscription plans (FREE/PREMIUM/ENTERPRISE)
    - `RiskLevelEnum`: Risk assessment levels (low/medium/high/unknown)
    - `SubscriptionStatusEnum`: Subscription states (active/inactive/past_due/canceled/trialing)

  - **Email Validation**:
    - `EmailDomain`: Domain information model
    - `EmailValidationRequest`: Single email validation request
    - `AdvancedEmailRequest`: Extended validation with historical checks
    - `BatchValidationRequest`: Batch email validation with concurrency controls
    - `EmailResponse`: Comprehensive validation response
    - `BatchEmailResponse`: Batch validation results

  - **DNS & SMTP Models**:
    - `DNSRecordSPF`: SPF record validation
    - `DNSRecordDKIM`: DKIM record validation
    - `DNSRecordDMARC`: DMARC policy validation
    - `DNSInfo`: Comprehensive DNS information
    - `SMTPInfo`: SMTP verification results

  - **Authentication & Authorization**:
    - `APIKeyCreateRequest`: API Key creation
    - `APIKeyMeta`: API Key metadata
    - `APIKeyResponse`: API Key response with credentials
    - `KeyRotationRequest`: Secure key rotation
    - `UserRegister`: User registration
    - `UserLogin`: User authentication
    - `UserInDB`: Database user model
    - `TokenData`: JWT token payload with validation

  - **Standard Responses**:
    - `ErrorResponse`: Standardized error format
    - `SuccessResponse`: Standard success response
    - `HealthCheckResponse`: System health status
    - `UsageMetrics`: API usage statistics
    - `PaginationParams`: Pagination controls

  - **Billing & Subscriptions**:
    - `SubscriptionStatus`: Subscription information
    - `CheckoutSessionResponse`: Payment session details

  - **Validation Features**:
    - Email format validation
    - Password strength requirements
    - API key scope validation
    - Input sanitization
    - Type conversion and coercion
    - Default values and field requirements

  - **Security Features**:
    - PII handling
    - Secure password hashing
    - Token validation
    - Rate limiting metadata
    - Audit logging fields
- `validations/`: listas de dominios temporales, versiones/tiers.
- `versioning/`: gestión de versiones API.

## Observability & Security

### Metrics & Monitoring
- **Prometheus Integration**:
  - Custom collectors for Redis metrics (memory usage, connections, latency)
  - Request/response metrics (latency, size, status codes)
  - Business metrics (validation results, batch processing stats)
  - System metrics (CPU, memory, disk I/O)
  - Custom application metrics (cache hit ratios, job queue depth)
  - Alert rules and recording rules

- **Grafana Dashboards**:
  - Real-time system health monitoring
  - API performance analytics
  - Error rate tracking
  - Rate limiting and quota usage
  - Business KPIs and SLAs
  - Custom alert panels

### Distributed Tracing
- **OpenTelemetry Integration**:
  - End-to-end request tracing
  - Service map visualization
  - Performance bottleneck identification
  - Trace context propagation
  - Custom span attributes
  - Sampling configuration

### Logging System
- **Structured Logging**:
  - JSON-formatted logs
  - Correlation IDs for request tracing
  - Log levels and severity
  - Contextual logging
  - Performance metrics in logs

- **Security Features**:
  - PII masking (emails, tokens, sensitive data)
  - Redaction of sensitive fields
  - Audit logging
  - Security event logging
  - Access control logging

### Rate Limiting
- **Multi-layered Protection**:
  - Global IP-based rate limiting
  - Per-user/per-API key limits
  - Tiered rate limits (Free/Premium/Enterprise)
  - Endpoint-specific limits
  - Cost-based request accounting
  - Burst handling

- **Advanced Features**:
  - Sliding window algorithm
  - Circuit breaker integration
  - Graceful degradation
  - Detailed rate limit headers
  - Quota usage reporting

### Health Monitoring
- **Liveness Probes** (`/health/liveness`):
  - Basic application responsiveness
  - Critical dependency checks
  - Fast fail detection

- **Readiness Probes** (`/health/readiness`):
  - Dependency health (Redis, database)
  - Resource availability
  - Warm-up status

- **Startup Probes** (`/health/startup`):
  - Initialization status
  - Configuration validation
  - Warm-up progress

- **Auth Health** (`/health/auth`):
  - Authentication service status
  - Token validation
  - User directory connectivity

### Security Monitoring
- **Threat Detection**:
  - Anomaly detection
  - Brute force prevention
  - Suspicious pattern matching
  - Automated threat response

- **Audit Trails**:
  - User activity logging
  - Configuration changes
  - Security events
  - Access attempts

### Alerting System
- **Notification Channels**:
  - Email alerts
  - Slack/Teams integration
  - PagerDuty escalation
  - Custom webhooks

- **Alert Types**:
  - System health alerts
  - Performance degradation
  - Security incidents
  - Business metrics
  - Custom alerts

## Scripts y tooling
- `audit-patches/`, `audit-tests/`: parches y tests de auditoría.
- `tests/`: suite extensa (auth, billing, validation, rate limiting, providers, metrics, middleware, etc.).
- `scripts/`: utilidades CLI (p.ej., creación de API keys, cambio de plan, etc.).
- `mailsafepro-cli/`: CLI empaquetada (setups y tests).

## Infrastructure & Additional Observability

### Prometheus Monitoring
- **Core Configuration** (`prometheus.yml`)
  - 15-second scrape interval for metrics collection
  - Alert manager integration
  - Multiple job configurations
  - Service discovery setup
  - Custom metric retention policies
  - Global and per-job configurations

  - **Targets**:
    - API service metrics
    - Worker metrics
    - System-level metrics
    - Custom application metrics
    - Third-party service monitoring

### Grafana Dashboards
- **Pre-configured Dashboards**:
  - **Email API Overview**:
    - Request rates and latencies
    - Error rates and types
    - Resource utilization
    - Business metrics
    - Rate limiting status

  - **Worker Monitoring**:
    - Queue depths and processing rates
    - Job success/failure rates
    - Worker pool utilization
    - Task duration percentiles
    - Error tracking

  - **ARQ Task Queue**:
    - Queue length monitoring
    - Worker status
    - Job execution times
    - Failure rates and types
    - Retry statistics

- **Data Source Configuration**:
  - Prometheus integration
  - Dashboard templating
  - Alert annotations
  - Time range controls
  - Variable substitution
  - Panel linking

### Alert Management
- **Alertmanager Configuration** (`alertmanager.yml`)
  - **Routing**:
    - Multi-level alert routing
    - Team-based notification
    - Alert grouping and deduplication
    - Mute timing controls
    - Alert inhibition rules

  - **Notification**:
    - Webhook integration
    - Status-based filtering
    - Alert grouping
    - Throttling controls
    - Silence management

  - **Severity Levels**:
    - Critical alerts (immediate notification)
    - Warning alerts (grouped notification)
    - Custom severity matching
    - Alert correlation
    - Escalation policies

  - **Integration**:
    - Webhook endpoints
    - Custom payload templates
    - Status updates
    - Alert annotations
    - External system hooks

### Test Coverage & Quality
- **Coverage Reports** (`htmlcov/`):
  - Interactive HTML reports
  - Line-by-line coverage
  - File-level summaries
  - Missing coverage highlighting
  - Historical trend analysis

  - **Metrics**:
    - Code coverage percentage
    - Test execution time
    - Branch coverage
    - Statement coverage
    - Test effectiveness

  - **Quality Gates**:
    - Minimum coverage requirements
    - Quality thresholds
    - Test result validation
    - Build integration
    - Historical tracking

### Additional Monitoring
- **System Metrics**:
  - CPU/Memory usage
  - Disk I/O
  - Network throughput
  - Process metrics
  - Container metrics

- **Application Metrics**:
  - Request rates
  - Error rates
  - Cache hit ratios
  - Database query performance
  - External service health

### Deployment & Configuration
- **Environment Management**:
  - Docker Compose configurations
  - Service dependencies
  - Health check configuration
  - Resource limits
  - Volume mappings

- **Security**:
  - Access controls
  - Authentication
  - TLS configuration
  - Secret management
  - Audit logging

## Notas sobre configuración/secrets
- `.env`, `.env.bak`, `.env.example`, `.env.production`: configuración; **no usar .env en producción**, cargar secretos vía entorno/secret manager.
- `config.py`:
  - **Core Settings**:
    - Environment configuration (development/staging/production)
    - Debug and testing modes
    - API version and base URL
    - Instance identification

  - **Security Configuration**:
    - CORS origins and headers
    - HTTPS and HSTS settings
    - Webhook HMAC secrets
    - Allowed hosts and security headers
    - Rate limiting configurations

  - **Authentication & JWT**:
    - JWT signing keys and algorithms
    - Token expiration settings
    - Key rotation support
    - Public/private key management
    - Token audience and issuer

  - **Email Validation**:
    - DNS/MX lookup timeouts
    - SMTP verification settings
    - Disposable domain lists
    - Retry and backoff configurations
    - Cache TTLs

  - **Database & Cache**:
    - Redis connection settings
    - Connection pooling
    - Cache TTLs and eviction policies
    - Database timeouts

  - **Stripe Integration**:
    - API keys (test/live)
    - Webhook secrets
    - Plan and price IDs
    - Success/cancel URLs
    - Billing settings

  - **Rate Limiting**:
    - Request limits per tier
    - Burst capacity
    - Time windows
    - IP-based limits

  - **Monitoring & Logging**:
    - Log levels
    - Metrics collection
    - Error tracking (Sentry)
    - Health check endpoints
    - Performance metrics

  - **API Documentation**:
    - Swagger/ReDoc settings
    - Authentication for docs
    - API versioning
    - Contact information

  - **Performance**:
    - Timeout settings
    - Connection pools
    - Batch processing
    - Concurrency limits

  - **Environment Management**:
    - Environment variable loading
    - .env file support
    - Type conversion
    - Default values
    - Validation rules
