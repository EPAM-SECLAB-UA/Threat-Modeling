


- Django Security Best Practices: Essential Strategies for Protecting Your Web App - Joseph Adediji, https://www.youtube.com/watch?v=6KDyCW-B_f4
- Secure Coding in Python Django, https://www.udemy.com/course/secpy-django/?utm_source=adwords&utm_medium=udemyads&utm_campaign=Search_DSA_Beta_Prof_la.EN_cc.ROW-English&campaigntype=Search&portfolio=ROW-English&language=EN&product=Course&test=&audience=DSA&topic=&priority=Beta&utm_content=deal4584&utm_term=_._ag_162511579404_._ad_696197165418_._kw__._de_c_._dm__._pl__._ti_dsa-1677053911088_._li_9061017_._pd__._&matchtype=&gad_source=1&gad_campaignid=21168154305&gbraid=0AAAAADROdO3jbv6dOu8GksfwkVYErrEvR&gclid=CjwKCAjw7_DEBhAeEiwAWKiCC1X-GjWJwC_3AZdVk6vs9FfISSV_mDvaih8UehyOw4lvqv0IdbdWkxoCFBYQAvD_BwE&couponCode=PMNVD2525
- Django Security Cheat Sheet, https://cheatsheetseries.owasp.org/cheatsheets/Django_Security_Cheat_Sheet.html
- DJA201 – Defending Django, https://www.securitycompass.com/training_courses/dja201-defending-django/
- Best Django security practices, https://escape.tech/blog/best-django-security-practices/
- Django web application security, https://developer.mozilla.org/en-US/docs/Learn_web_development/Extensions/Server-side/Django/web_application_security
- 







# Security by Design принципи

---

## Що таке Security by Design?

**Security by Design** - це підхід до розробки, коли безпека інтегрується в систему з самого початку проектування, а не додається як доповнення після розробки.

### 🎯 **Основна філософія:**
```
"Безпека не є опцією - це фундаментальна вимога"
```

**Ключові концепції:**
- **Проактивний підхід** - запобігання замість реагування
- **Вбудована безпека** - security як частина архітектури
- **Безпека за замовчуванням** - secure by default configurations
- **Мінімізація поверхні атак** - принцип найменших привілеїв

---

## Фундаментальні принципи Security by Design

### 🔐 **1. Least Privilege (Принцип найменших привілеїв)**

**Визначення:** Кожен користувач, процес або система повинні мати тільки мінімальні права, необхідні для виконання їх функцій.

**Практичне застосування:**

#### **User Access Management:**
```python
# Погано - надмірні права
class User:
    def __init__(self, role):
        if role == "user":
            self.permissions = ["read", "write", "delete", "admin", "execute"]
        
# Добре - мінімальні права
class User:
    def __init__(self, role):
        if role == "user":
            self.permissions = ["read"]
        elif role == "editor":
            self.permissions = ["read", "write"]
        elif role == "admin":
            self.permissions = ["read", "write", "delete", "user_management"]

    def can_perform(self, action):
        return action in self.permissions
```

#### **Database Access:**
```sql
-- Погано - надмірні права для application user
GRANT ALL PRIVILEGES ON *.* TO 'app_user'@'%';

-- Добре - мінімальні необхідні права
GRANT SELECT, INSERT, UPDATE ON application_db.users TO 'app_user'@'localhost';
GRANT SELECT ON application_db.products TO 'app_user'@'localhost';
```

#### **API Permissions:**
```javascript
// Role-based access control
const permissions = {
    'guest': ['products:read'],
    'user': ['products:read', 'orders:read', 'orders:create', 'profile:update'],
    'admin': ['products:*', 'orders:*', 'users:*', 'reports:*']
};

function checkPermission(userRole, action) {
    const userPermissions = permissions[userRole] || [];
    return userPermissions.some(permission => {
        const [resource, operation] = permission.split(':');
        const [requestedResource, requestedOperation] = action.split(':');
        
        return (resource === requestedResource || resource === '*') &&
               (operation === requestedOperation || operation === '*');
    });
}
```

### 🔒 **2. Defense in Depth (Глибинна оборона)**

**Визначення:** Множинні рівні безпеки, де кожен рівень забезпечує незалежний захист.

**Архітектура Defense in Depth:**

```
🌐 Internet
    ↓
🛡️ Layer 1: Perimeter Security
    - Firewalls
    - DDoS Protection
    - Web Application Firewall (WAF)
    ↓
🛡️ Layer 2: Network Security
    - Network Segmentation
    - VPN
    - Intrusion Detection Systems (IDS)
    ↓
🛡️ Layer 3: Host Security
    - Antivirus/Anti-malware
    - Host-based Firewalls
    - System Hardening
    ↓
🛡️ Layer 4: Application Security
    - Input Validation
    - Authentication & Authorization
    - Secure Coding Practices
    ↓
🛡️ Layer 5: Data Security
    - Encryption at Rest
    - Data Classification
    - Access Controls
    ↓
🗄️ Data Assets
```

**Практична реалізація:**
```python
# Defense in Depth для веб-додатка
class SecurityLayeredApp:
    def __init__(self):
        self.layers = [
            WAFProtection(),
            RateLimiting(),
            Authentication(),
            Authorization(),
            InputValidation(),
            OutputEncoding(),
            DataEncryption()
        ]
    
    def process_request(self, request):
        # Кожен layer може зупинити request
        for layer in self.layers:
            if not layer.validate(request):
                return layer.get_security_response()
        
        return self.handle_business_logic(request)

class WAFProtection:
    def validate(self, request):
        # SQL injection detection
        if self.detect_sql_injection(request):
            return False
        # XSS detection
        if self.detect_xss(request):
            return False
        return True

class RateLimiting:
    def validate(self, request):
        user_id = request.user_id
        if self.get_request_count(user_id) > self.get_rate_limit():
            return False
        return True
```

### 📝 **3. Secure by Default (Безпека за замовчуванням)**

**Визначення:** Система має бути безпечною в конфігурації за замовчуванням, без додаткових налаштувань.

**Приклади Secure by Default:**

#### **Database Configuration:**
```yaml
# PostgreSQL secure defaults
postgresql_config:
  ssl: "on"
  ssl_ciphers: "HIGH:MEDIUM:+3DES:!aNULL"
  password_encryption: "scram-sha-256"
  log_connections: "on"
  log_disconnections: "on"
  log_failed_connections: "on"
  shared_preload_libraries: "pg_stat_statements"
  
  # Disable dangerous features by default
  allow_system_table_mods: "off"
  default_transaction_isolation: "read committed"
```

#### **Web Server Headers:**
```nginx
# Nginx secure defaults
server {
    # Security headers by default
    add_header X-Frame-Options "DENY" always;
    add_header X-Content-Type-Options "nosniff" always;
    add_header X-XSS-Protection "1; mode=block" always;
    add_header Strict-Transport-Security "max-age=31536000; includeSubDomains" always;
    add_header Content-Security-Policy "default-src 'self'" always;
    add_header Referrer-Policy "strict-origin-when-cross-origin" always;
    
    # Disable server signature
    server_tokens off;
    
    # Disable unnecessary HTTP methods
    if ($request_method !~ ^(GET|HEAD|POST|PUT|DELETE|OPTIONS)$ ) {
        return 405;
    }
}
```

#### **Application Configuration:**
```python
# Flask secure defaults
class SecureFlaskConfig:
    # Session security
    SESSION_COOKIE_SECURE = True
    SESSION_COOKIE_HTTPONLY = True
    SESSION_COOKIE_SAMESITE = 'Lax'
    PERMANENT_SESSION_LIFETIME = timedelta(hours=1)
    
    # CSRF Protection
    WTF_CSRF_ENABLED = True
    WTF_CSRF_TIME_LIMIT = 3600
    
    # Security headers
    SECURITY_HEADERS = {
        'X-Frame-Options': 'DENY',
        'X-Content-Type-Options': 'nosniff',
        'X-XSS-Protection': '1; mode=block'
    }
    
    # Database security
    SQLALCHEMY_ENGINE_OPTIONS = {
        'pool_pre_ping': True,
        'pool_recycle': 300,
        'echo': False  # Don't log SQL in production
    }

app = Flask(__name__)
app.config.from_object(SecureFlaskConfig)
```

### 🚪 **4. Fail Securely (Безпечний відмов)**

**Визначення:** Система має відмовляти безпечно - в разі помилки або атаки система переходить в безпечний стан.

**Приклади Fail Securely:**

#### **Authentication Failure:**
```python
def authenticate_user(username, password):
    try:
        user = get_user_from_database(username)
        if user and verify_password(password, user.password_hash):
            log_security_event("LOGIN_SUCCESS", username)
            return create_secure_session(user)
        else:
            # Fail securely - don't reveal if user exists
            log_security_event("LOGIN_FAILURE", username, "Invalid credentials")
            return None
    except DatabaseException as e:
        # Database down - fail securely
        log_security_event("LOGIN_ERROR", username, "System unavailable")
        return None
    except Exception as e:
        # Unknown error - fail securely
        log_security_event("LOGIN_UNEXPECTED_ERROR", username, str(e))
        return None

# Generic error message regardless of failure reason
def login_endpoint():
    session = authenticate_user(request.username, request.password)
    if session:
        return {"status": "success", "session_id": session.id}
    else:
        return {"status": "error", "message": "Authentication failed"}
```

#### **Authorization Failure:**
```python
def check_access_permission(user, resource, action):
    try:
        # Get user permissions
        permissions = get_user_permissions(user.id)
        
        # Check if user has permission
        if has_permission(permissions, resource, action):
            return True
        else:
            # Fail securely - log and deny
            log_security_event("ACCESS_DENIED", user.id, f"{action} on {resource}")
            return False
            
    except PermissionSystemException:
        # Permission system down - fail securely (deny access)
        log_security_event("PERMISSION_SYSTEM_ERROR", user.id)
        return False
    except Exception as e:
        # Unknown error - fail securely (deny access)
        log_security_event("AUTHORIZATION_ERROR", user.id, str(e))
        return False
```

#### **Input Validation Failure:**
```python
def process_user_input(data):
    try:
        # Validate input
        validated_data = validate_input(data)
        return process_business_logic(validated_data)
        
    except ValidationException as e:
        # Invalid input - fail securely
        log_security_event("INPUT_VALIDATION_FAILURE", data, str(e))
        return {"error": "Invalid input format"}
        
    except Exception as e:
        # Processing error - fail securely
        log_security_event("PROCESSING_ERROR", data, str(e))
        return {"error": "Unable to process request"}

def validate_input(data):
    # Comprehensive validation
    if not data:
        raise ValidationException("Empty input")
    
    if len(data) > MAX_INPUT_LENGTH:
        raise ValidationException("Input too long")
    
    if contains_malicious_patterns(data):
        raise ValidationException("Potentially malicious input detected")
    
    return sanitize_input(data)
```

### 🔓 **5. Complete Mediation (Повний контроль доступу)**

**Визначення:** Кожен доступ до ресурсу має перевірятися системою безпеки.

**Реалізація Complete Mediation:**

#### **API Gateway Pattern:**
```python
class SecurityGateway:
    def __init__(self):
        self.authenticator = AuthenticationService()
        self.authorizer = AuthorizationService()
        self.auditor = AuditService()
        
    def mediate_request(self, request):
        # 1. Аутентифікація - хто це?
        user = self.authenticator.authenticate(request)
        if not user:
            self.auditor.log_failed_authentication(request)
            raise AuthenticationError("Authentication required")
        
        # 2. Авторизація - що дозволено?
        if not self.authorizer.authorize(user, request.resource, request.action):
            self.auditor.log_access_denied(user, request)
            raise AuthorizationError("Access denied")
        
        # 3. Аудит - зафіксувати дію
        self.auditor.log_access_granted(user, request)
        
        # 4. Виконати запит
        return self.execute_business_logic(request)

# Decorator для автоматичної медіації
def require_permission(resource, action):
    def decorator(func):
        def wrapper(request, *args, **kwargs):
            gateway = SecurityGateway()
            gateway.mediate_request(request)
            return func(request, *args, **kwargs)
        return wrapper
    return decorator

@require_permission("user_data", "read")
def get_user_profile(request):
    return UserService.get_profile(request.user_id)
```

#### **Database Access Mediation:**
```python
class DatabaseAccessMediator:
    def __init__(self):
        self.connection_pool = create_secure_connection_pool()
        self.query_validator = SQLQueryValidator()
        self.access_logger = DatabaseAccessLogger()
    
    def execute_query(self, user, query, params):
        # 1. Validate user permissions
        if not self.validate_user_database_access(user):
            raise DatabaseAccessError("User not authorized for database access")
        
        # 2. Validate query safety
        if not self.query_validator.is_safe_query(query):
            self.access_logger.log_dangerous_query(user, query)
            raise DatabaseSecurityError("Potentially dangerous query detected")
        
        # 3. Execute with logging
        self.access_logger.log_query_execution(user, query, params)
        
        try:
            result = self.connection_pool.execute(query, params)
            self.access_logger.log_query_success(user, query)
            return result
        except Exception as e:
            self.access_logger.log_query_failure(user, query, str(e))
            raise
```

### 🔍 **6. Economy of Mechanism (Економія механізмів)**

**Визначення:** Дизайн має бути простим і зрозумілим. Складність є ворогом безпеки.

**Приклади Economy of Mechanism:**

#### **Simple Authentication:**
```python
# Погано - складна система з множинними механізмами
class ComplexAuthenticator:
    def authenticate(self, credentials):
        if credentials.type == "password":
            return self.password_auth(credentials)
        elif credentials.type == "oauth":
            return self.oauth_auth(credentials)
        elif credentials.type == "saml":
            return self.saml_auth(credentials)
        elif credentials.type == "ldap":
            return self.ldap_auth(credentials)
        elif credentials.type == "certificate":
            return self.cert_auth(credentials)
        # ... ще 10 методів аутентифікації

# Добре - простий, але надійний механізм
class SimpleAuthenticator:
    def authenticate(self, username, password):
        # Один надійний метод
        user = self.get_user(username)
        if user and self.verify_password(password, user.password_hash):
            return self.create_session(user)
        return None
    
    def verify_password(self, password, hash):
        # Використовуємо перевірений алгоритм
        return bcrypt.checkpw(password.encode('utf-8'), hash)
```

#### **Simple Authorization:**
```python
# Простий RBAC замість складної системи з множинними правилами
class SimpleRBAC:
    def __init__(self):
        self.roles = {
            'user': ['read_own_data', 'update_own_profile'],
            'moderator': ['read_own_data', 'update_own_profile', 'moderate_content'],
            'admin': ['*']  # All permissions
        }
    
    def has_permission(self, user_role, permission):
        if user_role not in self.roles:
            return False
        
        user_permissions = self.roles[user_role]
        return '*' in user_permissions or permission in user_permissions

# Використання
rbac = SimpleRBAC()
if rbac.has_permission(user.role, 'read_own_data'):
    return get_user_data(user.id)
```

### 🔐 **7. Open Design (Відкритий дизайн)**

**Визначення:** Безпека системи не повинна залежати від секретності дизайну або алгоритмів.

**Приклади Open Design:**

#### **Cryptographic Implementation:**
```python
# Добре - використання стандартних, перевірених алгоритмів
import bcrypt
import cryptography.fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

class SecureCrypto:
    def __init__(self):
        # Використовуємо стандартні алгоритми, а не власні
        self.password_hasher = bcrypt
        self.key_derivation = PBKDF2HMAC
        
    def hash_password(self, password):
        # Стандартний bcrypt з відповідним cost factor
        salt = bcrypt.gensalt(rounds=12)
        return bcrypt.hashpw(password.encode('utf-8'), salt)
    
    def encrypt_data(self, data, password):
        # Стандартний KDF + Fernet encryption
        salt = os.urandom(16)
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=100000,
        )
        key = base64.urlsafe_b64encode(kdf.derive(password.encode()))
        f = Fernet(key)
        encrypted = f.encrypt(data.encode())
        return salt + encrypted
```

#### **Security Configuration:**
```yaml
# Відкрита конфігурація безпеки (без security through obscurity)
security_config:
  authentication:
    method: "bcrypt"
    cost_factor: 12
    session_timeout: 3600
    
  encryption:
    algorithm: "AES-256-GCM"
    key_derivation: "PBKDF2-SHA256"
    iterations: 100000
    
  headers:
    - "X-Frame-Options: DENY"
    - "X-Content-Type-Options: nosniff"
    - "Strict-Transport-Security: max-age=31536000"
    
  logging:
    level: "INFO"
    include_user_actions: true
    exclude_sensitive_data: true
```

### ⚠️ **8. Separation of Duties (Розділення обов'язків)**

**Визначення:** Критичні операції повинні вимагати участі більше ніж однієї особи або системи.

**Приклади Separation of Duties:**

#### **Financial Transactions:**
```python
class FinancialTransactionSystem:
    def __init__(self):
        self.transaction_creator = TransactionCreator()
        self.transaction_approver = TransactionApprover()
        self.transaction_executor = TransactionExecutor()
    
    def process_large_transaction(self, amount, from_account, to_account, creator_id):
        if amount > LARGE_TRANSACTION_THRESHOLD:
            # Step 1: Creator initiates transaction
            transaction = self.transaction_creator.create(
                amount, from_account, to_account, creator_id
            )
            
            # Step 2: Different person must approve
            approval_required = True
            if approval_required:
                self.notify_approvers(transaction)
                return {"status": "pending_approval", "transaction_id": transaction.id}
            
        # Step 3: System executes after approval
        return self.execute_transaction(transaction)
    
    def approve_transaction(self, transaction_id, approver_id):
        transaction = self.get_transaction(transaction_id)
        
        # Ensure approver is different from creator
        if approver_id == transaction.creator_id:
            raise SecurityError("Approver cannot be the same as creator")
        
        # Ensure approver has appropriate permissions
        if not self.has_approval_permission(approver_id, transaction.amount):
            raise SecurityError("Insufficient approval permissions")
        
        transaction.approved_by = approver_id
        transaction.status = "approved"
        
        return self.transaction_executor.execute(transaction)
```

#### **Code Deployment:**
```yaml
# CI/CD pipeline з розділенням обов'язків
stages:
  - name: "development"
    permissions:
      - developers: ["code_commit", "unit_test"]
      
  - name: "code_review"
    permissions:
      - senior_developers: ["code_review", "approve_merge"]
    rules:
      - reviewer_cannot_be_author: true
      - minimum_reviewers: 2
      
  - name: "security_review"
    permissions:
      - security_team: ["security_scan", "approve_security"]
    rules:
      - automatic_sast_scan: true
      - manual_review_for_high_risk: true
      
  - name: "production_deployment"
    permissions:
      - devops_team: ["deploy_to_production"]
    rules:
      - requires_all_approvals: true
      - deployment_window_restrictions: true
```

#### **Database Administration:**
```python
class DatabaseAdministration:
    def __init__(self):
        self.schema_admin = SchemaAdministrator()
        self.data_admin = DataAdministrator()
        self.backup_admin = BackupAdministrator()
    
    def execute_schema_change(self, change_request, requester_id):
        # Schema changes require multiple approvals
        approvals_needed = [
            ("database_architect", "schema_design"),
            ("security_team", "security_impact"),
            ("ops_team", "operational_impact")
        ]
        
        for role, approval_type in approvals_needed:
            if not self.has_approval(change_request.id, role, approval_type):
                return {"status": "pending", "waiting_for": role}
        
        # Execute only after all approvals
        return self.schema_admin.execute_change(change_request)
    
    def backup_database(self, database_name, admin_id):
        # Backup operations require two admins
        if not self.backup_admin.is_dual_control_satisfied(database_name, admin_id):
            return {"status": "awaiting_second_admin"}
        
        return self.backup_admin.execute_backup(database_name)
```

---

## Імплементація Security by Design

### 🏗️ **Архітектурні патерни**

#### **Zero Trust Architecture:**
```python
class ZeroTrustGateway:
    def __init__(self):
        self.identity_verifier = IdentityVerifier()
        self.device_validator = DeviceValidator()
        self.context_analyzer = ContextAnalyzer()
        self.policy_engine = PolicyEngine()
    
    def validate_access_request(self, request):
        # Never trust, always verify
        
        # 1. Verify identity
        identity = self.identity_verifier.verify(request.credentials)
        if not identity.is_verified:
            return AccessDecision.DENY
        
        # 2. Validate device
        device_status = self.device_validator.validate(request.device_info)
        if not device_status.is_trusted:
            return AccessDecision.DENY
        
        # 3. Analyze context
        context = self.context_analyzer.analyze(request.context)
        if context.risk_level > ACCEPTABLE_RISK_THRESHOLD:
            return AccessDecision.DENY
        
        # 4. Apply policies
        decision = self.policy_engine.evaluate(identity, device_status, context, request)
        
        return decision
```

#### **Secure API Gateway:**
```python
class SecureAPIGateway:
    def __init__(self):
        self.rate_limiter = RateLimiter()
        self.authenticator = JWTAuthenticator()
        self.authorizer = RBACAuthorizer()
        self.validator = InputValidator()
        self.monitor = SecurityMonitor()
    
    async def handle_request(self, request):
        try:
            # Security pipeline
            await self.rate_limiter.check_limits(request)
            user = await self.authenticator.authenticate(request)
            await self.authorizer.authorize(user, request)
            validated_input = await self.validator.validate(request)
            
            # Execute business logic
            response = await self.execute_service(validated_input)
            
            # Log successful access
            await self.monitor.log_access(user, request, "SUCCESS")
            
            return response
            
        except SecurityException as e:
            await self.monitor.log_security_violation(request, e)
            return self.create_security_error_response(e)
```

### 🔄 **Secure SDLC Integration**

#### **Security Requirements Phase:**
```yaml
# Security requirements template
security_requirements:
  authentication:
    - multi_factor_authentication: required
    - password_policy: 
        min_length: 12
        complexity: high
        rotation: 90_days
    - session_management:
        timeout: 30_minutes
        secure_cookies: true
        
  authorization:
    - principle: least_privilege
    - model: role_based_access_control
    - privilege_escalation: explicit_approval_required
    
  data_protection:
    - encryption_at_rest: AES_256
    - encryption_in_transit: TLS_1_3
    - data_classification: required
    - pii_handling: gdpr_compliant
    
  logging_monitoring:
    - security_events: all
    - retention_period: 7_years
    - real_time_alerting: critical_events
    - log_integrity: cryptographic_signatures
```

#### **Secure Design Patterns:**
```python
# Security-first design patterns

# 1. Secure Factory Pattern
class SecureObjectFactory:
    @staticmethod
    def create_user(user_data):
        # Validate input
        if not InputValidator.validate_user_data(user_data):
            raise SecurityError("Invalid user data")
        
        # Sanitize data
        sanitized_data = DataSanitizer.sanitize(user_data)
        
        # Create with secure defaults
        user = User(
            username=sanitized_data.username,
            email=sanitized_data.email,
            role="user",  # Default to least privilege
            is_active=False,  # Require activation
            created_at=datetime.utcnow(),
            password_hash=PasswordHasher.hash(sanitized_data.password)
        )
        
        # Log creation
        SecurityLogger.log_user_creation(user)
        
        return user

# 2. Secure Proxy Pattern
class SecureServiceProxy:
    def __init__(self, service, security_policy):
        self.service = service
        self.policy = security_policy
    
    def execute_operation(self, operation, user, *args, **kwargs):
        # Pre-execution security checks
        if not self.policy.is_operation_allowed(user, operation):
            raise UnauthorizedError(f"Operation {operation} not allowed for user {user.id}")
        
        # Rate limiting
        if not self.policy.check_rate_limit(user, operation):
            raise RateLimitExceededError("Rate limit exceeded")
        
        # Execute with monitoring
        start_time = time.time()
        try:
            result = getattr(self.service, operation)(*args, **kwargs)
            self.policy.log_successful_operation(user, operation, time.time() - start_time)
            return result
        except Exception as e:
            self.policy.log_failed_operation(user, operation, str(e))
            raise
```

### 📊 **Security Metrics and KPIs**

#### **Design Security Metrics:**
```python
class SecurityDesignMetrics:
    def __init__(self):
        self.metrics_collector = MetricsCollector()
    
    def calculate_security_score(self, system_design):
        score = 0
        max_score = 100
        
        # Principle adherence scoring
        principles_score = self.score_principle_adherence(system_design)
        score += principles_score * 0.4  # 40% weight
        
        # Architecture security scoring
        architecture_score = self.score_architecture_security(system_design)
        score += architecture_score * 0.3  # 30% weight
        
        # Implementation security scoring
        implementation_score = self.score_implementation_security(system_design)
        score += implementation_score * 0.3  # 30% weight
        
        return {
            "overall_score": score,
            "max_score": max_score,
            "percentage": (score / max_score) * 100,
            "breakdown": {
                "principles": principles_score,
                "architecture": architecture_score,
                "implementation": implementation_score
            }
        }
    
    def score_principle_adherence(self, design):
        principles = [
            ("least_privilege", self.check_least_privilege),
            ("defense_in_depth", self.check_defense_in_depth),
            ("secure_by_default", self.check_secure_by_default),
            ("fail_securely", self.check_fail_securely),
            ("complete_mediation", self.check_complete_mediation),
            ("economy_of_mechanism", self.check_economy_of_mechanism),
            ("open_design", self.check_open_design),
            ("separation_of_duties", self.check_separation_of_duties)
        ]
        
        total_score = 0
        for principle_name, checker in principles:
            principle_score = checker(design)
            total_score += principle_score
            
        return total_score / len(principles)
```

#### **Continuous Security Assessment:**
```python
class ContinuousSecurityAssessment:
    def __init__(self):
        self.assessment_engine = AssessmentEngine()
        self.metric_calculator = SecurityMetricCalculator()
    
    async def assess_system_continuously(self, system):
        while True:
            # Daily security assessment
            assessment = await self.assessment_engine.run_assessment(system)
            
            # Calculate metrics
            metrics = self.metric_calculator.calculate_metrics(assessment)
            
            # Check for degradation
            if metrics.security_score < MINIMUM_ACCEPTABLE_SCORE:
                await self.trigger_security_alert(system, metrics)
            
            # Store historical data
            await self.store_assessment_results(system, assessment, metrics)
            
            # Wait for next assessment cycle
            await asyncio.sleep(ASSESSMENT_INTERVAL)
    
    async def trigger_security_alert(self, system, metrics):
        alert = SecurityAlert(
            system_id=system.id,
            severity="HIGH",
