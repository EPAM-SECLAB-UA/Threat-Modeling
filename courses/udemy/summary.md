


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
