


# Application Security Fundamentals for Absolute Beginners
## Резюме курсу EPAM SECLAB Ukraine

---

## Огляд курсу

**Цільова аудиторія:** Початківці в галузі кібербезпеки та розробники без попереднього досвіду в Application Security

**Тривалість:** Самостійне навчання (Self-paced)

**Мова:** Англійська (рівень B1 мінімум)

**Формат:** Онлайн курс з практичними завданнями

---

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
