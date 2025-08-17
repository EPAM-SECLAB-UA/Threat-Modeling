

# DevSecOps using GitHub Actions: Secure CICD with GitHub

- https://ua.udemy.com/course/devsecops-crash-course-integrate-security-in-pipelines-2022/?referralCode=CFCD5C83BF3B2308D45C



# 1 Лекція: Вступ до курсу DevSecOps з GitHub Actions

## Привітання

Вітаємо на інтенсивному курсі з DevSecOps та GitHub Actions! Цей курс розроблено для фахівців, які прагнуть оволодіти сучасними практиками інтеграції безпеки в процеси розробки та розгортання програмного забезпечення.

## Структура курсу

### 📚 Модуль 1: Основи та вступ
**Тема:** Знайомство з курсом та цільовою аудиторією
- Хто може отримати користь від цього курсу
- Як курс допоможе стати DevSecOps або Security інженером
- Огляд навичок, які ви отримаєте

### 💼 Модуль 2: Кар'єрні можливості в безпеці
**Тема:** Огляд професійних шляхів у сфері кібербезпеки
- Security Engineer - інженер з безпеки
- DevSecOps Engineer - інженер DevSecOps
- Security Architect - архітектор безпеки
- Penetration Tester - тестувальник на проникнення
- Security Analyst - аналітик безпеки
- Compliance Specialist - спеціаліст з відповідності

### 🔐 Модуль 3: Основи DevSecOps
**Тема:** Розуміння концепції DevSecOps
- **Історія виникнення терміну:** від DevOps до DevSecOps
- **Філософія "Security as Code":** безпека як невід'ємна частина коду
- **Shift-Left підхід:** інтеграція безпеки на ранніх етапах розробки
- **Автоматизація безпеки:** зменшення людського фактора

### 🛠️ Модуль 4: Інструменти DevSecOps
**Тема:** Огляд інструментів безпеки на різних етапах

#### Етап розробки (Development):
- **SAST (Static Application Security Testing):**
  - SonarQube/SonarCloud
  - Checkmarx
  - Veracode
  - CodeQL

#### Етап збірки (Build Pipeline):
- **SCA (Software Composition Analysis):**
  - Snyk
  - OWASP Dependency-Check
  - WhiteSource (Mend)
  - Black Duck

#### Етап розгортання (Deployment):
- **DAST (Dynamic Application Security Testing):**
  - OWASP ZAP
  - Burp Suite Enterprise
  - Rapid7 AppSpider
  - Qualys WAS

- **IAST (Interactive Application Security Testing):**
  - Contrast Security
  - Hdiv Security

### 📖 Модуль 5: Термінологія безпеки
**Тема:** Ключові поняття, які використовуватимемо в курсі

**Основні терміни:**
- **CVE (Common Vulnerabilities and Exposures)** - база даних відомих вразливостей
- **CVSS (Common Vulnerability Scoring System)** - система оцінки критичності вразливостей
- **OWASP Top 10** - десятка найпоширеніших веб-вразливостей
- **False Positive** - помилково виявлена вразливість
- **False Negative** - пропущена реальна вразливість
- **Security Gates** - контрольні точки безпеки в pipeline
- **Compliance** - відповідність стандартам безпеки

### ⚙️ Модуль 6: GitHub Actions - основи
**Тема:** Фундаментальні знання GitHub Actions

**Ключові концепції:**
- **Workflows** - робочі процеси
- **Jobs** - завдання
- **Steps** - кроки
- **Actions** - дії
- **Runners** - виконавці
- **Secrets** - секрети
- **Artifacts** - артефакти

**Структура YAML файлу:**
```yaml
name: CI/CD Pipeline
on: [push, pull_request]
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v3
      - name: Setup
        run: echo "Hello DevSecOps"
```

### 🎯 Модуль 7: Перший YAML файл
**Тема:** Практичне створення простого workflow

**Мета модуля:**
- Створити базовий YAML файл
- Зрозуміти синтаксис GitHub Actions
- Запустити перший успішний workflow
- Налагодити проблеми, що можуть виникнути

### 🔍 Модуль 8: Інтеграція SAST
**Тема:** Static Application Security Testing з GitHub Actions

**Практичні завдання:**
- Налаштування SonarCloud
- Інтеграція з GitHub repository
- Аналіз результатів сканування
- Налаштування quality gates
- Обробка виявлених вразливостей

### 📦 Модуль 9: Software Composition Analysis (SCA)
**Тема:** Аналіз залежностей з використанням Snyk

**Що вивчимо:**
- Інтеграція Snyk з GitHub Actions
- Сканування package.json, pom.xml, requirements.txt
- Аналіз ліцензій третіх сторін
- Автоматичне створення pull requests для оновлень
- Моніторинг нових вразливостей

### 🌐 Модуль 10: Dynamic Application Security Testing (DAST)
**Тема:** Тестування веб-додатків з OWASP ZAP

**Практична реалізація:**
- Розгортання тестового додатку
- Налаштування OWASP ZAP
- Baseline та Full scan режими
- Аналіз HTTP трафіку
- Генерація звітів безпеки

### 🏗️ Модуль 11: Enterprise DevSecOps Pipeline
**Тема:** Комплексна реалізація на Java проєкті

**Компоненти pipeline:**
```
📋 План pipeline:
1. Code Checkout
2. Dependency Scanning (Snyk)
3. Static Code Analysis (SonarCloud)  
4. Build Application
5. Security Testing (OWASP ZAP)
6. Deploy to Staging
7. Generate Security Reports
8. Security Gate Decision
```

**Інструменти в дії:**
- **SonarCloud:** якість коду та security hotspots
- **Snyk:** аналіз вразливостей у залежностях
- **OWASP ZAP:** динамічне тестування безпеки
- **GitHub:** централізоване управління звітами

### 📈 Модуль 12: Наступні кроки та розвиток
**Тема:** Планування кар'єрного росту в DevSecOps

**Рекомендації для поглиблення знань:**
- **Сертифікації:**
  - Certified DevSecOps Professional (CDP)
  - AWS Certified Security - Specialty
  - CISSP (Certified Information Systems Security Professional)
  - CEH (Certified Ethical Hacker)

- **Додаткові інструменти для вивчення:**
  - Terraform для Infrastructure as Code
  - Ansible для автоматизації
  - Docker Security
  - Kubernetes Security
  - Cloud Security (AWS/Azure/GCP)

### 🔧 Модуль 13: Альтернативні інструменти та платформи
**Тема:** Огляд екосистеми DevSecOps

**CI/CD платформи:**
- Jenkins з Security плагінами
- GitLab CI/CD з вбудованою безпекою
- Azure DevOps Security
- CircleCI Security
- AWS CodePipeline

**Альтернативні інструменти безпеки:**
- Aqua Security для контейнерів
- Prisma Cloud для мультихмарної безпеки
- Checkmarx для enterprise SAST
- Rapid7 InsightAppSec для DAST

### 📄 Модуль 14: Створення професійного CV
**Тема:** Оформлення резюме DevSecOps інженера

**Ключові секції CV:**
- **Technical Skills:** інструменти та технології
- **Security Experience:** проєкти та досягнення
- **Certifications:** отримані сертифікати
- **Projects:** портфоліо DevSecOps проєктів

**Приклад опису досвіду:**
```
DevSecOps Engineer | Company Name | 2023-Present
• Implemented automated security scanning in CI/CD pipelines using GitHub Actions
• Reduced security vulnerabilities by 75% through SAST/DAST integration
• Established security gates that prevented 50+ vulnerable deployments
• Mentored development teams on secure coding practices
```

## Цільова аудиторія курсу

### 👨‍💻 Розробники (Developers)
- Хочуть інтегрувати безпеку в процес розробки
- Прагнуть розуміти security implications свого коду
- Мають базовий досвід з Git та CI/CD

### 🔧 DevOps інженери
- Бажають додати Security до своїх навичок
- Працюють з pipeline автоматизацією
- Знайомі з концепціями Infrastructure as Code

### 🛡️ Security спеціалісти
- Хочуть автоматизувати безпеку
- Прагнуть інтегруватися в DevOps процеси
- Мають знання в галузі кібербезпеки

### 🎓 Студенти та початківці
- Вивчають кібербезпеку або DevOps
- Хочуть отримати практичні навички
- Планують кар'єру в IT безпеці

## Переваги курсу

### 🎯 Практичний підхід
- **Hands-on лабораторії:** реальні проєкти та завдання
- **Real-world scenarios:** ситуації з практики
- **Step-by-step інструкції:** детальні покрокові посібники

### 🔄 Актуальність
- **Сучасні інструменти:** GitHub Actions, Snyk, SonarCloud
- **Industry best practices:** кращі практики індустрії
- **Enterprise готовність:** рішення для великих компаній

### 💼 Кар'єрні перспективи
- **Portfolio projects:** проєкти для портфоліо
- **Industry connections:** знайомство з інструментами ринку
- **Certification preparation:** підготовка до сертифікацій

## Рекомендації для успішного проходження

### 💪 Активна участь
- **Виконуйте всі лабораторні роботи**
- **Експериментуйте з налаштуваннями**
- **Створюйте власні модифікації**

### 📚 Додаткове навчання
- **Читайте документацію інструментів**
- **Слідкуйте за Security блогами**
- **Приєднуйтесь до DevSecOps спільнот**

### 🎓 Практичне застосування
- **Застосовуйте знання в робочих проєктах**
- **Діліться досвідом з колегами**
- **Будуйте власне портфоліо**

## Висновки

Цей курс розроблено як комплексний вступ до світу DevSecOps з практичним фокусом на GitHub Actions. Ви отримаєте:

✅ **Теоретичні знання** про DevSecOps концепції  
✅ **Практичні навички** роботи з інструментами безпеки  
✅ **Real-world досвід** створення enterprise pipeline  
✅ **Кар'єрні поради** для розвитку в галузі  

Готуйтеся до захоплюючої подорожі у світ автоматизованої безпеки!


# Agenda курсу DevSecOps з GitHub Actions

```mermaid
flowchart TD
    A[About the course<br/>Про курс] --> B[Security as a Career<br/>Безпека як кар'єра]
    B --> C[DevSecOps Introduction<br/>Вступ до DevSecOps]
    C --> D[Tools used for DevSecOps<br/>Інструменти DevSecOps]
    
    D --> E[Basic Security Terms for the course<br/>Базові терміни безпеки]
    E --> F[Basics of GitHub Actions<br/>Основи GitHub Actions]
    F --> G[Create a simple yaml file in GitHub Actions<br/>Створення простого YAML файлу]
    G --> H[Integrate SAST in GitHub Actions<br/>Інтеграція SAST]
    
    H --> I[Integrate SCA in GitHub Actions<br/>Інтеграція SCA]
    I --> J[Integrate DAST in GitHub Actions<br/>Інтеграція DAST]
    J --> K[Implement End to End Case Study on Java Project<br/>Комплексний проєкт на Java]
    K --> L[Next Steps<br/>Наступні кроки]
    
    style A fill:#b19cd9
    style B fill:#6b9bd2
    style C fill:#e19a9a
    style D fill:#c488a7
    style E fill:#5dade2
    style F fill:#a569bd
    style G fill:#6b9bd2
    style H fill:#e19a9a
    style I fill:#b19cd9
    style J fill:#5dade2
    style K fill:#a569bd
    style L fill:#6b9bd2
```

## Альтернативний вигляд (блок-схема)

```
┌─────────────────┐    ┌─────────────────┐    ┌─────────────────┐    ┌─────────────────┐
│   About the     │───▶│  Security as a  │───▶│   DevSecOps     │───▶│  Tools used for │
│     course      │    │     Career      │    │  Introduction   │    │    DevSecOps    │
└─────────────────┘    └─────────────────┘    └─────────────────┘    └─────────────────┘
                                                                              │
                                                                              ▼
┌─────────────────┐    ┌─────────────────┐    ┌─────────────────┐    ┌─────────────────┐
│  Integrate SAST │◀───│   Create simple │◀───│  Basics of      │◀───│ Basic Security  │
│ in GitHub Actions│    │   YAML file     │    │ GitHub Actions  │    │ Terms for course│
└─────────────────┘    └─────────────────┘    └─────────────────┘    └─────────────────┘
          │
          ▼
┌─────────────────┐    ┌─────────────────┐    ┌─────────────────┐    ┌─────────────────┐
│  Integrate SCA  │───▶│  Integrate DAST │───▶│ Implement End   │───▶│   Next Steps    │
│ in GitHub Actions│    │ in GitHub Actions│    │ to End Case     │    │                 │
└─────────────────┘    └─────────────────┘    │ Study on Java   │    └─────────────────┘
                                              │    Project      │
                                              └─────────────────┘
```

## Структурований план курсу

### 🎯 Блок 1: Основи та теорія
1. **About the course** - Про курс
2. **Security as a Career** - Безпека як кар'єра  
3. **DevSecOps Introduction** - Вступ до DevSecOps
4. **Tools used for DevSecOps** - Інструменти DevSecOps

### 📚 Блок 2: Підготовка та основи
5. **Basic Security Terms for the course** - Базові терміни безпеки
6. **Basics of GitHub Actions** - Основи GitHub Actions
7. **Create a simple yaml file in GitHub Actions** - Створення простого YAML файлу

### 🔧 Блок 3: Практична інтеграція інструментів
8. **Integrate SAST in GitHub Actions** - Інтеграція SAST (Static Application Security Testing)
9. **Integrate SCA in GitHub Actions** - Інтеграція SCA (Software Composition Analysis)
10. **Integrate DAST in GitHub Actions** - Інтеграція DAST (Dynamic Application Security Testing)

### 🏗️ Блок 4: Комплексна реалізація та розвиток
11. **Implement End to End Case Study on Java Project** - Комплексний проєкт на Java
12. **Next Steps** - Наступні кроки та розвиток

---

**Загальна тривалість:** 12 модулів  
**Фокус:** Практичне впровадження DevSecOps з GitHub Actions  
**Кінцевий результат:** Повноцінний DevSecOps pipeline на реальному проєкті


-----------------------------------------------------------------------



# 2 Лекція: Цільова аудиторія та переваги курсу DevSecOps

## Привітання

Вітаємо, експерти з безпеки! Ласкаво просимо на нову лекцію нашого курсу. У цій лекції ми з'ясуємо, чому саме ви повинні вивчити цей курс і хто є цільовою аудиторією для навчання DevSecOps.

## 🎯 Цільова аудиторія курсу

Цей курс спеціально розроблений для наступних категорій фахівців:

### 👨‍🎓 Новачки в IT-безпеці (Freshers)
**Характеристики:**
- Студенти або випускники IT-спеціальностей
- Особи без досвіду роботи в кібербезпеці
- Бажання розпочати кар'єру в галузі безпеки

**Що отримують від курсу:**
- Фундаментальні знання DevSecOps
- Практичні навички роботи з інструментами
- Готовність до entry-level позицій

### 🔒 Security Engineers (Інженери з безпеки)
**Поточний досвід:**
- Робота з традиційними інструментами безпеки
- Знання принципів кібербезпеки
- Досвід проведення security assessments

**Мета навчання:**
- Інтеграція безпеки в DevOps процеси
- Автоматизація security тестування
- Перехід від reactive до proactive підходу

### 🧪 QA Engineers (Інженери з тестування)
**Наявні компетенції:**
- Досвід автоматизації тестування
- Знання CI/CD pipeline
- Розуміння процесів якості ПЗ

**Розширення навичок:**
- Додавання security тестування до QA процесів
- Вивчення SAST, DAST, SCA інструментів
- Створення comprehensive testing strategy

### 💼 IT-професіонали (Загальна категорія)
**Включає:**
- DevOps інженерів
- Software розробників
- System адміністраторів
- Project менеджерів у IT

**Причини навчання:**
- Розширення професійного кругозору
- Підвищення ринкової вартості
- Відповідність сучасним industry trends

## 📈 Чому варто вивчати DevSecOps?

### 🌟 Нішевий домен з високим попитом

**Статистика ринку:**
- DevSecOps вважається одним з найперспективніших напрямків в IT
- Ріст вакансій на 150% за останні 3 роки
- Shortage кваліфікованих спеціалістів у всьому світі

**Тенденції галузі:**
```
2020: DevOps + Security = окремі команди
2021: Початок інтеграції безпеки в DevOps
2022: DevSecOps стає industry standard
2023: Масове впровадження DevSecOps практик
2024: Критичний shortage DevSecOps талантів
```

### 💰 Високооплачувані вакансії

**Діапазон зарплат DevSecOps інженерів:**

| Рівень досвіду | Зарплата (США) | Зарплата (Європа) | Зарплата (Україна) |
|----------------|----------------|-------------------|-------------------|
| Junior (0-2 роки) | $80,000-120,000 | €45,000-65,000 | $18,000-30,000 |
| Middle (2-5 років) | $120,000-160,000 | €65,000-85,000 | $30,000-50,000 |
| Senior (5+ років) | $160,000-220,000 | €85,000-120,000 | $50,000-80,000 |

### 🚀 Недостатність правильного таланту

**Проблеми ринку:**
- **Skills Gap:** розрив між потребами роботодавців та навичками кандидатів
- **Technology Evolution:** швидка еволюція інструментів та практик
- **Cross-functional Requirements:** потреба в знаннях Dev, Ops та Security одночасно

**Наше рішення:**
- Практичний курс з реальними інструментами
- Hands-on досвід з enterprise технологіями
- Підготовка готових до роботи спеціалістів

## 🎯 Цілі курсу

### 🏗️ Створення правильного таланту для ринку

**Що ми робимо:**
1. **Ідентифікуємо gap** на ринку DevSecOps спеціалістів
2. **Аналізуємо потреби** роботодавців та industry
3. **Розробляємо curriculum** відповідно до ринкових вимог
4. **Забезпечуємо практичний досвід** з реальними проєктами

**Результат:**
- Підготовлені спеціалісти готові до роботи з першого дня
- Закриття gap між попитом та пропозицією
- Підвищення загального рівня DevSecOps в індустрії

### 💼 Допомога інженерам у кар'єрному зростанні

**Переваги для учасників:**

#### 📊 Підвищення зарплати
- **Immediate impact:** негайне підвищення ринкової вартості
- **Career progression:** швидші промоції та кар'єрний ріст
- **Job security:** стабільність через високий попит

#### 🎓 Upskilling в найновіших технологіях
- **Modern tools:** GitHub Actions, SonarCloud, Snyk, OWASP ZAP
- **Industry practices:** real-world підходи від провідних компаній
- **Future-ready skills:** підготовка до майбутніх технологій

#### 🌐 Розширення професійних можливостей
- **Remote opportunities:** можливість роботи з global командами
- **Consulting potential:** можливості для freelance та консалтингу
- **Leadership roles:** підготовка до lead та architect позицій

## 🔥 Чому не можна пропустити цю можливість?

### ⏰ Timing є критичним

**Ринкові фактори:**
- DevSecOps знаходиться на піку adoption curve
- Early adopters отримують найбільші переваги
- Competition за таланти буде тільки зростати

### 📚 Унікальність курсу

**Що робить наш курс особливим:**
- **Практичний підхід:** реальні проєкти замість теорії
- **Industry tools:** робота з enterprise інструментами
- **End-to-end experience:** повний цикл DevSecOps pipeline
- **Real-world scenarios:** кейси з практики великих компаній

### 🎯 Гарантований результат

**Що ви отримаєте після курсу:**
- ✅ Портфоліо з реальними DevSecOps проєктами
- ✅ Досвід роботи з топовими інструментами ринку
- ✅ Розуміння enterprise DevSecOps процесів
- ✅ Готовність до співбесід на DevSecOps позиції
- ✅ Network з однодумцями та експертами

## 💡 Перспективи після курсу

### 🚀 Кар'єрні шляхи

**Можливі позиції:**
1. **DevSecOps Engineer** - основна спеціалізація
2. **Security Automation Engineer** - фокус на автоматизації
3. **Application Security Engineer** - безпека додатків
4. **Cloud Security Engineer** - хмарна безпека
5. **Security Architect** - архітектурні рішення

### 📈 Траєкторія зростання

```
Junior DevSecOps Engineer (0-2 роки)
          ↓
Middle DevSecOps Engineer (2-5 років)
          ↓
Senior DevSecOps Engineer (5+ років)
          ↓
Lead DevSecOps Engineer / Security Architect
          ↓
Principal Engineer / Director of Security
```

## 🎊 Заключення

DevSecOps представляє унікальну можливість для IT-професіоналів:

### 🌟 Ключові переваги:
- **Високий попит** на ринку праці
- **Привабливі зарплати** у всіх регіонах
- **Перспективний напрямок** з постійним розвитком
- **Можливість впливу** на безпеку продуктів

### 🎯 Наша місія:
Підготувати нове покоління DevSecOps інженерів, які зможуть закрити gap на ринку та допомогти компаніям створювати більш безпечні продукти.

**Не втрачайте цю можливість стати частиною майбутнього IT-безпеки!**

---

*Дякуємо за увагу! До зустрічі на наступній лекції, де ми розглянемо кар'єрні можливості в сфері безпеки.*


----------------------------------------------------

# 3 Лекція: Основні терміни безпеки в DevSecOps

## Привітання

Вітаємо, експерти з безпеки! Ласкаво просимо на нову лекцію нашого курсу. У цій лекції ми вивчимо різні терміни безпеки, які будемо використовувати протягом всього курсу. Розуміння цих концепцій є критично важливим для успішного опанування DevSecOps.

## 🔍 SAST - Static Application Security Testing

### Визначення
**SAST** (Статичне тестування безпеки додатків) - це тип **white box тестування**, що аналізує вихідний код для виявлення проблем безпеки в нашому коді.

### Характеристики SAST
- 🔬 **Аналіз вихідного коду** без виконання програми
- 📝 **White box підхід** - повний доступ до коду
- ⚡ **Раннє виявлення** вразливостей на етапі розробки
- 🔄 **Інтеграція в CI/CD** pipeline

### Методи виконання SAST

#### 🔧 Ручне тестування
**Підхід:**
- Використання **source code checklist**
- Ручний аналіз коду на наявність вразливостей
- Code review з фокусом на безпеку

**Переваги:**
- ✅ Глибокий аналіз специфічних кейсів
- ✅ Розуміння бізнес-логіки
- ✅ Низький рівень false positives

**Недоліки:**
- ❌ Часозатратний процес
- ❌ Залежність від експертизи аналітика
- ❌ Складно масштабувати

#### 🤖 Автоматизоване тестування
**Популярні інструменти:**

| Інструмент | Тип | Особливості |
|------------|-----|-------------|
| **SonarQube** | Open Source/Commercial | Підтримка 25+ мов, інтеграція з CI/CD |
| **Fortify** | Commercial | Enterprise рішення від Micro Focus |
| **Veracode** | Cloud-based | SaaS платформа з швидким скануванням |
| **Checkmarx** | Commercial | Advanced pattern recognition |

### Приклад використання SAST

```yaml
# GitHub Actions workflow для SAST
name: SAST Security Scan
on: [push, pull_request]

jobs:
  sast:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v3
      - name: Run SonarQube Scan
        uses: sonarqube-quality-gate-action@master
        env:
          SONAR_TOKEN: ${{ secrets.SONAR_TOKEN }}
```

## 📦 SCA - Software Composition Analysis

### Визначення
**SCA** (Аналіз складу програмного забезпечення) - процес сканування, який допомагає ідентифікувати третьосторонні бібліотеки та їх безпеку.

### Що аналізує SCA?

#### 📚 Третьосторонні бібліотеки
- **Dependencies** в package.json, pom.xml, requirements.txt
- **Transitive dependencies** (залежності залежностей)
- **Version conflicts** та outdated бібліотеки

#### ⚖️ Ліцензійні питання
- **License compatibility** між різними бібліотеками
- **Commercial vs Open Source** ліцензії
- **Compliance** з корпоративними політиками

#### 🔓 Безпекові проблеми
- **Known vulnerabilities** (CVE база даних)
- **Security advisories** від maintainers
- **CVSS scores** для оцінки критичності

### Інструменти SCA

**Snyk - лідер ринку:**
```bash
# Встановлення Snyk CLI
npm install -g snyk

# Аутентифікація
snyk auth

# Сканування проєкту
snyk test

# Моніторинг проєкту
snyk monitor
```

**Альтернативні інструменти:**
- **OWASP Dependency-Check** (безкоштовний)
- **WhiteSource (Mend)** (enterprise)
- **Black Duck** (comprehensive)

## 🌐 DAST - Dynamic Application Security Testing

### Визначення
**DAST** (Динамічне тестування безпеки додатків) - це **black box тестування** веб та мобільних додатків з використанням автоматизованих інструментів.

### Характеристики DAST
- 🕳️ **Black box підхід** - тестування без доступу до коду
- 🌐 **Runtime аналіз** працюючого додатку
- 🔄 **HTTP traffic inspection** та аналіз responses
- 📱 **Web та mobile** додатки

### Популярні DAST інструменти

#### 🆓 Open Source
**OWASP ZAP:**
```bash
# Запуск ZAP в baseline режимі
docker run -t owasp/zap2docker-stable zap-baseline.py \
  -t https://example.com

# Full scan режим
docker run -t owasp/zap2docker-stable zap-full-scan.py \
  -t https://example.com
```

#### 💼 Commercial
| Інструмент | Особливості |
|------------|-------------|
| **Burp Suite Enterprise** | Advanced crawling, custom checks |
| **Veracode DAST** | Cloud-based scanning |
| **WebInspect** | Micro Focus enterprise solution |
| **Rapid7 AppSpider** | Comprehensive web app testing |

### DAST vs SAST порівняння

| Аспект | SAST | DAST |
|--------|------|------|
| **Тип тестування** | White box | Black box |
| **Етап тестування** | Development | QA/Production |
| **Доступ до коду** | Повний | Відсутній |
| **False positives** | Високі | Середні |
| **Coverage** | Високий | Обмежений |

## 🔄 IAST - Interactive Application Security Testing

### Визначення
**IAST** (Інтерактивне тестування безпеки додатків) - відносно новий підхід, що **поєднує SAST та DAST** для подолання їх обмежень.

### Як працює IAST?
- 🔗 **Інструментація коду** під час виконання
- 📊 **Real-time аналіз** data flow
- 🎯 **Specific workflows** сканування
- 🔍 **Inside-out підхід** до безпеки

### Переваги IAST
- ✅ **Низький рівень false positives**
- ✅ **Accurate vulnerability detection**
- ✅ **Real-time feedback** розробникам
- ✅ **Better coverage** критичних шляхів

### Інструменти IAST
- **Contrast Security** - лідер ринку IAST
- **Hdiv Security** - enterprise рішення
- **Seeker by Synopsys** - comprehensive platform

## 🏗️ IaC - Infrastructure as Code

### Визначення
**IaC** (Інфраструктура як код) - процес створення інфраструктури за допомогою файлів коду замість ручного налаштування.

### Популярні IaC інструменти

#### ☁️ Cloud-специфічні
**AWS CloudFormation:**
```yaml
# CloudFormation template приклад
AWSTemplateFormatVersion: '2010-09-09'
Resources:
  MyS3Bucket:
    Type: AWS::S3::Bucket
    Properties:
      BucketName: my-secure-bucket
      PublicAccessBlockConfiguration:
        BlockPublicAcls: true
```

#### 🌐 Multi-cloud
**Terraform:**
```hcl
# Terraform приклад
resource "aws_s3_bucket" "example" {
  bucket = "my-secure-bucket"
  
  server_side_encryption_configuration {
    rule {
      apply_server_side_encryption_by_default {
        sse_algorithm = "AES256"
      }
    }
  }
}
```

### IaC Security Testing
**Інструменти для безпеки IaC:**
- **Checkov** - static analysis для Terraform
- **TFSec** - security scanner для Terraform
- **AWS Config** - compliance моніторинг
- **Azure Policy** - governance для Azure

## 🔌 API Security

### Визначення
**API Security** - процес виявлення проблем безпеки в API (Application Programming Interfaces).

### API vs Microservices

#### 🔗 Розуміння різниці
**API (Application Programming Interface):**
- Інтерфейс для взаємодії між системами
- Може включати множину endpoints
- Broader scope функціональності

**Microservice:**
- **Підмножина API**
- Specific business функція
- Single responsibility принцип

#### 🛒 Практичний приклад: E-commerce
```
E-commerce API
├── User Registration API
│   ├── Create User (microservice)
│   ├── Delete User (microservice)
│   └── Update User (microservice)
├── Product Management API
│   ├── Add Product (microservice)
│   ├── Update Product (microservice)
│   └── Delete Product (microservice)
└── Order Processing API
    ├── Create Order (microservice)
    ├── Update Order (microservice)
    └── Cancel Order (microservice)
```

### API Security Testing
**Ключові аспекти:**
- 🔐 **Authentication** механізми
- 🛡️ **Authorization** controls
- 📊 **Input validation**
- 🔒 **Data encryption**
- 📈 **Rate limiting**
- 🎯 **OWASP API Top 10** compliance

### Інструменти API Security
- **OWASP ZAP** - API endpoint testing
- **Postman** - manual API testing
- **Burp Suite** - comprehensive API security
- **42Crunch** - specialized API security platform

## 📊 Порівняльна таблиця всіх методів

| Метод | Етап | Тип тестування | Переваги | Недоліки |
|-------|------|----------------|----------|----------|
| **SAST** | Development | White box | Раннє виявлення, повний coverage | Високі false positives |
| **SCA** | Build | Dependency analysis | License та CVE checking | Залежить від баз даних |
| **DAST** | QA/Production | Black box | Реальні вразливості | Обмежений coverage |
| **IAST** | Runtime | Hybrid | Низькі false positives | Потребує інструментацію |
| **IaC Security** | Infrastructure | Static analysis | Prevention підхід | Cloud-специфічний |
| **API Security** | Runtime | Black/Gray box | Business logic focus | Complex setup |

## 🎯 Висновки

Розуміння цих безпекових термінів критично важливе для:

### ✅ Успішної імплементації DevSecOps
- Правильний вибір інструментів для кожного етапу
- Розуміння strengths та limitations кожного підходу
- Створення comprehensive security strategy

### 🚀 Професійного розвитку
- Communication з security командами
- Technical interviews preparation
- Industry best practices adoption

**У наступних лекціях ми практично імплементуємо кожен з цих підходів у GitHub Actions pipeline!**

---

*Дякуємо за увагу! Сподіваємось, ця лекція була корисною. До зустрічі на наступній лекції, де ми розпочнемо вивчення основ GitHub Actions.*


--------------------------------------------------
