


 # Secure Programming: Implementing OWASP Standards in a Django and FastAPI Application
 https://medium.com/@adrialnathanael/secure-programming-implementing-owasp-standards-in-a-django-and-fastapi-application-c5119678806b


 # Резюме: Безпечне програмування з використанням стандартів OWASP у Django та FastAPI додатку

## 🔒 **Основна ідея**
Автор розповідає про впровадження найкращих практик безпеки в веб-додатку з Django фронтендом та FastAPI бекендом, використовуючи стандарти OWASP (Open Web Application Security Project).

## 🎯 **Аналіз загроз за моделлю STRIDE**
Автор провів аналіз потенційних загроз:
- **Spoofing** - видавання себе за легітимних користувачів
- **Tampering** - несанкціонована зміна даних
- **Repudiation** - заперечення виконаних дій
- **Information Disclosure** - несанкціонований доступ до інформації
- **Denial of Service** - виведення додатку з ладу
- **Elevation of Privilege** - отримання несанкціонованих прав

## 🛡️ **Впровадження захисту**

### **1. CSRF захист**
```javascript
// Отримання CSRF токену з cookies
function getCookie(name) {
  // Код для отримання токену
}
// Використання в запитах
const csrftoken = getCookie("csrftoken")
```

### **2. Валідація введених даних**
```javascript
// Перевірка назви проекту
const projectNameRegex = /^[a-zA-Z0-9_]+$/
if (!projectNameRegex.test(projectName)) {
  showNotification("Назва може містити тільки літери, цифри та підкреслення", "error")
}
```

### **3. Безпека завантаження файлів**
```javascript
function validateFile(file) {
  const isClass = file.name.toLowerCase().endsWith(".class.jet")
  const isSequence = file.name.toLowerCase().endsWith(".sequence.jet")
  // Дозволено тільки певні типи файлів
}
```

## 📋 **Впровадження OWASP Top 10**

### **1. Контроль доступу**
- Використання middleware для безпеки заголовків
- Додавання `X-Content-Type-Options`, `X-Frame-Options`, `Content-Security-Policy`

### **2. Криптографічні помилки**
- Безпечне хешування паролів з Django
- Використання Argon2 та PBKDF2

### **3. Запобігання ін'єкціям**
- Параметризовані запити в SQLAlchemy
- Валідація всіх користувацьких введень

### **4. Налаштування безпеки**
```python
PASSWORD_VALIDATORS = [
    {'NAME': 'django.contrib.auth.password_validation.UserAttributeSimilarityValidator'},
    {'NAME': 'django.contrib.auth.password_validation.MinimumLengthValidator', 'OPTIONS': {'min_length': 12}},
]
SESSION_COOKIE_SECURE = True
CSRF_COOKIE_SECURE = True
```

### **5. Логування та моніторинг**
```python
LOGGING = {
    'loggers': {
        'security': {
            'handlers': ['security_file'],
            'level': 'INFO',
        },
    },
}
```

## 🔧 **Інструменти тестування безпеки**

### **SonarQube**
- Виявлення уразливостей у коді
- Ідентифікація security hotspots
- Метрики якості коду
- Безперервний моніторинг

### **OWASP ZAP (заплановано)**
- Автоматичне виявлення уразливостей
- Пасивне та активне сканування
- Тестування API
- Детальні звіти з рекомендаціями

## 📊 **Результати впровадження**
- ✅ **Зменшена кількість уразливостей** за результатами SonarQube
- ✅ **Покращена валідація введень** - всі дані перевіряються
- ✅ **Безпечне завантаження файлів** - тільки дозволені типи
- ✅ **Захищена комунікація** - CSRF захист для всіх API
- ✅ **Автоматизовані перевірки** через CI/CD pipeline

## 🎯 **Ключові висновки**
1. **Безпека з самого початку** - не як додаток, а як основа розробки
2. **Використання перевірених фреймворків** як OWASP
3. **Автоматизоване тестування** з інструментами на кшталт SonarQube
4. **Багаторівневий захист** - defense in depth
5. **Правильна валідація та автентифікація** як фундамент

## 💡 **Практичне застосування**
Стаття демонструє реальний приклад того, як можна системно підійти до безпеки веб-додатку, поєднуючи Django та FastAPI з дотриманням міжнародних стандартів OWASP. Автор показує конкретні приклади коду та конфігурацій, які можна використовувати у власних проектах.



-------------------------------------------------------------------------------------------


# Безпечне програмування: Впровадження стандартів OWASP у додатку Django та FastAPI

**Адріал Натанаель**  
8 хвилин читання  
20 квітня 2025 р.

## Вступ

У сучасному взаємопов'язаному цифровому середовищі безпека не може бути другорядним питанням у веб-розробці. Оскільки кіберзагрози стають все більш складними, впровадження надійних заходів безпеки є обов'язковим для захисту даних користувачів та підтримки цілісності додатків.

Ця стаття досліджує, як я впровадив найкращі практики безпеки у своєму додатку з Django фронтендом та FastAPI бекендом, дотримуючись стандартів OWASP (Open Web Application Security Project). Інтегруючи безпеку з самого початку процесу розробки, я створив стійкий додаток, який захищає дані користувачів, зберігаючи при цьому відмінну продуктивність та зручність використання.

## Розуміння загроз та ризиків у веб-додатках

Перед впровадженням будь-яких заходів безпеки я провів ретельний аналіз загроз, щоб зрозуміти, з якими уразливостями може зіткнутися мій додаток Django та FastAPI.

### Моделювання загроз за допомогою STRIDE

Ми можемо використовувати модель STRIDE для систематичної ідентифікації потенційних загроз:

- **Spoofing (Підміна)**: Зловмисники видають себе за легітимних користувачів
- **Tampering (Втручання)**: Несанкціонована модифікація даних
- **Repudiation (Заперечення)**: Користувачі заперечують дії, які вони виконали
- **Information Disclosure (Розкриття інформації)**: Несанкціонований доступ до конфіденційної інформації
- **Denial of Service (Відмова в обслуговуванні)**: Виведення додатку з ладу
- **Elevation of Privilege (Підвищення привілеїв)**: Отримання несанкціонованих прав доступу

Для мого додатку я ідентифікував кілька ключових ризиків:

- **Cross-Site Request Forgery (CSRF)**: Зловмисники обманюють користувачів, змушуючи їх виконувати небажані дії
- **Cross-Site Scripting (XSS)**: Впровадження шкідливих скриптів у веб-сторінки
- **Уразливості валідації введення**: Дозвіл на обробку шкідливих даних
- **Уразливості завантаження файлів**: Завантаження шкідливих файлів, які можуть бути виконані
- **Слабкості аутентифікації**: Слабкі політики паролів або управління сесіями
- **Небезпечні прямі посилання на об'єкти**: Доступ до несанкціонованих ресурсів

Раннє розуміння цих загроз дозволило мені пріоритизувати заходи безпеки протягом усього процесу розробки.

## Впровадження стандартів безпеки: Аутентифікація та авторизація

### Впровадження захисту від CSRF

Django надає вбудований захист від CSRF, який я повністю впровадив у своєму додатку. Ось як це працює в моєму JavaScript фронтенді:

```javascript
// Отримання CSRF токену з cookies
function getCookie(name) {
  let cookieValue = null
  if (document.cookie && document.cookie !== "") {
    const cookies = document.cookie.split(";")
    for (const cookie of cookies) {
      const trimmed = cookie.trim()
      if (trimmed.startsWith(name + "=")) {
        cookieValue = decodeURIComponent(trimmed.substring(name.length + 1))
        break
      }
    }
  }
  return cookieValue
}

// Використання CSRF токену в запитах
const csrftoken = getCookie("csrftoken")
// Включення токену в fetch запити
const response = await fetch("/convert_page/", {
  method: "POST",
  headers: { "X-CSRFToken": csrftoken },
  body: formData,
  credentials: "same-origin",
})
```

Ця реалізація запобігає CSRF атакам, забезпечуючи обробку лише запитів з дійсним CSRF токеном.

### Валідація та санітизація введення

Я впровадив комплексну валідацію введення для запобігання атакам впровадження:

```javascript
// Валідація назви проекту
const projectName = projectNameInput.value.trim()

// Перевірка, що назва проекту не порожня
if (!projectName) {
  showNotification("Будь ласка, введіть назву проекту.", "error")
  return
}

// Валідація формату назви проекту (тільки букви, цифри та підкреслення)
const projectNameRegex = /^[a-zA-Z0-9_]+$/
if (!projectNameRegex.test(projectName)) {
  showNotification("Назва проекту може містити тільки літери, цифри та підкреслення.", "error")
  return
}
```

### Безпека завантаження файлів

Забезпечення безпеки завантаження файлів є критично важливим для запобігання виконанню шкідливих файлів. Моя реалізація включає:

```javascript
// Валідація типу файлу
function validateFile(file) {
  const isClass = file.name.toLowerCase().endsWith(".class.jet")
  const isSequence = file.name.toLowerCase().endsWith(".sequence.jet")
  if (!isClass && !isSequence) {
    return `Недійсний тип файлу: ${file.name}. Дозволені тільки .class.jet та .sequence.jet`
  }
  if (isClass) {
      classFileCount++
      if (classFileCount > 1) {
        classFileCount--
        return "Дозволений тільки один .class.jet файл!"
      }
    }
    return null
  }
```

Ця валідація забезпечує прийняття тільки очікуваних типів файлів, запобігаючи завантаженню потенційно шкідливих файлів.

## Впровадження стандартів OWASP

OWASP Top 10 представляє найкритичніші ризики безпеки для веб-додатків. Я зосередився на вирішенні кожної з цих уразливостей у своєму додатку Django та FastAPI.

### 1. Порушений контроль доступу

Django надає надійні механізми контролю доступу, які я доповнив власним middleware:

```python
# Приклад middleware.py для FastAPI
from fastapi import Request, FastAPI
from fastapi.middleware.base import BaseHTTPMiddleware
from starlette.responses import Response

class SecurityHeadersMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request: Request, call_next):
        response = await call_next(request)
        
        # Додавання заголовків безпеки
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["X-Frame-Options"] = "DENY"
        response.headers["Content-Security-Policy"] = "default-src 'self'"
        
        return response

# Додавання middleware до FastAPI додатку
app = FastAPI()
app.add_middleware(SecurityHeadersMiddleware)
```

### 2. Криптографічні помилки

Я впровадив безпечну обробку паролів з вбудованим хешуванням Django:

```python
# У Django models.py
from django.contrib.auth.models import AbstractUser
from django.contrib.auth.hashers import make_password

class User(AbstractUser):
    def save(self, *args, **kwargs):
        # Забезпечення хешування пароля при збереженні
        if self._password is not None:
            self.password = make_password(self._password)
            self._password = None
        super().save(*args, **kwargs)
```

### 3. Запобігання впровадженню

Мій FastAPI бекенд використовує параметризовані запити для запобігання SQL ін'єкції:

```python
# Приклад використання SQLAlchemy з FastAPI для запобігання SQL ін'єкції
from sqlalchemy.orm import Session
from fastapi import Depends

# Отримання користувача за ID (безпечно від SQL ін'єкції)
def get_user(db: Session, user_id: int):
    return db.query(User).filter(User.id == user_id).first()

# API endpoint
@app.get("/users/{user_id}")
def read_user(user_id: int, db: Session = Depends(get_db)):
    user = get_user(db, user_id)
    if user is None:
        raise HTTPException(status_code=404, detail="Користувач не знайдений")
    return user
```

### 4. Небезпечний дизайн

Я застосував принципи безпеки-за-дизайном через:

- **Моделювання загроз**: Раннє виявлення потенційних уразливостей
- **Безпечні значення за замовчуванням**: Використання безпечних налаштувань Django та FastAPI
- **Захист у глибину**: Множинні рівні контролю безпеки

### 5. Неправильна конфігурація безпеки

Моє розгортання включає перевірку конфігурації безпеки в CI/CD pipeline:

```yaml
# Приклад GitHub workflow для перевірки конфігурації безпеки
name: Security Configuration Check

on:
  push:
    branches: [ main, staging ]
  pull_request:
    branches: [ main ]

jobs:
  check-security:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v3
      
      - name: Перевірка налаштувань Django
        run: |
          if grep -q "DEBUG = True" config/production.py; then
            echo "ПОМИЛКА: Режим відладки увімкнений у продакшені!"
            exit 1
          fi
          
      - name: Перевірка security middleware
        run: |
          if ! grep -q "SecurityMiddleware" config/settings.py; then
            echo "ПОМИЛКА: SecurityMiddleware не увімкнений!"
            exit 1
          fi
```

### 6. Уразливі та застарілі компоненти

Я використовую GitHub Dependabot для автоматичного сканування уразливих залежностей:

```yaml
# .github/dependabot.yml
version: 2
updates:
  - package-ecosystem: "pip"
    directory: "/"
    schedule:
      interval: "weekly"
    open-pull-requests-limit: 10
  - package-ecosystem: "npm"
    directory: "/"
    schedule:
      interval: "weekly"
    open-pull-requests-limit: 10
```

### 7. Помилки ідентифікації та аутентифікації

На додаток до системи аутентифікації Django, я впровадив додатковий захист:

```python
# settings.py
PASSWORD_HASHERS = [
    'django.contrib.auth.hashers.Argon2PasswordHasher',
    'django.contrib.auth.hashers.PBKDF2PasswordHasher',
    'django.contrib.auth.hashers.PBKDF2SHA1PasswordHasher',
]

PASSWORD_VALIDATORS = [
    {
        'NAME': 'django.contrib.auth.password_validation.UserAttributeSimilarityValidator',
    },
    {
        'NAME': 'django.contrib.auth.password_validation.MinimumLengthValidator',
        'OPTIONS': {
            'min_length': 12,
        }
    },
    {
        'NAME': 'django.contrib.auth.password_validation.CommonPasswordValidator',
    },
    {
        'NAME': 'django.contrib.auth.password_validation.NumericPasswordValidator',
    },
]

# Використання безпечних cookies
SESSION_COOKIE_SECURE = True
CSRF_COOKIE_SECURE = True
```

### 8. Помилки цілісності програмного забезпечення та даних

Я впровадив перевірки цілісності для критичних операцій:

```python
# Приклад перевірки цілісності в Django views
@require_http_methods(["POST"])
@csrf_protect
def upload_file(request):
    """Завантаження файлу з перевірками цілісності"""
    if not request.user.is_authenticated:
        return HttpResponseForbidden()
    
    # Перевірка цілісності файлу за допомогою хешу
    uploaded_file = request.FILES['file']
    file_hash = hashlib.sha256(uploaded_file.read()).hexdigest()
    
    # Скидання вказівника файлу
    uploaded_file.seek(0)
    
    # Логування завантаження файлу для аудиту
    AuditLog.objects.create(
        user=request.user,
        action="file_upload",
        details=json.dumps({
            'filename': uploaded_file.name,
            'size': uploaded_file.size,
            'hash': file_hash
        })
    )
    
    # Обробка файлу
    # ...
    
    return JsonResponse({'success': True})
```

### 9. Помилки логування та моніторингу безпеки

Я впровадив комплексне логування для подій, пов'язаних з безпекою:

```python
# Django settings.py для логування безпеки
LOGGING = {
    'version': 1,
    'disable_existing_loggers': False,
    'formatters': {
        'verbose': {
            'format': '{levelname} {asctime} {module} {message}',
            'style': '{',
        },
    },
    'handlers': {
        'security_file': {
            'level': 'INFO',
            'class': 'logging.FileHandler',
            'filename': 'logs/security.log',
            'formatter': 'verbose',
        },
    },
    'loggers': {
        'security': {
            'handlers': ['security_file'],
            'level': 'INFO',
            'propagate': False,
        },
    },
}

# Використання в views
import logging
security_logger = logging.getLogger('security')

def login_view(request):
    # ... логіка аутентифікації ...
    if user is not None:
        security_logger.info(
            f"Успішний вхід: user={username}, ip={request.META.get('REMOTE_ADDR')}"
        )
    else:
        security_logger.warning(
            f"Невдалий вхід: user={username}, ip={request.META.get('REMOTE_ADDR')}"
        )
```

### 10. Захист від Server-Side Request Forgery (SSRF)

Я впровадив захист від SSRF атак:

```python
# Приклад FastAPI для безпечної валідації URL
import ipaddress
from urllib.parse import urlparse
from fastapi import HTTPException

def is_safe_url(url: str) -> bool:
    """Перевірка, чи є URL безпечним (не вказує на внутрішні ресурси)"""
    parsed = urlparse(url)
    
    # Дозволяємо тільки http та https схеми
    if parsed.scheme not in ('http', 'https'):
        return False
    
    # Перевіряємо, чи не розв'язується hostname у приватний IP
    try:
        ip = socket.gethostbyname(parsed.netloc)
        ip_obj = ipaddress.ip_address(ip)
        
        if ip_obj.is_private or ip_obj.is_loopback:
            return False
    except:
        return False
    
    return True

@app.get("/proxy")
async def proxy_endpoint(url: str):
    if not is_safe_url(url):
        raise HTTPException(status_code=400, detail="Недійсний або заборонений URL")
    
    # Продовжуємо з запитом, якщо URL безпечний
    # ...
```

## Впровадження тестування безпеки

### Теоретичне впровадження OWASP ZAP

Хоча я ще не інтегрував OWASP ZAP у свій робочий процес, розуміння його можливостей є критично важливим для комплексного тестування безпеки. OWASP ZAP (Zed Attack Proxy) - це потужний інструмент, який діє як проксі "людина-посередині" для перехоплення та перевірки повідомлень між браузером та додатком.

Ось як я планую інтегрувати OWASP ZAP у свій робочий процес:

```yaml
# Запланований GitHub workflow для інтеграції OWASP ZAP
name: Security Scan with OWASP ZAP

on:
  schedule:
    - cron: '0 0 * * 1'  # Щотижневе сканування по понеділках
  workflow_dispatch:  # Дозволити ручний запуск

jobs:
  zap_scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v3
      
      - name: Запуск додатку для тестування
        run: docker-compose up -d
      
      - name: ZAP Baseline Scan
        uses: zaproxy/action-baseline@v0.7.0
        with:
          target: 'http://localhost:8000'
          rules_file_name: '.zap/rules.tsv'
          cmd_options: '-a'
```

Ключові переваги OWASP ZAP включають:

- Автоматичне виявлення уразливостей безпеки
- Пасивне сканування для ненав'язливого тестування
- Активне сканування для глибокого виявлення уразливостей
- Сканування API для тестування бекенд-сервісів
- Детальні звіти з рекомендаціями щодо усунення

### Переваги SonarQube для тестування безпеки

Я активно використовував SonarQube для виявлення проблем безпеки в моєму коді:

SonarQube надає:

- Виявлення точок безпеки
- Ідентифікацію уразливостей
- Метрики якості коду, що впливають на безпеку
- Безперервний моніторинг через інтеграцію CI/CD

## Результати та вплив

Впровадження цих заходів безпеки значно покращило безпекову позицію мого додатку:

- **Зменшена кількість уразливостей**: Сканування SonarQube показують мінімальні проблеми безпеки
- **Покращена валідація введення**: Всі введення користувачів належним чином валідуються та санітизуються
- **Посилена безпека завантаження файлів**: Приймаються тільки дозволені типи файлів
- **Безпечна комунікація**: Вся API комунікація включає CSRF захист

## Висновок

Безпечне програмування - це обов'язкова практика, яка повинна бути інтегрована протягом усього життєвого циклу розробки. Застосовуючи стандарти OWASP до мого додатку Django та FastAPI, я створив більш безпечну та стійку систему.

Ключові висновки з цього впровадження включають:

- Безпека повинна розглядатися з самого початку розробки
- Дотримання встановлених фреймворків, таких як OWASP, забезпечує комплексний захист
- Автоматизоване тестування з інструментами, такими як SonarQube, є обов'язковим для постійної безпеки
- Множинні рівні безпеки забезпечують захист у глибину
- Валідація введення та належна аутентифікація є основними заходами безпеки

Хоча жоден додаток не може бути на 100% безпечним, дотримання цих практик значно зменшує ризик порушень безпеки та захищає як дані користувачів, так і цілісність додатку.

Які практики безпеки ви дотримуєтеся у своїй роботі з розробки? Поділіться своїм досвідом у коментарях!


--------------------------------------------------------------






