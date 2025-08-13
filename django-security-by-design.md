
# UDEMY

- Python Django: Ultimate Web Security Checklist - 2025, https://www.udemy.com/course/python-django-ultimate-web-security-checklist-2022/?utm_source=adwords&utm_medium=udemyads&utm_campaign=Search_DSA_Beta_Prof_la.EN_cc.ROW-English&campaigntype=Search&portfolio=ROW-English&language=EN&product=Course&test=&audience=DSA&topic=&priority=Beta&utm_content=deal4584&utm_term=_._ag_162511579404_._ad_696197165418_._kw__._de_c_._dm__._pl__._ti_dsa-1677053911088_._li_9061017_._pd__._&matchtype=&gad_source=1&gad_campaignid=21168154305&gbraid=0AAAAADROdO3jbv6dOu8GksfwkVYErrEvR&gclid=CjwKCAjw7_DEBhAeEiwAWKiCC1NnKeTkDUnSQc5l6ulJmKXKzDJN6zCglU9KERdfGgQcEbQ0fydlSxoCIcUQAvD_BwE&couponCode=PMNVD2525
- Secure by Design: Django Best Practices for Web Security, https://medium.com/@StartXLabs/secure-by-design-django-best-practices-for-web-security-b5a668921b47
- DjangoCon Europe 2023 | A Beginners Guide to Security Exploits in Action, https://www.youtube.com/watch?v=CN6zJlqdxt0
- 


- Django Security Best Practices: Essential Strategies for Protecting Your Web App - Joseph Adediji, https://www.youtube.com/watch?v=6KDyCW-B_f4
- Secure Coding in Python Django, https://www.udemy.com/course/secpy-django/?utm_source=adwords&utm_medium=udemyads&utm_campaign=Search_DSA_Beta_Prof_la.EN_cc.ROW-English&campaigntype=Search&portfolio=ROW-English&language=EN&product=Course&test=&audience=DSA&topic=&priority=Beta&utm_content=deal4584&utm_term=_._ag_162511579404_._ad_696197165418_._kw__._de_c_._dm__._pl__._ti_dsa-1677053911088_._li_9061017_._pd__._&matchtype=&gad_source=1&gad_campaignid=21168154305&gbraid=0AAAAADROdO3jbv6dOu8GksfwkVYErrEvR&gclid=CjwKCAjw7_DEBhAeEiwAWKiCC1X-GjWJwC_3AZdVk6vs9FfISSV_mDvaih8UehyOw4lvqv0IdbdWkxoCFBYQAvD_BwE&couponCode=PMNVD2525
- Django Security Cheat Sheet, https://cheatsheetseries.owasp.org/cheatsheets/Django_Security_Cheat_Sheet.html
- DJA201 – Defending Django, https://www.securitycompass.com/training_courses/dja201-defending-django/
- Best Django security practices, https://escape.tech/blog/best-django-security-practices/
- Django web application security, https://developer.mozilla.org/en-US/docs/Learn_web_development/Extensions/Server-side/Django/web_application_security
- 




# Практики безпеки Django
## Security Best Practices для Django додатків

---

## Чому важлива безпека?

### 📊 **Статистика кіберзагроз:**
- **2023 рік:** 2,300+ кібератак з 343+ млн жертв по всьому світу
- **72% збільшення** витоків даних у 2023 році
- **$4.4 млн** - середня вартість витоку даних
- **Nigerian NIN/BVN data** доступні на чорному ринку за ₦100

### 🎯 **Чому розробники ігнорують безпеку:**
```
❌ "Головне, щоб додаток працював"
❌ "Безпека - це не мої проблеми"
❌ "Ніхто не буде атакувати мій маленький додаток"
❌ "Додам безпеку пізніше"
```

### 💰 **Реальні наслідки:**
- **Twitter hack 2020:** $121,000 втрачено через Bitcoin scam
- **Особисті дані:** NIN, BVN, адреси, фото - все на продаж
- **AI impersonation:** клонування голосу та зображень
- **Репутаційні втрати** та правові наслідки

---

## Authentication vs Authorization

### 🔐 **Authentication (Аутентифікація)**
**Визначення:** Підтвердження того, що ви є тим, за кого себе видаєте.

**Приклад:**
```python
# Django authentication
from django.contrib.auth import authenticate, login

def login_view(request):
    if request.method == 'POST':
        username = request.POST['username']
        password = request.POST['password']
        
        # Аутентифікація користувача
        user = authenticate(request, username=username, password=password)
        
        if user is not None:
            login(request, user)
            return redirect('dashboard')
        else:
            messages.error(request, 'Неправильні дані для входу')
    
    return render(request, 'login.html')
```

### 🛡️ **Authorization (Авторизація)**
**Визначення:** Перевірка дозволів на виконання конкретних дій.

**Приклад LMS системи:**
```python
from django.contrib.auth.decorators import login_required, user_passes_test
from django.contrib.auth.models import Group

def is_teacher(user):
    return user.groups.filter(name='Teachers').exists()

def is_student(user):
    return user.groups.filter(name='Students').exists()

@login_required
@user_passes_test(is_teacher)
def teacher_dashboard(request):
    """Тільки викладачі можуть бачити цю сторінку"""
    return render(request, 'teacher_dashboard.html')

@login_required
@user_passes_test(is_student)
def student_dashboard(request):
    """Тільки студенти можуть бачити цю сторінку"""
    return render(request, 'student_dashboard.html')

@login_required
@user_passes_test(is_teacher)
def update_grades(request, student_id):
    """Тільки викладачі можуть оновлювати оцінки"""
    if request.method == 'POST':
        # Логіка оновлення оцінок
        pass
```

**Проблема без proper authorization:**
```python
# НЕБЕЗПЕЧНО - будь-хто може отримати доступ
def teacher_dashboard(request):
    # Немає перевірки ролей!
    return render(request, 'teacher_dashboard.html')

# Студент може змінити свої оцінки:
# GET /teacher/update-grades/123/
```

### 🔒 **Покращені практики безпеки:**

#### **Strong Password Policies:**
```python
# settings.py
AUTH_PASSWORD_VALIDATORS = [
    {
        'NAME': 'django.contrib.auth.password_validation.UserAttributeSimilarityValidator',
    },
    {
        'NAME': 'django.contrib.auth.password_validation.MinimumLengthValidator',
        'OPTIONS': {
            'min_length': 12,  # Мінімум 12 символів
        }
    },
    {
        'NAME': 'django.contrib.auth.password_validation.CommonPasswordValidator',
    },
    {
        'NAME': 'django.contrib.auth.password_validation.NumericPasswordValidator',
    },
]

# Custom password validator
class CustomPasswordValidator:
    def validate(self, password, user=None):
        if not any(char.isdigit() for char in password):
            raise ValidationError("Пароль повинен містити хоча б одну цифру")
        if not any(char.isupper() for char in password):
            raise ValidationError("Пароль повинен містити хоча б одну велику літеру")
        if not any(char in "!@#$%^&*" for char in password):
            raise ValidationError("Пароль повинен містити спеціальні символи")
```

#### **Two-Factor Authentication:**
```python
# Інтеграція з django-otp
from django_otp.decorators import otp_required
from django_otp.plugins.otp_totp.models import TOTPDevice

@login_required
@otp_required
def sensitive_view(request):
    """Потребує 2FA для доступу"""
    return render(request, 'sensitive_data.html')

def setup_2fa(request):
    """Налаштування 2FA для користувача"""
    device = TOTPDevice.objects.create(
        user=request.user,
        name='default'
    )
    return render(request, 'setup_2fa.html', {'qr_code': device.config_url})
```

#### **Session Management:**
```python
# settings.py
# Session timeout - 30 хвилин
SESSION_COOKIE_AGE = 1800  # 30 хвилин в секундах
SESSION_EXPIRE_AT_BROWSER_CLOSE = True
SESSION_SAVE_EVERY_REQUEST = True  # Оновлювати час сесії при кожному запиті

# Secure session cookies
SESSION_COOKIE_SECURE = True  # Тільки через HTTPS
SESSION_COOKIE_HTTPONLY = True  # Заборонити доступ через JavaScript
SESSION_COOKIE_SAMESITE = 'Strict'  # CSRF захист

# Custom middleware для автоматичного logout
class SessionTimeoutMiddleware:
    def __init__(self, get_response):
        self.get_response = get_response

    def __call__(self, request):
        if request.user.is_authenticated:
            last_activity = request.session.get('last_activity')
            if last_activity:
                time_since_activity = timezone.now() - datetime.fromisoformat(last_activity)
                if time_since_activity.total_seconds() > 1800:  # 30 хвилин
                    logout(request)
                    messages.info(request, 'Сесія закінчилася через неактивність')
                    return redirect('login')
            
            request.session['last_activity'] = timezone.now().isoformat()
        
        return self.get_response(request)
```

---

## Веб-атаки та захист

### 🕷️ **Cross-Site Scripting (XSS)**

**Django має вбудований захист, але його можна відключити:**

#### **Автоматичне екранування (за замовчуванням):**
```html
<!-- Django автоматично екранує контент -->
<p>{{ user_input }}</p>  <!-- Безпечно -->

<!-- Якщо user_input = "<script>alert('XSS')</script>" -->
<!-- Django виведе: &lt;script&gt;alert('XSS')&lt;/script&gt; -->
```

#### **Небезпечне відключення екранування:**
```html
<!-- НЕБЕЗПЕЧНО - не робіть так без валідації! -->
<p>{{ user_input|safe }}</p>
<p>{% autoescape off %}{{ user_input }}{% endautoescape %}</p>
```

#### **Безпечне використання HTML контенту:**
```python
from django.utils.html import strip_tags, escape
from django.utils.safestring import mark_safe
import bleach

def safe_html_content(request):
    user_html = request.POST.get('content')
    
    # Метод 1: Видалити всі HTML теги
    clean_text = strip_tags(user_html)
    
    # Метод 2: Використати bleach для дозволених тегів
    allowed_tags = ['p', 'br', 'strong', 'em', 'ul', 'ol', 'li']
    clean_html = bleach.clean(user_html, tags=allowed_tags, strip=True)
    
    # Метод 3: Екранувати HTML
    escaped_html = escape(user_html)
    
    return render(request, 'content.html', {
        'safe_content': mark_safe(clean_html)
    })
```

#### **Content Security Policy (CSP):**
```python
# settings.py
# Додати CSP middleware
MIDDLEWARE = [
    'csp.middleware.CSPMiddleware',
    # ... інші middleware
]

# CSP налаштування
CSP_DEFAULT_SRC = ("'self'",)
CSP_SCRIPT_SRC = ("'self'", "'unsafe-inline'")
CSP_STYLE_SRC = ("'self'", "'unsafe-inline'")
CSP_IMG_SRC = ("'self'", "data:", "https:")
CSP_FONT_SRC = ("'self'", "https://fonts.gstatic.com")
```

### 🔒 **Cross-Site Request Forgery (CSRF)**

#### **Стандартне використання CSRF токенів:**
```html
<!-- Django форма з CSRF захистом -->
<form method="post">
    {% csrf_token %}
    <input type="text" name="username">
    <input type="password" name="password">
    <button type="submit">Увійти</button>
</form>
```

#### **AJAX запити з CSRF токенами:**
```javascript
// Отримання CSRF токену
function getCSRFToken() {
    return document.querySelector('[name=csrfmiddlewaretoken]').value;
}

// Або з cookies
function getCSRFTokenFromCookie() {
    const cookieValue = document.cookie
        .split('; ')
        .find(row => row.startsWith('csrftoken='))
        ?.split('=')[1];
    return cookieValue;
}

// AJAX запит з CSRF токеном
fetch('/api/update-profile/', {
    method: 'POST',
    headers: {
        'Content-Type': 'application/json',
        'X-CSRFToken': getCSRFTokenFromCookie(),
    },
    body: JSON.stringify({
        'name': 'New Name',
        'email': 'new@email.com'
    })
})
.then(response => response.json())
.then(data => console.log(data));
```

#### **Vue.js/React інтеграція:**
```javascript
// Vue.js приклад
import axios from 'axios';

// Налаштування axios для автоматичного включення CSRF токену
axios.defaults.xsrfCookieName = 'csrftoken';
axios.defaults.xsrfHeaderName = 'X-CSRFToken';

// React приклад
const CSRFToken = () => {
    const [csrftoken, setCsrftoken] = useState('');
    
    useEffect(() => {
        const token = document.querySelector('[name=csrfmiddlewaretoken]').value;
        setCsrftoken(token);
    }, []);
    
    return (
        <input type="hidden" name="csrfmiddlewaretoken" value={csrftoken} />
    );
};
```

---

## DEBUG налаштування

### 🚨 **Небезпека DEBUG = True в продакшені:**

**Що розкривається при DEBUG = True:**
```python
# Інформація, доступна зловмисникам:
{
    "url_patterns": [
        "/admin/",
        "/api/users/",
        "/api/payments/",
        "/api/secret-endpoint/"
    ],
    "template_paths": [
        "/app/templates/",
        "/app/secret_templates/"
    ],
    "secret_keys": "django-insecure-your-secret-key-here",
    "database_info": {
        "engine": "postgresql",
        "name": "production_db",
        "host": "db.company.com"
    },
    "installed_apps": [
        "django_extensions",
        "debug_toolbar",
        "payment_processor"
    ]
}
```

### ✅ **Правильне налаштування DEBUG:**

#### **Метод 1: Різні settings файли**
```python
# settings/base.py
SECRET_KEY = 'django-insecure-dev-key'
DEBUG = False  # За замовчуванням False

# settings/development.py
from .base import *
DEBUG = True
ALLOWED_HOSTS = ['localhost', '127.0.0.1']

# settings/production.py
from .base import *
DEBUG = False
ALLOWED_HOSTS = ['yourdomain.com', 'www.yourdomain.com']
SECRET_KEY = os.environ.get('SECRET_KEY')
```

#### **Метод 2: Environment Variables (Рекомендований)**
```python
# settings.py
from decouple import config

DEBUG = config('DEBUG', default=False, cast=bool)
SECRET_KEY = config('SECRET_KEY')
ALLOWED_HOSTS = config('ALLOWED_HOSTS', default='').split(',')

# Database
DATABASES = {
    'default': {
        'ENGINE': 'django.db.backends.postgresql',
        'NAME': config('DB_NAME'),
        'USER': config('DB_USER'),
        'PASSWORD': config('DB_PASSWORD'),
        'HOST': config('DB_HOST', default='localhost'),
        'PORT': config('DB_PORT', default='5432'),
    }
}
```

#### **Environment файл (.env):**
```bash
# .env (додати в .gitignore!)
DEBUG=False
SECRET_KEY=your-super-secret-production-key-here
DB_NAME=production_db
DB_USER=prod_user
DB_PASSWORD=super_secure_password
DB_HOST=db.production.com
ALLOWED_HOSTS=yourdomain.com,www.yourdomain.com

# Email settings
EMAIL_HOST=smtp.gmail.com
EMAIL_PORT=587
EMAIL_HOST_USER=your-email@gmail.com
EMAIL_HOST_PASSWORD=your-app-password

# API Keys
PAYSTACK_SECRET_KEY=sk_test_your_paystack_secret
CLOUDINARY_API_KEY=your_cloudinary_key
CLOUDINARY_API_SECRET=your_cloudinary_secret
```

### 🛠️ **Custom Error Pages:**
```python
# views.py
from django.shortcuts import render

def custom_404(request, exception):
    return render(request, '404.html', status=404)

def custom_500(request):
    return render(request, '500.html', status=500)

# urls.py
handler404 = 'myapp.views.custom_404'
handler500 = 'myapp.views.custom_500'
```

```html
<!-- templates/404.html -->
<!DOCTYPE html>
<html>
<head>
    <title>Сторінка не знайдена</title>
</head>
<body>
    <div class="error-container">
        <h1>404 - Сторінка не знайдена</h1>
        <p>Вибачте, запитувана сторінка не існує.</p>
        <a href="{% url 'home' %}">Повернутися на головну</a>
    </div>
</body>
</html>
```

---

## Environment Variables

### 🔐 **Чому не треба зберігати секрети в коді:**

**ПОГАНО - секрети в settings.py:**
```python
# НЕ РОБІТЬ ТАК!
SECRET_KEY = 'django-insecure-hardcoded-key-123'
EMAIL_HOST_PASSWORD = 'myemailpassword123'
PAYSTACK_SECRET_KEY = 'sk_test_abc123def456'
AWS_SECRET_ACCESS_KEY = 'wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY'

DATABASES = {
    'default': {
        'ENGINE': 'django.db.backends.postgresql',
        'NAME': 'myproject',
        'USER': 'postgres',
        'PASSWORD': 'mypassword123',  # Секрет в коді!
        'HOST': 'localhost',
        'PORT': '5432',
    }
}
```

### ✅ **Правильне використання python-decouple:**

**Установка:**
```bash
pip install python-decouple
```

**Налаштування:**
```python
# settings.py
from decouple import config, Csv
from django.core.exceptions import ImproperlyConfigured

# Basic settings
DEBUG = config('DEBUG', default=False, cast=bool)
SECRET_KEY = config('SECRET_KEY')

if not SECRET_KEY:
    raise ImproperlyConfigured('SECRET_KEY environment variable is required')

# Database
DATABASES = {
    'default': {
        'ENGINE': 'django.db.backends.postgresql',
        'NAME': config('DB_NAME'),
        'USER': config('DB_USER'),
        'PASSWORD': config('DB_PASSWORD'),
        'HOST': config('DB_HOST', default='localhost'),
        'PORT': config('DB_PORT', default='5432', cast=int),
    }
}

# Email settings
EMAIL_BACKEND = 'django.core.mail.backends.smtp.EmailBackend'
EMAIL_HOST = config('EMAIL_HOST', default='smtp.gmail.com')
EMAIL_PORT = config('EMAIL_PORT', default=587, cast=int)
EMAIL_USE_TLS = config('EMAIL_USE_TLS', default=True, cast=bool)
EMAIL_HOST_USER = config('EMAIL_HOST_USER')
EMAIL_HOST_PASSWORD = config('EMAIL_HOST_PASSWORD')

# API Keys
PAYSTACK_PUBLIC_KEY = config('PAYSTACK_PUBLIC_KEY')
PAYSTACK_SECRET_KEY = config('PAYSTACK_SECRET_KEY')

# Allowed hosts
ALLOWED_HOSTS = config('ALLOWED_HOSTS', default='', cast=Csv())
```

**Важливо - .gitignore:**
```bash
# .gitignore
.env
.env.local
.env.production
.env.staging
*.env
```

---

## Brute Force атаки

### 🛡️ **Захист за допомогою django-axes:**

**Установка та налаштування:**
```bash
pip install django-axes
```

```python
# settings.py
INSTALLED_APPS = [
    # ...
    'axes',
    # ...
]

MIDDLEWARE = [
    # ...
    'axes.middleware.AxesMiddleware',
    # ...
]

# Налаштування Axes
AXES_FAILURE_LIMIT = 5  # Максимум 5 невдалих спроб
AXES_COOLOFF_TIME = 1  # Блокування на 1 годину
AXES_LOCK_OUT_BY_COMBINATION_USER_AND_IP = True
AXES_ENABLE_ADMIN = True  # Захистити admin панель

# Опціонально: використовувати cache для швидкості
AXES_CACHE = 'axes_cache'
CACHES = {
    'default': {
        'BACKEND': 'django.core.cache.backends.locmem.LocMemCache',
    },
    'axes_cache': {
        'BACKEND': 'django.core.cache.backends.redis.RedisCache',
        'LOCATION': 'redis://127.0.0.1:6379/1',
    }
}
```

### 🤖 **Додавання CAPTCHA:**

**django-simple-captcha:**
```bash
pip install django-simple-captcha
```

```python
# forms.py
from django import forms
from captcha.fields import CaptchaField

class LoginForm(forms.Form):
    username = forms.CharField(max_length=150)
    password = forms.CharField(widget=forms.PasswordInput)
    captcha = CaptchaField()

# views.py
def login_view(request):
    if request.method == 'POST':
        form = LoginForm(request.POST)
        if form.is_valid():
            # Перевірити captcha перед аутентифікацією
            username = form.cleaned_data['username']
            password = form.cleaned_data['password']
            
            user = authenticate(request, username=username, password=password)
            if user:
                login(request, user)
                return redirect('dashboard')
    else:
        form = LoginForm()
    
    return render(request, 'login.html', {'form': form})
```

### 🔗 **Зміна admin URL:**

**ПОГАНО:**
```python
# urls.py - НЕ РОБІТЬ ТАК
urlpatterns = [
    path('admin/', admin.site.urls),  # Легко здогадатися
    path('backend/', admin.site.urls),  # Теж погано
]
```

**ДОБРЕ:**
```python
# urls.py
import secrets
from django.conf import settings

# Генерувати випадковий admin URL
ADMIN_URL = getattr(settings, 'ADMIN_URL', f'admin-{secrets.token_urlsafe(16)}/')

urlpatterns = [
    path(ADMIN_URL, admin.site.urls),
    # path('secure-mgmt-portal-xyz789/', admin.site.urls),
]

# settings.py
ADMIN_URL = config('ADMIN_URL', default='admin-a1b2c3d4e5f6/')
```

### 🍯 **Honeypot для admin:**

**django-admin-honeypot:**
```bash
pip install django-admin-honeypot
```

```python
# settings.py
INSTALLED_APPS = [
    # ...
    'admin_honeypot',
    # ...
]

# urls.py
urlpatterns = [
    # Справжній admin на прихованому URL
    path('real-admin-xyz789/', admin.site.urls),
    
    # Fake admin (honeypot) на стандартному URL
    path('admin/', include('admin_honeypot.urls', namespace='admin_honeypot')),
]
```

**Логування спроб:**
```python
# models.py
from admin_honeypot.models import LoginAttempt

# Переглянути спроби входу
attempts = LoginAttempt.objects.all()
for attempt in attempts:
    print(f"IP: {attempt.ip_address}, Username: {attempt.username}, Time: {attempt.timestamp}")
```

---

## SSL/TLS налаштування

### 🔒 **Налаштування HTTPS в Django:**

```python
# settings.py для production
# Примушення HTTPS
SECURE_PROXY_SSL_HEADER = ('HTTP_X_FORWARDED_PROTO', 'https')
SECURE_SSL_REDIRECT = True  # Перенаправлення HTTP на HTTPS
SECURE_HSTS_SECONDS = 31536000  # 1 рік
SECURE_HSTS_INCLUDE_SUBDOMAINS = True
SECURE_HSTS_PRELOAD = True

# Secure cookies
SECURE_CONTENT_TYPE_NOSNIFF = True
SECURE_BROWSER_XSS_FILTER = True
SECURE_REFERRER_POLICY = 'strict-origin-when-cross-origin'

# Session security
SESSION_COOKIE_SECURE = True
CSRF_COOKIE_SECURE = True
```

### 🌐 **Nginx конфігурація:**

```nginx
# /etc/nginx/sites-available/myproject
server {
    listen 80;
    server_name yourdomain.com www.yourdomain.com;
    return 301 https://$server_name$request_uri;  # Редирект на HTTPS
}

server {
    listen 443 ssl http2;
    server_name yourdomain.com www.yourdomain.com;

    # SSL сертифікати (Let's Encrypt)
    ssl_certificate /etc/letsencrypt/live/yourdomain.com/fullchain.pem;
    ssl_certificate_key /etc/letsencrypt/live/yourdomain.com/privkey.pem;

    # SSL налаштування
    ssl_protocols TLSv1.2 TLSv1.3;
    ssl_ciphers ECDHE-RSA-AES128-GCM-SHA256:ECDHE-RSA-AES256-GCM-SHA384;
    ssl_prefer_server_ciphers off;

    # Security headers
    add_header Strict-Transport-Security "max-age=31536000; includeSubDomains; preload" always;
    add_header X-Frame-Options "DENY" always;
    add_header X-Content-Type-Options "nosniff" always;
    add_header X-XSS-Protection "1; mode=block" always;
    add_header Referrer-Policy "strict-origin-when-cross-origin" always;

    location / {
        proxy_pass http://127.0.0.1:8000;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
    }

    location /static/ {
        alias /path/to/your/static/files/;
        expires 1y;
        add_header Cache-Control "public, immutable";
    }

    location /media/ {
        alias /path/to/your/media/files/;
        expires 1y;
        add_header Cache-Control "public";
    }
}
```

---

## Django Security Settings

### 🛡️ **Комплексні налаштування безпеки:**

```python
# settings.py - додати в кінець файлу
if not DEBUG:
    # Security Middleware
    SECURE_PROXY_SSL_HEADER = ('HTTP_X_FORWARDED_PROTO', 'https')
    SECURE_SSL_REDIRECT = True
    
    # HSTS налаштування
    SECURE_HSTS_SECONDS = 31536000  # 1 рік
    SECURE_HSTS_INCLUDE_SUBDOMAINS = True
    SECURE_HSTS_PRELOAD = True
    
    # Content Security
    SECURE_CONTENT_TYPE_NOSNIFF = True
    SECURE_BROWSER_XSS_FILTER = True
    X_FRAME_OPTIONS = 'DENY'
    SECURE_REFERRER_POLICY = 'strict-origin-when-cross-origin'
    
    # Cookie Security
    SESSION_COOKIE_SECURE = True
    SESSION_COOKIE_HTTPONLY = True
    SESSION_COOKIE_SAMESITE = 'Strict'
    CSRF_COOKIE_SECURE = True
    CSRF_COOKIE_HTTPONLY = True
    CSRF_COOKIE_SAMESITE = 'Strict'
    
    # Додаткові заголовки безпеки
    SECURE_CROSS_ORIGIN_OPENER_POLICY = 'same-origin'
    
    # Content Security Policy (потребує django-csp)
    CSP_DEFAULT_SRC = ("'self'",)
    CSP_SCRIPT_SRC = ("'self'",)
    CSP_STYLE_SRC = ("'self'", "'unsafe-inline'")
    CSP_IMG_SRC = ("'self'", "data:", "https:")
    CSP_FONT_SRC = ("'self'", "https://fonts.gstatic.com")
    CSP_CONNECT_SRC = ("'self'",)
    CSP_FRAME_ANCESTORS = ("'none'",)
```

### ⚡ **Middleware порядок для безпеки:**

```python
MIDDLEWARE = [
    'django.middleware.security.SecurityMiddleware',  # Перший!
    'whitenoise.middleware.WhiteNoiseMiddleware',  # Для статичних файлів
    'corsheaders.middleware.CorsMiddleware',  # CORS
    'csp.middleware.CSPMiddleware',  # CSP
    'django.contrib.sessions.middleware.SessionMiddleware',
    'django.middleware.common.CommonMiddleware',
    'django.middleware.csrf.CsrfViewMiddleware',  # CSRF
    'django.contrib.auth.middleware.AuthenticationMiddleware',
    'axes.middleware.AxesMiddleware',  # Brute force protection
    'django.contrib.messages.middleware.MessageMiddleware',
    'django.middleware.clickjacking.XFrameOptionsMiddleware',
    # Ваші custom middleware в кінці
]
```

---

## Додаткові заходи безпеки

### 💰 **Fintech специфічні заходи:**

#### **Database Row Locking:**
```python
from django.db import transaction
from django.db.models import F

class PaymentService:
    @transaction.atomic
    def transfer_money(self, from_account, to_account, amount):
        # Заблокувати рядки для оновлення
        sender = Account.objects.select_for_update().get(id=from_account.id)
        receiver = Account.objects.select_for_update().get(id=to_account.id)
        
        # Перевірити баланс
        if sender.balance < amount:
            raise InsufficientFundsError("Недостатньо коштів")
        
        # Виконати переказ атомарно
        sender.balance = F('balance') - amount
        receiver.balance = F('balance') + amount
        
        sender.save(update_fields=['balance'])
        receiver.save(update_fields=['balance'])
        
        # Створити запис транзакції
        Transaction.objects.create(
            from_account=sender,
            to_account=receiver,
            amount=amount,
            status='completed'
        )
```

#### **Input Validation для фінансових операцій:**
```python
from decimal import Decimal, InvalidOperation
from django import forms

class TransferForm(forms.Form):
    amount = forms.DecimalField(
        max_digits=10,
        decimal_places=2,
        min_value=Decimal('0.01'),  # Мінімум 1 копійка
        max_value=Decimal('1000000.00')  # Максимум 1 млн
    )
    to_account = forms.CharField(max_length=20)
    description = forms.CharField(max_length=200, required=False)
    
    def clean_amount(self):
        amount = self.cleaned_data['amount']
        
        # Перевірка на негативне значення (додаткова безпека)
        if amount <= 0:
            raise forms.ValidationError("Сума повинна бути більше 0")
        
        # Перевірка на максимальну суму
        if amount > Decimal('50000.00'):  # Ліміт 50,000
            raise forms.ValidationError("Перевищено ліміт переказу")
        
        return amount
    
    def clean_to_account(self):
        account_number = self.cleaned_data['to_account']
        
        # Валідація номера рахунку
        if not account_number.isdigit():
            raise forms.ValidationError("Номер рахунку може містити тільки цифри")
        
        if len(account_number) != 10:
            raise forms.ValidationError("Номер рахунку повинен містити 10 цифр")
        
        # Перевірка існування рахунку
        if not Account.objects.filter(account_number=account_number).exists():
            raise forms.ValidationError("Рахунок не знайдено")
        
        return account_number
```

#### **Rate Limiting для API:**
```python
from django.core.cache import cache
from django.http import JsonResponse
from functools import wraps
import time

def rate_limit(max_requests=5, time_window=60):
    """
    Декоратор для обмеження кількості запитів
    max_requests: максимум запитів
    time_window: часове вікно в секундах
    """
    def decorator(view_func):
        @wraps(view_func)
        def wrapper(request, *args, **kwargs):
            # Ключ для cache на основі IP та view
            cache_key = f"rate_limit:{request.META.get('REMOTE_ADDR')}:{view_func.__name__}"
            
            # Отримати поточну кількість запитів
            current_requests = cache.get(cache_key, 0)
            
            if current_requests >= max_requests:
                return JsonResponse({
                    'error': 'Rate limit exceeded',
                    'detail': f'Maximum {max_requests} requests per {time_window} seconds'
                }, status=429)
            
            # Збільшити лічильник
            cache.set(cache_key, current_requests + 1, time_window)
            
            return view_func(request, *args, **kwargs)
        return wrapper
    return decorator

# Використання
@rate_limit(max_requests=3, time_window=300)  # 3 запити за 5 хвилин
def transfer_money_api(request):
    if request.method == 'POST':
        form = TransferForm(request.POST)
        if form.is_valid():
            # Логіка переказу
            pass
    return JsonResponse({'status': 'success'})
```

### 🔍 **Audit Logging:**
```python
import logging
from django.contrib.auth.signals import user_logged_in, user_logged_out, user_login_failed
from django.dispatch import receiver

# Налаштування security logger
security_logger = logging.getLogger('security')

class SecurityAuditMiddleware:
    def __init__(self, get_response):
        self.get_response = get_response

    def __call__(self, request):
        # Логувати підозрілі запити
        if self.is_suspicious_request(request):
            security_logger.warning(
                f"Suspicious request from {request.META.get('REMOTE_ADDR')}: "
                f"{request.method} {request.path}"
            )
        
        response = self.get_response(request)
        return response
    
    def is_suspicious_request(self, request):
        suspicious_patterns = [
            '/admin/',
            '/wp-admin/',
            '/.env',
            '/api/admin',
            'eval(',
            '<script',
            'union select',
            'drop table'
        ]
        
        path = request.path.lower()
        query = request.META.get('QUERY_STRING', '').lower()
        
        return any(pattern in path or pattern in query for pattern in suspicious_patterns)

# Signal handlers для аутентифікації
@receiver(user_logged_in)
def log_user_login(sender, request, user, **kwargs):
    security_logger.info(
        f"User login: {user.username} from {request.META.get('REMOTE_ADDR')}"
    )

@receiver(user_logged_out)
def log_user_logout(sender, request, user, **kwargs):
    security_logger.info(
        f"User logout: {user.username} from {request.META.get('REMOTE_ADDR')}"
    )

@receiver(user_login_failed)
def log_login_failure(sender, credentials, request, **kwargs):
    security_logger.warning(
        f"Failed login attempt: {credentials.get('username')} "
        f"from {request.META.get('REMOTE_ADDR')}"
    )
```

### 🌐 **DDoS Protection з Cloudflare:**

**Налаштування Cloudflare в Django:**
```python
# settings.py
# Налаштування для роботи з Cloudflare
SECURE_PROXY_SSL_HEADER = ('HTTP_CF_VISITOR', '{"scheme":"https"}')

# Middleware для отримання справжніх IP адрес через Cloudflare
class CloudflareMiddleware:
    def __init__(self, get_response):
        self.get_response = get_response
    
    def __call__(self, request):
        # Cloudflare передає справжній IP в заголовку CF-Connecting-IP
        cf_connecting_ip = request.META.get('HTTP_CF_CONNECTING_IP')
        if cf_connecting_ip:
            request.META['REMOTE_ADDR'] = cf_connecting_ip
        
        return self.get_response(request)

# Додати до MIDDLEWARE
MIDDLEWARE = [
    'myapp.middleware.CloudflareMiddleware',
    # ... інші middleware
]
```

---

## Security Checklist

### ✅ **Deployment Security Checklist:**

```python
# checklist.py - Скрипт для автоматичної перевірки
import os
import sys
from django.conf import settings

class SecurityChecker:
    def __init__(self):
        self.errors = []
        self.warnings = []
        self.passed = []
    
    def check_debug_setting(self):
        """Перевірити, що DEBUG = False в продакшені"""
        if getattr(settings, 'DEBUG', True):
            self.errors.append("❌ DEBUG = True (CRITICAL: Must be False in production)")
        else:
            self.passed.append("✅ DEBUG = False")
    
    def check_secret_key(self):
        """Перевірити SECRET_KEY"""
        secret_key = getattr(settings, 'SECRET_KEY', '')
        
        if not secret_key:
            self.errors.append("❌ SECRET_KEY is empty")
        elif 'django-insecure' in secret_key:
            self.errors.append("❌ Using default insecure SECRET_KEY")
        elif len(secret_key) < 50:
            self.warnings.append("⚠️ SECRET_KEY is too short (should be 50+ chars)")
        else:
            self.passed.append("✅ SECRET_KEY is properly configured")
    
    def check_allowed_hosts(self):
        """Перевірити ALLOWED_HOSTS"""
        allowed_hosts = getattr(settings, 'ALLOWED_HOSTS', [])
        
        if not allowed_hosts or '*' in allowed_hosts:
            self.errors.append("❌ ALLOWED_HOSTS is not properly configured")
        else:
            self.passed.append("✅ ALLOWED_HOSTS is configured")
    
    def check_https_settings(self):
        """Перевірити HTTPS налаштування"""
        https_checks = [
            ('SECURE_SSL_REDIRECT', True),
            ('SECURE_HSTS_SECONDS', lambda x: x > 0),
            ('SESSION_COOKIE_SECURE', True),
            ('CSRF_COOKIE_SECURE', True),
        ]
        
        for setting_name, expected in https_checks:
            value = getattr(settings, setting_name, None)
            if callable(expected):
                if not expected(value):
                    self.warnings.append(f"⚠️ {setting_name} should be properly configured")
                else:
                    self.passed.append(f"✅ {setting_name} is configured")
            elif value != expected:
                self.warnings.append(f"⚠️ {setting_name} should be {expected}")
            else:
                self.passed.append(f"✅ {setting_name} = {expected}")
    
    def check_csrf_protection(self):
        """Перевірити CSRF захист"""
        middleware = getattr(settings, 'MIDDLEWARE', [])
        
        if 'django.middleware.csrf.CsrfViewMiddleware' not in middleware:
            self.errors.append("❌ CSRF middleware is not enabled")
        else:
            self.passed.append("✅ CSRF protection is enabled")
    
    def check_security_middleware(self):
        """Перевірити security middleware"""
        middleware = getattr(settings, 'MIDDLEWARE', [])
        
        required_middleware = [
            'django.middleware.security.SecurityMiddleware',
            'django.middleware.clickjacking.XFrameOptionsMiddleware',
        ]
        
        for mw in required_middleware:
            if mw not in middleware:
                self.warnings.append(f"⚠️ {mw} should be in MIDDLEWARE")
            else:
                self.passed.append(f"✅ {mw} is enabled")
    
    def check_database_security(self):
        """Перевірити налаштування бази даних"""
        databases = getattr(settings, 'DATABASES', {})
        default_db = databases.get('default', {})
        
        # Перевірити, що не використовується SQLite в продакшені
        if default_db.get('ENGINE') == 'django.db.backends.sqlite3':
            self.warnings.append("⚠️ Using SQLite in production (consider PostgreSQL)")
        
        # Перевірити, що пароль не за замовчуванням
        password = default_db.get('PASSWORD', '')
        if not password or password in ['password', '123456', 'admin']:
            self.errors.append("❌ Database password is weak or missing")
        else:
            self.passed.append("✅ Database password is configured")
    
    def run_all_checks(self):
        """Запустити всі перевірки"""
        self.check_debug_setting()
        self.check_secret_key()
        self.check_allowed_hosts()
        self.check_https_settings()
        self.check_csrf_protection()
        self.check_security_middleware()
        self.check_database_security()
        
        return self.generate_report()
    
    def generate_report(self):
        """Згенерувати звіт"""
        print("\n" + "="*60)
        print("🔒 DJANGO SECURITY AUDIT REPORT")
        print("="*60)
        
        if self.errors:
            print(f"\n🚨 CRITICAL ISSUES ({len(self.errors)}):")
            for error in self.errors:
                print(f"  {error}")
        
        if self.warnings:
            print(f"\n⚠️ WARNINGS ({len(self.warnings)}):")
            for warning in self.warnings:
                print(f"  {warning}")
        
        if self.passed:
            print(f"\n✅ PASSED CHECKS ({len(self.passed)}):")
            for check in self.passed:
                print(f"  {check}")
        
        # Рекомендації
        print(f"\n📋 SECURITY SCORE: {len(self.passed)}/{len(self.passed) + len(self.warnings) + len(self.errors)}")
        
        if self.errors:
            print("\n🚨 ACTION REQUIRED: Fix critical issues before deployment!")
            return False
        elif self.warnings:
            print("\n⚠️ REVIEW RECOMMENDED: Address warnings for better security")
            return True
        else:
            print("\n🎉 EXCELLENT: All security checks passed!")
            return True

# Використання
if __name__ == "__main__":
    import django
    django.setup()
    
    checker = SecurityChecker()
    success = checker.run_all_checks()
    
    sys.exit(0 if success else 1)
```

### 📋 **Manual Deployment Checklist:**

```markdown
# 🔒 Django Production Deployment Security Checklist

## ✅ Basic Security
- [ ] DEBUG = False
- [ ] SECRET_KEY from environment variable
- [ ] ALLOWED_HOSTS properly configured
- [ ] .env file in .gitignore
- [ ] No hardcoded secrets in code

## 🔐 Authentication & Authorization
- [ ] Strong password validation enabled
- [ ] User roles and permissions configured
- [ ] Admin URL changed from default
- [ ] Two-factor authentication (if needed)
- [ ] Session timeout configured

## 🛡️ Web Security
- [ ] CSRF protection enabled
- [ ] XSS protection configured
- [ ] HTTPS enforced (SSL redirect)
- [ ] Security headers configured
- [ ] HSTS enabled
- [ ] Content Security Policy (if needed)

## 🌐 Network Security
- [ ] SSL certificate installed and valid
- [ ] Cloudflare or CDN configured
- [ ] Firewall rules configured
- [ ] Database not accessible from internet
- [ ] Admin panel IP restricted (if needed)

## 📊 Monitoring & Logging
- [ ] Security logging enabled
- [ ] Error logging configured
- [ ] Log rotation configured
- [ ] Security alerts configured
- [ ] Backup strategy implemented

## 🔧 Additional Security
- [ ] django-axes for brute force protection
- [ ] Rate limiting implemented
- [ ] Input validation on all forms
- [ ] File upload restrictions
- [ ] Database connection encryption

## 🚀 Performance & Availability
- [ ] Static files served efficiently
- [ ] Database optimized
- [ ] Caching configured
- [ ] Load balancing (if needed)
- [ ] Health checks configured

## 📱 API Security (if applicable)
- [ ] API authentication implemented
- [ ] API rate limiting
- [ ] CORS properly configured
- [ ] API versioning strategy
- [ ] API documentation security reviewed
```

---

## Заключення

### 🎯 **Ключові принципи Django Security:**

1. **Security by Default** - Django має чудові інструменти, але їх треба активувати
2. **Defense in Depth** - використовуйте кілька рівнів захисту
3. **Principle of Least Privilege** - надавайте мінімальні необхідні права
4. **Regular Security Audits** - регулярно перевіряйте налаштування безпеки

### 📚 **Рекомендовані пакети:**
```bash
# Основні security пакети
pip install python-decouple
pip install django-axes
pip install django-csp
pip install django-simple-captcha
pip install django-admin-honeypot

# Для API
pip install djangorestframework
pip install django-cors-headers
pip install django-oauth-toolkit

# Для моніторингу
pip install django-extensions
pip install django-debug-toolbar  # Тільки для розробки!
```

### 🔄 **Security Maintenance:**
- **Регулярно оновлюйте Django** та всі залежності
- **Моніторьте CVE** для Django та використовуваних пакетів
- **Проводьте security audits** перед кожним релізом
- **Навчайте команду** кращим практикам безпеки

### 💡 **Пам'ятайте:**
> "Безпека - це не одноразова задача, а постійний процес. Кожен новий feature може створити нові вразливості, тому безпека має бути частиною вашої культури розробки."

**Найважливіше правило:** Ніколи не жертвуйте безпекою заради швидкості розробки. Виправлення security breach коштує набагато дорожче, ніж його запобігання.



