# VK Auth Extension

SSO авторизация через ВКонтакте (VK ID). **1 функция** с роутингом по action.

> ⚠️ **Авторизация через VK не работает в редакторе!**
>
> VK блокирует работу в iframe. Для проверки авторизации откройте сайт **в отдельной вкладке браузера**.

---

# [AUTH] Общее для виджетов авторизации

## Логика привязки аккаунтов

Функция автоматически связывает аккаунты по email:

1. **Поиск по provider_id** (google_id/vk_id) → если найден, логиним
2. **Поиск по email** → если найден, привязываем провайдера к существующему аккаунту
3. **Новый пользователь** → создаём запись

Это позволяет пользователю войти через любой провайдер, если email совпадает.

## Требования к базе данных

Функция работает с полями таблицы `users`:

| Поле | Тип | Требования |
|------|-----|------------|
| `google_id` / `vk_id` | VARCHAR(50) | Может быть NULL |
| `email` | VARCHAR(255) | Может быть NULL |
| `name` | VARCHAR(255) | Может быть NULL |
| `avatar_url` | TEXT | Может быть NULL |
| `email_verified` | BOOLEAN | DEFAULT FALSE/TRUE |
| `created_at` | TIMESTAMP | DEFAULT CURRENT_TIMESTAMP |
| `updated_at` | TIMESTAMP | DEFAULT CURRENT_TIMESTAMP |
| `last_login_at` | TIMESTAMP | Может быть NULL |

**⚠️ Если столбец имеет `NOT NULL` без `DEFAULT` — функция упадёт при вставке!**

### Проверка структуры БД перед установкой

**ОБЯЗАТЕЛЬНО перед установкой расширения:**

1. Выполни `SELECT column_name, is_nullable, column_default FROM information_schema.columns WHERE table_name = 'users';`
2. Найди все столбцы с `is_nullable = 'NO'` и `column_default = NULL`
3. Такие столбцы вызовут ошибку при INSERT, если мы не передаём для них значение
4. **Типичные проблемы:**
   - `password_hash NOT NULL` — передай пустую строку `''`
   - `role NOT NULL` — передай дефолтное значение (например `'user'`)
   - Кастомные поля проекта — уточни у пользователя

**Если нашёл NOT NULL поля без DEFAULT — добавь их в INSERT с дефолтными значениями!**

## Добавление секретов

**ОБЯЗАТЕЛЬНО вызови тулу `put_secret` для КАЖДОГО секрета!**

```python
put_secret("PROVIDER_CLIENT_ID", "<от пользователя>")
put_secret("PROVIDER_CLIENT_SECRET", "<от пользователя>")
put_secret("PROVIDER_REDIRECT_URI", "https://{домен}/auth/{provider}/callback")
put_secret("JWT_SECRET", "<сгенерируй сам>")
```

- Вызывай `put_secret` для КАЖДОГО секрета отдельно
- **JWT_SECRET генерируй сам** (64 hex символа), не спрашивай у пользователя
- Покажи пользователю в чате каждый вызов тулы

## После установки

**ОБЯЗАТЕЛЬНО:** Последним шагом добавь кнопку входа на фронтенд, чтобы пользователь сразу видел результат!

Используй компоненты из `/frontend`:
- `VkLoginButton.tsx` — кнопка входа
- `useVkAuth.ts` — хук авторизации

**Скажи пользователю:**

> ✅ Авторизация настроена!
>
> **Важно:**
> - Проверяйте авторизацию **в отдельной вкладке**, не в редакторе
> - Если email уже использовался — аккаунт автоматически привяжется

## API (общий для всех провайдеров)

```
GET  ?action=auth-url  — получить URL для авторизации
POST ?action=callback  — обмен code на токены (body: { code, ... })
POST ?action=refresh   — обновление токена (body: { refresh_token })
POST ?action=logout    — выход (body: { refresh_token })
```

## Безопасность

- JWT access tokens (15 мин)
- Refresh tokens хешируются (SHA256) перед сохранением
- Автоочистка протухших токенов при каждом запросе
- CSRF protection через state параметр
- Параметризованные SQL-запросы
- Валидация JWT_SECRET (минимум 32 символа)
- CORS ограничение через `ALLOWED_ORIGINS`
- Скрытие внутренних ошибок от клиента

---

# [VK] Специфичное для VK Auth

## Чеклист интеграции

### Шаг 1: Подготовка базы данных

```sql
ALTER TABLE users ADD COLUMN IF NOT EXISTS vk_id VARCHAR(50);
ALTER TABLE users ADD COLUMN IF NOT EXISTS avatar_url TEXT;
CREATE INDEX IF NOT EXISTS idx_users_vk_id ON users(vk_id);
```

### Шаг 2: Сопровождение пользователя в VK ID

**Скажи пользователю:**

> Для авторизации через VK нужно создать приложение в VK ID. Я помогу пошагово:
>
> ⚠️ **Требуется подтверждение профиля через ГосУслуги + ИНН**
>
> 1. Перейдите на [id.vk.com/about/business/go](https://id.vk.com/about/business/go)
> 2. Нажмите **"Подтвердить профиль"** (требуется ГосУслуги + ИНН)
> 3. После подтверждения нажмите **"Добавить приложения"**
> 4. Введите **название приложения** (минимум 3 символа)
> 5. Выберите платформу **Web**
> 6. Загрузите иконку приложения
> 7. Добавьте **базовый домен**: `https://{ваш-домен}` (например: `coder.arnld.ai`)
> 8. Добавьте **Redirect URL**: `https://{ваш-домен}/auth/vk/callback`
> 9. Нажмите **"Создать приложение"**
> 10. В настройках приложения скопируйте **ID приложения**
> 11. В разделе **"Ключи доступа"** скопируйте **Защищённый ключ**
>
> Пришлите мне **ID приложения** и **Защищённый ключ** когда будут готовы!

### Шаг 3: Добавление секретов

Когда пользователь пришлёт ID приложения и Защищённый ключ:

```python
put_secret("VK_CLIENT_ID", "<ID приложения от пользователя>")
put_secret("VK_CLIENT_SECRET", "<Защищённый ключ от пользователя>")
put_secret("VK_REDIRECT_URI", "https://{домен-пользователя}/auth/vk/callback")
put_secret("JWT_SECRET", "<сгенерируй: 64 hex символа>")
```

### Шаг 4: Создание страниц

1. **Страница с кнопкой входа** — добавь `VkLoginButton`
2. **Страница callback** `/auth/vk/callback` — обработка редиректа
3. **Страница профиля** — показать данные пользователя после входа

---

## Создание приложения VK ID (детально)

> **Требуется подтверждение профиля через ГосУслуги + ИНН**

### Шаг 1: Регистрация в VK ID для бизнеса

1. Перейди на [id.vk.com/about/business/go](https://id.vk.com/about/business/go)
2. Нажми **"Подтвердить профиль"** (требуется ГосУслуги + ИНН)
3. После подтверждения нажми **"Добавить приложения"**

### Шаг 2: Регистрация приложения

1. Введи **название приложения** (минимум 3 символа)
2. Выбери платформу **Web**
3. Загрузи иконку приложения
4. Нажми **"Далее"**

### Шаг 3: Данные для регистрации

| Поле | Значение |
|------|----------|
| **Базовый домен** | `your-domain.com` (без https://) |
| **Redirect URL** | `https://your-domain.com/auth/vk/callback` |

Нажми **"Создать приложение"**

### Шаг 4: Получение ключей

1. Перейди в настройки приложения
2. Скопируй **ID приложения** (например: `54414920`)
3. В разделе **"Ключи доступа"** скопируй **Защищённый ключ**

---

## Frontend компоненты

| Файл | Описание |
|------|----------|
| `useVkAuth.ts` | Хук авторизации |
| `VkLoginButton.tsx` | Кнопка "Войти через VK" |
| `UserProfile.tsx` | Профиль пользователя |

### Пример использования

```tsx
const AUTH_URL = "https://functions.poehali.dev/xxx-vk-auth";

const auth = useVkAuth({
  apiUrls: {
    authUrl: `${AUTH_URL}?action=auth-url`,
    callback: `${AUTH_URL}?action=callback`,
    refresh: `${AUTH_URL}?action=refresh`,
    logout: `${AUTH_URL}?action=logout`,
  },
});

// Кнопка входа
<VkLoginButton onClick={auth.login} isLoading={auth.isLoading} />

// После авторизации
if (auth.isAuthenticated && auth.user) {
  return <UserProfile user={auth.user} onLogout={auth.logout} />;
}
```

### Страница callback

```tsx
// app/auth/vk/callback/page.tsx
"use client";

import { useEffect } from "react";
import { useRouter } from "next/navigation";
import { useVkAuth } from "@/hooks/useVkAuth";

const AUTH_URL = "https://functions.poehali.dev/xxx-vk-auth";

export default function VkCallbackPage() {
  const router = useRouter();
  const auth = useVkAuth({
    apiUrls: {
      authUrl: `${AUTH_URL}?action=auth-url`,
      callback: `${AUTH_URL}?action=callback`,
      refresh: `${AUTH_URL}?action=refresh`,
      logout: `${AUTH_URL}?action=logout`,
    },
  });

  useEffect(() => {
    // handleCallback() автоматически извлекает code, device_id, state из URL
    auth.handleCallback().then((success) => {
      if (success) {
        router.push("/profile");
      }
    });
  }, []);

  return (
    <div className="flex items-center justify-center min-h-screen">
      <p>Авторизация...</p>
    </div>
  );
}
```

---

## Поток авторизации (PKCE)

```
1. Пользователь нажимает "Войти через VK"
2. Frontend → GET ?action=auth-url → получает auth_url + code_verifier + state
3. Frontend сохраняет code_verifier и state в sessionStorage
4. Редирект на VK для авторизации
5. VK → редирект на callback с ?code=...&device_id=...&state=...
6. Frontend извлекает code, device_id из URL
7. Frontend → POST ?action=callback { code, code_verifier, device_id }
8. Backend обменивает code на токены через VK API
9. Backend проверяет vk_id → email → создаёт/привязывает пользователя
10. Редирект на страницу профиля
```

> **PKCE** (Proof Key for Code Exchange) — защита от перехвата authorization code
