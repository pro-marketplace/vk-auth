# VK Auth Extension

SSO авторизация через ВКонтакте (VK ID). **1 функция** с роутингом по action.

---

## Для ассистента: перед интеграцией

1. **Проверь таблицу users** — должен быть столбец `vk_id`:
   ```sql
   ALTER TABLE users ADD COLUMN IF NOT EXISTS vk_id VARCHAR(50);
   ALTER TABLE users ADD COLUMN IF NOT EXISTS avatar_url TEXT;
   CREATE INDEX IF NOT EXISTS idx_users_vk_id ON users(vk_id);
   ```

2. **ОБЯЗАТЕЛЬНО добавь ВСЕ секреты через тулу добавления секретов:**
   ```
   VK_CLIENT_ID=<ID приложения>
   VK_CLIENT_SECRET=<Защищённый ключ>
   VK_REDIRECT_URI=<Доверенный Redirect URL>
   JWT_SECRET=<сгенерируй: openssl rand -hex 32>
   ```

   **Покажи пользователю в чате вызов тулы для каждого секрета!**

3. **Создай страницу callback** — на неё VK перенаправит после авторизации

---

## Создание приложения VK ID

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

**ВАЖНО:** У вас есть 2 среды — добавьте ОБЕ!

| Среда | Базовый домен | Redirect URL |
|-------|---------------|--------------|
| **Разработка** | `preview--{project}.poehali.dev` | `https://preview--{project}.poehali.dev/auth/vk/callback` |
| **Продакшн** | `your-domain.com` или `{project}--preview.poehali.dev` | `https://your-domain.com/auth/vk/callback` |

1. Добавь **базовый домен** продакшна
2. Нажми **"+ Добавить базовый домен"** → добавь домен разработки
3. Добавь **Redirect URL** продакшна
4. Нажми **"+ Добавить доверенный Redirect URL"** → добавь URL разработки
5. Нажми **"Создать приложение"**

### Шаг 4: Способы входа

Выбери нужные способы:
- **Кнопка One Tap** — авторизация в одно касание
- **Шторка авторизации** — всплывающее окно
- **Виджет 3 в 1** — VK + Одноклассники + Mail

Нажми **"К настройке"** или **"Настроить позже"**

### Шаг 5: Получение ключей

1. Перейди в настройки приложения
2. Скопируй **ID приложения** (например: `54414920`)
3. В разделе **"Ключи доступа"** скопируй **Защищённый ключ**
4. Проверь **Доверенный Redirect URL** — должен совпадать с `VK_REDIRECT_URI`

---

## Установка

### 1. База данных

```sql
CREATE TABLE users (
    id SERIAL PRIMARY KEY,
    vk_id VARCHAR(50) UNIQUE,
    email VARCHAR(255),
    name VARCHAR(255),
    avatar_url TEXT,
    email_verified BOOLEAN DEFAULT TRUE,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    last_login_at TIMESTAMP
);

CREATE TABLE refresh_tokens (
    id SERIAL PRIMARY KEY,
    user_id INTEGER REFERENCES users(id) ON DELETE CASCADE,
    token_hash VARCHAR(64) NOT NULL,
    expires_at TIMESTAMP NOT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX idx_users_vk_id ON users(vk_id);
CREATE INDEX idx_refresh_tokens_hash ON refresh_tokens(token_hash);
```

### 2. Переменные окружения

| Переменная | Описание | Где взять |
|------------|----------|-----------|
| `VK_CLIENT_ID` | ID приложения | Настройки приложения VK ID |
| `VK_CLIENT_SECRET` | Защищённый ключ | Раздел "Ключи доступа" |
| `VK_REDIRECT_URI` | URL callback страницы | Должен совпадать с "Доверенный Redirect URL" |
| `JWT_SECRET` | Секрет для токенов (мин. 32 символа) | `openssl rand -hex 32` |
| `ALLOWED_ORIGINS` | (опционально) Разрешённые домены через запятую | `https://example.com,https://app.example.com` |

---

## API

```
GET  ?action=auth-url  — получить URL для авторизации VK
POST ?action=callback  — обмен code на токены (body: { code })
POST ?action=refresh   — обновление токена (body: { refresh_token })
POST ?action=logout    — выход (body: { refresh_token })
```

---

## Frontend

| Файл | Описание |
|------|----------|
| `useVkAuth.ts` | Хук авторизации |
| `VkLoginButton.tsx` | Кнопка "Войти через VK" |
| `UserProfile.tsx` | Профиль пользователя |

```tsx
const AUTH_URL = "https://functions.poehali.dev/xxx";

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

Создай страницу `/auth/vk/callback` которая:
1. Вызывает `auth.handleCallback()` — автоматически извлечёт code, device_id, state из URL
2. Редиректит на главную при успехе

```tsx
// pages/auth/vk/callback.tsx или app/auth/vk/callback/page.tsx
"use client";

import { useEffect } from "react";
import { useRouter } from "next/navigation";
import { useVkAuth } from "@/hooks/useVkAuth";

export default function VkCallbackPage() {
  const router = useRouter();
  const auth = useVkAuth({
    apiUrls: {
      authUrl: `${process.env.NEXT_PUBLIC_VK_AUTH_URL}?action=auth-url`,
      callback: `${process.env.NEXT_PUBLIC_VK_AUTH_URL}?action=callback`,
      refresh: `${process.env.NEXT_PUBLIC_VK_AUTH_URL}?action=refresh`,
      logout: `${process.env.NEXT_PUBLIC_VK_AUTH_URL}?action=logout`,
    },
  });

  useEffect(() => {
    // handleCallback() автоматически извлекает code, device_id, state из URL
    auth.handleCallback().then((success) => {
      if (success) {
        router.push("/");
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
2. Frontend → GET ?action=auth-url → получает auth_url + code_verifier
3. Frontend сохраняет code_verifier в sessionStorage
4. Редирект на VK для авторизации
5. VK → редирект на callback с ?code=...&device_id=...&state=...
6. Frontend извлекает code, device_id из URL
7. Frontend → POST ?action=callback { code, code_verifier, device_id }
8. Backend обменивает code на токены через VK API
9. Показываем UserProfile
```

> **PKCE** (Proof Key for Code Exchange) — защита от перехвата authorization code

---

## Безопасность

- JWT access tokens (15 мин)
- Refresh tokens хешируются (SHA256) перед сохранением в БД
- Автоочистка протухших токенов при каждом запросе
- CSRF protection через state параметр
- PKCE (code_verifier/code_challenge) защита OAuth flow
- Параметризованные SQL-запросы (защита от SQL injection)
- Валидация JWT_SECRET (минимум 32 символа)
- CORS ограничение через `ALLOWED_ORIGINS`
- Скрытие внутренних ошибок от клиента

---

## Тестирование

> ⚠️ **Вход через VK не работает в редакторе!**
>
> VK блокирует авторизацию внутри iframe. Для проверки авторизации открой сайт **в отдельной вкладке браузера**.
