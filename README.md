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

1. **Базовый домен**: `your-site.com` (без https://)
2. **Доверенный Redirect URL**: `https://your-site.com/auth/vk/callback`
3. Нажми **"Создать приложение"**

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
| `JWT_SECRET` | Секрет для токенов | `openssl rand -hex 32` |

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
1. Получает `code` из URL параметров
2. Вызывает `auth.handleCallback(code)`
3. Редиректит на главную

```tsx
// pages/auth/vk/callback.tsx
useEffect(() => {
  const code = new URLSearchParams(window.location.search).get("code");
  if (code) {
    auth.handleCallback(code).then((success) => {
      if (success) router.push("/");
    });
  }
}, []);
```

---

## Поток авторизации

```
1. Пользователь нажимает "Войти через VK"
2. Frontend → GET ?action=auth-url → получает URL
3. Редирект на VK для авторизации
4. VK → редирект на callback с ?code=...
5. Frontend → POST ?action=callback → обмен code на токены
6. Показываем UserProfile
```

---

## Безопасность

- JWT access tokens (15 мин)
- Refresh tokens (30 дней) в localStorage
- CSRF protection через state параметр
- Секреты только на сервере

---

## Тестирование

**Важно:** Тестируй в отдельной вкладке! VK блокирует iframe.
