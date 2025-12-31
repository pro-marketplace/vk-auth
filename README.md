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
2. Добавь переменные `VK_CLIENT_ID`, `VK_CLIENT_SECRET`, `VK_REDIRECT_URI`
3. **Создай страницу callback** — на неё VK перенаправит после авторизации

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

| Переменная | Описание |
|------------|----------|
| `DATABASE_URL` | PostgreSQL connection string |
| `MAIN_DB_SCHEMA` | Схема БД |
| `JWT_SECRET` | `openssl rand -hex 32` |
| `VK_CLIENT_ID` | ID приложения VK |
| `VK_CLIENT_SECRET` | Защищённый ключ |
| `VK_REDIRECT_URI` | URL callback страницы |

### 3. Создание приложения VK

1. Перейди в [VK для разработчиков](https://vk.com/apps?act=manage)
2. **Создать приложение** → тип "Веб-сайт"
3. В настройках укажи:
   - **Адрес сайта**: URL твоего сайта
   - **Базовый домен**: домен сайта
   - **Redirect URI**: `https://your-site.com/auth/vk/callback`
4. Скопируй **ID приложения** и **Защищённый ключ**

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
