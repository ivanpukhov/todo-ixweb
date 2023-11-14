Ваш API для управления целями (Goal Management API) предоставляет ряд эндпоинтов для различных операций. Далее приведена подробная документация по каждому эндпоинту.

### 1. Регистрация пользователя (Register User)
- **Метод:** `POST`
- **Путь:** `/register`
- **Описание:** Этот роут позволяет новым пользователям регистрироваться в системе.
- **Тело запроса:**
    - `username`: Имя пользователя.
    - `password`: Пароль.
- **Пример тела запроса:**
  ```json
  {
      "username": "newuser",
      "password": "password123"
  }
  ```
- **Ответ:** Возвращает JWT токен для аутентификации.

### 2. Вход пользователя (Login User)
- **Метод:** `POST`
- **Путь:** `/login`
- **Описание:** Этот роут позволяет существующим пользователям входить в систему.
- **Тело запроса:**
    - `username`: Имя пользователя.
    - `password`: Пароль.
- **Пример тела запроса:**
  ```json
  {
      "username": "existinguser",
      "password": "password123"
  }
  ```
- **Ответ:** Возвращает JWT токен для аутентификации.

### 3. Создание цели (Create Goal)
- **Метод:** `POST`
- **Путь:** `/goals`
- **Описание:** Создаёт новую цель для пользователя. Поддерживает создание глобальных, месячных, недельных и дневных целей.
- **Тело запроса:**
    - `name`: Название цели.
    - `description`: Описание цели.
    - `goalType`: Тип цели (`global`, `monthly`, `weekly`, `daily`).
    - `parentId`: ID родительской цели (если применимо).
- **Пример тела запроса:**
  ```json
  {
      "name": "Выучить React",
      "description": "Изучить основы React за месяц",
      "goalType": "monthly",
      "parentId": 1
  }
  ```
- **Ответ:** Возвращает ID созданной цели.

### 4. Получение всех целей (Get All Goals)
- **Метод:** `GET`
- **Путь:** `/goals`
- **Описание:** Получение списка всех целей для текущего пользователя.
- **Ответ:** Список всех целей пользователя.

### 5. Получение дерева целей (Get Goal Tree)
- **Метод:** `GET`
- **Путь:** `/goals/:goalId`
- **Описание:** Получение дерева целей, включая подцели, для конкретной цели.
- **Параметры пути:**
    - `goalId`: ID цели.
- **Ответ:** Возвращает дерево целей, начиная с указанной цели.

### 6. Отметка цели как выполненной (Mark Goal as Completed)
- **Метод:** `PUT`
- **Путь:** `/goals/:goalId/complete`
- **Описание:** Помечает цель как выполненную или невыполненную.
- **Параметры пути:**
    - `goalId`: ID цели.
- **Тело запроса:**
    - `isCompleted`: Статус выполнения (true или false).
- **Пример тела запроса:**
  ```json
  {
      "isCompleted": true
  }
  ```
- **Ответ:** Подтверждение обновления статуса цели.

### 7. Добавление комментария к цели (Add Comment to Goal)
- **Метод:** `POST`
- **Путь:** `/goals/:goalId/comments`
- **Описание:** Добавляет комментарий к определенной цели.
- **Параметры пути:**
    - `goalId`: ID цели.
- **Тело запроса:**
    - `comment`: Текст комментария.
- **Пример тела запроса:**


  ```json
  {
      "comment": "Хороший прогресс!"
  }
  ```
- **Ответ:** ID добавленного комментария.

### 8. Получение всех целей верхнего уровня (Get Top Level Goals)
- **Метод:** `GET`
- **Путь:** `/goals/top-level`
- **Описание:** Получение всех целей верхнего уровня (без родительских целей) для пользователя.
- **Ответ:** Список целей верхнего уровня.

### 9. Получение целей и комментариев пользователя (для администраторов) (Get User Goals and Comments - Admin)
- **Метод:** `GET`
- **Путь:** `/admin/users/:userId/goals`
- **Описание:** Получение всех целей и комментариев для определенного пользователя. Только для администраторов.
- **Параметры пути:**
    - `userId`: ID пользователя.
- **Ответ:** Список целей и комментариев пользователя.
