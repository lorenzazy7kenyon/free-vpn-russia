# Reality конфигурации

В этом каталоге размещаются проверенные бесплатные конфигурации VLESS + Reality.

## Содержимое

- `verified.txt` — share-ссылки конфигураций, прошедших валидацию формата и проверку доступности. Файл создаётся автоматически и появляется здесь только при наличии проверенных конфигураций.

## Формат конфигурации

Share-ссылка Reality выглядит так (значения в угловых скобках — заполнители):

```
vless://<uuid>@<host>:<port>?encryption=none&security=reality&sni=<domain>&fp=chrome&pbk=<publickey>&sid=<shortid>&type=tcp&flow=xtls-rprx-vision#<name>
```

Обязательные параметры Reality: `security=reality`, `pbk` (публичный ключ, 43 символа base64url), `sni`.

## Как использовать

Скопируйте share-ссылку и импортируйте её в совместимый VPN-клиент, поддерживающий Reality. Подробнее — в [docs/reality.md](../../docs/reality.md).

Подписка: [subscriptions/reality.txt](../../subscriptions/reality.txt).
