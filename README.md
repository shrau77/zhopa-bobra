# 🦫 zhopa-bobra

SNI Hunter for TSPU Whitelists. Потому что никто не хочет лезть в жопу бобра.

## 🎯 Что делает

1. **Извлекает SNI** из VPN конфигов (VLESS, Trojan, VMess)
2. **Проверяет живучесть** (DNS → TCP → TLS → HTTP)
3. **Классифицирует** по категориям (banks, ecommerce, social, government...)
4. **Генерирует whitelist** для обхода ТСПУ

## 🚀 Запуск

```bash
# Собрать
go build -o zhopa-bobra

# Из файлов с конфигами
./zhopa-bobra -input verified_ru.txt,output/all_mixed.txt

# Из Certificate Transparency логов
./zhopa-bobra -ct yandex.ru,sberbank.ru,vk.com

# Всё вместе
./zhopa-bobra -input proxies.txt -ct yandex.ru -output target_sni.txt -min-count 2

# Verbose режим
./zhopa-bobra -input proxies.txt -v
```

## 📋 Флаги

| Флаг | Описание | По умолчанию |
|------|----------|--------------|
| `-input` | Файлы с конфигами (через запятую) | - |
| `-output` | Выходной файл whitelist | `target_sni.txt` |
| `-ct` | Домены для CT logs (через запятую) | - |
| `-min-count` | Мин. использований SNI | `2` |
| `-tls` | Проверять TLS handshake | `true` |
| `-http` | Проверять HTTP | `true` |
| `-v` | Verbose вывод | `false` |

## 📁 Результаты

```
results/
├── sni_full.json       # Полный JSON со всеми данными
├── target_sni.txt      # RU whitelist
├── whitelist_all.txt   # Все живые SNI
├── sni_banks.txt       # Банки
├── sni_ecommerce.txt   # E-commerce
├── sni_social.txt      # Соцсети
├── sni_government.txt  # Госучреждения
└── ...
```

## 🔬 Как работает проверка

1. **DNS** - резолвим домен
2. **TCP** - коннект на порт 443
3. **TLS** - handshake с SNI
4. **HTTP** - GET запрос на https://sni/

Если все этапы прошли - SNI считается живым.

## 📊 Категории SNI

| Категория | Примеры |
|-----------|---------|
| banks | sberbank.ru, tinkoff.ru, alfabank.ru |
| ecommerce | ozon.ru, wildberries.ru, yandex.ru |
| social | vk.com, ok.ru, mail.ru |
| government | gosuslugi.ru, mos.ru, nalog.ru |
| tech | hh.ru, habr.ru, 2gis.ru |
| mobile | mts.ru, megafon.ru, beeline.ru |
| cloud | yandexcloud.net, sbercloud.ru |

## 🎲 Источники SNI

1. **Конфиги** - парсим VLESS/Trojan/VMess ссылки
2. **CT Logs** - crt.sh API для поиска поддоменов
3. **Частота** - SNI используемый多次 = хороший кандидат

## ⚠️ Blacklist

Автоматически отсеиваем:
- Google, YouTube, Facebook, etc
- .ir, .cn, .pk домены
- Cloudflare, AWS, Azure
- VPN/Proxy-related домены

## 🔗 Интеграция с твоим пайплайном

```bash
# 1. После работы scout
./zhopa-bobra -input loshad-scoc/verified_ru.txt

# 2. После работы hpp
./zhopa-bobra -input hpp/output/all_mixed.txt,hpp/output/ultra_elite.txt

# 3. Обновить whitelist для node-filter
./zhopa-bobra -input proxies.txt -output ../node-filter/whitelists.txt
```

---

*🦫 Не лезь в жопу бобра*
