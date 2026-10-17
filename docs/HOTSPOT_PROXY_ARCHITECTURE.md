# Архитектура раздачи VPN по Wi-Fi Hotspot (Без Root)

В этом документе описана архитектура и техническая реализация встроенной раздачи VPN-трафика через точку доступа Wi-Fi (Hotspot) на порт `1080` (SOCKS5 + HTTP Mixed Mode) без root-прав и без сторонних приложений.

---

## 1. Проблема: почему обычная точка доступа не раздает VPN на Android

В ОС Android сетевой стек разделяет трафик локального интерфейса устройства и трафик режима модема (tethering):
1. Пакеты приложений самого телефона маршрутизируются в виртуальный интерфейс `tun0` (таблица маршрутизации VPN).
2. Пакеты клиентов точки доступа (`wlan1` / `ap0`) в ядре Linux маршрутизируются напрямую в физический апплинк оператора (`rmnet_data0`), полностью минуя `tun0`.
3. Без root-прав на Android невозможно изменить правила `iptables` / `nftables` для перенаправления tethering-трафика в `tun0`.

Единственное надежное решение без root — запуск **встроенного локального прокси-сервера** на интерфейсе `0.0.0.0:1080`, к которому подключаются устройства из сети хотспота.

---

## 2. Ловушка AOSP `netd` и ошибка `-EPERM`

Чтобы трафик клиентов прокси уходил в туннель, исходящие сокеты прокси-сервера должны быть привязаны к виртуальной сети VPN через системный вызов `vpnNetwork.bindSocket(socket)`.

### Архитектурный тупик:
1. **Исходное состояние в CSQTT:**
   Для предотвращения маршрутной петли приложение исключалось из собственного VPN:
   ```kotlin
   builder.addDisallowedApplication(applicationContext.packageName)
   ```
2. **Ограничение AOSP `netd` (`fwmarkd`):**
   Если пакет исключен из VPN через `addDisallowedApplication`, демон Android `netd` при попытке выполнить `vpnNetwork.bindSocket(socket)` безусловно отклоняет операцию с ошибкой:
   ```text
   java.net.SocketException: Binding socket to network 119 failed: EPERM (Operation not permitted)
   ```
3. **Последствие:**
   Прокси-сервер не может направить трафик в `tun0`. Исходящие соединения прокси выходят в физическую сеть мобильного оператора, и раздача VPN не работает.

### Дилемма:
- **Если приложение исключено (`addDisallowedApplication`):** прокси получает `-EPERM` и не может направить трафик клиентов в `tun0`.
- **Если приложение включено в VPN:** прокси может привязаться к `tun0`, **НО** нативное ядро (`libclient.so`) при отправке QUIC/UDP на релеи VK попадает в свой собственный `tun0`, образуя бесконечную маршрутную петлю (туннель внутри туннеля), и соединение мгновенно погибает.

---

## 3. Архитектурное решение: `LD_PRELOAD` + UDS `SCM_RIGHTS`

Чтобы разрешить эту дилемму, реализована схема с избирательной защитой сокетов нативного ядра через нативный хук:

```
+-----------------------------------------------------------------------------------+
| Android App (UID: 10xxx)                                                          |
|                                                                                   |
|  [VpnService]                                                                     |
|    |                                                                              |
|    +-- Включен в состав VPN (нет addDisallowedApplication)                         |
|    |                                                                              |
|    +-- LocalVpnProxyServer (0.0.0.0:1080)                                         |
|    |     |                                                                        |
|    |     +--> vpnNetwork.bindSocket() ---> В виртуальную сеть tun0 (УСПЕШНО!)     |
|    |                                                                              |
|    +-- ProtectSocketServer (noBackupFilesDir/protect_sock)                        |
|          ^                                                                        |
|          | SCM_RIGHTS (передача файлового дескриптора)                            |
|          | + ACK (0x01)                                                           |
|          |                                                                        |
|  [libclient.so (Дочерний Rust-процесс ядра туннеля)]                              |
|    |                                                                              |
|    +-- LD_PRELOAD = libprotect_shim.so                                            |
|    |                                                                              |
|    +-- socket() / sendto() / connect()                                            |
|          |                                                                        |
|          +--> Перехватываются шимом protect_shim.c                                |
|          +--> Отправляются в ProtectSocketServer                                  |
|          +--> Вызывается VpnService.protect(fd)                                   |
|          +--> Сокет ядра получает метку обхода VPN в ядре Linux                   |
|          +--> Пакеты к VK TURN идут напрямую в LTE/Wi-Fi (НЕТ ПЕТЛИ!)             |
+-----------------------------------------------------------------------------------+
```

---

## 4. Составные компоненты решения

### 1. Нативный перехватчик: `app/src/main/cpp/protect_shim.c`
- Собирается через CMake как `libprotect_shim.so`.
- Экспортирует с дефолтной видимостью функции `socket`, `connect`, `sendto`, `close`.
- При создании сокета `AF_INET` / `AF_INET6`:
  1. Создает настоящий системный сокет через `real_socket`.
  2. Подключается к локальному Unix Domain Socket (`VPN_PROTECT_SOCK_PATH`).
  3. Передает файловый дескриптор в Android-процесс через `sendmsg` с управляющим сообщением `SCM_RIGHTS`.
  4. Синхронно ожидает 1 байт подтверждения (`0x01`).
  5. Отмечает дескриптор в атомарной битовой карте `protected_fd_bitmap` (lock-free, C11 atomics) для исключения повторной защиты.
- Имеет встроенный цикл ожидания (до 50 повторов с шагом 30 мс) на случай временной задержки запуска сервиса.
- Корректно сохраняет и восстанавливает `errno`.

### 2. Сервер защиты дескрипторов: `ProtectSocketServer.kt`
- Слушает UDS по пути `context.noBackupFilesDir/protect_sock` с правами доступа `0600` (`chmod 384`).
- Проверяет `localSocket.peerCredentials.uid == Process.myUid()`, исключая вызовы от посторонних приложений.
- При получении дескриптора вызывает системный `vpnService.protect(pfd.fd)`.
- Опционально привязывает сокет к физической сети при наличии активного подключения.
- Отправляет байт `0x01` клиенту шима.

### 3. Гарантия инжекции: `TunVpnService.kt`, `TunnelService.kt`, `TunnelManager.kt`
- В `TunVpnService.kt` удален `builder.addDisallowedApplication(packageName)`. Приложение входит в состав VPN.
- В `TunVpnService.onCreate()` и при обработке раннего интента `INIT_PROTECT` сервер `protectSocketServer` поднимается заранее, до порождения нативного процесса `libclient.so`.
- В `TunnelManager.kt` переменные `LD_PRELOAD` и `VPN_PROTECT_SOCK_PATH` безусловно прописываются в окружение `ProcessBuilder`, если файл библиотеки присутствует в `nativeLibraryDir`.

### 4. Встроенный сервер прокси: `LocalVpnProxyServer.kt`
- Слушает `0.0.0.0:1080` и автоматически распознает тип протокола (Single-Port Multiplexing):
  - **SOCKS5 (RFC 1928):**
    - `CMD_CONNECT` (0x01) — полнодуплексный TCP-релей с backpressure и сокетными буферами ядра.
    - `CMD_UDP_ASSOCIATE` (0x03) — полноценный релей UDP-дейтаграмм для резолвинга DNS и отправки UDP через туннель.
  - **HTTP CONNECT / HTTP Proxy:** туннелирование HTTPS и проксирование стандартных HTTP-запросов.
- Исходящие TCP- и UDP-сокеты привязываются к `vpnNetwork` через `network.bindSocket(socket)`, направляя весь трафик клиентов точки доступа строго в туннель `tun0`.

### 5. UI и отображение настроек: `SettingsTab.kt` и `HotspotProxyInfoDialog.kt`
- Переключатель в настройках: «Раздача VPN по Hotspot».
- Диалоговое окно с определением текущего IP-адреса точки доступа (например, `192.168.43.1`), портом `1080` и инструкцией для клиентов (Windows, macOS, Linux, Android, iOS).

---

## 5. Карта измененных файлов

| Файл | Назначение |
|---|---|
| `app/src/main/cpp/protect_shim.c` | PLT-перехватчик сетевых вызовов `socket`/`sendto` через `LD_PRELOAD` |
| `app/src/main/cpp/CMakeLists.txt` | Сборка `libprotect_shim.so` через CMake и NDK |
| `app/build.gradle.kts` | Подключение `externalNativeBuild { cmake { ... } }` |
| `app/src/main/AndroidManifest.xml` | `android:extractNativeLibs="true"` (распаковка `.so` в `nativeLibraryDir` с SELinux `apk_data_file`) |
| `app/src/main/java/com/csqtt/client/proxy/ProtectSocketServer.kt` | UDS-сервер приема дескрипторов (`SCM_RIGHTS`) и вызова `vpnService.protect()` |
| `app/src/main/java/com/csqtt/client/proxy/VpnNetworkManager.kt` | Мониторинг сети VPN и привязка сокетов (`bindSocketToVpn`, `bindDatagramSocketToVpn`) |
| `app/src/main/java/com/csqtt/client/proxy/LocalVpnProxyServer.kt` | Смешанный SOCKS5 / HTTP прокси-сервер с поддержкой TCP и `UDP ASSOCIATE` |
| `app/src/main/java/com/csqtt/client/proxy/BidirectionalTcpRelay.kt` | Асинхронный дуплексный TCP-релей с backpressure |
| `app/src/main/java/com/csqtt/client/proxy/HotspotIpDetector.kt` | Определение IP точки доступа телефона |
| `app/src/main/java/com/csqtt/client/TunVpnService.kt` | Управление жизненным циклом `protectSocketServer` и `proxyServer`, включение приложения в VPN |
| `app/src/main/java/com/csqtt/client/TunnelManager.kt` | Инжекция `LD_PRELOAD` и `VPN_PROTECT_SOCK_PATH` в `ProcessBuilder` |
| `app/src/main/java/com/csqtt/client/TunnelService.kt` | Предупреждающая инициализация (`INIT_PROTECT`) перед стартом нативного ядра |
| `app/src/main/java/com/csqtt/client/SettingsStore.kt` | Хранение состояния переключателя `hotspotProxyEnabled` |
| `app/src/main/java/com/csqtt/client/ui/SettingsTab.kt` | UI переключателя и вызова информационного диалога |
| `app/src/main/java/com/csqtt/client/ui/HotspotProxyInfoDialog.kt` | Диалог с инструкциями и параметрами прокси для подключения |

---

## 6. Как проверить работу

1. В приложении включить переключатель «Раздача VPN по Hotspot» в Настройках.
2. Включить туннель CSQTT.
3. Включить стандартную «Точку доступа Wi-Fi» на телефоне.
4. На подключаемом ноутбуке или другом смартфоне указать в настройках сети:
   - **Тип прокси:** SOCKS5 (или HTTP)
   - **IP:** адрес шлюза точки доступа (обычно `192.168.43.1`)
   - **Порт:** `1080`
5. В `adb logcat` видны подтверждения:
   ```text
   ProtectShim: Socket fd=... protected successfully via .../protect_sock
   LocalVpnProxyServer: LocalVpnProxyServer listening on 0.0.0.0:1080
   LocalVpnProxyServer: SOCKS5 UDP ASSOCIATE established on local UDP port ...
   ```
