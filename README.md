# dokebicollector

Rust 기반 침해사고 초동 대응 아티팩트 수집기.  
Windows / Linux / macOS(Intel · Apple Silicon) 에서 단일 바이너리로 동작하며, 실행 결과를 SHA-256 해시와 함께 보존한다.

---

## 빌드

```bash
cargo build --release
# 결과물: target/release/dokebicollector  (Linux/macOS)
#         target/release/dokebicollector.exe  (Windows)
```

## 실행

```powershell
# Windows — 관리자 PowerShell에서 실행 권장
.\dokebicollector.exe --output C:\Cases --name case-001

# Linux / macOS — root(sudo) 실행 권장
sudo ./dokebicollector --output /cases --name case-001
```

| 옵션 | 기본값 | 설명 |
|---|---|---|
| `-o, --output` | `collection-output` | 결과 저장 최상위 디렉터리 |
| `-n, --name` | `default` | 케이스 이름 (하위 디렉터리명으로 사용) |

> **권한 경고**  
> 관리자(Windows) 또는 root(Linux/macOS) 권한 없이 실행하면 시작 시 경고를 출력하고,  
> 접근 불가 항목은 `collection_manifest.json` 의 `errors` 에 사유와 함께 기록된다.

---

## 출력 구조

```
<output>/<case-name>/<YYYYMMDDTHHMMSSZ>/
├── commands/               ← OS 명령 실행 결과 (.txt)
├── evtx/                   ← Windows 이벤트 로그 (.evtx)  [Windows 전용]
├── registry/               ← 레지스트리 하이브 덤프 (.hiv)  [Windows 전용]
├── artifacts/              ← 파일/디렉터리 직접 복사본
├── browser/                ← 브라우저 아티팩트 (사용자별·브라우저별)
│   ├── Chrome/<username>/<profile>/
│   ├── Edge/<username>/<profile>/
│   ├── Firefox/<username>/<profile>/
│   └── ...
├── collection_manifest.json   ← 전체 수집 결과 + 각 파일 SHA-256
└── collection_manifest.sha256 ← 매니페스트 파일 자체의 SHA-256
```

---

## 수집 항목

> **현재 구현 기준**  
> 이 README는 현재 Rust 소스에 구현된 수집 범위를 기준으로 작성되었다.  
> 기존 도구에서 제공하던 `Windows_lite` 별도 프로파일, NTFS 저수준 아티팩트(`$MFT`, `$LogFile`, `$UsnJrnl`, ADS),
> pagefile/swapfile, IE `WebCacheV01.dat`, Naver Whale, LNK/JumpList/RDP Bitmap Cache, 전체 실행파일 MD5/SHA1/SHA256 전수 해시,
> Linux ELF 전수 해시, macOS Mach-O 전수 해시 및 `praudit` XML 변환은 아직 구현되어 있지 않다.

### 공통 동작

- 각 OS별 라이브 명령 결과는 `commands/` 아래 `.txt` 파일로 저장한다.
- 직접 복사 가능한 파일/디렉터리는 `artifacts/` 아래에 저장한다.
- 브라우저 아티팩트는 사용자 홈 디렉터리를 순회해 `browser/` 아래에 저장한다.
- 수집된 파일과 매니페스트에는 SHA-256 해시를 기록한다. MD5/SHA1 해시는 생성하지 않는다.
- 접근 불가, 파일 잠금, 미존재 항목은 실행을 중단하지 않고 `collection_manifest.json` 에 상태와 사유를 기록한다.

### Windows

단일 Windows 수집 플로우만 제공한다. 별도의 `Windows_lite` 모드는 없다.

#### 명령 수집 (`commands/`)

| 파일명 | 수집 내용 |
|---|---|
| `time_info.txt` | 현재 시각, 타임존 |
| `system_info.txt` | `systeminfo` 출력 (OS 버전, 패치 이력, 메모리 등) |
| `users_sessions.txt` | 현재 로그인 세션 (`query user`, `qwinsta`) |
| `processes.txt` | 실행 중 프로세스 전체 (PID, PPID, 이름, 커맨드라인, 경로) |
| `services.txt` | 서비스 목록 (이름, 상태, 시작 모드, 실행 경로) |
| `drivers.txt` | 드라이버 목록 (이름, 상태, 경로) |
| `network_connections.txt` | 활성 TCP/UDP 연결 및 수신 포트 + PID (`netstat -ano`) |
| `routes.txt` | 라우팅 테이블 |
| `arp.txt` | ARP 캐시 |
| `dns_cache.txt` | DNS 클라이언트 캐시 |
| `firewall_rules.txt` | 활성화된 방화벽 규칙 |
| `firewall_status.txt` | 방화벽 프로파일별 상태 (`netsh advfirewall`) |
| `scheduled_tasks.txt` | 스케줄 작업 전체 목록 및 상세 정보 |
| `local_users.txt` | 로컬 계정 목록 및 속성 |
| `local_groups.txt` | 로컬 그룹 및 administrators 멤버 |
| `autorun_hklm_run.txt` | `HKLM\...\Run` 자동실행 항목 |
| `autorun_hkcu_run.txt` | `HKCU\...\Run` 자동실행 항목 |
| `autorun_hklm_runonce.txt` | `HKLM\...\RunOnce` 항목 |
| `startup_folders.txt` | 시작 프로그램 폴더 내 파일 목록 |
| `installed_software.txt` | 설치된 프로그램 목록 (이름, 버전, 설치일, 제조사) |
| `shares.txt` | 공유 폴더 목록 |
| `defender_status.txt` | Windows Defender 상태 |
| `logon_sessions.txt` | 로그온 세션 목록 (WMI) |
| `named_pipes.txt` | 활성 Named Pipe 목록 |
| `env_vars.txt` | 환경 변수 |
| `hosts_file.txt` | `C:\Windows\System32\drivers\etc\hosts` 내용 |

#### 이벤트 로그 (`evtx/`)  ★ 관리자 권한 필요 항목 포함

`wevtutil epl` 을 통해 서비스 경유로 내보내므로 파일 잠금 문제 없음.  
채널이 설치되지 않은 경우(`not_found`) 오류로 처리하지 않고 매니페스트에 기록.

| 파일명 | 이벤트 채널 | 주요 이벤트 ID |
|---|---|---|
| `Security.evtx` | Security ★ | 4624·4625(로그인), 4648(명시적 로그인), 4672(특수 권한), 4688(프로세스 생성), 4698·4702(스케줄 작업), 4720·4722·4724(계정 변경), 1102(로그 삭제) |
| `System.evtx` | System | 7045(서비스 생성), 7036(서비스 상태 변경) |
| `Application.evtx` | Application | 앱 오류, 설치 이벤트 |
| `Sysmon_Operational.evtx` | Sysmon/Operational | 1(프로세스), 3(네트워크), 7(모듈 로드), 11(파일 생성), 22(DNS) |
| `PowerShell_Operational.evtx` | PowerShell/Operational | 4103(파이프라인 실행), 4104(스크립트 블록) |
| `Windows_PowerShell.evtx` | Windows PowerShell | 400·800(PowerShell 세션) |
| `TaskScheduler_Operational.evtx` | TaskScheduler/Operational | 106(작업 등록), 140·141(수정/삭제) |
| `WMI_Operational.evtx` | WMI-Activity/Operational | WMI 쿼리·구독 활동 |
| `Defender_Operational.evtx` | Windows Defender/Operational | 1116·1117(악성코드 탐지) |
| `RDP_RemoteConnectionManager.evtx` | TerminalServices-RemoteConnectionManager | 1149(RDP 연결 시도) |
| `RDP_LocalSessionManager.evtx` | TerminalServices-LocalSessionManager | 21·23·24·25(RDP 세션 이벤트) |
| `RDP_CoreTS.evtx` | RdpCoreTS/Operational | RDP 연결 상세 |
| `BITS_Client.evtx` | BITS-Client/Operational | 백그라운드 파일 전송 |
| `DNS_Client.evtx` | DNSClient/Operational | DNS 쿼리 이력 |

#### 레지스트리 하이브 (`registry/`)  ★ 관리자 권한 필요

`reg save` 로 오프라인 분석 가능한 형태로 덤프.

| 파일명 | 원본 하이브 | 포함 정보 |
|---|---|---|
| `SAM.hiv` | HKLM\SAM | 로컬 계정 해시, 마지막 로그인 |
| `SYSTEM.hiv` | HKLM\SYSTEM | 서비스, ShimCache(AppCompatCache), 타임존, USB 이력 |
| `SOFTWARE.hiv` | HKLM\SOFTWARE | 설치 소프트웨어, Run 키, AppCompat 관련 설정 |
| `SECURITY.hiv` | HKLM\SECURITY | LSA Secrets, 도메인 캐시 자격증명 |

#### 파일 직접 복사 (`artifacts/`)

| 경로 | 설명 |
|---|---|
| `C:/Windows/Prefetch/` | 프리패치 파일 — 실행 이력 |
| `C:/Windows/System32/drivers/etc/hosts` | hosts 파일 변조 여부 |

---

### Linux

#### 명령 수집 (`commands/`)

| 파일명 | 수집 내용 |
|---|---|
| `time_info.txt` | UTC 시각, timedatectl 상태 |
| `host_info.txt` | `uname -a`, `/etc/os-release`, hostnamectl |
| `uptime.txt` | 시스템 가동 시간 |
| `logged_in_users.txt` | 현재 로그인 사용자 (`who`, `w`) |
| `last_logins.txt` | 최근 로그인 이력 100건 |
| `failed_logins.txt` | 실패 로그인 이력 (`lastb`) |
| `processes.txt` | 전체 프로세스 트리 + 커맨드라인 (`ps auxwwf`) |
| `open_files.txt` | 열린 파일 및 소켓 (`lsof`) |
| `network_connections.txt` | TCP/UDP 연결 및 PID (`ss -pant`) |
| `routes.txt` | 라우팅 테이블 |
| `neighbors.txt` | ARP/Neighbor 테이블 (`ip neigh`) |
| `interfaces.txt` | 네트워크 인터페이스 주소 |
| `iptables.txt` | iptables 규칙 |
| `nftables.txt` | nftables 규칙 |
| `systemd_units.txt` | 전체 systemd 유닛 목록 |
| `systemd_failed.txt` | 실패 상태 유닛 목록 |
| `crontab_root.txt` | root crontab 및 cron 디렉터리 목록 |
| `sudoers.txt` | sudoers 파일 내용 및 sudoers.d 목록 |
| `passwd_shadow.txt` | `/etc/passwd`, 그룹 목록 |
| `suid_sgid_files.txt` | SUID/SGID 파일 목록 |
| `dmesg.txt` | 최근 커널 메시지 500줄 |
| `env_vars.txt` | 환경 변수 |
| `hosts_file.txt` | `/etc/hosts`, `/etc/resolv.conf` |

> `passwd_shadow.txt` 파일명은 호환성을 위해 유지하지만, 현재 명령 수집은 `/etc/passwd` 와 그룹 목록을 기록하며 `/etc/shadow` 내용은 직접 출력하지 않는다.

#### 파일 직접 복사 (`artifacts/`)

| 경로 | 설명 |
|---|---|
| `/var/log/auth.log` | 인증 로그 (Debian/Ubuntu) |
| `/var/log/secure` | 인증 로그 (RHEL/CentOS) |
| `/var/log/syslog` | 시스템 로그 |
| `/var/log/messages` | 시스템 로그 (RHEL 계열) |
| `/var/log/kern.log` | 커널 로그 |
| `/var/log/audit/audit.log` | auditd 감사 로그 |
| `/var/log/dpkg.log` | dpkg 패키지 변경 이력 |
| `/var/log/apt/history.log` | apt 설치/제거 이력 |
| `/etc/passwd` | 계정 정보 |
| `/etc/group` | 그룹 정보 |
| `/etc/sudoers` | sudo 권한 설정 |
| `/etc/crontab` | 시스템 Cron |
| `/etc/ssh/sshd_config` | SSH 데몬 설정 |
| `/etc/hosts` | hosts 파일 |
| `/etc/resolv.conf` | DNS 설정 |
| `/etc/systemd/system/` | 사용자 정의 systemd 서비스 유닛 |
| `/var/spool/cron/` | 사용자별 Crontab |

---

### macOS (Intel / Apple Silicon 공통)

#### 명령 수집 (`commands/`)

| 파일명 | 수집 내용 |
|---|---|
| `time_info.txt` | UTC 시각, 타임존 |
| `host_info.txt` | `sw_vers`, `uname -a` |
| `uptime.txt` | 시스템 가동 시간 |
| `logged_in_users.txt` | 현재 로그인 사용자 |
| `last_logins.txt` | 최근 로그인 이력 100건 |
| `processes.txt` | 전체 프로세스 목록 + 커맨드라인 |
| `open_files.txt` | 열린 파일/소켓 (`lsof`) |
| `network_connections.txt` | TCP/UDP 연결 |
| `routes.txt` | 라우팅 테이블 |
| `arp.txt` | ARP 캐시 |
| `interfaces.txt` | 네트워크 인터페이스 (`ifconfig`) |
| `launchd_list.txt` | 실행 중인 launchd 작업 목록 |
| `firewall_status.txt` | Application Firewall 상태 |
| `users.txt` | 시스템 사용자 목록 (서비스 계정 제외) |
| `admin_group.txt` | admin 그룹 멤버 |
| `suid_files.txt` | SUID/SGID 파일 목록 |
| `quarantine_events.txt` | 다운로드/격리 이벤트 200건 (QuarantineEventsV2) |
| `env_vars.txt` | 환경 변수 |
| `hosts_file.txt` | `/etc/hosts` |
| `system_profiler.txt` | OS 버전, 하드웨어 정보 |

#### 파일 직접 복사 (`artifacts/`)

| 경로 | 설명 |
|---|---|
| `/etc/hosts` | hosts 파일 변조 여부 |
| `/etc/resolv.conf` | DNS 설정 |
| `/Library/LaunchDaemons/` | 시스템 전역 LaunchDaemon (지속성) |
| `/Library/LaunchAgents/` | 시스템 전역 LaunchAgent (지속성) |
| `/Library/Application Support/com.apple.TCC/TCC.db` | 앱 권한 승인 DB |
| `/var/db/auth.db` | 인증 정책 DB |
| `/var/log/install.log` | 설치 이력 로그 |
| `/private/etc/passwd` | 계정 정보 |
| `/private/etc/sudoers` | sudo 권한 설정 |

---

## 매니페스트 구조

수집 완료 후 `collection_manifest.json` 에 전체 결과가 기록된다.

```json
{
  "collector_version": "0.1.0",
  "started_at_utc": "2026-04-26T13:25:06Z",
  "finished_at_utc": "2026-04-26T13:27:00Z",
  "host": "DESKTOP-XXXX",
  "os": "windows",
  "case_name": "case-001",
  "output_dir": "C:/Cases/case-001/20260426T132506Z",
  "command_results": [
    {
      "name": "processes",
      "command": "Get-CimInstance Win32_Process ...",
      "status": "ok",
      "exit_code": 0,
      "output_file": "...",
      "sha256": "a1b2c3...",
      "error": null
    }
  ],
  "evtx_exports": [...],
  "registry_exports": [...],
  "copied_artifacts": [...],
  "browser_artifacts": [...],
  "errors": []
}
```

각 항목의 `status` 값:

| status | 의미 |
|---|---|
| `ok` | 수집 성공 |
| `not_found` | 파일/채널 미존재 또는 비활성화 (오류 아님) |
| `locked` | 브라우저 실행 중 파일 잠김 — 브라우저 종료 후 재수집 권장 |
| `command_error` | 명령은 실행됐지만 비정상 종료 코드 반환 |
| `write_error` | 명령 출력 파일 기록 실패 |
| `mkdir_error` | 대상 디렉터리 생성 실패 |
| `copy_error` | 파일 복사 실패 |
| `empty_or_unreadable` | 디렉터리가 비어 있거나 읽을 수 없어 복사된 파일 없음 |
| `error` | 수집 실패 (권한 부족 등) — `error` 필드에 사유 기록 |
| `exec_error` | 명령 자체 실행 실패 |

---

---

## 브라우저 아티팩트 수집 (`browser/`)

시스템의 **모든 사용자 홈 디렉터리**를 자동 탐색하여 브라우저별 프로파일 파일을 복사한다.  
브라우저 실행 중 파일이 잠긴 경우 `status: locked` 으로 기록하고 계속 진행한다.

### Windows

| 브라우저 | 수집 파일 |
|---|---|
| Chrome | `History`, `Cookies`, `Login Data`, `Web Data`, `Bookmarks`, `Extensions` |
| Edge | `History`, `Cookies`, `Login Data`, `Web Data`, `Bookmarks` |
| Brave | `History`, `Cookies`, `Login Data`, `Web Data`, `Bookmarks` |
| Firefox | `places.sqlite`, `cookies.sqlite`, `downloads.sqlite`, `logins.json`, `key4.db` |

프로파일 경로: `C:\Users\<user>\AppData\Local\<Browser>\User Data\Default`  
Firefox: `C:\Users\<user>\AppData\Roaming\Mozilla\Firefox\Profiles\<profile>`

### Linux

| 브라우저 | 수집 파일 |
|---|---|
| Chrome | `History`, `Cookies`, `Login Data`, `Web Data`, `Bookmarks` |
| Chromium | `History`, `Cookies`, `Login Data`, `Web Data`, `Bookmarks` |
| Brave | `History`, `Cookies`, `Login Data`, `Web Data`, `Bookmarks` |
| Firefox | `places.sqlite`, `cookies.sqlite`, `logins.json`, `key4.db` |

프로파일 경로: `~/.config/<Browser>/Default`  
Firefox: `~/.mozilla/firefox/<profile>`

### macOS

| 브라우저 | 수집 파일 |
|---|---|
| Chrome | `History`, `Cookies`, `Login Data`, `Web Data`, `Bookmarks` |
| Edge | `History`, `Cookies`, `Login Data`, `Web Data`, `Bookmarks` |
| Brave | `History`, `Cookies`, `Login Data`, `Web Data`, `Bookmarks` |
| Firefox | `places.sqlite`, `cookies.sqlite`, `logins.json`, `key4.db` |
| Safari | `History.db`, `History.db-wal`, `History.db-shm`, `Downloads.plist`, `Bookmarks.plist` |

프로파일 경로: `~/Library/Application Support/<Browser>/Default`  
Firefox: `~/Library/Application Support/Firefox/Profiles/<profile>`  
Safari: `~/Library/Safari`

### 수집 파일 분석 참고

| 파일 | 포함 정보 |
|---|---|
| `History` / `places.sqlite` | 방문 URL, 타임스탬프, 방문 횟수 |
| `Cookies` / `cookies.sqlite` | 세션 쿠키, 인증 토큰 흔적 |
| `Login Data` | 저장된 자격증명 (암호화) |
| `Web Data` | 자동완성 데이터, 폼 입력 이력 |
| `Bookmarks` | 북마크 (C2 도메인 등록 여부 확인) |
| `downloads.sqlite` | 다운로드 이력, 저장 경로 |
| `logins.json` / `key4.db` | Firefox 저장 자격증명 |
| `History.db` | Safari 방문 이력 |
| `Downloads.plist` | Safari 다운로드 이력 |

---

## 의존 크레이트

| 크레이트 | 용도 |
|---|---|
| `clap` | CLI 인수 파싱 |
| `serde` / `serde_json` | JSON 직렬화 |
| `chrono` | UTC 타임스탬프 |
| `sha2` | SHA-256 파일 해시 |
| `walkdir` | 디렉터리 재귀 복사 |
