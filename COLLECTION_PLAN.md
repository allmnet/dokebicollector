# Rust 기반 침해사고 대응 수집기 설계 (Windows / Linux / macOS)

## 1) 목표

이 문서는 **침해사고 발생 시 포렌식/초동분석용 아티팩트 수집기**를 Rust로 구현하기 위한 수집 기준이다.

핵심 원칙:
- 휘발성 데이터(메모리/네트워크/프로세스) 우선
- 원본 보존(읽기 위주, 변경 최소화)
- 무결성 검증(해시/수집 로그)
- 운영체제별 공통 스키마로 저장(JSONL + 원본 파일)

---

## 2) 공통 수집 우선순위 (모든 OS)

### P0 (즉시, 휘발성)
- 현재 시간/타임존/부팅시간
- 로그인 사용자/세션
- 실행 중 프로세스 트리 + 커맨드라인 + 부모 PID
- 활성 네트워크 연결(로컬/원격 IP, 포트, PID)
- 라우팅 테이블, ARP/Neighbor
- 메모리 관련 정보(가능 범위 내)
- 최근 실행 이력(쉘 히스토리/런치 포인트)

### P1 (중요 로그)
- 시스템 보안/인증 로그
- 시스템 서비스/데몬 로그
- 스케줄러 작업(Cron/Task Scheduler/Launchd)
- 원격접속 흔적(RDP/SSH/VPN)

### P2 (지속성/변조 흔적)
- 자동실행 항목(Startup, Run key, LaunchAgents 등)
- 계정/권한/그룹 변경 이력
- 방화벽/보안제품 설정 및 로그
- 설치 프로그램/패키지 이력

### P3 (심화 포렌식)
- 파일시스템 저널/감사로그
- 브라우저 아티팩트
- EDR/AV 상세 텔레메트리
- 컨테이너/가상화/클라우드 에이전트 로그

---

## 3) Windows 수집 항목

## 3.1 이벤트 로그(EVTX)

필수 채널:
- Security
- System
- Application
- Microsoft-Windows-Sysmon/Operational (Sysmon 설치 시)
- Microsoft-Windows-PowerShell/Operational
- Windows PowerShell
- Microsoft-Windows-TaskScheduler/Operational
- Microsoft-Windows-WMI-Activity/Operational
- Microsoft-Windows-Windows Defender/Operational
- Microsoft-Windows-TerminalServices-RemoteConnectionManager/Operational
- Microsoft-Windows-TerminalServices-LocalSessionManager/Operational

중요 이벤트 예시:
- 인증/계정: 4624, 4625, 4634, 4648, 4672, 4688, 4698, 4720, 4722, 4723, 4724, 4728, 4732, 4740
- 로그 삭제: 1102
- PowerShell: 4103, 4104
- 서비스 생성: 7045
- 스케줄 작업 생성/변경: 106, 140, 141

EVTX 경로:
- C:/Windows/System32/winevt/Logs/*.evtx

## 3.2 아티팩트/레지스트리
- Prefetch: C:/Windows/Prefetch/*
- Amcache: C:/Windows/appcompat/Programs/Amcache.hve
- ShimCache(AppCompatCache): SYSTEM hive 내
- Jump Lists: C:/Users/<user>/AppData/Roaming/Microsoft/Windows/Recent/AutomaticDestinations/*
- LNK 최근문서: C:/Users/<user>/AppData/Roaming/Microsoft/Windows/Recent/*
- Startup 폴더:
  - C:/ProgramData/Microsoft/Windows/Start Menu/Programs/StartUp/
  - C:/Users/<user>/AppData/Roaming/Microsoft/Windows/Start Menu/Programs/Startup/
- 레지스트리 하이브:
  - C:/Windows/System32/config/{SAM,SECURITY,SOFTWARE,SYSTEM}
  - C:/Users/<user>/NTUSER.DAT

자동실행(주요 키):
- HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\Run
- HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run
- Services, Winlogon, AppInit_DLLs, IFEO

## 3.3 시스템/네트워크
- 프로세스/서비스/드라이버 목록
- netstat/ARP/route/방화벽 규칙
- DNS 캐시
- 로컬 사용자/그룹/권한
- 설치 프로그램 목록(MSI, Uninstall key)

## 3.4 수집 시 주의
- 관리자 권한 필요 항목 분리(권한 실패 시 로그에 사유 기록)
- 실시간 변경 파일(EVTX, 레지스트리)은 가능한 원본 복사 + 메타데이터 수집

---

## 4) Linux 수집 항목

배포판별 경로 차이를 고려해 존재하는 파일만 수집한다.

## 4.1 로그
- systemd journal: /var/log/journal/, journalctl 출력(부팅 단위 포함)
- 인증 로그:
  - Debian/Ubuntu: /var/log/auth.log
  - RHEL/CentOS: /var/log/secure
- 시스템 로그: /var/log/syslog 또는 /var/log/messages
- 커널 로그: /var/log/kern.log, dmesg 출력
- 감사 로그(auditd): /var/log/audit/audit.log
- SSH 로그(인증 로그 내 포함 + sshd 설정)
- sudo 로그

## 4.2 지속성/권한/실행 흔적
- 계정/그룹:
  - /etc/passwd, /etc/shadow(권한 필요), /etc/group, /etc/sudoers, /etc/sudoers.d/*
- Cron/at:
  - /etc/crontab, /etc/cron.*, /var/spool/cron/*, at queue
- systemd 서비스:
  - /etc/systemd/system/*, /usr/lib/systemd/system/*, enabled units 목록
- SSH:
  - /etc/ssh/sshd_config, ~/.ssh/authorized_keys
- 쉘 이력:
  - ~/.bash_history, ~/.zsh_history
- 자동실행 스크립트:
  - /etc/rc.local, profile.d, login scripts

## 4.3 네트워크/프로세스
- ps 트리(커맨드라인 포함)
- 열린 포트/소켓(ss -pant)
- 라우팅/ARP(ip route, ip neigh)
- iptables/nftables 규칙
- DNS 설정(/etc/resolv.conf, systemd-resolved 상태)

## 4.4 패키지/무결성
- 패키지 이력:
  - dpkg: /var/log/dpkg.log
  - apt: /var/log/apt/history.log
  - yum/dnf history
- 무결성 도구(AIDE 등) 결과가 있으면 수집

---

## 5) macOS 수집 항목 (Intel / Apple Silicon 공통)

## 5.1 로그
- Unified Logs: `log show` / `log collect` 결과
- 설치 로그: /var/log/install.log
- 시스템 로그(버전별 일부 통합): /var/log/system.log (존재 시)
- 보안/승인 관련:
  - /var/db/auth.db
  - TCC DB(권한 승인):
    - 시스템: /Library/Application Support/com.apple.TCC/TCC.db
    - 사용자: ~/Library/Application Support/com.apple.TCC/TCC.db

## 5.2 실행/지속성
- LaunchAgents/LaunchDaemons:
  - /System/Library/LaunchDaemons
  - /System/Library/LaunchAgents
  - /Library/LaunchDaemons
  - /Library/LaunchAgents
  - ~/Library/LaunchAgents
- Login Items / Background Items 정보
- Cron(사용 중이면) 및 쉘 프로파일
- 최근 실행/다운로드:
  - ~/Library/Preferences/com.apple.LaunchServices.QuarantineEventsV2

## 5.3 계정/네트워크/프로세스
- 현재 사용자, 관리자 그룹 멤버
- 실행 프로세스/부모관계
- 네트워크 연결(lsof -i, netstat)
- 인터페이스/라우팅/ARP
- 방화벽 상태:
  - /usr/libexec/ApplicationFirewall/socketfilterfw --getglobalstate

## 5.4 아키텍처 주의사항
- Intel/Apple Silicon 모두 수집 로직은 동일하되, 바이너리 메타데이터에 아키텍처(x86_64/arm64) 기록
- Rosetta 설치 여부/사용 흔적 수집(가능 시)

---

## 6) Rust 구현 권장 구조

예시 디렉터리:
- src/main.rs
- src/collector/mod.rs
- src/collector/common.rs
- src/collector/windows.rs
- src/collector/linux.rs
- src/collector/macos.rs
- src/output/jsonl.rs
- src/output/archive.rs
- src/hash/mod.rs
- src/privilege.rs
- src/error.rs

핵심 설계:
- 공통 인터페이스:
  - `collect_volatile()`
  - `collect_logs()`
  - `collect_persistence()`
  - `collect_system_state()`
- 결과 포맷:
  - `artifacts/<os>/<category>/...` 원본 복사
  - `events.jsonl` 정규화 이벤트
  - `collection_manifest.json` (수집 항목, 성공/실패, 오류사유)
- 해시:
  - SHA-256 (파일별 + 전체 매니페스트)
- 압축:
  - tar.zst 또는 zip + 해시파일

권장 크레이트:
- CLI: clap
- 직렬화: serde, serde_json
- 시간: chrono
- 에러: anyhow, thiserror
- 해시: sha2
- 압축: tar, zstd 또는 zip
- 병렬 처리: rayon (필요 시)

---

## 7) 정규화 이벤트 스키마 예시

```json
{
  "ts": "2026-04-23T10:15:30Z",
  "host": "endpoint-01",
  "os": "windows",
  "category": "process",
  "source": "security_evtx",
  "event_id": "4688",
  "severity": "info",
  "pid": 1234,
  "ppid": 888,
  "user": "DOMAIN\\alice",
  "command_line": "powershell -enc ...",
  "raw_ref": "artifacts/windows/evtx/Security.evtx",
  "collector_version": "0.1.0"
}
```

---

## 8) 운영 시 체크리스트

- 시간 동기화 상태 기록(NTP, timezone)
- 수집 시작/종료 시각 및 수행자 기록
- 수집 실패 항목은 반드시 이유 남김(권한/파일잠금/미존재)
- 민감정보(토큰/비밀번호) 마스킹 규칙 적용
- 법적/내부 규정에 맞게 보관기간 및 접근통제 적용

---

## 9) 빠른 우선 구현 범위 (MVP)

1. 공통: 프로세스/네트워크/사용자/시간/해시/매니페스트
2. Windows: Security/System/Application EVTX + Run 키 + Task Scheduler
3. Linux: auth/syslog/journal + cron + systemd unit
4. macOS: unified log(요약) + launchd + quarantine/TCC
5. 결과 압축 및 무결성 파일 생성

이 MVP만으로도 초동 침해분석에 필요한 핵심 흔적 대부분을 확보할 수 있다.
