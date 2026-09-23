# WfpProcessSandbox Validation Results

Date: 2026-09-24

## 1. Purpose

Windows Filtering Platform（WFP）を使用して、Windows上でCodexを動作させる際に、

- Codex自身に必要なTCP通信は許可する
- Codexが起動した別プロセスのTCP通信は遮断する
- Windows全体の通信には影響させない
- Controller異常終了時にもFilterを残留させない

という軽量なネットワーク隔離が成立するかを検証した。

本PoCは完全なWindows sandboxの構築を目的としない。

---

# 2. Test Environment

## OS

```text
Windows 11 Home
Version: 25H2
OS Build: 26200.9457
x64
```

## Build Environment

```text
Visual Studio Build Tools 2026
MSVC: 19.51.36260
CMake: 4.3.1-msvc1
Windows SDK: 10.0.26100.0
C++17
```

## Codex

```text
Codex CLI: 0.156.1
Model used during E2E: GPT-6-Luna
```

## Dedicated Windows User

```text
WfpCodexTest
Local group: Users
Administrator: No
```

SIDは実行時に解決した。

ソースコードへのSIDハードコードは行っていない。

---

# 3. WFP Architecture

## Phase 1

Phase 1では、対象実行ファイルのAPP_IDのみを条件としてTCPをBLOCKした。

使用Layer:

```text
FWPM_LAYER_ALE_AUTH_CONNECT_V4
FWPM_LAYER_ALE_AUTH_CONNECT_V6
```

Filter条件:

```text
ALE_APP_ID == target executable
AND
IP_PROTOCOL == TCP
```

Action:

```text
FWP_ACTION_BLOCK
```

Session:

```text
FWPM_SESSION_FLAG_DYNAMIC
```

---

## Phase 2

Phase 2では専用Windowsユーザーを隔離境界とし、指定したallowed applicationだけTCPを許可した。

同一Sublayer内に以下を配置した。

### PERMIT

```text
ALE_USER_ID == dedicated user
AND
ALE_APP_ID == allowed executable
AND
IP_PROTOCOL == TCP
→ PERMIT
```

Weight:

```text
0xF000000000000000
```

### BLOCK

```text
ALE_USER_ID == dedicated user
AND
IP_PROTOCOL == TCP
→ BLOCK
```

Weight:

```text
0x1000000000000000
```

IPv4 / IPv6それぞれにPERMIT / BLOCKを作成し、合計4 Filterを使用した。

Phase 2のSublayer / Filter追加はWFP transaction内で実施する。

SessionはPhase 1と同様にDynamic Sessionを使用する。

---

# 4. Phase 1 Results

## 4.1 IPv4 Direct Outbound

Baseline:

```text
CONNECT_SUCCESS
```

WFP active:

```text
CONNECT_FAILED error=10013
```

Dynamic Session終了後:

```text
CONNECT_SUCCESS
```

Result:

```text
PASS
```

---

## 4.2 IPv6 Direct Outbound

Target:

```text
2606:4700:4700::1111:443
```

Baseline:

```text
CONNECT_SUCCESS
```

WFP active:

```text
CONNECT_FAILED error=10013
```

Dynamic Session終了後:

```text
CONNECT_SUCCESS
```

Result:

```text
PASS
```

---

## 4.3 IPv4 Loopback

Target:

```text
127.0.0.1
```

WFP active:

```text
LOOPBACK_CONNECT_FAILED
connect error=10013
```

Result:

```text
PASS
```

対象EXE自身のlocalhost TCPも遮断された。

---

## 4.4 IPv6 Loopback

Target:

```text
::1
```

WFP active:

```text
LOOPBACK_CONNECT_FAILED
connect error=10013
```

Result:

```text
PASS
```

---

## 4.5 Unrelated Process

WfpTestClient.exeをBLOCKした状態で、別プロセスのcurl.exeを実行。

```text
curl.exe https://example.com/
```

Result:

```text
SUCCESS
```

判定:

```text
PASS
```

対象外プロセスへの影響は観測されなかった。

---

## 4.6 Child Process Escape

WfpTestClient.exeからcurl.exeを子プロセスとして起動。

```text
WfpTestClient.exe
  -> curl.exe
      -> https://example.com/
```

Result:

```text
HTTP response received
CURL_EXIT_CODE=0
```

判定:

```text
ESCAPE CONFIRMED
```

ALE_APP_ID単独では、子プロセスへFilterは継承されない。

---

## 4.7 Copied Executable Escape

対象:

```text
WfpTestClient.exe
```

を別path／別ファイル名へコピー。

```text
WfpTestClient-copy.exe
```

Original executable:

```text
CONNECT_FAILED error=10013
```

Copied executable:

```text
CONNECT_SUCCESS
```

判定:

```text
ESCAPE CONFIRMED
```

ALE_APP_IDは実行ファイルpathに依存するため、別pathのコピーは別APP_IDとして扱われる。

---

## 4.8 Multiple Instances

同一pathのWfpTestClient.exeを2プロセス同時起動。

Result:

```text
INSTANCE_1: CONNECT_FAILED error=10013
INSTANCE_2: CONNECT_FAILED error=10013
```

判定:

```text
CONFIRMED
```

Filter単位はPIDではなくAPP_IDであり、同じpathの全processへ適用される。

---

## 4.9 Normal Dynamic Session Cleanup

Controller正常終了後:

```text
CONNECT_SUCCESS
```

判定:

```text
PASS
```

---

## 4.10 Forced Termination Cleanup

Controllerを以下で強制終了。

```powershell
Stop-Process -Id <controller PID> -Force
```

終了前:

```text
CONNECT_FAILED error=10013
```

Controller終了後:

```text
CONNECT_SUCCESS
```

判定:

```text
PASS
```

Controller異常終了後にもDynamic SessionのFilterが残留しないことを実測した。

---

# 5. Phase 1 Conclusion

Phase 1では以下を確認した。

```text
WFP Dynamic Session                 PASS
IPv4 direct TCP                     PASS
IPv6 direct TCP                     PASS
IPv4 loopback                       PASS
IPv6 loopback                       PASS
Unrelated process unaffected        PASS
Normal cleanup                      PASS
Forced termination cleanup          PASS
```

一方、ALE_APP_ID単独には以下の制約がある。

```text
Child process escape                CONFIRMED
Copied executable escape            CONFIRMED
```

したがって、

```text
ALE_APP_ID alone
```

はアプリ単位の通信制御には有効だが、エージェントのsecurity boundaryとしては不十分と判断した。

---

# 6. Phase 2 Results

Phase 2では、

```text
Dedicated Windows User
+
ALE_USER_ID
+
Allowed APP_ID PERMIT
+
User-wide TCP BLOCK
```

を使用した。

Dedicated user:

```text
WfpCodexTest
```

Allowed Test Application:

```text
C:\Users\Public\WfpProcessSandboxTest\WfpTestClient.exe
```

---

## 6.1 Allowed Application IPv4

WfpCodexTest:

```text
WfpTestClient.exe tcp 1.1.1.1 443
```

Result:

```text
CONNECT_SUCCESS
```

判定:

```text
PASS
```

---

## 6.2 Allowed Application IPv6

WfpCodexTest:

```text
WfpTestClient.exe tcp 2606:4700:4700::1111 443
```

Result:

```text
CONNECT_SUCCESS
```

判定:

```text
PASS
```

---

## 6.3 Child curl Blocking

Allowed TestClientからcurl.exeを起動。

```text
WfpTestClient.exe
  -> curl.exe
      -> https://example.com/
```

Result:

```text
curl: (7) Failed to connect to example.com:443
CURL_EXIT_CODE=7
```

判定:

```text
PASS
```

Phase 1で成立したchild-process escapeをPhase 2では遮断できた。

---

## 6.4 Copied Executable Blocking

WfpCodexTestで:

```text
WfpTestClient-copy.exe tcp 1.1.1.1 443
```

Result:

```text
CONNECT_FAILED error=10013
```

判定:

```text
PASS
```

Phase 1で成立したcopied-path escapeをPhase 2では遮断できた。

---

## 6.5 Unrelated User

通常ユーザーから:

```text
WfpTestClient.exe
```

Result:

```text
CONNECT_SUCCESS
```

Copied executable:

```text
CONNECT_SUCCESS
```

判定:

```text
PASS
```

FilterはWfpCodexTestのSIDに限定され、他Windowsユーザーには影響しない。

---

## 6.6 Normal Cleanup

ControllerをCtrl+Cで終了。

終了後、WfpCodexTestでpreviously blocked copied executableを実行。

```text
CONNECT_SUCCESS
```

判定:

```text
PASS
```

---

## 6.7 Phase 2 Forced Termination Cleanup

Phase 2専用のforce-kill testは再実施していない。

```text
NOT RUN
```

Phase 1ではDynamic Sessionのforce-kill cleanupを実測済み。

---

# 7. Codex E2E

## 7.1 Codex Installation

Dedicated userへCodex CLI 0.156.1をインストール。

Native executable:

```text
%APPDATA%\npm\node_modules\@openai\codex\node_modules\@openai\codex-win32-x64\vendor\x86_64-pc-windows-msvc\bin\codex.exe
```

このpathは検証時点の実体pathであり、恒久的な設計contractとはしない。

---

## 7.2 Model Communication Baseline

WFP無効状態でCodex CLIを起動。

Input:

```text
Reply exactly: CODEX_BASELINE_OK
```

Result:

```text
CODEX_BASELINE_OK
```

判定:

```text
PASS
```

---

## 7.3 Codex Default Sandbox Issue

Codex既定sandboxでは、WFP無効状態でもshell実行時に以下が発生した。

```text
shell process failed to start
setup refresh had errors
```

単純な:

```text
cmd.exe /d /c echo SHELL_BASELINE_OK
```

も実行前に失敗した。

このため、この問題はWFP由来ではなくCodex内部sandbox/setup refresh側の問題として切り分けた。

最終E2Eでは、この無関係な問題を回避するため、

```text
--sandbox danger-full-access
```

を使用した。

これはWFP境界の検証を目的としたものであり、production推奨設定を意味しない。

---

## 7.4 Codex Model Communication Under WFP

Phase 2 WFP policyを有効化。

Allowed application:

```text
codex.exe
```

Input:

```text
Reply exactly: CODEX_WFP_OK
```

Result:

```text
CODEX_WFP_OK
```

判定:

```text
PASS
```

Codex自身のmodel-provider通信は維持できた。

---

## 7.5 Child cmd.exe

Codexから:

```text
cmd.exe /d /c echo SHELL_WFP_OK
```

Result:

```text
SHELL_WFP_OK
Exit code: 0
```

判定:

```text
PASS
```

子プロセス生成自体は妨げられていない。

---

## 7.6 Child curl.exe

Codexから:

```text
curl.exe https://example.com/
```

Result:

```text
curl: (7) Failed to connect to example.com:443
```

Codexは最初の失敗後、

```text
retrying outside the sandbox
```

として再試行した。

Retry result:

```text
curl: (7) Failed to connect to example.com:443
```

判定:

```text
PASS
```

Codex内部sandboxの内外に関係なく、同じDedicated Windows User配下で起動されたcurl.exeのTCP通信がWFPで遮断された。

---

## 7.7 Codex Remained Connected

curl.exeの通信失敗後もCodex自身はmodel connectionを維持し、結果をユーザーへ報告できた。

判定:

```text
PASS
```

つまり以下が同時に成立した。

```text
Codex model communication    ALLOW
Child process creation       ALLOW
Child process TCP            BLOCK
Codex result reporting       ALLOW
```

---

## 7.8 Final Cleanup

WFP Controller / Dynamic Session終了後にWfpCodexTestから直接:

```powershell
curl.exe https://example.com/
```

を実行。

Result:

```text
Example Domain HTML returned
```

判定:

```text
PASS
```

WFP FilterがSession終了後に残留していないことを確認した。

---

# 8. Final Result

本環境において、以下の構成が成立することを実証した。

```text
WFP Dynamic Session
+
Dedicated Windows User
+
ALE_USER_ID user-wide TCP BLOCK
+
Explicit allowed APP_ID TCP PERMIT
```

この構成により、

```text
Codex自身
  -> model-provider TCP
  -> ALLOW

Codex
  -> cmd.exe
  -> process execution ALLOW

Codex
  -> curl.exe
  -> TCP BLOCK

Codex
  -> copied / alternate executable
  -> TCP BLOCK
```

という制御が可能だった。

---

# 9. Confirmed Properties

```text
IPv4 filtering                        PASS
IPv6 filtering                        PASS
IPv4 loopback filtering               PASS
IPv6 loopback filtering               PASS

APP_ID specific filtering             PASS
Unrelated application unaffected      PASS
Unrelated Windows user unaffected     PASS

Child process escape with APP_ID only
                                       CONFIRMED

Copied executable escape with APP_ID only
                                       CONFIRMED

Child process blocked with USER_ID policy
                                       PASS

Copied executable blocked with USER_ID policy
                                       PASS

Codex own model communication          PASS
Codex child curl TCP denied            PASS

Normal Dynamic Session cleanup         PASS
Forced cleanup Phase 1                 PASS
```

---

# 10. Security Interpretation

本PoCから、ALE_APP_ID単独はsecurity boundaryとして不十分であることが分かった。

一方、

```text
Dedicated Windows User
+
ALE_USER_ID deny-by-default
+
Explicit allowed application
```

を組み合わせることで、今回必要としていた範囲のTCP isolationは実現できた。

特にCodex自身に必要な通信を維持しながら、Codexが起動する別processのTCP通信を遮断できた点を、本PoCの主要成果とする。

---

# 11. Explicit Non-Claims

本PoCは完全なsandboxではない。

以下は検証対象外であり、安全性を主張しない。

```text
UDP
QUIC
ICMP

filesystem isolation
Protected OOS filesystem denial

named pipe
IPC
shared memory

process privilege escalation
administrator escape
kernel escape

complete exfiltration prevention

DNS/domain allowlisting
destination/IP allowlisting

TLS inspection
HTTP inspection

Windows service deployment
WFP Broker service
UAC operational workflow
production credential management
```

---

# 12. OOS Handling

Protected OOSへの完全なfilesystemアクセス防止は本PoCのscope外とする。

FX-LLMでは、OOSアクセスやExposureの不正が発生した場合は既存のprovenance / exposure / qualification / audit boundaryで検出・失格させる責任分界を維持する。

WFP PoCをProtected OOS完全隔離の代替とは扱わない。

---

# 13. Operationalization

Production運用へ適用する場合、今後検討が必要な事項:

```text
Administrator privilege handling
WFP Broker / Windows Service
UAC-free operation
Dedicated user lifecycle
Codex installation/update
Allowed application path updates
Session recovery
Audit logging
FX-LLM runtime integration
```

これらは本PoCでは未実装。

---

# 14. Final PoC Status

```text
WFP technical feasibility:
PASS

ALE_APP_ID-only security boundary:
REJECTED

Dedicated-user ALE_USER_ID isolation:
PASS

Codex E2E:
PASS

Dynamic cleanup:
PASS

PoC status:
COMPLETE
```

## Final Conclusion

Windows 11上で、

```text
WFP Dynamic Session
+ dedicated standard Windows user
+ ALE_USER_ID user-wide TCP deny
+ explicit allowed application permit
```

を使用することで、Codex自身に必要なTCP通信を維持しながら、同一Dedicated User配下の子プロセスや別実行ファイルによるTCP通信を遮断できることを実機で確認した。

今回定義した脅威モデルに対する技術的成立性は確認済みとする。

追加のsandbox escape探索は本PoCのscope外とし、ここで検証を終了する。
