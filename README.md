# WfpProcessSandbox PoC

## Purpose

This PoC explores lightweight outbound TCP isolation on Windows using Windows Filtering Platform (WFP) user-mode management APIs. It covers two designs: Phase 1 blocks one executable path by ALE app ID; Phase 2 blocks TCP for one dedicated Windows user by default while permitting one selected app ID. The PoC validates IPv4, IPv6, loopback, unrelated-user behavior, child/copy escape behavior, Codex CLI end-to-end behavior, and dynamic-session cleanup. It is a feasibility demonstration, not a production sandbox.

Detailed manual evidence is recorded in [docs/validation-results.md](docs/validation-results.md).

## Architecture

### Phase 1 — APP_ID-only block

- `WfpProcessSandbox.exe` opens one `FwpmEngineOpen0` dynamic session.
- It creates a PoC sublayer with one block filter at each of `FWPM_LAYER_ALE_AUTH_CONNECT_V4` and `FWPM_LAYER_ALE_AUTH_CONNECT_V6`.
- Each filter matches `FWPM_CONDITION_ALE_APP_ID` for the target executable plus `FWPM_CONDITION_IP_PROTOCOL == IPPROTO_TCP`.
- `run` installs the filters before creating the target process; `hold` keeps them active until Ctrl+C.
- This design blocks every process using the same matched app ID, but a child executable or copied executable at another path has a different app ID and can escape.

Phase 1 sublayer GUID: `2dfa9fcd-e74e-43fe-92e7-5b78c3e93e32`.

### Phase 2 — dedicated-user deny-by-default

- `user-hold` resolves the supplied Windows user to a SID at runtime; no SID is hard-coded.
- A separate Phase 2 sublayer contains four filters: IPv4/IPv6 PERMIT for `ALE_USER_ID + ALE_APP_ID + TCP`, and IPv4/IPv6 BLOCK for `ALE_USER_ID + TCP`.
- PERMIT uses weight `0xF000000000000000`; BLOCK uses `0x1000000000000000` in the same sublayer.
- Filter creation is wrapped in an explicit WFP transaction.
- For the selected user, TCP from the allowed app ID is permitted; TCP from other app IDs is blocked.
- A second process using the same allowed executable path/app ID also matches the permit rule. This PoC does not claim PID- or process-tree-specific isolation.

Phase 2 sublayer GUID: `8ae41945-9f24-4e51-b356-8c3be4467e29`.

## Safety model

Both phases use `FWPM_SESSION_FLAG_DYNAMIC`. Closing the engine handle or losing the WFP session removes the PoC sublayer and filters. The PoC does not create persistent or boot-time filters, Windows Firewall rules, registry changes, network-adapter changes, routes, NAT, a provider, a kernel driver, or callouts.

Phase 2 is scoped to one Windows user SID and TCP at the outbound ALE connect layers. UDP, QUIC, ICMP, filesystem access, IPC, named pipes, shared memory, secrets, Protected OOS filesystem access, Administrator/kernel escape, and complete exfiltration prevention are outside scope.

The controller requires an elevated Administrator token to manage WFP.

## Build requirements

- Windows 11 x64 for the target evaluation.
- C++17, CMake 3.20 or later, MSVC C++ tools, and the Windows SDK WFP/Winsock headers and libraries.
- No third-party dependencies or test framework.

## Build

From an MSVC developer PowerShell or command prompt:

```powershell
cmake -S . -B build -A x64
cmake --build build --config Release
```

The executables are expected under `build\Release\` with the Visual Studio generator.

## Usage

Run one executable with WFP filters installed before process creation:

```powershell
WfpProcessSandbox.exe run --app C:\temp\WfpTestClient.exe -- tcp 1.1.1.1 443
```

Hold the filters for manual checks in another terminal:

```powershell
WfpProcessSandbox.exe hold --app C:\temp\WfpTestClient.exe
```

While `ACTIVE` is shown, try the target executable and an unrelated process. Press Ctrl+C in the controller terminal to close the dynamic session.

Test-client commands:

```powershell
WfpTestClient.exe tcp 1.1.1.1 443
WfpTestClient.exe tcp 2606:4700:4700::1111 443
WfpTestClient.exe loopback4
WfpTestClient.exe loopback6
WfpTestClient.exe spawn-curl https://example.com/
```

`tcp` accepts numeric IP addresses only and gives each connect attempt a five-second timeout. `spawn-curl` starts the Windows `System32\curl.exe` with a finite request timeout. It deliberately does not add curl to the WFP filter target.

## Test procedure

1. Build the two executables.
2. Run `WfpTestClient.exe tcp 1.1.1.1 443` without a controller filter. Only interpret the blocked result if this baseline prints `CONNECT_SUCCESS`.
3. Run the matching `WfpProcessSandbox.exe run --app <WfpTestClient.exe> -- tcp 1.1.1.1 443` command. A reachable baseline followed by `CONNECT_FAILED` is the IPv4 block observation.
4. Repeat for `2606:4700:4700::1111:443` only when the unfiltered IPv6 baseline succeeds. Otherwise record `SKIPPED: no usable external IPv6 connectivity`.
5. Run the `loopback4` and `loopback6` client modes under `run` or while `hold` is active. Record the actual result; loopback behavior is intentionally not assumed.
6. While `hold --app <WfpTestClient.exe>` displays `ACTIVE`, run `curl.exe https://example.com/` in a separate terminal. The unrelated process is expected to remain outside the filter.
7. Under the same hold session, run `WfpTestClient.exe spawn-curl https://example.com/`. The WfpTestClient direct outbound TCP is filtered, but its `curl.exe` child has a different app ID and is not targeted.
8. For normal cleanup, press Ctrl+C in the hold terminal and retry the target TCP connection after the controller exits.
9. For forced-termination cleanup, start `hold` and end only that controller process (for example, its single process entry in Task Manager). Do not terminate Windows components or unrelated processes. Retry the target connection after it exits and record whether the dynamic session removed its filters.
10. `scripts\run_poc.ps1` automates the external IPv4/IPv6 baseline and block attempts, filtered loopback modes, and child-process escape. It requires an elevated PowerShell session and does not change firewall or host network settings. The unrelated-process and forced-termination checks are manual.

## Phase 1 observed results

Build environment: Windows 11 Home x64 (build 26200), MSVC 19.51.36260.0, CMake 4.3.1-msvc1, and Windows SDK 10.0.26100.0.

CMake configure: **PASS** — `cmake -S . -B build -A x64`, Visual Studio 18 2026 generator, x64 platform.

Release build: **PASS** — `cmake --build build --config Release`; exit code 0, no compile or link errors.

The build completed without launching either executable. PE inspection confirmed that both output files are x64 executables. Artifact timestamps are 2026-09-23 20:43:30 UTC for the controller and 2026-09-23 20:43:31 UTC for the test client.

- Controller: `build\Release\WfpProcessSandbox.exe` (46,592 bytes); imports `fwpuclnt.dll`, `ADVAPI32.dll`, and `KERNEL32.dll`, plus the MSVC runtime.
- Test Client: `build\Release\WfpTestClient.exe` (37,888 bytes); imports `WS2_32.dll` and `KERNEL32.dll`, plus the MSVC runtime.

Phase 1 results retained from the existing PoC validation:

- IPv4 direct outbound BLOCK: **PASS**
- IPv6 direct outbound BLOCK: **PASS**
- IPv4 loopback BLOCK: **PASS**
- IPv6 loopback BLOCK: **PASS**
- unrelated process unaffected: **PASS**
- normal Dynamic Session cleanup: **PASS**
- forced-termination cleanup: **PASS**
- child-process escape under APP_ID-only filtering: **CONFIRMED**
- copied-executable escape under APP_ID-only filtering: **CONFIRMED**
- multiple processes from the same APP_ID path all blocked: **CONFIRMED**


## Phase 1 limitations

- This matches an executable image path, not a process ID, process name, user SID, or process tree.
- A child executable such as `curl.exe` has its own ALE app ID and is not blocked by the parent's filter.
- Only outbound TCP authorization at the two specified ALE layers is in scope. There is no UDP, DNS, ICMP, QUIC, filesystem, secret, or process-tree isolation.
- IPv4 and IPv6 loopback BLOCK are recorded as PASS for the Phase 1 test environment; other Windows builds should be checked separately.
- Phase 1 forced-termination cleanup is recorded as PASS above. Phase 2 forced-termination cleanup remains untested.
- This PoC does not provide production hardening, service recovery, or policy persistence.

## Phase 1 security implications

An app-ID TCP filter can test direct connections from one executable image, but does not establish a security boundary around code that can launch another executable. A normal user or Administrator with authority over WFP may have other ways to alter system policy. Phase 1 forced-termination cleanup is recorded as PASS; the corresponding Phase 2 result remains untested.

## Phase 2 - User isolation PoC

### Purpose

Phase 2 checks whether TCP connection authorization for one dedicated Windows user can be blocked by default while permitting one selected executable. It adds the `user-hold` controller mode; Phase 1 `run` and `hold` behavior is unchanged.

```powershell
WfpProcessSandbox.exe user-hold --user WfpCodexTest --allow-app C:\path\to\WfpTestClient.exe
```

The user name is resolved at runtime. No user SID is hard-coded.

### Threat model

For TCP connections at the outbound ALE connect layers, the policy permits the selected allowed-app image when it runs as the selected user. Other app IDs running as that same user, including a child executable such as `curl.exe`, alternate executables, and a copy of the allowed executable at another path, match the user-wide TCP block. Another process using the exact same allowed executable path/app ID would also match the PERMIT rule; this is not a PID- or process-tree boundary.

This PoC does not protect UDP, QUIC, filesystem access, IPC, named pipes, shared memory, secrets readable by Codex, OOS data access, malicious kernel code, or against Administrator escape. It is not a complete Windows sandbox.

### Filter architecture

- Phase 2 uses its own dynamic-session sublayer, `WfpProcessSandbox User Isolation PoC Sublayer`, GUID `8ae41945-9f24-4e51-b356-8c3be4467e29`. It does not create a provider.
- It adds four filters at `FWPM_LAYER_ALE_AUTH_CONNECT_V4` and `FWPM_LAYER_ALE_AUTH_CONNECT_V6`: one PERMIT and one BLOCK filter per layer.
- Each PERMIT filter has exactly three conditions: `FWPM_CONDITION_ALE_USER_ID`, `FWPM_CONDITION_ALE_APP_ID`, and `FWPM_CONDITION_IP_PROTOCOL == IPPROTO_TCP`.
- Each BLOCK filter has exactly two conditions: `FWPM_CONDITION_ALE_USER_ID` and `FWPM_CONDITION_IP_PROTOCOL == IPPROTO_TCP`. It has no APP_ID condition.
- The PERMIT action is `FWP_ACTION_PERMIT`; the BLOCK action is `FWP_ACTION_BLOCK`.

### ALE_USER_ID handling

`LookupAccountNameW` resolves the supplied account to a SID, and `ConvertSidToStringSidW` creates the SID text for logging. The SID is placed in a `TRUSTEE_IS_SID` trustee. `BuildSecurityDescriptorW` builds a self-relative security descriptor whose DACL grants that SID `FWP_ACTRL_MATCH_FILTER`. The resulting bytes are supplied as `FWP_SECURITY_DESCRIPTOR_TYPE` for `FWPM_CONDITION_ALE_USER_ID`; the SID pointer or SID string is not used directly as the condition value. This follows Microsoft's [Permitting and Blocking Applications and Users](https://learn.microsoft.com/en-us/windows/win32/fwp/permitting-and-blocking-applications-and-users) sample pattern.

### Permit / Block ordering

All four filters use the same Phase 2 sublayer. The filter weight type is explicitly `FWP_UINT64` for both address families:

- PERMIT: `0xF000000000000000`
- BLOCK: `0x1000000000000000`

The higher-weight PERMIT is evaluated before the lower-weight BLOCK within the sublayer. `FWPM_FILTER_FLAG_CLEAR_ACTION_RIGHT` is not set, and no callout or custom override is used.

### Dynamic Session and transaction

The controller opens the WFP engine with `FWPM_SESSION_FLAG_DYNAMIC`. It starts an explicit WFP transaction, adds the Phase 2 sublayer and all four filters, and commits only after all additions succeed. An intermediate failure aborts the transaction; closing the engine handle ends the dynamic session and removes its WFP objects.

### Safety

The Phase 2 BLOCK filters always include `FWPM_CONDITION_ALE_USER_ID` and `FWPM_CONDITION_IP_PROTOCOL == IPPROTO_TCP`. There is no TCP-only global BLOCK filter. Phase 2 does not add persistent or boot-time filters, Windows Firewall rules, registry changes, a provider, kernel driver, or callout. `user-hold` checks for an elevated Administrator token before parsing its arguments or changing the WFP session.

### Manual WfpTestClient test plan

1. In an elevated controller PowerShell, start `WfpProcessSandbox.exe user-hold --user WfpCodexTest --allow-app <absolute-path-to-WfpTestClient.exe>` and wait for `USER_ISOLATION_ACTIVE`.
2. In a separate PowerShell session running as `WfpCodexTest`, run `WfpTestClient.exe tcp 1.1.1.1 443`. If the unfiltered route is reachable, expect `CONNECT_SUCCESS`.
3. In that same dedicated-user session, run `WfpTestClient.exe spawn-curl https://example.com/`. Expect the `curl.exe` connection to fail under the user-wide BLOCK.
4. Copy `WfpTestClient.exe` to a different path. As `WfpCodexTest`, run the copied executable with `tcp 1.1.1.1 443`. Expect `CONNECT_FAILED` when the baseline route is reachable.
5. From an unrelated Windows user, run the original `WfpTestClient.exe tcp 1.1.1.1 443`. Expect `CONNECT_SUCCESS` when the baseline route is reachable.
6. As `WfpCodexTest`, run the allowed app with `tcp 2606:4700:4700::1111 443` if the unfiltered IPv6 route is available. Expect `CONNECT_SUCCESS`.
7. Press Ctrl+C in the controller PowerShell to close the dynamic WFP session. After the controller exits, retry the allowed-app TCP command as `WfpCodexTest` and record whether connectivity is restored.
8. For a separate forced-termination check, start a fresh controller session, end only that `WfpProcessSandbox.exe` controller process, then retry the allowed-app TCP command as `WfpCodexTest` and record whether connectivity is restored.

### Observed Phase 2 results

Manual validation on the target Windows 11 machine completed successfully for the intended PoC scope:

- dedicated-user allowed-app IPv4 TCP: **PASS**
- dedicated-user allowed-app IPv6 TCP: **PASS**
- child `curl.exe` TCP blocking: **PASS**
- copied executable at another path blocked: **PASS**
- unrelated Windows user unaffected: **PASS**
- normal Dynamic Session cleanup: **PASS**
- Phase 2 forced-termination cleanup: **NOT RUN**

Phase 1 forced-termination cleanup was separately observed as **PASS**.

### Codex CLI E2E

Codex CLI 0.156.1 was installed for the dedicated standard user and tested with the native `codex.exe` as the allowed app.

- model communication without WFP: **PASS** (`CODEX_BASELINE_OK`)
- model communication under Phase 2 WFP: **PASS** (`CODEX_WFP_OK`)
- child `cmd.exe /d /c echo SHELL_WFP_OK`: **PASS**
- child `curl.exe https://example.com/`: **BLOCKED**
- Codex retry of curl "outside the sandbox": **BLOCKED**
- Codex remained able to report the blocked result over its own model connection: **PASS**
- after the WFP controller exited, direct `curl.exe https://example.com/` succeeded again: **PASS**

The default Codex Windows sandbox could not start even a baseline shell command because of an unrelated `setup refresh had errors` condition while WFP was disabled. The final WFP E2E therefore used `--sandbox danger-full-access` only to remove that unrelated variable; this is not a production recommendation.

### Limitations

The policy covers TCP authorization only at the two ALE connect layers, matches the permitted executable by WFP app ID, and relies on the dynamic session remaining active. It does not track process trees, distinguish different processes sharing the same allowed app ID, or isolate files, IPC, UDP/QUIC, credentials, or other operating-system resources. Phase 2 forced-termination cleanup was not separately re-run.

## Conclusion

Phase 1 showed that APP_ID-only filtering can block direct IPv4/IPv6 TCP (including loopback) but is not a sufficient security boundary because child executables and copied executables can escape. Phase 2 demonstrated that a dedicated Windows user plus user-wide TCP BLOCK and an explicit allowed-app PERMIT can keep Codex model communication working while blocking TCP from other app IDs under that dedicated user. The tested PoC scope is complete; it should not be interpreted as a complete Windows sandbox.
