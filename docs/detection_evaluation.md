# 결정적 탐지 평가 기준선 (Phase 6)

Phase 6.2는 평가 수치나 trusted internal `analyze()` 계산 의미를 변경하지 않는다. 내부 원래 계정은 join을 위해 남을 수 있지만 평가 text/JSON은 승인된 scalar만 출력한다. Deprecated legacy API와 HTML 보고서의 공개 출력 migration은 [개인정보 경계 문서](public_analysis_privacy.md)에 기록한다.

## 목적과 범위

`uv run python -m app.evaluation`은 오프라인 `synthetic_boundary_corpus`에서 **현재 구현**의 parser·탐지·상관관계·risk·조사 사례 계약을 서로 분리해 검사한다. `--format json`과 `--scenario <고정 ID>`를 지원한다. 결과는 stdout에만 쓰고 네트워크·LLM·현재 시각·환경변수·난수·DB를 사용하지 않는다. 실패 시 종료 코드 1, 라벨·fixture 오류 시 2다. `--scenario`는 정확한 ID만 허용한다. JSON은 고정 필드와 정렬된 키, 고정 6자리 소수 문자열을 사용한다.

이 수치는 **합성·경계 시나리오에서의 구현 정확도**다. 실제 운영환경의 공격 탐지율이나 침해 확률이 아니다. 탐지는 침해 확정이 아니고 상관관계는 인과관계가 아니며 조사 사례는 incident verdict가 아니다.

## 현행 계약 확인표

| 계층 | 코드에서 확인한 기준 | 경계·제한 |
| --- | --- | --- |
| Brute Force | IP별 실패 5회 이상, 대상 계정 정확히 1개, 전체 실패 폭 60초 이하 | 5·60 포함; 전체 폭 기준, 부분 슬라이딩 창 아님 |
| Password Spraying-like | IP별 실패 4회 이상, 대상 계정 3개 이상, 전체 실패 폭 60초 이하 | 4·3·60 포함; 같은 계정 반복은 계정 수 증가 아님 |
| Path Traversal | 반복 percent-decode 후 path 또는 query에 `../` 또는 `..\` 포함 | HTTP status와 무관하게 관찰; 200은 파일 접근 성공 증거 아님 |
| Failed Login → Successful Login | 동일 IP·계정, 실패가 성공보다 **앞**, 60초 이하 | 0초/역전 제외, 60초 포함, 60초+1µs 제외 |
| Brute Force → Successful Login | Brute 탐지 선행, 동일 IP·계정, 마지막 실패 뒤 성공 60초 이하 | 동일 경계; 탐지 시작부터의 전체 사례 범위는 별도 case 최대 120초 |
| Spray → Successful Login | 탐지와 동일 IP·계정 실패 뒤 성공 60초 이하 | production relation은 있지만 typed target membership이 없어 Spray case는 no-go |
| 정규화 | application·SSH는 `Asia/Seoul`; access는 로그 내 `%z`; 내부 UTC aware | 파일 parser는 초 단위 시각; 직접 normalized-event 테스트로 µs 경계 검사 |
| 중복·순서 (Phase 6 당시) | 실패 이벤트는 중복도 횟수에 포함; subject ordering은 case assembler의 IPv4/IPv6 numeric 순서 | 동일 subject에 여러 성공 후보가 있으면 correlation의 첫 matching success 선택은 입력순서에 영향받았음. Phase 6.1 수정은 아래 참조 |
| Risk/confidence | HIGH/MEDIUM/LOW categorical; likelihood×impact matrix와 별도 confidence | 새로운 score 없음; 1~2 실패 후 인증 관계만 있는 경우 risk LOW, confidence MEDIUM 가능 |
| Case | Brute-success가 generic auth 관계에 우선; Path Traversal 독립 | Spray-success no-go, 미지원 관계는 자동 결합하지 않음 |

위 표는 Phase 6 시작 시 코드 기준이다. 기존 문서와 상충하는 경우 이 평가에서 규칙을 바꾸지 않았다. 파일 시각이 초 단위라는 점 때문에 파일 fixture만으로 `+1µs`를 표기할 수 없으며, 이를 별도 normalized-event 단위 테스트로 분리했다.

## Typed 라벨과 fixture

`app/evaluation/corpus.py`의 frozen `EvaluationScenario`는 고정 ID·설명·source·고정 fixture 이름·`ExpectedParser`·`ExpectedDetection`·`ExpectedRelation`·`ExpectedRisk`·`ExpectedCase`·독립 관찰 수·경계 근거·한계를 담는다. fixture는 `sample_logs/evaluation/`의 작은 UTF-8 합성 로그만 사용한다. 예약 IP 대역과 합성 계정을 사용하며 실제 credential/token/cookie는 없다. account 원문은 fixture 내부 join에만 존재하고 CLI 출력·JSON에는 들어가지 않는다. raw line·query·fixture 경로도 결과에 복사하지 않는다. 중복 ID, 모르는 type/level, naive label timestamp, 잘못된 fixture 이름은 평가 전 fail closed다.

고정 시나리오 21개: `login_only`, `brute_below`, `brute_exact`, `brute_over_window`, `brute_success`, `brute_other_account`, `brute_success_late`, `spray_exact`, `spray_success`, `spray_below_accounts`, `spray_over_window`, `auth_transition`, `auth_transition_late`, `traversal`, `normal_web`, `brute_above`, `low_failures`, `spray_below_failures`, `success_before`, `traversal_raw`, `traversal_false_like`. 기대값은 승인된 threshold·relation·case 계약과 명시적 음성 경계에서 작성했고 실행 결과를 golden으로 복사하지 않았다.

## 계층별 비교와 metric

Parser는 line/parsed/ignored/failed 수, event type·subject·account 존재 여부·HTTP method/status·첫/마지막 canonical UTC를 비교한다. Detection은 시나리오의 고정 subject별 type 존재와 승인된 failure count·target count·window·시간 범위를 비교한다. Correlation은 type과 정확한 failure/success endpoint를 비교한다. Risk는 기존 risk level·confidence와 likelihood/impact/confidence rationale 및 evidence 필드 존재를 비교한다. Case는 규칙·순서·최고 위험도·supporting relation·기대 observation 수·독립 관찰 수와 Timeline 내 관찰/관계 수 일치를 비교한다. 지원되지 않은 Spray case는 만들지 않는다. 실패를 0건의 정상 분석으로 변환하지 않는다.

Detection별 TP/FP/FN/TN은 시나리오당 각 type의 기대·실제 존재로 계산한다. support=TP+FN. Correlation은 relation type별 TP/FP/FN만 계산하며 TN·accuracy는 정의하지 않는다. 두 계층을 합쳐 점수화하지 않는다.

```text
precision = TP / (TP + FP)
recall = TP / (TP + FN)
F1 = 2 × precision × recall / (precision + recall)
```

분모 0은 `not_applicable`이다. F1은 동치인 `2TP/(2TP+FP+FN)`으로 계산한다. 이 작은 fixture의 support를 운영 데이터로 일반화할 수 없고 같은 fixture로 규칙을 조정한 뒤 같은 fixture로 평가하면 과적합된다.

## Phase 6 baseline (2026-10-09)

21/21 시나리오 통과, parser 75/75 line parse(ignored 0, failed 0), risk 21/21, case 21/21. 실패 시나리오 없음.

| Detection | TP | FP | FN | TN | precision | recall | F1 | support |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| Brute Force | 6 | 0 | 0 | 15 | 1.000000 | 1.000000 | 1.000000 | 6 |
| Password Spraying-like | 2 | 0 | 0 | 19 | 1.000000 | 1.000000 | 1.000000 | 2 |
| Path Traversal | 2 | 0 | 0 | 19 | 1.000000 | 1.000000 | 1.000000 | 2 |

| Relation | TP | FP | FN | precision | recall | F1 |
| --- | ---: | ---: | ---: | ---: | ---: | ---: |
| Failed Login → Successful Login | 3 | 0 | 0 | 1.000000 | 1.000000 | 1.000000 |
| Brute Force → Successful Login | 1 | 0 | 0 | 1.000000 | 1.000000 | 1.000000 |
| Password Spray → Successful Login | 1 | 0 | 0 | 1.000000 | 1.000000 | 1.000000 |

## 외부 공개 데이터셋 조사 (공식 출처, 2026-10-09 확인)

| 후보/공식 배포처 | 형식·라벨·시각 | 크기·라이선스/개인정보 | 현재 parser 적합성 |
| --- | --- | --- | --- |
| [UNB CIC-IDS2017](https://www.unb.ca/cic/datasets/ids-2017.html) | 2017년 7월 5일 PCAP 및 timestamp/IP/protocol/attack label이 있는 network-flow CSV; SSH brute와 web attack 포함 | 일별 11+11+13+7.8+8.3 GB; 재배포·인용 조건은 배포처 정책 재확인 필요; packet payload 개인정보 검토 필요 | **직접 비교 불가**: 현재 auth/access parser의 계정·HTTP path 라벨과 flow 라벨이 다름. 변환기만으로 의미 동등성 보장 불가 |
| [UNB CSE-CIC-IDS2018](https://www.unb.ca/cic/datasets/ids-2018.html) | PCAP/flow CSV와 일부 로그, attack/benign label·시각 | 대용량 AWS 배포, 정확한 선택 파일 크기 확인 전 다운로드 보류; 원본 payload 개인정보·재배포 조건 검토 필요 | **변환기·라벨 검증 필요**; 현 parser 직접 입력 불가 |
| [Loghub HDFS/BGL](https://github.com/logpai/loghub) | HDFS/BGL 시스템 로그의 anomaly label·timestamp | HDFS v1 약 1.47 GiB, BGL 약 709 MiB; 공개 repository의 dataset별 사용/재배포 조건과 비식별화 확인 필요 | **라벨 의미가 달라 비교 불가**: 인증 실패·성공, traversal label이 아님 |
| 공개 SSH auth 로그 | 현재 공식 배포처·정확한 account 단위 label·라이선스가 검증된 후보 없음 | 크기·개인정보 미확인 | **보류**. 이름만 보고 corpus에 편입하지 않음 |

외부 데이터셋을 자동 다운로드하거나 이 커밋에 포함하지 않는다. 위 자료의 공격 라벨은 이 프로젝트의 5회/4회/60초 임계값을 승인하는 외부 표준이 아니다.

## 한계와 Phase 6.1 절차

21개 파일 fixture 외에 normalized-event 단위 테스트는 다중 IP 관계 분리, IPv4/IPv6 순서, 입력 순서 반전, 60초+1µs, naive timestamp 거부, 중복 실패 이벤트 계수, HTTP 5xx에서의 Path Traversal 관찰, Spray relation의 사례 no-go를 확인한다. 이들은 CLI corpus metric의 support에 포함하지 않는다.

현재 파일 fixture는 parser 실패·ignored line, SSH, 다중 subject 파일, 모든 URL pattern, 동일 relation 중복, 여러 성공 후보 입력순서, 실제 운영 오탐/미탐을 완전히 포괄하지 않는다. 보완은 새로운 **독립 라벨**과 작은 합성 fixture를 먼저 추가한 뒤 수행한다. 특히 다중 성공 후보의 순서성은 현 production correlation의 계약 위험으로 분리해 기록한다. parser 파일 시각은 초 단위이므로 µs 단위는 normalized-event 테스트로만 측정한다.

Phase 6.1에서 실패가 나면 `scenario / expected / actual / affected layer / likely cause / privacy-safe reproduction / recommended follow-up`을 기록하고, telemetry 근거와 오탐·미탐 tradeoff를 검토한 별도 커밋에서만 규칙을 바꾼다. 이 Phase 6은 detector threshold, correlation window, risk, parser 의미, case grouping을 변경하지 않았다.

## Phase 6.1 — SSH·parser 경계와 결정적 관계 선택

2026-10-09 기준 고정 ID 21개를 유지하면서 22개를 추가해 총 **43개**다. SSH 13개는 실제 `ssh` registry/parser 경로를 사용한다. 정상 publickey 성공, password 실패 1회·4회·5회/60초, 같은/다른 계정 성공, 성공 선행, 파일 입력 순서와 다른 두 성공 후보를 평가한다. SSH의 `Failed|Accepted password|publickey for ... from ...`만 positive 라벨이며, 지원하지 않는 문구는 timestamp가 맞으면 `event_type=None`인 parsed event다. 새 SSH 문법은 추가하지 않았다.

Parser-only 9개는 production `analyze()`를 호출하지 않는다. SSH unsupported/잘못된 timestamp/whitespace/extra text/잘못된 IP, application 잘못된 timestamp·IP 누락, access 불완전 요청·빈 line을 직접 parser에 전달한다. `parsed`는 `NormalizedEvent` 반환, `ignored`는 `None`, `rejected`(`failed` JSON 필드)는 parser/UTC 정규화 예외를 뜻한다. SSH unsupported와 잘못된 IP, application의 IP 누락은 **parsed지만 attribution이 되지 않거나 후속 adapter에서 거부**될 수 있다. Invalid UTF-8은 decode·loader 또는 로컬 업로드 경계에서 parser 전에 거부되므로 parser 통계로 세지 않는다. 줄별 typed 기대 disposition과 실제를 비교해 `unexpected_parse_count`, `unexpected_rejection_count`를 별도로 낸다. Parser-only의 분석 결과를 정상 0건으로 위장하지 않는다.

정상 활동 중심 추가 항목은 같은 IP의 다수 성공·같은 시각 성공, 한 번 실패 후 정상 재시도, 모니터링 계정 성공, 집중된 웹 health/metrics 요청과 정상 query·점·percent·HTTP 404/500이다. 정상 재시도도 기존 **인증 관계는 positive**이며 탐지만 negative다. `automation_ambiguous`는 현재 규칙상 Brute 관찰이지만 승인된 자동화 여부가 로그에 없으므로 `ambiguous_operational`로 분리한다. 분석·risk·case 계약은 비교하되 detection/correlation confusion matrix에서는 제외하고 고정 이유와 개수를 출력한다. 이는 실제 FP를 0으로 단정하기 위한 조치가 아니다.

### 성공 후보 선택 정책

수정 전에는 세 인증 관계 함수가 `ip_logs` 입력 순서의 첫 matching success에서 반환했다. 테스트는 같은 실패 뒤 10초·20초 성공에서 20초 기록이 먼저 입력되면 20초 endpoint를 고르는 실패를 먼저 재현했다. 현재는 per-IP 입력의 동일 subject·정확한 account, 실패가 성공보다 엄격히 앞서고 기존 60초 범위 안인 **모든 쌍**의 delta를 비교해 가장 작은 양의 delta 쌍 하나를 선택한다. Production pipeline timestamp는 parser가 canonical UTC로 정규화한다. 직접 호출하는 오래된 단위 테스트의 naive timestamp는 기존 함수 계약을 유지하되, naive/aware 혼합은 후보에서 제외한다. 60초 포함, 0초·역전 제외와 120초 case 상한은 변경하지 않았다.

최소 delta의 완전히 같은 event 쌍(모든 내부 필드가 같은 duplicate)은 한 endpoint fact로 접는다. 같은 최소 delta에서 source·auth context·raw record 등 내부 event 내용이 다른 쌍이나 서로 다른 timestamp 쌍은 안전한 유일 후보를 입증할 수 없어 관계 없음으로 fail closed한다. Raw record는 동률 판별에서 **정확한 중복 여부 확인에만** 쓰고 선택 key·반환값·평가 출력에 복사하지 않는다. UUID/hash/object identity/입력 위치는 쓰지 않는다. 이는 외부 보안 표준의 새 임계값이 아니라 기존 관계에서 입력순서 비결정성을 제거하기 위한 프로젝트 선택 정책이다. 정상 단일-success fixture의 출력은 유지된다.

후보가 모호해 관계가 없어지면 기존 risk의 correlation signal과 case 존재 여부도 달라질 수 있다. 이것은 새 risk 계산이나 case 규칙이 아니라 부정확한 관계를 fail closed한 결과다. Raw 내부 correlation dict는 기존 adapter join 때문에 원래 account와 rationale을 포함하므로 **그 객체의 직접 `repr()`은 개인정보 안전 경계가 아니다**. CLI 평가 text/JSON, case assembly/projection, bounded error에는 원래 account·raw line·query·경로를 넣지 않는다. 내부 dict를 로그에 출력해서는 안 된다.

### 갱신된 baseline

43/43 시나리오 통과. Parser는 입력 134줄 중 parsed 129, ignored 2, rejected 3; unexpected parse/rejection 각 0이다. SSH 시나리오 13개. Parser-only 9개를 제외한 risk·case는 각각 34/34. Ambiguous operational 1개는 confusion matrix에서 제외해 labeled denominator는 33개다.

| Detection | TP | FP | FN | TN | precision | recall | F1 | support |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| Brute Force | 11 | 0 | 0 | 22 | 1.000000 | 1.000000 | 1.000000 | 11 |
| Password Spraying-like | 2 | 0 | 0 | 31 | 1.000000 | 1.000000 | 1.000000 | 2 |
| Path Traversal | 2 | 0 | 0 | 31 | 1.000000 | 1.000000 | 1.000000 | 2 |

| Relation | TP | FP | FN | precision | recall | F1 |
| --- | ---: | ---: | ---: | ---: | ---: | ---: |
| Failed Login → Successful Login | 6 | 0 | 0 | 1.000000 | 1.000000 | 1.000000 |
| Brute Force → Successful Login | 3 | 0 | 0 | 1.000000 | 1.000000 | 1.000000 |
| Password Spray → Successful Login | 1 | 0 | 0 | 1.000000 | 1.000000 | 1.000000 |

외부 근거: [NIST SP 800-92의 rule-based event correlation 정의](https://csrc.nist.gov/glossary/term/Rule_Based_Event_Correlation)는 timestamp, IP, event type 등 관찰 가능한 필드의 결합을 설명하지만 특정 closest-success 정책이나 60초를 지정하지 않는다. [OpenSSH 공식 매뉴얼](https://www.openssh.org/manual.html)과 [sshd_config의 인증·로그 설정](https://man.openbsd.org/sshd_config)은 password/publickey 및 logging 설정의 배경이다. 실제 `Failed`/`Accepted` 줄 해석은 저장소의 SSH parser regex에 한정한다. 두 자료를 이 프로젝트 임계값의 권위로 사용하지 않는다.

남은 공백: 실제 운영 로그·승인 활동 ground truth, 여러 source의 동시각 distinct event identity, parser 이전의 invalid UTF-8/업로드 검증, 모든 parser 오류 형태, cross-worker·live 순서, 성공·실패 시각이 동률인 일부 데이터 품질 문제. 합성 수치의 운영 일반화는 금지한다.

## Phase 8 — 웹 요청 관찰 확장 (2026-10-10)

기존 43개 ID·라벨·계산 의미를 유지하고 36개 작은 NCSA fixture를 추가해 **79/79** 시나리오다. 새 fixture는 SQLi-like·XSS-like·민감 리소스 요청의 명확한 category와 일반 단어/문서/asset/단독 quote·주석/잘못된 percent encoding의 음성 경계를 분리한다. Scanning 양성은 임계값 정확 충족(`web_scan_exact`), 초과(`web_scan_above`), 60초 정확 경계(`web_scan_boundary`)를 독립 라벨로 평가한다. request 수 부족, 중복 대상, 정상 asset burst는 음성 라벨이다. 파일 parser는 초 단위이므로 60초+1µs·입력 permutation·같은 요청 반복 및 복합 유형은 별도 normalized-event 불변식 테스트이며 support에 포함하지 않는다. 이 수치는 포함 라벨에만 유효하고 실제 운영환경 precision/recall이 아니다. 상세 관찰 계약과 공식 자료는 [웹 요청 설계](web_attack_observation_design.md)에 있다.

Parser: 200줄 중 parsed 195, ignored 2, rejected 3, 예상 밖 parse/rejection 0. Risk·case는 각각 70/70. Ambiguous operational 1개는 기존과 같이 confusion matrix에서 제외한다. 기존 인증 관계 TP는 6/3/1, FP/FN 0으로 유지됐다.

| Detection | TP | FP | FN | TN | precision | recall | F1 | support |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| Brute Force | 11 | 0 | 0 | 58 | 1.000000 | 1.000000 | 1.000000 | 11 |
| Password Spraying-like | 2 | 0 | 0 | 67 | 1.000000 | 1.000000 | 1.000000 | 2 |
| Path Traversal | 2 | 0 | 0 | 67 | 1.000000 | 1.000000 | 1.000000 | 2 |
| SQL Injection-like | 5 | 0 | 0 | 64 | 1.000000 | 1.000000 | 1.000000 | 5 |
| XSS-like | 5 | 0 | 0 | 64 | 1.000000 | 1.000000 | 1.000000 | 5 |
| Sensitive Resource Probing-like | 4 | 0 | 0 | 65 | 1.000000 | 1.000000 | 1.000000 | 4 |
| Web Scanning-like | 3 | 0 | 0 | 66 | 1.000000 | 1.000000 | 1.000000 | 3 |

특히 Scanning support=3도 작은 합성 표본이므로 이 1.0 수치를 일반화할 수 없다. `request_count`는 선택된 60초 창의 실제 eligible request event 수로 반복 target·동일 raw line도 각각 세며, `distinct_target_count`만 canonical target identity 수다. stable ingestion ID가 없어 원본 event는 중복 제거하지 않는다. 가장 이른 적격 시작점의 최대 60초 창에서 최종 observation 하나만 생성한다. 승인된 스캐너와 NAT/proxy, 운영 로그 누락, Unicode/encoding 변형 및 실제 악성/정상 ground truth는 평가 공백이다.

## Phase 9 — 별도 Linux 프로세스 실행 분류 평가 (2026-10-10)

기존 **79/79** IP 기반 parser·detection·correlation·risk·case 시나리오와 위 confusion matrix는 변경하지 않는다. `linux_process_execution_evaluation`은 별도 합성 Linux Audit fixture **21/21**개를 parser → normalized process event → 기존 count-only aggregate와 새 typed classifier 순서로 확인한다. 셸 4건, 네트워크 전송 도구 4건, 권한·소유권 변경 도구 3건, 임시 디렉터리 실행 4건의 category 관찰이 라벨과 일치한다. `linux_temp_curl`과 `linux_temp_bash`는 한 실행이 두 category에 속하므로 category 합계 15는 classified unique execution 수와 같은 의미가 아니다. 이름 유사·경로 sibling·CWD-only·식별 불일치 등 non-match는 별도 unclassified로 남는다. Outcome·aggregate consistency는 각각 21/21이다.

Linux category metric은 expected/actual observation 수, false/missed category assignment, expected unique execution 수를 별도로 제시한다. Category assignment의 precision·recall은 포함된 라벨에서만 계산하고 분모가 0이면 `not_applicable`이다. TN universe가 정의되지 않아 IP 탐지의 TN·accuracy를 재사용하지 않는다. CLI text와 JSON은 같은 고정 수치를 담고 JSON은 정렬된 key와 결정적 순서로 출력한다. `--scenario`는 기존 79개 IP 시나리오만 필터링하며 Linux 21개 section은 독립적으로 유지된다. 평가 fixture 안의 argv·path·node·serial 원문은 결과에 복사하지 않는다. 같은 fixture에서 만든 합성 라벨은 운영환경 악성 탐지율이 아니며 정상 관리·자동화 사용, Audit 정책의 누락, `comm` truncation, `argv[0]` spoofing은 남은 평가 공백이다. 분류·보호 경계는 [Linux Audit 프로세스 실행 문서](linux_audit_process_execution.md)를 참고한다.

Phase 9.1 로컬 웹 화면은 같은 Phase 9 분류기와 별도 privacy-safe 범주 집계를 사용한다. 기존 79개 인증·웹 시나리오 및 Linux 21개 오프라인 시나리오의 라벨·metric을 변경하지 않는다. 웹 UI가 추가되어도 합성 평가 일치도를 운영환경 악성 탐지율로 일반화할 수 없다.

## DETECT-1 — Path Traversal 참조 범위의 측정된 한계

이 절의 결과·현행이라는 표현은 **DETECT-1 당시 v1 정책**의 역사적 기록이다. DETECT-2 이후의 production v2 결과와 구분한다. 원 manifest·fixture·라벨·hash는 그대로 두며, 재현 테스트는 byte-identical한 test-only v1 detector를 명시적으로 주입한다. 새 정책의 정답 oracle로 사용하지 않는다.

기준 main `88a5716b9332bd673ee0806429487bec3bca261c`, 동결 evidence commit `5f3c26aa809a6b38e8349009c45dec9539ea6650`, 최초 확인일 2026-11-15, P2 의미 감사일 2026-11-16. **Production 변경 없음, 원 판정 `DETECT_1_EVIDENCE_ONLY` 유지**.

**측정 범위: `FROZEN_INTERNAL_LABEL_AGREEMENT_ONLY` — 동결 내부 라벨과의 일치도입니다. RFC 3986 문법 정확도가 아닙니다. 테스트 통과는 라벨의 의미적 타당성을 검증하지 않습니다.**

P2 감사 결과, 동결 라벨은 하나의 일관된 참조 명제를 따르지 않는다. Literal path 문법, 프로젝트 decoding/역슬래시 신호, query의 lexical 신호와 backend 해석의 불확실성이 섞여 있다. 아래 TP/FP/FN/TN과 precision/recall/F1은 이 **혼합 의미의 동결 라벨표에 대한 산술 재현값**으로만 보존한다. 라벨의 정답성, 현행 탐지 계약의 구현 정확도, RFC 적합성, 실제 공격 탐지율의 증거로 인용하지 않는다. 해시 목록의 기존 `label_scope` 문자열도 당시 metadata로 보존할 뿐 단일 oracle이 검증됐다는 뜻이 아니다.

### 기존 평가 감사와 선택 근거

기존 `detector_accuracy_cli --format json`은 별도 46개를 유지한다. 각 탐지기의 TP/FP/FN/TN과 양성/음성 support는 Brute 4/0/0/3 (4/3), Spray 2/0/0/5 (2/5), Traversal 5/0/0/1 (5/1), SQLi 4/0/0/2 (4/2), XSS 4/0/0/1 (4/1), Sensitive 4/0/0/2 (4/2), Scanning 3/0/0/4 (3/4)다. Parser 제외 0, 계정 관측 부족의 미확정 라벨 2개(Brute·Spray 각 1), 합성 운영 false-alert 후보 7개다. 승인된 재시도·점검·문서 검색도 관측 패턴을 충족하면 TP이며 승인 맥락만으로 FP로 바꾸지 않는다.

기존 Traversal은 encoding·query·backslash·오류 응답·문서 검색을 포함하지만 음성은 점을 포함하는 일반 이름 한 사례다. 코드의 `../`·`..\\` 부분 문자열 검사와 **완전한 부모 구성요소**의 차이, 마지막 부모 구성요소, 매핑 경로 동등성을 보여주지 못한다. 따라서 이번에는 `path_traversal` 하나만 선택했다. 기존 79개·Linux 21개 및 auth 전용 counterfactual development 16개·holdout 14개는 바꾸거나 새 challenge support에 합치지 않는다. Auth 전용 mutation/label 정책을 웹 입력에 억지로 적용하거나 새 평가 엔진을 만들지 않는다. 기존 `detector_accuracy.evaluate(manifest_path)`와 `Confusion`을 그대로 재사용한다.

### Research Basis와 관찰 필드 연결

- RFC Editor, [RFC 3986 §3.3·§3.4·§5.2.4](https://www.rfc-editor.org/rfc/rfc3986#section-3.3), 2005-01, P2 재확인 2026-11-16: 완전한 두 점 path 구성요소와 일반 이름의 일부를 구분하며 마지막 구성요소도 참조 해석에 포함한다. Query는 별도의 비계층적 데이터다. Query 문자열을 path로 취급해 dot-segment 해석을 적용할 수 없다. 이 사실은 일부 동결 라벨의 근거이지만 라벨표 전체가 RFC oracle이라는 근거는 아니다.
- OWASP, [Path Traversal](https://owasp.org/www-community/attacks/Path_Traversal), 게시일 미표시·P2 재확인 2026-11-16: percent encoding·backslash 변형과 OS별 파일명 처리를 고려해야 한다. 이는 조사 신호와 backend 확인 필요성을 설명하며, RFC의 path 문법이나 이 fixture의 실제 서버 동작을 대신 정의하지 않는다.
- MITRE, [CWE-22](https://cwe.mitre.org/data/definitions/22.html), v5.0 갱신 2026-10-28: 제한된 디렉터리 밖으로의 경로 해석이 약점의 핵심이다. 요청 필드·HTTP 상태만으로 실제 파일 접근이나 경계 이탈을 알 수 없으므로 성공·악의성 라벨을 만들지 않았다.

관찰 연결은 **원 요청 URI → parser가 분리한 `NormalizedEvent.http.path/query` → 현행 반복 `unquote`와 부분 문자열 관찰**이다. 이 pipeline의 결과와 동결 내부 라벨을 비교한다. 반복 percent-decoding은 프로젝트 처리이며 RFC의 literal 문법 판정과 같지 않다. Unicode folding이나 backend 파일 처리도 수행·검증하지 않는다. 현행 decoding·공개 Evidence·탐지 임계값·시간 창·Risk는 그대로다.

### 실행 전 고정한 14개

`sample_logs/detect_1_path_reference/manifest.json`은 기존 정확도 manifest schema다. CLF와 수동 선택 JSONL 표현, 라벨 근거와 운영 맥락을 함께 고정했다. 근거가 기록돼 있다는 사실과 그 근거가 하나의 명제로 일관되게 적용됐다는 평가는 구분한다. 원본 target·IP·query를 평가 출력에 넣지 않는다.

### 명제 A–E와 실제 fixture 감사

- **A — literal path 문법**: 원문 path를 slash로 분리했을 때 완전한 ASCII 두 점 구성요소가 있는가. Percent-decoding 전의 관찰이며 query는 포함하지 않는다. 이것은 RFC 전체 적합성 검사가 아니다.
- **B — 프로젝트 신호**: 현행 반복 `unquote` 후 path 또는 query에 두 점과 slash/backslash의 부분 문자열이 있는가. 완전한 구성요소 경계를 요구하지 않으므로 A와 다르다.
- **C — query lexical 신호**: query에 어떤 문자 신호가 있는가. 매개변수가 실제 파일 경로인지, RFC path 참조로 평가되는지 증명하지 않는다.
- **D — backend 해석**: 서버·OS·라우트가 입력을 재작성하거나 파일 경로로 처리하는가. **모든 14개에서 검증되지 않았다.**
- **E — 실제 의도·성공**: 실제 악의성·승인·exploit 성공인가. **모든 14개에서 입증되지 않았다.** 아래 운영 맥락은 내부 합성 설정이며 E의 ground truth가 아니다.

두 표현의 실제 request 값과 parser의 path/query 분리를 읽어 확인했다. 다음 표의 A–C는 관찰 설명이며 **기존 라벨의 변경이나 승인표가 아니다**. d07은 입력 문자열을 읽을 수 있어도 calendar 오류로 pipeline에서 거부된다. 그 외 13개는 인식됐다.

| ID suffix (`detect1_` 접두사) | A: literal path 부모 구성요소 | B: 프로젝트 신호 | C: query 관찰 | 동결 label / 합성 맥락 |
| --- | --- | --- | --- | --- |
| d01_named_dot_suffix | 없음; 일반 이름의 두 점 suffix | 있음; suffix 부분 문자열 | query 없음 | PATTERN_ABSENT / KNOWN_BENIGN |
| d02_named_three_dots | 없음; 일반 이름의 세 점 suffix | 있음; suffix 부분 문자열 | query 없음 | PATTERN_ABSENT / KNOWN_BENIGN |
| d03_encoded_named_suffix | 없음; percent-encoded 이름 suffix | 있음; decoding 뒤 이름 suffix | query 없음 | PATTERN_ABSENT / KNOWN_BENIGN |
| d04_parent_with_leaf | 있음; 부모 구성요소 뒤 leaf | 있음 | query 없음 | PATTERN_PRESENT / SIMULATED_ATTACK |
| d05_terminal_parent | 있음; 마지막 부모 구성요소 | 없음; 뒤 구분자 없음 | query 없음 | PATTERN_PRESENT / SIMULATED_ATTACK |
| d06_document_query | 없음 | 있음; query에서 일치 | ASCII 상대 참조 문자 신호 | PATTERN_PRESENT / KNOWN_BENIGN |
| d07_invalid_calendar | 입력에는 있음 | 입력에는 신호가 있지만 분석 제외 | query 없음 | PATTERN_PRESENT / UNVERIFIED |
| v01_encoded_named_component | 없음; percent-encoded 이름 suffix | 있음; decoding 뒤 이름 suffix | query 없음 | PATTERN_ABSENT / KNOWN_BENIGN |
| v02_encoded_terminal_parent | literal 두 점 없음 | 없음; decoding 후 마지막 두 점만 남음 | query 없음 | PATTERN_PRESENT / UNVERIFIED |
| v03_terminal_parent_with_query | 있음; 마지막 부모 구성요소 | 없음 | 일반 query; 부모 참조 토큰 없음 | PATTERN_PRESENT / SIMULATED_ATTACK |
| v04_backslash_query | 없음 | 있음; decoding 뒤 query에서 일치 | encoded 역슬래시·혼합 구분자 | PATTERN_PRESENT / AMBIGUOUS |
| v05_current_directory | 없음; 한 점 구성요소 | 없음 | query 없음 | PATTERN_ABSENT / KNOWN_BENIGN |
| v06_bare_dot_run | 없음; path의 3점 구성요소 | 있음; 그 안의 부분 문자열 | query 없음 | PATTERN_UNDETERMINED / AMBIGUOUS |
| v07_unicode_dot_alias | 없음; 해당 문자는 path에 없음 | 없음; ASCII 토큰으로 folding하지 않음 | percent-decoding 후 U+FF0E 두 개와 slash | PATTERN_UNDETERMINED / UNVERIFIED |

필수 telemetry는 시각·관측 IP·HTTP method·원 path·status, query 사례는 query도 포함한다. JSONL의 키는 고정 승인 mapping으로 연결하며 protocol·response size를 만들지 않는다. 두 표현의 공통 정규화 필드를 먼저 비교하고, 그 뒤 기존 pipeline의 탐지·실제 evidence(없는 response size 제외)·관계·위험도를 비교한다. **14개 논리 사례이며 28개 독립 표본이 아니다.** 모든 자료·라벨은 이번 개발 과정에서 내부 구성한 비민감 합성 자료다. 독립 인간 검토나 실제 운영 ground truth가 아니다.

최초 후보 실행 전 manifest SHA-256은 `040c3d2f394c50d985ee158ef7337c0bc7a8c314e5f2d75c3a032c2fbb8c61cd`, 전체 fixture·manifest hash 목록 SHA-256은 `c95f142b87ae8686cbcd2c3277736f3657c73286a3ee40b30a7d5f459e2a659b`로 고정했다. Hash 목록 자체의 digest는 테스트에 별도로 고정하며 재봉인으로 라벨을 바꾸지 않는다. 개발 7개 실행 후 Production을 변경하지 않기로 결정하고 나머지 검증 7개를 처음 실행했다.

### 제외 분모와 v06/v07의 의미

| 제외 ID | 기존 evaluator 분류 | 보존하는 이유 |
| --- | --- | --- |
| detect1_d07_invalid_calendar | PARSER_EXCLUDED | calendar 오류로 거부된 입력은 detector 음성으로 세지 않음 |
| detect1_v06_bare_dot_run | LABEL_UNDETERMINED | backend의 dot 처리 정보 부족이라는 원 동결 판단을 보존 |
| detect1_v07_unicode_dot_alias | LABEL_UNDETERMINED | query의 Unicode folding·파일 처리 정보 부족이라는 원 동결 판단을 보존 |

v06은 literal path의 3점 구성요소다. A에서는 완전한 두 점 구성요소가 없고, B에서는 그 일부가 부분 문자열 검사에 일치한다. 원래 미확정 판단은 **D의 불확실성**을 이유로 했다. 이 이유는 순수한 A 문법의 존재 여부를 미확정으로 만들지는 않는다.

v07의 전각 마침표 두 개는 **path가 아니라 query 값**을 percent-decode한 뒤 나타난다. 현행 처리는 이를 ASCII 두 점으로 Unicode folding하지 않는다. 원래 미확정 판단은 이 query가 backend에서 어떻게 처리되는지 모른다는 **C→D 해석 공백** 때문이었다. RFC path 문법의 불확실성이라고 설명할 수 없으며, query에 path의 dot-segment 규칙을 적용해서도 안 된다.

따라서 두 제외는 **당시 동결 내부 라벨표의 제외 규칙**으로 재현할 수 있지만, A만을 일관되게 평가한 제외 기준으로 정당화할 수 없다. 반대로 D를 명제로 삼으면 다른 12개도 backend ground truth가 없다. 두 라벨을 사후에 양성/음성으로 재분류하거나 분모를 다시 계산하지 않았다. d01/d02/d03/v01의 이름 suffix 판단, d06/v04의 query 신호, v02의 decoding 뒤 마지막 구성요소 판단도 A 하나로 동일시하지 않는다.

### 지표 — 동결 내부 라벨과의 일치도만 재현

14개 중 동결 양성 6개·음성 5개가 점수 분모 11개를 구성한다. 미확정 2개와 parser 거부 1개는 위와 같이 제외한다. 기존 evaluator의 TP/FP/FN/TN 및 precision/recall/F1 명칭을 유지하되, 이 표에서는 혼합 의미의 내부 라벨에 대한 일치/불일치 분류만 뜻한다.

| 범위 | TP | FP | FN | TN | 양성/음성 support | 미확정/parser 제외 | precision / recall / F1 |
| --- | ---: | ---: | ---: | ---: | --- | --- | --- |
| 개발 7개 | 2 | 3 | 1 | 0 | 3 / 3 | 0 / 1 | 0.400000 / 0.666667 / 0.500000 |
| 별도 검증 7개 | 1 | 1 | 2 | 1 | 3 / 2 | 2 / 0 | 0.500000 / 0.333333 / 0.400000 |
| 전체 14개 | 3 | 4 | 3 | 1 | 6 / 5 | 2 / 1 | 0.428571 / 0.500000 / 0.461538 |

CLF와 JSONL mapping의 공통 event 사실 및 해당 결과가 일치했다. 동결 라벨상 양성인데 non-match인 3개와 음성인데 match인 4개가 위 FN/FP 칸에 들어간다. 이는 단일하게 검증된 부모 참조 정의의 FP/FN이나 현행 substring 계약의 구현 결함을 확정하지 않는다. 운영 false-alert 후보 5개 중 문서 query는 동결 라벨상 TP다. 실제 파일 접근·공격 성공·악의성의 오탐/미탐으로 해석하지 않는다. 기존 46개 평가와 이 표는 같은 모집단·같은 명제를 측정하지 않는다.

재사용 evaluator의 `synthetic_detector_pattern_accuracy` 및 `DETECTOR_FALSE_POSITIVE/NEGATIVE` 같은 출력 이름에는 이 P2 범위가 자동으로 들어가지 않는다. DETECT-1 결과를 인용할 때는 반드시 **동결 내부 라벨 일치도, 혼합 의미, 위 세 제외 규칙**을 함께 제시해야 한다. Raw summary나 숫자만으로 RFC 정확도·정책 타당성을 주장할 수 없다.

Production 보정을 하지 않았다. 현행 API adapter는 `path_pattern`을 두 구분자 패턴으로 제한한다. 관측되지 않은 뒤 구분자를 만들거나 mixed label 점수를 올리기 위해 공개 Evidence·탐지 명제를 바꾸지 않았다. Backend 정규화·파일 처리의 불확실성을 A 문법이나 E의 안전 판정으로 전환하지 않는다. 결과는 동일하며 Production RED/GREEN은 해당하지 않는다.

### 별도 버전 감사가 필요한 범위와 PR 통합 한계

이번 P2에서 새 metric·라벨·corpus는 만들지 않는다. 단일 RFC 문법 또는 명시적으로 정한 decoding 정책의 지표가 필요하다면 **14개 전부**를 별도 버전의 동일한 명제로 감사해야 한다. 우선 확인 대상은 제외 의미가 섞인 v06/v07, query 범위인 d06/v04/v07, percent-decoding 범위인 d03/v01/v02, parser 단위인 d07이다. 나머지 대조 사례도 새 명제와 동일하게 평가해야 한다. 이 요구는 원 동결 라벨의 타당성 승인이나 사후 재분류가 아니다.

P2 판정은 `DETECT_1_P2_DOCUMENTED_LIMITATION`이다. PR은 **동결 자료·기존 동작의 특성 기록·방법론적 한계 공개** 범위로 통합할 수 있다. 단일한 참조 기준의 정확도 검증, 탐지 보정 완료, 라벨 정책 승인 또는 운영 GO로 소개할 수 없다. PR 설명의 Findings에도 지표가 혼합 의미의 동결 라벨표와의 일치도라는 점을 포함해야 한다.

회귀는 고정 hash·현재 결과 재현·정규화 동등성·문서의 측정 범위와 제외 분모·개인정보 경계를 보호한다. 라벨의 의미적 정답성을 assert하지 않는다. 새 framework/CLI는 없으며 `uv run pytest -q tests/test_detect_1_path_reference.py`로 재현한다. 실제 운영 정확도, 승인 활동의 오탐률, 서버 취약 여부·파일 접근 성공·로그 진위는 계속 미검증이다. 추가로 필요한 근거는 proxy/backend의 target 재작성·정규화 설정, 라우트 처리와 파일 접근 기록, 승인 활동 맥락이다. Snapshot payload·source pin·개인정보 공개 계약·기존 46/79/21 및 S1 HOLD·운영 NO_GO는 바꾸지 않는다.

## DETECT-2 — 관찰 종류를 구분한 Path Traversal v2

### Research Basis와 관찰 명제

- IETF [RFC 3986](https://www.rfc-editor.org/rfc/rfc3986), 2005-01: §2.1의 `%HH`, §3.3의 완전한 dot-segment와 마지막 `..`, §3.4의 비계층 query, §5.2.4의 dot-segment 처리를 구분한다. §2.4는 같은 문자열의 반복 decoding을 URI 표준 처리로 사용하지 말라고 경고한다. 따라서 아래 제한된 반복 decoding은 **프로젝트의 의심 문자열 탐색 heuristic**이며 RFC 정규화·서버 동작 재현이 아니다.
- [OWASP Path Traversal](https://owasp.org/www-community/attacks/Path_Traversal), 발행일 미표기: encoding·이중 encoding·운영체제별 separator 예시는 탐색 대상의 근거다. 이 설명이 임의 backend의 해석이나 모든 encoding 지원을 보장하지 않는다.
- MITRE [CWE-22](https://cwe.mitre.org/data/definitions/22.html), CWE 5.0 / 2026-10-28 갱신: 제한 디렉터리 밖의 자원 접근은 backend가 경로를 처리하는 조건을 포함한다. Access 로그의 요청 문자열만으로 취약점·허용 디렉터리 이탈을 입증할 수 없다.

| 명제 | 필요한 관찰 → 저장소 필드 → 조건 | 결론의 한계 |
| --- | --- | --- |
| A | 원문 target의 path → `NormalizedEvent.http.path` → `/`로 분리한 완전한 ASCII `..` 구성요소 | literal path 구문 관찰, 끝의 `..` 포함 |
| B | 같은 path → 최대 3단계 strict percent-decoding → 완전한 `..` 구성요소 | RFC 규범이 아닌 프로젝트 heuristic |
| C | target의 query → `http.query` → 제한된 decoding 뒤 `../` 또는 `..\\` 문자열 | query는 비계층 자료이며 검색·문서화에서도 나타남 |
| D | proxy/backend 재작성·라우팅·파일 경로 처리 기록 | 현재 로그만으로 미확정 |
| E | 승인 맥락·파일 접근/권한·실제 응답 내용 등 | 공격 목적·악용 성공·취약점은 미확정, HTTP 200도 증거가 아님 |

### Production 계약과 소비자

`path_traversal` 타입은 유지하되 A/B/C와 backend 의존 역슬래시 관찰의 **합집합**이다. path의 일반 이름 `filename..`·`file...` 내부는 일치하지 않는다. 마지막 부모 구성요소는 관찰된 그대로 `path_pattern=".."`이며 존재하지 않는 `/`를 붙이지 않는다. Unicode 유사 점은 ASCII로 접지 않는다. 역슬래시는 URI 표준 separator라고 주장하지 않는다.

새 내부 Evidence `path_observation_kind`는 다음 네 고정 코드만 허용한다. 원문 path에서 먼저 찾고 없으면 decoding 결과, 그 뒤 query를 확인하므로 이벤트당 대표 관찰 하나다.

| 고정 코드 | 의미 |
| --- | --- |
| `PATH_PARENT_SEGMENT` | 원문 path의 `/` 경계 완전한 부모 구성요소 |
| `DECODED_PATH_PARENT_REFERENCE` | decoding 뒤 path의 부모 참조 형태 |
| `BACKSLASH_PARENT_REFERENCE` | 부모 참조 경계에 역슬래시가 있는 backend 의존 형태 |
| `QUERY_REFERENCE_STRING` | query의 부모 참조형 부분 문자열, backend path라고 해석하지 않음 |

Query의 `file=../…`와 `q=../…`는 같은 C 관찰이다. 파라미터 이름으로 파일 처리·악의성을 추정하지 않는다. 따라서 정상 검색/문서화도 계속 관찰될 수 있다. 역슬래시·query는 경로 구성요소 A의 정확도에 합쳐 보고하지 않는다. 아래 표의 명제는 명시된 v2 관찰 합집합이며 RFC 정확도가 아니다.

내부의 decoded path/query는 종전처럼 private다. Incident adapter는 고정 kind와 실제 pattern 조합을 검증한 뒤 redacted Evidence만 전달한다. V1 investigation API/UI는 기존 redacted 구조를 유지하고 고정 reason 문구에서 path 또는 질의 문자열이며 서버 해석·공격 의도 미확인임을 명시한다. Legacy API는 **기존** `pattern_category`에 한국어 고정 범주만 채운다. 보고서 projection의 `observation_kind`와 HTML/CLI 범주도 고정 allowlist다. 경로·query·원래 IP·원문·미선택 mapping 필드를 새 공개 출력에 넣지 않는다. Terminal `..`는 v2 범주가 있어야 승인되며, 알 수 없는 kind는 거부한다. 과거 v1의 `../`·`..\\` Evidence reader는 동결 재현 및 기존 입력 계약을 위해 유지한다.

단일 IP의 기존 한 개 detection slot은 가장 이른 timestamp를 대표로 선택한다. 같은 시각은 고정 범주 순서, method/status/size, private path/query의 사전순으로 결정해 입력 순서에 의존하지 않는다. Private target은 동률 해소에만 쓰고 식별자·hash·공개 Evidence로 만들지 않는다. 위험 계산식·상관관계·threshold는 변경하지 않았다. 대표 관찰 또는 탐지 여부가 달라지면 기존 risk 계산에 들어가는 사실은 달라질 수 있다. 이 slot은 전체 traversal 이벤트 수나 관찰 종류별 건수를 뜻하지 않는다.

### Decoding 범위와 미평가

`decode_url()`은 각 component에 UTF-8 8,192 bytes, 최대 3 transform layer를 적용한다. 값은 표준 임계값이 아닌 고정 엔지니어링 자원 제한이다. 최대 3번의 선형 탐색이며 URL decoding이 입력 크기를 증폭시키지 않는다. 원래 `%HH`를 검사하고 UTF-8 strict decoding을 사용한다. `%25`에서 나온 literal percent는 보존하고 plus를 공백으로 바꾸지 않는다. control/format/surrogate, malformed escape, invalid UTF-8, 범위 초과는 `None`으로 **미평가** 처리한다. 잘못된 encoding을 replacement 문자로 손실 복구하지 않는다. 다른 웹 Detector의 `_bounded_decode()`는 변경하지 않았다.

지원 범위 밖은 정상·안전·TN이 아니다. 기존 DetectionResult의 non-match는 이 규칙의 지원된 관찰이 없다는 뜻만 가진다. 별도 미평가 건수를 공개하거나 입력 인식 완료를 전체 규칙 평가 완료로 바꾸지 않는다. 원문에 분명한 참조와 잘못된 encoding이 섞이면 decoding은 profile 밖이다. P2 보정 이후에는 독립적인 원문 관찰을 보존하고 encoding 미평가 사유를 별도로 전달한다. 4단계 이상 encoding·Unicode/backend 변형은 회피/미관찰 가능성이 남는다. Parser가 먼저 거부한 입력도 detector 음성으로 세지 않는다.

### 독립 합성 사례와 변경 전후

`tests/test_path_traversal_semantics_detect_2.py`는 DETECT-1 라벨을 재활용하지 않는다. 개발 기대값을 Production 변경 전에 작성했고 처음 14개에서 11개 assertion이 RED였다. 후속 8개 검증의 mixed percent-data query가 decoder 결함을 드러내 수정에 사용됐다. 이를 수정에 사용하지 않은 검증이라고 부르지 않는다. 그 뒤 별도의 최종 8개를 고정하고 실행했다. 내부 작성 합성이며 독립 사람 검토·현실 ground truth가 아니다.

표 순서는 TP / FP / FN / TN이며, encoding profile 밖은 제외한다. FP/FN은 선언된 문자열 명제와의 차이이고 운영 공격/정상 라벨이 아니다. Query·역슬래시 관찰의 악의성은 이 분모에 없다.

| 집합 | 유효 분모 / 범위 밖 | v1 | v2 |
| --- | --- | --- | --- |
| 개발 14 | 12 / 2 | 6 / 2 / 1 / 3 | 7 / 0 / 0 / 5 |
| 수정에 사용된 후속 8 | 7 / 1 | 3 / 1 / 1 / 2 | 4 / 0 / 0 / 3 |
| 별도 최종 검증 8 | 6 / 2 | 3 / 2 / 1 / 0 | 4 / 0 / 0 / 2 |

같은 명제·같은 유효 분모에서만 비교했다. DETECT-1의 11 scored 사례와 합산·성능 비교하지 않는다. 단일 사례별 관찰과 기존 `Confusion` 산술만 재사용하며 새 평가 엔진은 없다. CLF/Combined·고정 Nginx JSON·수동 mapping은 parser disposition과 공통 event 필드를 먼저 비교한 뒤 detection/Evidence·Correlation·Risk·API/HTML 개인정보 경계를 비교한다. 서로 다른 protocol/response-size/raw는 존재하지 않는 값으로 채우지 않는다. 실제 backend 악용이나 실제 Nginx 요청 수용을 실험한 것은 아니다.

### 동결 증거와 Snapshot

DETECT-1 전체 fixture bytes·manifest·labels·hashes는 불변이다. `FROZEN_INTERNAL_LABEL_AGREEMENT_ONLY`와 혼합 라벨 제외 규칙도 그대로다. `tests/detect1_path_policy_v1.py`의 세 함수 source tail은 기준 commit `b0a5dcb4b56101e1f20312527da1bbe3664ef196`과 동일하며 SHA-256 `8473bd6994e5e466b626909b385a023001062ec33661d7aed9f01d55def1a976`로 검사한다. `app/`은 이 replay helper를 import하지 않는다. 기존 모든 assertion·3/4/3/1 결과는 v1에 대해 보존하고 v2는 위 별도 명제로 검증한다. unbounded v1 decoder는 고정 비민감 historical fixture 재현 전용이다.

Snapshot은 현재 탐지 성능 보고서가 아니라 기존 auth counterfactual 결과다. 초기 DETECT-2에서는 37개 source pin 중 변경된 5개만 실제 소스 hash로 갱신했으며 pin 수·payload schema·13,783 bytes·기존 asset SHA-256을 유지한다. 이전 pin 거부, 신규 pin 검증, 추가 필드·재봉인 변조 거부, 전달 기본 OFF를 계속 검사한다. S1 HOLD와 운영 NO_GO는 변경하지 않는다. 추가 backend telemetry·승인 맥락·real-world 평가 없이 서버 취약점·공격 성공·운영 탐지율을 주장할 수 없다.

### PR #7 P2 — 원문 관찰과 인코딩 평가 상태 분리

초기 v2는 `decode_url(path) is None`에서 즉시 일반 음성을 반환했다. 이는 다른 부분의 잘못된 escape/UTF-8 때문에 이미 관찰되는 완전한 ASCII `..`를 억제했다. 또한 미평가가 ordinary negative와 구별되지 않았다. RFC 3986 §2.1/§3.3/§3.4와 위 OWASP·CWE 근거를 다시 확인했다. 전체 URI가 적합하거나 backend가 해석한다고 주장하지 않고, 제한된 원문 문자열에서 독립적으로 성립하는 구성요소 관찰을 보존한다.

`DetectionResult`에 내부 optional `unassessed_reason` 하나를 추가했다. 허용 값은 `None` 또는 고정 코드 `PATH_REFERENCE_ENCODING`뿐이다. 이유는 입력·경로·query·개수·IP를 담지 않는다. 이 필드는 API DTO에 추가되지 않는다.

| 상태 | `is_detected` | `unassessed_reason` | 해석 |
| --- | --- | --- | --- |
| 지원 범위의 음성 | false | None | 선언된 문자열 관찰 없음. 안전 판정 아님 |
| 양성 근거 없는 미평가 | false | 고정 코드 | encoded 관찰 판단 불가. TN이 아님 |
| 원문/지원된 view에서 확정 관찰 + 일부 미평가 | true | 고정 코드 | 관찰은 유지하지만 다른 인코딩 평가가 완료됐다는 뜻은 아님 |
| 지원 범위에서 관찰 | true | None | 선언된 관찰만 확인. backend·의도·성공 미확정 |

Path와 query의 원문 관찰은 decoding 성공을 전제로 하지 않는다. 기존 자원/문자 한도 안에서 path는 완전한 부모 구성요소, query는 기존 `../`·`..\\` lexical 관찰만 찾는다. 원문 query에서도 의미를 추측하지 않는다. Decoding이 불가능한 path는 새 **private** Evidence `url_original_path`로 명시하고, 이를 `url_decoded_path`라고 이름 붙이지 않는다. 둘은 정확히 하나만 허용하며, original path로 decoded-path kind를 주장할 수 없다. 정상 decoding 결과와 기존 v1 Evidence는 그대로 읽는다. Replacement character를 사용하지 않는다.

공개 API의 key/schema는 유지한다. Legacy의 미평가 음성은 기존 `pattern_category`에 고정된 ‘인코딩 관찰 평가 미완료’를 표시하고 risk limitation에도 고정 안내를 추가한다. 로컬 investigation은 기존 `bounded_warnings`, HTML/LLM용 projection은 기존 limitation, CLI Evidence는 고정 안내를 사용한다. 원문·미선택 JSON 필드·잘못된 escape 값은 내보내지 않는다. CLI의 기존 검증된 IP subject header는 변경하지 않았으며 Evidence/notice에 새 IP를 넣지 않는다. bool만 읽는 소비자는 지원 음성과 미평가를 구별할 수 없으므로 함께 제공되는 category/경고를 읽어야 한다.

동일 IP에 미평가 레코드가 하나라도 있으면 대표 관찰에 관계없이 고정 사유를 보존한다. 기존 가장 이른 대표 관찰 선택과 입력 순서 불변성은 유지한다. 이 상태는 해당 IP 입력 집합의 인코딩 미평가를 뜻하며 선택된 이벤트의 성공/실패나 위험도를 추가 추정하지 않는다. Risk·Correlation 계산식은 그대로다. Live에는 미평가 전달 계약이 없으므로 기존 invariant failure로 prepare를 거부하며 결과·history를 commit하지 않는다. 새 live schema나 publication을 추가하지 않는다.

CLF와 고정 Nginx JSON Parser는 `/a/../%FF`, `/a/../%GG`, `/a/%2525252e%2525252e/` 같은 문자열을 정상화할 수 있다. 승인형 mapping은 기존 URI 검증 때문에 `%GG`는 worker 전에 거부한다. 이 parser 차이를 변경하지 않는다. `%FF`·깊은 encoding은 mapping에서 정상화돼도 detector의 encoded-reference 평가가 미완료일 수 있다. Parser 인식 완료는 모든 규칙 평가 완료가 아니다.

`tests/test_path_traversal_p2.py`의 focused RED는 6 failed / 3 passed였다. 원문 관찰 유실과 미평가→일반 음성 축약을 재현했다. 예외로 요청 전체를 중단하는 방안은 production 변경 전에 검토했으나, 기존 malformed-query 사례의 다른 웹 규칙 분석까지 차단하므로 채택하지 않았다. 고정 상태와 기존 공개 경고 경로로 보정했다. 테스트 오류에는 source-derived 값 대신 고정 메시지와 고정 case ID를 사용한다.

평가의 fixture·라벨은 변경하지 않는다. 기존 79개 중 `web_sql_malformed_percent`는 SQL lexical 음성을 그대로 평가하되 Path Traversal의 encoded-query 음성을 입증하지 못한다. 따라서 해당 규칙 TN을 **67→66**, 신규 `excluded_unassessed=1`로 명시한다. TP=2/FP=0/FN=0과 다른 규칙의 분모는 유지한다. 평가 CLI의 기존 metric에 이 제외 수를 추가하며 text/JSON 둘 다 표시한다. 이는 점수 향상이나 라벨 변경이 아니라 미평가를 TN에서 제거한 것이다. 46개 detector-accuracy evaluator는 unassessed non-match를 만나면 기존 bounded `analysis_failed`로 중단하여 TN으로 세지 않는다. 기존 46개에는 이 제외 입력이 없어 결과가 유지된다.

DETECT-1의 동결 bytes·manifest·라벨·v1 replay는 불변이다. Snapshot 13,783 bytes도 재생성하지 않는다. P2에서 수정된 기존 pinned 소스 6개의 정확한 hash만 갱신하고 pin 수 37개를 유지한다. 미평가 안내는 공격 판단도 안전 판단도 아니며 운영 NO_GO와 S1 HOLD를 변경하지 않는다.
