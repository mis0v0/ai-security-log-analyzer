# Phase 24.2 — deterministic locked dependency evidence bundle

**판정: CONDITIONAL GO (macOS 로컬 evidence 생성).** `uv.lock`을 resolution의 권위 있는 입력으로 유지하면서, artifact hash가 있는 runtime/development requirements와 CycloneDX 1.5 graph를 별도 계층으로 검증한다. Ubuntu 실행·CI gate·vulnerability DB·license 판단·릴리스 asset은 포함하지 않는다. Phase 24.1의 OSV-Scanner와 deprecated `-S` SBOM 입력은 여전히 **공식 release gate NO-GO**다.

## 경계와 실제 사용

`uv run python -m scripts.dependency_evidence_bundle_24_2`는 현재 checkout의 `pyproject.toml`·`uv.lock`만 읽는다. 현재 고정된 uv **0.11.26**의 `uv export --locked --offline`을 실행한다. runtime은 `--no-dev`, development-inclusive는 기본 dev group을 사용한다. 두 requirements export에는 `--no-emit-project --no-header --no-annotate`를 적용하고 hash를 제거하지 않는다. CycloneDX는 uv의 `--preview-features sbom-export --format cyclonedx1.5` 출력이다. 출력·uv cache는 전용 임시 위치에 두고 검증 후 제거한다. CLI는 경로나 파일 내용 없이 count와 lock digest 앞 12자리만 출력한다. 보존이 필요한 경우 내부 `create_bundle(project, fresh_private_output)` API를 사용해야 하며, 임의 public 디렉터리에 자동 저장하지 않는다.

`uv export --help`에서 확인한 `--no-dev`, `--no-emit-project`, hash 기본 포함, CycloneDX preview, `--locked`, `--offline` 외 옵션을 가정하지 않는다. `uv.lock`의 현재 schema v1/revision 3, registry source, root virtual package, artifact URL/hash만 명시적으로 받는다. local/editable 또는 다른 registry/source가 생기면 자동 승인하지 않고 `LOCKFILE_UNSUPPORTED`다. `uv.lock` parser는 resolver가 아니며, **closure는 uv export가 결정**한다. Requirements의 각 package/version에 나열된 모든 artifact SHA-256의 **집합**을 lock과 대조한다. Marker/platform 분기는 uv의 locked export 의미에 맡기며, export의 marker 문자열을 독립적으로 해석·재작성하지 않는다. 따라서 requirements에는 여러 플랫폼 wheel hash가 함께 있다. 특정 OS에서 실제 선택된 wheel의 설치 증거라고 주장하지 않는다.

## Bundle 계약

private directory `0700`, 각 file `0600`이다. 기존 output·symlink parent·잘못된 owner/mode는 거부한다. known file만 생성·검증하며 실패 시 생성된 known file만 정리한다. 파일 단위 임시 쓰기→fsync→rename을 사용한다. 디렉터리 전체를 단일 원자 transaction으로 공개한다고 주장하지 않으며, default CLI는 임시 위치에서만 실행해 완료 전 artifact를 외부 소비자에게 제공하지 않는다. 삭제는 secure erase가 아니다.

| 파일 | 역할 | checksum 의미 |
| --- | --- | --- |
| `runtime-requirements.txt` | runtime locked package/version/marker와 가능한 artifact hash | 원본 file bytes SHA-256 |
| `development-requirements.txt` | runtime + dev locked package/version/marker/hash | 원본 file bytes SHA-256 |
| `runtime.cdx.json`, `development.cdx.json` | **수정하지 않은** CycloneDX 1.5 component·dependency graph | manifest에는 **canonical graph** SHA-256; raw bytes는 `checksums.sha256`에만 |
| `manifest.json` | schema/policy v1, project name/version/Python contract, uv version, lock digest, scope count, 위 파일 이름·digest kind·digest, 고정 validation 상태 | 결정적 JSON bytes |
| `checksums.sha256` | 다섯 evidence 파일의 실제 byte SHA-256 | 원본 CycloneDX의 UUID·timestamp 때문에 비결정적 |

Manifest는 닫힌 key 집합을 검증한다. timestamp, machine ID, 절대 경로, hostname, 계정·IP·원문·credential, scanner finding, `ZERO_FINDINGS` 문구를 담지 않는다. 원본 CycloneDX에는 `serialNumber` UUID와 `metadata.timestamp`가 매 실행 달라진다. 이를 제거한 파일을 공식 SBOM처럼 가장하지 않는다. `manifest.json`은 원본 SBOM byte hash가 아닌 graph semantic digest를 기록하므로 반복·UTC/KST에서 byte-identical할 수 있다. 실제 원본 파일 무결성은 별도의 **비결정적** `checksums.sha256`과 post-write validator가 확인한다. 두 digest 종류를 혼동하면 안 된다.

현재 macOS arm64의 실제 checkout에서 root `0.2.0`, lock root 포함 58 package, runtime **37** package·artifact hash **534**, development-inclusive **57** package·artifact hash **804**다. CycloneDX component/graph entry는 각각 37/38, 57/58이다. runtime에 Hypothesis·Schemathesis는 없고 dev-inclusive에는 있다. macOS installed environment의 55개와 lock/export의 57개는 platform marker 때문에 같지 않으며 이것은 **lock inventory**, 설치된 binary inventory가 아니다. `uv.lock` SHA-256은 `7a943f2eba872d356fad4618d1c887428a0f18eaf3491b923d50055ca7edd40e`다. Requirements bytes, manifest bytes, canonical graph는 두 실행과 UTC/Asia/Seoul에서 일치했다. 원본 CycloneDX bytes와 `checksums.sha256`의 동일성은 요구하지 않는다.

## 실패·개인정보·후속 경계

고정 오류 코드는 `LOCKFILE_INVALID`, `LOCKFILE_UNSUPPORTED`, `EXPORT_FAILED`, `EXPORT_CONTAINS_CREDENTIAL`, `EXPORT_HASH_MISMATCH`, `RUNTIME_SCOPE_MISMATCH`, `DEVELOPMENT_SCOPE_MISMATCH`, `CYCLONEDX_INVALID`, `BUNDLE_INCOMPLETE`, `BUNDLE_WRITE_FAILED`, `BUNDLE_VALIDATION_FAILED`다. 내부 예외·절대 경로·export/SBOM 원문을 CLI에 출력하지 않는다. 현재 공식 PyPI registry와 files.pythonhosted artifact HTTPS URL만 허용하며 credential URL은 거부한다. `uv --no-config --offline`에 최소 환경을 전달하고 별도 임시 cache를 사용한다. 일반 stdout/stderr에 raw bundle을 출력하지 않는다. 민감한 실제 로그·config·checkpoint·`.env`를 입력으로 쓰지 않는다. 임시 output은 명시적으로 정리하지만 filesystem snapshot·backup의 잔존이나 secure erase 부재를 숨기지 않는다.

License는 installed distribution metadata, PyPI metadata와 원본 package license의 차이를 별도로 검토해야 하며 이번 manifest의 필수 무결성 필드가 아니다. unknown/dual license를 임의 값으로 축약하지 않는다. Vulnerability는 특정 DB snapshot의 조회 결과이고 package의 단순 존재가 exploitability가 아니다. Phase 24.1의 OSV `-L`은 SBOM을 0 package로 추출해 false zero를 냈고 `-S`는 deprecated다. 따라서 이 bundle을 OSV와 자동 연결하거나 0 finding을 주장하지 않는다. 향후 공식 지원 입력과 package count가 검증되기 전까지 자동 vulnerability gate는 NO-GO다.

개발용 5회 warm 표본은 median **1.165초**, nearest-rank p95/max **1.209초**였다(uv export 4회, 별도 private uv cache, private write/validation 포함; macOS arm64, uv 0.11.26). 네트워크 사용·실제 DB scan은 없다. 운영 SLA나 CI 상한이 아니다. PR 후보는 임시 bundle 생성·계약·결정성 검증 후 삭제이며 이번 단계에 workflow를 추가하지 않았다. Scheduled/release vulnerability 검사는 별도 provenance·DB snapshot gate가 필요하다. raw SBOM/report를 GitHub artifact로 업로드하거나 공개 Release에 첨부하려면 별도 승인이다.

## SEC-4-R2 Ubuntu CI toolchain candidate

위 Phase 24.2 기록은 당시 도구와 측정 결과다. CI 후보는 Ubuntu 24.04 x86_64 GNU에서 다음 두 파일을 고정한다.

| 배포 저장소와 태그 | 아카이브 | 공개 SHA-256 |
| --- | --- | --- |
| `astral-sh/uv` · `0.13.9` | `uv-x86_64-unknown-linux-gnu.tar.gz` | `a7fbaff2b9a271d85c1bdb540941090fd1ce011797b4abeb48e4dcd39c2471d5` |
| `astral-sh/python-build-standalone` · `20261110` | `cpython-3.12.16+20261110-x86_64-unknown-linux-gnu-install_only_stripped.tar.gz` | `6a9e62dad033790aef722dbd370e0ce76ce17b73627ba3ae679f537049350b39` |

uv 0.13.9의 오프라인 카탈로그와 일치하는 Python stripped 변형이다. 별도의 `install_only.tar.gz`는 SHA-256 `c2f87d4b4e8db3abddb0f116c6ccfc503d0cbdbb9ee8faacddad1b679ec12e99`를 가지며 이 워크플로의 입력 범위 밖이다. 두 upstream GitHub Release의 공개 메타데이터에서 이름·해시와 태그 대상 커밋을 대조했다. [uv 릴리스](https://github.com/astral-sh/uv/releases/tag/0.13.9), [Python 릴리스](https://github.com/astral-sh/python-build-standalone/releases/tag/20261110)

CI는 정확한 이름의 파일만 받아 SHA-256을 검사한다. 이어 `gh release verify-asset`으로 GitHub의 서명된 릴리스 attestation을 검증해 digest와 저장소·태그를 결속한다. 별도로 `gh attestation verify`는 Astral 빌드 증명이 SLSA provenance v1이며 서명 저장소와 `.github/workflows/release.yml`, 빌드 소스 ref `refs/heads/main` 및 태그가 가리키는 고정 소스 커밋과 일치하는지 검증한다. 이 빌드 ref와 릴리스 태그는 서로 다른 검증 항목이다. 공개 메타데이터에서 두 종류의 증명이 각 digest에 등록된 것을 확인했다. Python 빌드 증명은 self-hosted upstream runner를 기록한다. [GitHub 릴리스 검증](https://cli.github.com/manual/gh_release_verify-asset), [GitHub 빌드 증명 검증](https://cli.github.com/manual/gh_attestation_verify)

두 아카이브가 모두 검증된 뒤에만 임시 디렉터리에 추출한다. 누락·불일치·검증기 오류는 작업을 실패시키며 이전 도구로 되돌아가는 경로는 없다. 워크플로는 캐시를 사용하지 않고 검증한 Python의 절대 경로를 선택하며 Python 자동 다운로드를 금지한다. 기존 locked/no-build 설치와 revision 3 증거 검사는 유지한다.

로컬 테스트는 검증기 성공·오류를 합성 fixture로 대체해 제어 흐름을 확인했다. 실제 Ubuntu 아카이브 다운로드, 암호학적 검증, 추출·실행, locked 설치 및 전체 CI는 미검증이다. 별도 승인 후 Ubuntu 24.04에서 읽기 전용 토큰을 사용하는 러너 제공 `gh`의 두 검증 명령이 모두 성공하는지 확인하고, 후보 SHA의 고정 버전·lock·증거 번들·전체 회귀 결과를 기록한다. 브라우저와 실제 HTTP 검증은 별도 게이트다. `INSTALL_HOLD`를 유지한다.
