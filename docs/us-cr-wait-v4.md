# 미국판 v4 — CR 보호 대기 우회 실험

[펌웨어 다운로드](https://raw.githubusercontent.com/ZanghyunCho/TX720/main/firmware/FWC365TL_US_v4_CR_wait_bypass_EXPERIMENTAL.efu)

미국판 v3를 바탕으로 CR 모터 보호 계산에서 **인쇄 전 추가 대기에 사용하는 CR 조회값**만
0으로 반환하도록 바꾼 후보입니다. PF(급지 모터) 대기 조회는 유지합니다.
스캐너 닫힘·무칩·잔량 100%·패널 청소 수정도 v3 그대로 포함합니다.

**CR 모터 열 보호의 대기를 우회합니다. 연속 출력 중 모터·구동 회로가 과열되거나 손상될 수 있습니다.**
실제 프린터에서 속도 개선·온도·안전성을 확인하지 않았습니다.
감속이 사라져도 안전 온도라는 의미는 아닙니다. 다른 원인의 감속은 남을 수 있습니다.
온도 검증 없이 대량 연속 출력이 안전하다고 판단하지 마세요.
이상 발열·냄새·구동음이 있으면 사용을 중단하고 전원을 분리하세요.

이전 상태로 돌아갈 때 사용할 [v3 파일](https://raw.githubusercontent.com/ZanghyunCho/TX720/main/firmware/FWC365TL_US_chipless_candidate_v3_EXPERIMENTAL.efu)도 유지합니다.
장치가 이전 버전 재기록을 받아들이는지까지 검증한 것은 아닙니다.
일본판에는 적용하지 않습니다.

## 변경 근거

압축 해제된 Xtensa 코드 `0x400aaa78`의 첫 네 바이트:

```text
213c0031 → 0c020df0
           movi.n a2,0
           ret.n
```

이 함수는 CR 표와 상태를 공통 구간별 계산 함수 `0x400acc84`에 전달합니다.
PF 조회는 별도 함수 `0x400aea08`이며 바꾸지 않습니다.
수신부 `0x400acf00`은 두 조회값의 최댓값을 ARM 쪽으로 반환합니다.
ARM `0x41a34428`은 이 값이 양수이면 인쇄 동작 전 대기 함수로 전달합니다.

따라서 모든 모터 보호를 일괄 삭제하는 변경이 아니라 이 경로의 CR 대기 기여분을 제거하는 변경입니다.
온도 모델의 전체 갱신 수식·모든 보호 경로·실제 모터 온도를 검증한 것은 아닙니다.
[세부 추적 기록](cr-heat-investigation.md).

## 검증 결과

- 원본 ARM CROM 압축 해제기를 실행해 세 구간을 모두 정상적으로 복원했습니다.
  v3 대비 Xtensa 구간에서 **의도한 네 바이트만** 다릅니다.
- 첫 IPL, 메타데이터, 나머지 압축 해제 구간, PF 조회·계수 표는 v3 그대로입니다.
  v3의 패널 청소 명령어 수정도 유지됩니다.
- Ghidra Xtensa p-code 에뮬레이션 **180개 사례**로 원본 CR/PF 조회를
  구간별 계산식과 비교하고, 수정 후 CR=0·PF 유지·스택 및 보존 레지스터 유지를 확인했습니다.
- Xtensa 분석에는 초기화 이후 Extended L32R 상수 풀 `0x80010000`을 반영한 별도 언어 모델을 썼습니다.
  기본 Ghidra Xtensa 언어만으로는 이 상수 풀이 올바르게 해석되지 않습니다.
  FLIX 확장의 의미는 모델링하지 않았으며 검증한 조회 경로에서는 실행하지 않습니다.
  실제 CPU 실행이나 물리 모터 에뮬레이션 검증은 아닙니다.

재압축 과정에서 발견된 잘못된 후보는 배포하지 않았습니다.
최종 블록 위치는 ARM 레지스터의 중간 카운터가 아닌 디코더 출력 컨텍스트의 실제 위치로 추적했고,
완성 패키지의 전체 압축 해제 결과를 비교해 확인했습니다.

- [빌드 보고서](../reports/us-cr-wait-v4-build.json)
- [원본 압축 해제기 검증](../reports/us-cr-wait-v4-native-validation.json)
- [Xtensa 조회 실행 검증](../reports/us-cr-wait-v4-query-validation.json)

SHA-256:

```text
eace524e8e4850c97ea31681b2dc7175ce60935f0a890393e888bef3c4ac17db
```

## 재현 도구

```bash
python3 tools/patch_us_cr_wait_v4.py \
  firmware/FWC365TL_US_chipless_candidate_v3_EXPERIMENTAL.efu \
  /tmp/TX720_US_v4.efu --manifest /tmp/TX720_US_v4-build.json

python3 tools/validate_us_cr_wait_v4.py --analysis-root /path/to/firmware-analysis \
  firmware/FWC365TL_US_chipless_candidate_v3_EXPERIMENTAL.efu \
  /tmp/TX720_US_v4.efu --output /tmp/TX720_US_v4-validation.json
```

원본 압축 해제기 검증은 Unicorn과 원본에서 추출한 미국판
`us/crom-extracted/{40000000,41a0d000,43e51000}.bin`이 필요합니다.
분석 루트의 `python-libs` 또는 Python 환경에 Unicorn을 설치합니다.

Xtensa 검증에는 Ghidra 12.2와 다음 도구를 제공합니다.

1. `python3 tools/prepare_tx720_xtensa.py /path/to/ghidra`로 별도 언어 소스를 생성합니다.
   출력된 `tx720_le.slaspec`을 해당 Ghidra의 `support/sleigh`로 컴파일합니다.
2. 원본 `40000000.bin`을 BinaryLoader, 베이스 `0x40000000`,
   언어 `Xtensa:LE:32:TX720core2`로 별도 프로젝트에 가져옵니다.
3. [CrWaitValidate.java](../tools/ghidra/CrWaitValidate.java)를 실행합니다.
   첫 스크립트 인자로 보고서 출력 경로를 지정할 수 있습니다.
   이 스크립트는 분석 프로젝트의 코드 네 바이트를 일시 수정해 검증한 뒤 복원합니다.
   실제 프린터와 통신하지 않습니다.

블록 재구성 계획은 [us-cr-wait-crom-plan.json](../tools/us-cr-wait-crom-plan.json)입니다.
