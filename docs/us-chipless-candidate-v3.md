# 미국판 후보 v3 — 일반 헤드 청소의 더미 판정 우회

[v3 EFU 다운로드](https://raw.githubusercontent.com/ZanghyunCho/TX720/main/firmware/FWC365TL_US_chipless_candidate_v3_EXPERIMENTAL.efu)

**실제 청소·인쇄·복구 성공은 아직 확인하지 않은 실험 후보입니다.**
v2의 무칩 상태 전달·잔량 100%·스캐너 닫힘 수정을 유지합니다.
실제 잉크 공급이 필요하며, 잔량 표시는 실제 잉크 양을 측정하지 않습니다.

## 사용자 보고와 원인 추적

사용자는 v2 적용 후 작동한다고 보고했지만, 패널에서 헤드 청소를 누르면 움직이지 않고
바로 완료가 된다고 보고했습니다. 잉크를 채운 카트리지를 장착한 상태이며,
서비스 프로그램에서는 실제 청소가 된다고 추가 확인했습니다.

원본 일반 청소 함수 `0x41a45738`은 더미 카트리지 판정 `0x41a35e4c`가 1이면
청소 모드 선택이나 실행 함수를 호출하지 않고 0(성공)을 반환합니다.
v2의 합성 칩 데이터로 이 조건이 성립합니다. 명령 9 처리부 `0x41a4866c`도 이 함수를 호출합니다.

v3는 **이 호출 지점 `0x41a4573c`만** `bl 0x41a35e4c`에서 `mov r0,#0`으로 바꿉니다.
따라서 일반 청소의 이른 성공 반환을 건너뛰고 기존 모드 선택 `0x41a456b8`과
기존 실행 요청 `0x41a434a0`으로 진행합니다.
전역 더미 판정 함수나 다른 호출 지점을 바꾸지 않습니다.

## 압축 코드 수정

해당 명령어는 두 번째 IPL의 CROM 압축 데이터에 있습니다.
원래 ARM 압축 해제기를 추적해 대상이 포함된 블록과, 그 명령어를 역참조하는 후속 블록을 찾았습니다.
두 블록만 같은 출력 길이의 리터럴 블록으로 바꿉니다.
후속 블록을 함께 바꾸는 것은 역참조 때문에 다른 명령어까지 달라지는 것을 방지하기 위해서입니다.

압축 스트림은 241바이트 커지며 기존 `0xff` 여유 공간 안에 들어갑니다.
이미지 길이와 다른 리소스의 저장 위치를 유지하고, 두 번째 IPL의 합계·salted SHA-1을 갱신합니다.
첫 번째 IPL은 v2와 완전히 같습니다. 지역·버전 메타데이터도 유지합니다.

## 검증 범위

- v3 패키지에서 읽은 두 IPL로 원본 ARM CROM 압축 해제기를 실행했습니다. 이 단계에는 stub이 없습니다.
- 세 개 출력 영역의 길이를 확인했습니다.
- 원본 해제 결과와 비교해 **`0x41a4573c`~`0x41a4573f` 4바이트만 변경**됐습니다.
  나머지 코드·언어 리소스 및 두 초기 데이터 영역은 바이트 단위로 같습니다.
- v2/v3 일반 청소 함수와 명령 9 처리부를 모드 1·2·3, 실행 결과 0·1·`0x55`로 비교한 36건을 통과했습니다.
  v2는 더미 상태에서 실행 요청 없이 성공합니다. v3는 선택한 모드로 실행 요청을 보내고 결과를 반환합니다.
- 기존 명령의 이른 차단 조건 두 가지, 전역 더미 판정, 스택·보존 레지스터를 유지하는지 확인했습니다.
- ZIP CRC, 두 IPL의 합계·SHA-1, v2 첫 번째 IPL 보존과 정확한 CROM 블록 재구성을 확인했습니다.

청소 경로 비교에서는 모드 선택·하드웨어 실행·정리·준비 상태·응답 경계를 stub으로 대체합니다.
실제 모터·펌프를 에뮬레이션하거나 실기 청소 시간을 측정한 검사는 아닙니다.

[패치 기록](../reports/us-chipless-candidate-v3-patch.json),
[압축 해제·청소 경로 비교 결과](../reports/us-chipless-candidate-v3-validation.json),
[재현용 CROM 블록 계획](../tools/us-cleaning-crom-plan.json).

## 재현

정확한 공개 미국판 v2 파일에서 재현합니다. 빌드는 Python 표준 라이브러리만 필요합니다.
실행 검증에는 Unicorn 2.1.4와 원본에서 추출한 미국판 CROM 파일이 필요합니다.

```sh
python3 tools/patch_us_cleaning_v3.py firmware/FWC365TL_US_chipless_candidate_v2_EXPERIMENTAL.efu output/US_v3.efu --manifest output/patch.json
python3 tools/validate_us_cleaning_v3.py --analysis-root /path/to/firmware-analysis output/US_v3.efu --output output/validation.json
python3 tools/verify_packages.py
```

기존 출력은 덮어쓰지 않습니다. v2 파일과 기록도 그대로 보존합니다.
