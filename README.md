# EPSON TX720WD — 스캐너 유닛 닫힘 판정 실험

힌지 손상으로 스캐너 유닛을 닫힌 상태로 유지하기 어려운 기기의 펌웨어를 분석한 프로젝트입니다.
센서 입력을 읽는 ARM 코드 두 곳을 항상 닫힘 값으로 반환하도록 수정합니다.

**실제 프린터의 업데이트·부팅·인쇄·스캔·복구는 검증하지 않은 실험본입니다.**
패치 후 유닛을 열어도 닫힘으로 인식하도록 의도했으므로 내부 작업은 전원 플러그를 빼고 하세요.

## 미국판 무칩·100% 후속 실험 후보

[미국판 v2 다운로드](https://raw.githubusercontent.com/ZanghyunCho/TX720/main/firmware/FWC365TL_US_chipless_candidate_v2_EXPERIMENTAL.efu) · [변경 및 검증 범위](docs/us-chipless-candidate-v2.md)

v1에서 남았던 장착·잉크 종료 상태 전달 경로를 추가로 수정한 후보입니다.
원본 상태 판정 코드의 수정 전/후 오류 비교는 통과했지만 **실제 부팅·인쇄는 아직 미검증**입니다.
스캐너 닫힘 패치를 포함합니다. 빈 카트리지 상태로 인쇄·헤드 청소를 하지 마세요.

## 스캐너 닫힘 전용 다운로드

| 제공받은 원본 구분 | 원본 버전 / 대상 식별자 | 수정본 |
| --- | --- | --- |
| 미국/영어판 — `FWC365TL.efu` | `21.21.AW03G6.FY10` / `AW*FY10` | [미국판 실험본 다운로드](https://raw.githubusercontent.com/ZanghyunCho/TX720/main/firmware/FWC365TL_US_scanner_closed_EXPERIMENTAL.efu) |
| 일본판 — `FWC365TL_JP.efu` | `22.22.AJ06I7.FY10` / `AJ*FY10` | [일본판 실험본 다운로드](https://raw.githubusercontent.com/ZanghyunCho/TX720/main/firmware/FWC365TL_JP_scanner_closed_EXPERIMENTAL.efu) |

두 파일의 원래 모델·버전·언어 리소스를 유지합니다. 원본 구분은 제공된 파일 기준이며,
각 지역 모델 전체에 대한 호환성을 보증하지 않습니다. **이미 일본판으로 바뀐 기기에 미국판을
기록할 수 있는지, 기록하면 언어가 복원되는지는 확인하지 않았습니다.** 버전 제한이나 모델
검증을 해제하거나 위장하는 수정도 포함하지 않습니다.

향후 변경도 두 원본을 각각 확인하고 패치·검증·다운로드 파일을 함께 관리합니다.

**위 표의 다운로드는 스캐너 닫힘 패치만 포함합니다.**
미국판 무칩·잔량 100% 목표의 별도 [후보 v1 다운로드 및 검증 범위](docs/us-chipless-candidate-v1.md)를 제공합니다.
원본 더미 카트리지 승인·100% 메시지 생성의 ARM 실행 검증은 통과했지만,
**실기에서는 업데이트 후에도 카트리지 장착 요구가 남았다는 실패 보고가 있습니다.** 무칩 동작 성공본이 아닙니다.
일본판 무칩 후보는 아직 없습니다. 선행 분석은 [잉크 분석 기록](docs/ink-investigation.md)에 있습니다.

## 확인한 내용

- 일본판과 미국판의 서로 다른 코드 위치를 각각 추적했습니다.
- 두 버전 모두 센서 점검 화면에서 `Close!`를 선택하는 값이 입력 레지스터
  `0xF8016024`의 bit 6까지 연결됨을 확인했습니다. 원래 값 0이 닫힘입니다.
- 오류 문구를 삭제하는 대신, 기존 우회 플래그를 확인하는 getter와 raw getter의
  반환값을 모두 0으로 고정합니다.
- 각 버전 **15,360회**, 합계 **30,720회** ARM 함수 실행 검증을 통과했습니다.
  모든 입력 바이트 값과 우회 플래그 조합, 일반 호출 경로, 점검 화면용 getter,
  스택 및 보존 레지스터를 검사했습니다. 별도의 Photo Tray/DUP 입력도 유지됩니다.
- ZIP CRC와 IPL의 업데이트 보조 코드 합계, 본문 합계, salted SHA-1이 일치합니다.
  두 번째 IPL 이미지와 RCX 메타데이터는 그대로입니다.

자세한 근거는 [분석 기록](docs/scanner-unit-patch.md),
정확한 변경 범위와 해시는 [reports](reports), 다운로드 검증용 해시는
[SHA256SUMS](firmware/SHA256SUMS)에 있습니다.

## 동일한 원본으로 재현

Python 3의 표준 라이브러리만 사용합니다. 다음 도구는 프린터와 통신하지 않습니다.
등록된 원본 SHA-256과 일치하는 파일만 처리하고, 원본 및 기존 출력 파일을 덮어쓰지 않습니다.

```sh
# 미국/영어판
python3 tools/patch_scanner_closed.py FWC365TL.efu output/FWC365TL_US_scanner_closed_EXPERIMENTAL.efu --manifest output/us-patch.json

# 일본판
python3 tools/patch_scanner_closed.py FWC365TL_JP.efu output/FWC365TL_JP_scanner_closed_EXPERIMENTAL.efu --manifest output/jp-patch.json
```

원본 펌웨어는 이 저장소에 포함하지 않았습니다. 다른 버전에 이 오프셋을 그대로 적용하지 마세요.

해시를 확인하려면 저장소 루트에서 다음을 실행합니다.

```sh
python3 tools/verify_packages.py
cd firmware
sha256sum -c SHA256SUMS
```
