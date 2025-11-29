# SookMissing_Analyzer

### 🔮 Analyzer 실행시키기
#### 1) 최신 버전 실행
```bash
docker run -d -p 8000:8000 --name smishing_app -e API_KEY={API_KEY} hongdabagi/smishing-analyzer
```

#### 2) API
- Request
- 비정상
```json
{
  "text": "[Telegram] 계정이 비정상적인 로그인 시도로 인해 제한되었습니다. 해제하려면 보안 코드를 확인하세요: http://bit.ly/telegram-security"
}
```
```json
{
  "text": "[Web발신] (주)쿠팡 489,000원 결제 완료. 본인 아닐 시 즉시 소비자 센터 신고: 02-1234-5678"
}
```
```json
{
  "text": "[Web발신]\n(광고)[KB국민은행] 고객님은 정부지원 서민대출 승인 대상자입니다.\n\n- 한도: 최대 1억원\n- 금리: 연 2.5% 고정\n- 필요서류 없이 비대면 즉시 입금 가능합니다.\n\n▼상담신청\n010-9999-8888 (김미영 팀장)\n무료수신거부 080-123-4567",
  "sender_number": "01099998888"
}
```

- 정상
```json
"text": "[Web발신]\n[CJ대한통운] 고객님, 주문하신 상품이 오늘(27일) 14~16시 사이에 배송될 예정입니다.\n\n- 운송장번호: 1234-5678-9012\n- 위탁장소: 문 앞\n- 배송조회: https://www.cjlogistics.com/ko/tool/parcel/tracking\n\n부재 시 문 앞에 두고 가겠습니다.",
  "sender_number": "01099998888"
```
```json
{
  "text": "[Web발신]\n[Naver] 인증번호 [123456]를 입력해주세요. 타인에게 절대 알려주지 마세요.",
  "sender_number": "15883820"
}
```
- Response

```json
{
  "total_score": 70,
  "risk_level": "위험",
  "context_score": 70,
  "url_score": 0,
  "smishing_type": "대출 권유 및 투자 유도",
  "reason": "KB국민은행과 같은 금융기관은 대출 상담을 위해 개인 휴대폰 번호(010)를 사용하지 않습니다. 정부지원 서민대출을 명목으로 비대면 신청 및 상담을 유도하는 것은 전형적인 대출 사기 수법입니다. 발신 번호와 메시지 내용 모두 사칭이 명확하게 의심됩니다.",
  "official_url": null,
  "sender_status": "의심"
}
```
