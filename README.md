# SookMissing_Analyzer

### 🔮 Analyzer 실행시키기
#### 1) 최신 버전 실행
```bash
docker run -d -p 8000:8000 \
  --name smishing_app \
  -e API_KEY=[API_KEY] \
  hongdabagi/smishing-analyzer:latest
```

#### 2) API
- Request
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

- Response

```json
{
  "total_score": 75,
  "risk_level": "위험",
  "context_score": 65,
  "url_score": 10,
  "smishing_type": "온라인 서비스 및 계정 보안 위협 (로그인 감지, 계정 동결 등)",
  "reason": "텔레그램 계정이 비정상적인 로그인 시도로 제한되었다는 허위 메시지입니다. 보안 코드 확인을 명목으로 단축 URL 클릭을 유도하며, 이는 계정 정보 탈취를 목적으로 하는 피싱일 가능성이 높습니다. 긴급성을 조장하여 사용자의 즉각적인 반응을 유도하는 전형적인 수법입니다. (추가 탐지: 보안 미적용 사이트, 단축 URL 사용(사이트 숨김))",
  "official_url": "https://telegram.org"
}
```
