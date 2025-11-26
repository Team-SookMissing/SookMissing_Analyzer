import google.generativeai as genai
import os
import json
from dotenv import load_dotenv

SMISHING_TYPES = [
    "정상",    
    "온라인 서비스 및 계정 보안 위협 (로그인 감지, 계정 동결 등)",     
    "결제·구매 및 쇼핑몰 사칭 (허위 결제 문자, 배송 이슈 등)",    
    "공공기관 및 법 집행 기관 사칭 (검찰, 경찰, 과태료 등)",    
    "가족 및 지인 사칭 (액정 파손, 급전 요청 등)",    
    "택배 및 물류 사칭 (주소지 불명, 반송 등)",
    "대출 권유 및 투자 유도",
    "정부 지원금 및 복지 빙자",   
    "단순 본인 인증 및 개인정보 요구",     
    "기타 위협"
]

load_dotenv()
GOOGLE_API_KEY = os.getenv("GOOGLE_API_KEY")

model = None

if GOOGLE_API_KEY:
    genai.configure(api_key=GOOGLE_API_KEY)
    model = genai.GenerativeModel(
    'gemini-2.5-flash',
    system_instruction="""
        당신은 사이버 보안 전문가이자 스미싱 탐지 AI입니다. 항상 JSON 형식으로만 응답합니다.
    """)

def analyze_context(text: str, sender_number = None) -> dict:
    if not GOOGLE_API_KEY or model is None:
        return{
            "risk_score" : 0,
            "smishing_type" : "Server Error",
            "reason" : "API KEY 설정 오류로 분석 불가",
            "official_url" : None
        }
    
    types_str = ", ".join(SMISHING_TYPES)


    if sender_number:
        sender_info_str = sender_number
        analysis_guide = """
        1. [관계 분석 필수] [발신 번호]'와 [사용자 메시지] 내용 의 논리적 관계를 검토하세요.
            - 금융/공공기관/기업 사칭의 경우 '010'으로 시작하는 번호나 '006'과 같이 국제 발신번호로 오면 비정상으로 탐지합니다.
            -[최우선 예외 규칙] 단, 택배, 믈류, 중고 거래, 지인 등의 경우 '010' 번호로 오더라도 정상으로 간주합니다.

        2. 다음 [사용자 메시지]를 분석하여 아래의 JSON 스키마에 맞춰 결과를 반환하세요.
        """
    else:
        sender_info_str = "정보 없음"
        analysis_guide = """
        1. [발신 번호] 정보가 없으므로, 오직 [사용자 메시지] 만으로 판단하세요.

        2.다음 [사용자 메시지]를 분석하여 아래의 JSON 스키마에 맞춰 결과를 반환하세요.
        """
    
    prompt = f"""
        
        [분석 가이드]
        {analysis_guide}

        [출력 스타일 가이드]
        - 판단 근거(reason)를 작성할 때, '예외 규칙', '가이드', '1번 항목' 같은 내부 용어를 절대 언급하지 마세요.
        - 대신, "택배 기사님은 배송 업무를 위해 개인 휴대폰(010)을 사용하는 경우가 많으므로 정상적인 메시지로 보입니다."와 같이 일반 사용자가 이해하기 쉬운 문장으로 설명하세요.
        
        [JSON 스키마]
        {{
            "risk_score": int, // 문맥적 위험도를 0~70점 사이의 범주로 평가하세요. 0은 정상 70점은 스미싱 위험도가 매우 높음을 의미
            "smishing_type": str, // 아래 [분류 기준] 중 하나를 정확히 선택
            "reason": str, // 발신 번호가 있다면 발신 번호 검증 결과를 포함한 판단 근거를 3문장 이내로 요약하세요.
            "official_url": str | null // 사칭된 기관/서비스의 공식 URL (없거나 식별 불가 시 JSON null값을 반환하세요.)

            "sender_status": str // "정상", "의심", "Unknown" 중 하나를 선택하세요.
        }}

        [분류 기준 (smishing_type)]
        {types_str}

        [사용자 메시지]
        {text}

        [발신 번호]
        {sender_info_str}
        """
    
    try:
        response = model.generate_content(
            prompt,
            generation_config={"response_mime_type": "application/json"}
        )
        
        clean_text = response.text.replace("```json", "").replace("```", "").strip()

        return json.loads(clean_text)
    
    except json.JSONDecodeError:
        return {
                    "risk_score": 50,
                    "smishing_type": "Parse Error",
                    "reason": "AI 응답 형식이 올바르지 않아 분석에 실패했습니다.",
                    "official_url": None,
                    "sender_status" : None
                }
    
    except Exception as e:
        print(f"Gemini API Error: {e}")
        return {
            "risk_score" : 0,
            "smishing_type" : "API Error",
            "reason" : "AI 서버 통신 중 오류 발생",
            "official_url" : None,
            "sender_status" : None
        }
