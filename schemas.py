from pydantic import BaseModel, Field
from typing import Optional

class AnalyzeRequest(BaseModel):
    text: str
    sender_number: Optional[str] = None
    
class AnalyzeResponse(BaseModel):
    total_score: int = Field(..., description="최종 위험도 (0~100)")
    risk_level: str = Field(..., description="위험 등급 (안전/주의/심각)")
    

    context_score: int = Field(..., description="AI 문맥 점수 (0~70)")
    url_score: int = Field(..., description="URL 패턴 점수 (0~30)")
    

    smishing_type: str
    reason: str = Field(..., description="최종 판단 근거")
    official_url: Optional[str] = None
    sender_status: Optional[str] = None