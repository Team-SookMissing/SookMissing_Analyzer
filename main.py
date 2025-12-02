
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

import contextAnalyzer as llm
import urlAnalyzer as utils
import schemas


app = FastAPI(title="Sookkmishing Analyzer")

origins = [
    "http://localhost:3000",
    "http://127.0.0.1:3000",
    "http://localhost:9000"
]

app.add_middleware(
    CORSMiddleware,
    allow_origins = origins,
    allow_credentials = True,
    allow_methods = ["*"],
    allow_headers=["*"],
)


@app.post("/analyze", response_model=schemas.AnalyzeResponse)
async def analyze_smishing(request: schemas.AnalyzeRequest):

    urls = utils.extract_urls(request.text)


    url_result = {"url":None, "score": 0, "reasons":[]}

    if urls:
        url_result = utils.analyze_url_pattern(urls[0])

    ai_result = llm.analyze_context(request.text, request.sender_number)
    

    context_score = ai_result.get("risk_score", 0)
    url_score = url_result["score"]
    total_score = min(url_score + context_score, 100)
    

    risk_level = "안전"
    if total_score >= 60: risk_level = "위험"
    elif total_score >= 30: risk_level = "주의"

   
    final_reason = ai_result.get("reason", "분석 불가")
    if url_result["reasons"]:
        url_reason_str = ", ".join(url_result["reasons"])
        final_reason = f"{final_reason} (추가 탐지: {url_reason_str})"



    return schemas.AnalyzeResponse(
        total_score=total_score,
        risk_level=risk_level,
        context_score=context_score,
        url_score=url_score,
        smishing_type=ai_result.get("smishing_type", "알 수 없음"),
        reason=final_reason,
        official_url=ai_result.get("official_url"),
        sender_status = ai_result.get("sender_status"),
        solution=ai_result.get("solution")

    )
