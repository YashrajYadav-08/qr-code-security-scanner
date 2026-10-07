from fastapi import FastAPI
from pydantic import BaseModel, HttpUrl

from app.services.url_risk import classify_url

app = FastAPI(title="QR Guard API", version="0.1.0")


class URLRequest(BaseModel):
    url: str


class URLResponse(BaseModel):
    url: str
    normalized_url: str
    risk_level: str
    risk_score: int
    reasons: list[str]
    suspicious: bool


@app.get("/health")
def health_check():
    return {"status": "ok"}


@app.post("/api/v1/classify", response_model=URLResponse)
def classify_endpoint(payload: URLRequest):
    result = classify_url(payload.url)
    return URLResponse(
        url=result["url"],
        normalized_url=result["normalized_url"],
        risk_level=result["risk_level"],
        risk_score=result["risk_score"],
        reasons=result["reasons"],
        suspicious=result["suspicious"],
    )
