from pydantic import BaseModel


class AnalysisResponse(BaseModel):

    id: int
    filename: str
    total_events: int
    threats_detected: int
    severity: str
    threats: list
    iocs: dict