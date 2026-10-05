from sqlalchemy import Column, Integer, String, Text

from database import Base


class Analysis(Base):

    __tablename__ = "analyses"

    id = Column(
        Integer,
        primary_key=True,
        index=True
    )

    filename = Column(
        String(255),
        nullable=False
    )

    total_events = Column(
        Integer,
        default=0
    )

    threats_detected = Column(
        Integer,
        default=0
    )

    severity = Column(
        String(20),
        default="Low"
    )

    threats = Column(
        Text
    )

    iocs = Column(
        Text
    )