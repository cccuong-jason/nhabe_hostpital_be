from sqlalchemy import Boolean, Column, Enum, Integer, String, DateTime

from database.database import Base
from entities.enum import (
    BooleanChoice,
    DamageClassification, ImpactAssessment, IncidentClassification,
    IncidentSubject,
    ReportForm, SituationClassification,
)


class Report(Base):
    __tablename__ = "reports"

    id = Column(Integer, primary_key=True, index=True)
    report_reference = Column(String, unique=True, index=True)
    is_required = Column(Enum(ReportForm))
    unit = Column(String, default=None)
    client_fullname = Column(String, default=None)
    client_birthdate = Column(DateTime, default=None)
    client_medical_record_id = Column(String, default=None)
    client_gender_male = Column(Boolean, default=None)
    department = Column(String, default=None)
    incident_subject = Column(Enum(IncidentSubject))
    incident_location = Column(String, default=None)
    exact_location = Column(String, default=None)
    issued_date = Column(DateTime, default=None)
    short_description = Column(String, default=None)
    proposal_solution = Column(String, default=None)
    performed_treatment = Column(String, default=None)
    is_informed = Column(Enum(BooleanChoice))
    is_recorded = Column(Enum(BooleanChoice))
    is_family_noticed = Column(Enum(BooleanChoice))
    is_client_noticed = Column(Enum(BooleanChoice))
    incident_classification = Column(Enum(IncidentClassification))
    impact_assessment = Column(Enum(ImpactAssessment))
    reporter_fullname = Column(String, default=None)
    reporter_phone = Column(String, default=None)
    reporter_email = Column(String, default=None)
    reporter_type = Column(String, default=None)
    observer_1 = Column(String, default=None)
    observer_2 = Column(String, default=None)
    title = Column(String, default=None)
    status = Column(String, default='đang xử lý')
    situation_classification = Column(Enum(SituationClassification))
    damage_classification = Column(Enum(DamageClassification))
    created_at = Column(DateTime, default=None)
    updated_at = Column(DateTime, default=None)
