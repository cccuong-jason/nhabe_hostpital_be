from typing import Optional

from pydantic import BaseModel
from datetime import date, datetime, time, timedelta

from entities.report import (
    BooleanChoice,
    DamageClassification,
    ImpactAssessment,
    IncidentClassification,
    IncidentSubject,
    ReportForm,
    SituationClassification,
)


class ReportBase(BaseModel):
    is_required: Optional[ReportForm] = None
    unit: Optional[str] = None
    client_fullname: Optional[str] = None
    client_birthdate: Optional[datetime] = None
    client_medical_record_id: Optional[str] = None
    client_gender_male: Optional[bool] = None
    department: Optional[str] = None
    incident_subject: Optional[IncidentSubject] = None
    incident_location: Optional[str] = None
    exact_location: Optional[str] = None
    issued_date: Optional[datetime] = None
    short_description: Optional[str] = None
    proposal_solution: Optional[str] = None
    performed_treatment: Optional[str] = None
    is_informed: Optional[BooleanChoice] = None
    is_recorded: Optional[BooleanChoice] = None
    is_family_noticed: Optional[BooleanChoice] = None
    is_client_noticed: Optional[BooleanChoice] = None
    incident_classification: Optional[IncidentClassification] = None
    impact_assessment: Optional[ImpactAssessment] = None
    reporter_fullname: Optional[str] = None
    reporter_phone: Optional[str] = None
    reporter_email: Optional[str] = None
    reporter_type: Optional[str] = None
    observer_1: Optional[str] = None
    observer_2: Optional[str] = None
    title: Optional[str] = None
    status: Optional[str] = 'đang xử lý'
    situation_classification: Optional[SituationClassification] = None
    damage_classification: Optional[DamageClassification] = None
    created_at: Optional[datetime] = None
    updated_at: Optional[datetime] = None


class ReportRequestCreate(ReportBase):
    report_reference: str


class ReportRequestUpdate(ReportBase):
    pass


class Report(ReportBase):
    id: int
    report_reference: str

    class Config:
        orm_mode = True
