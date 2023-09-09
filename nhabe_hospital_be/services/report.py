from typing import List, Optional, Tuple

from faker import Faker
from sqlalchemy.orm import Session

import entities
from entities.report import Report
from models.report import ReportRequestCreate, ReportRequestUpdate
from repositories import report as report_repository

from entities.enum import SituationClassification, DamageClassification, IncidentClassification, \
    BooleanChoice, IncidentSubject, ReportForm, ImpactAssessment


def list_report(db: Session, page: int, limit: int) -> List[entities.Report]:
    return report_repository.list_report(db, page, limit)


def get_total_objects(db: Session) -> int:
    return db.query(Report).count()


def create_report(
        db: Session,
        report: ReportRequestCreate,
) -> Tuple[Optional[entities.Report], Optional[str]]:
    if report_repository.get_report_by_report_reference(db, report.report_reference):
        return None, "report_reference have already existed"

    return report_repository.create_report(db, report), None


def create_report_fake(db: Session, report: ReportRequestCreate) -> Tuple[Optional[entities.Report], Optional[str]]:
    fake = Faker()
    report.report_reference = fake.uuid4()
    report.is_required = fake.random_element(elements=[ReportForm.IS_REQUIRED, ReportForm.IS_VOLUNTARY])
    report.unit = fake.random_element(elements=("Unit A", "Unit B", "Unit C"))
    report.client_fullname = fake.name()
    report.client_birthdate = fake.date_of_birth().year
    report.client_gender_male = fake.random_element(elements=(True, False))
    report.department = fake.random_element(elements=("Department A", "Department B", "Department C"))
    report.incident_subject = fake.random_element(
        elements=[IncidentSubject.CLIENT, IncidentSubject.VISITOR, IncidentSubject.STAFF,
                  IncidentSubject.INFRASTRUCTURE])
    report.incident_location = fake.address()
    report.exact_location = fake.random_element(elements=("Location A", "Location B", "Location C"))
    report.issued_date = fake.date_time().timestamp()
    report.short_description = fake.text(max_nb_chars=100)
    report.proposal_solution = fake.text(max_nb_chars=100)
    report.performed_treatment = fake.text(max_nb_chars=100)
    report.is_informed = fake.random_element(
        elements=[BooleanChoice.YES, BooleanChoice.NO, BooleanChoice.NOT_ACKNOWLEDGED])
    report.is_recorded = fake.random_element(
        elements=[BooleanChoice.YES, BooleanChoice.NO, BooleanChoice.NOT_ACKNOWLEDGED])
    report.is_family_noticed = fake.random_element(
        elements=[BooleanChoice.YES, BooleanChoice.NO, BooleanChoice.NOT_ACKNOWLEDGED])
    report.is_client_noticed = fake.random_element(
        elements=[BooleanChoice.YES, BooleanChoice.NO, BooleanChoice.NOT_ACKNOWLEDGED])
    report.incident_classification = fake.random_element(
        elements=[IncidentClassification.HAPPEN, IncidentClassification.NOT_HAPPEN])
    report.impact_assessment = fake.random_element(
        elements=[ImpactAssessment.LIGHT, ImpactAssessment.MEDIUM, ImpactAssessment.HARD])
    report.reporter_fullname = fake.name()
    report.reporter_phone = fake.phone_number()
    report.reporter_email = fake.email()
    report.reporter_type = fake.random_element(elements=("Reporter A", "Reporter B", "Reporter C"))
    report.observer_1 = fake.name()
    report.observer_2 = fake.name()
    report.title = fake.sentence()
    report.status = fake.random_element(elements=("Status A", "Status B", "Status C"))
    report.situation_classification = fake.random_element(
        elements=[SituationClassification.A, SituationClassification.B, SituationClassification.C,
                  SituationClassification.D, SituationClassification.E, SituationClassification.F,
                  SituationClassification.G, SituationClassification.H, SituationClassification.I])
    report.damage_classification = fake.random_element(
        elements=[DamageClassification.NC0, DamageClassification.NC1, DamageClassification.NC2,
                  DamageClassification.NC3])
    report.created_at = fake.date_time().timestamp()
    report.updated_at = fake.date_time().timestamp()

    # Save the report to the database
    # db.add(report)
    # db.commit()
    # db.refresh(report)

    return report_repository.create_report(db, report), None


def get_report(db: Session, report_id: int) -> Optional[Report]:
    return report_repository.get_report(db, report_id)


def update_report(
        db: Session, report_id: int, report: ReportRequestUpdate
) -> Tuple[Optional[Report], Optional[str]]:
    if not report_repository.get_report_by_report_id(db, report_id):
        return None, "report_id does not exist"

    return report_repository.update_report(db, report_id, report), None


def delete_report(db: Session, report_id: int) -> Optional[str]:
    if not report_repository.get_report_by_report_id(db, report_id):
        return "report_id does not exist"

    report_repository.delete_report(db, report_id)
