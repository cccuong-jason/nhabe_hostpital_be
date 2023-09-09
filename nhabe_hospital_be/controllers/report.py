from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy.orm import Session

from database.database import SessionLocal
from models.report import ReportRequestCreate, ReportRequestUpdate
from services import report as report_service
from fastapi import status
from jose import jwt

router = APIRouter()


# Dependency
def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


@router.get("/report/list/", status_code=status.HTTP_200_OK)
async def list_report(db: Session = Depends(get_db), page: int = Query(1, ge=1, description="Page number"),
                      limit: int = Query(20, ge=1, description="Items per page") ):
    total_objects = report_service.get_total_objects(db)  # Get the total number of objects
    reports = report_service.list_report(db, page, limit)

    next_page = page + 1 if len(reports) == limit else None  # Calculate the next page number
    previous_page = page - 1 if page > 1 else None  # Calculate the previous page number

    return {
        "total_objects": total_objects,
        "per_page": limit,
        "current_page": page,
        "next_page": next_page,
        "previous_page": previous_page,
        "reports": reports
    }


@router.post("/report/create/", status_code=status.HTTP_201_CREATED)
async def create_report(report: ReportRequestCreate, db: Session = Depends(get_db)):
    try:
        report, err = report_service.create_report(db, report)
    except Exception as err:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail=str(err)
        )

    if err:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=err)

    return {"report": report}


@router.post("/report/create/fake/", status_code=status.HTTP_201_CREATED)
async def create_report_fake(report: ReportRequestCreate, db: Session = Depends(get_db)):
    try:
        report, err = report_service.create_report_fake(db, report)
    except Exception as err:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail=str(err)
        )

    if err:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=err)

    return {"report": report}


@router.get("/report/get/{report_id}/", status_code=status.HTTP_200_OK)
async def get_report(report_reference: str, db: Session = Depends(get_db)):
    report = report_service.get_report(db, report_reference)
    if not report:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Report not found with given report_id={report_reference}",
        )

    return {"report": report}


@router.put("/report/update/{report_id}", status_code=status.HTTP_200_OK)
async def update_report(
        report_reference: str, report: ReportRequestUpdate, db: Session = Depends(get_db)
):
    try:
        report, err = report_service.update_report(db, report_reference, report)
    except Exception as err:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail=str(err)
        )

    if err:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Report not found with given report_id={report_reference}",
        )

    return {"report": report}


@router.delete("/report/delete/{report_id}", status_code=status.HTTP_200_OK)
async def delete_report(report_reference: str, db: Session = Depends(get_db)):
    try:
        err = report_service.delete_report(db, report_reference)
    except Exception as err:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail=str(err)
        )

    if err:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Report not found with given report_id={report_reference}",
        )

    return {"message": "Deleted"}
