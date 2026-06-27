"""Routes supplémentaires pour l'API Gravity Security."""

from fastapi import APIRouter

router = APIRouter()


@router.get("/api/version")
async def version():
    return {"name": "Gravity Security", "version": "1.0.0", "build": "2026.06"}
