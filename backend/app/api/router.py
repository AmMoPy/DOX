from fastapi import APIRouter
from .auth_ep import router as auth_router
from .upload_ep import router as upload_router
from .sse_ep import router as sse_router
from .search_chat_ep import router as search_chat_router
from .sys_ep import router as system_router
from .admin_ep import router as admin_router
from .sec_ep import router as security_router

# Main router that combines all others
main_router = APIRouter()

# Include all sub-routers
main_router.include_router(auth_router)
main_router.include_router(upload_router)
main_router.include_router(sse_router) # bypassed by axios
main_router.include_router(search_chat_router)
main_router.include_router(system_router)
main_router.include_router(admin_router)
main_router.include_router(security_router) 