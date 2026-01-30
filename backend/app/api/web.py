from app.config.setting import settings
from fastapi import APIRouter, Request
from fastapi.responses import HTMLResponse

router = APIRouter()

BASE_DIR = settings.paths.PROJECT_ROOT

@router.get("/", response_class=HTMLResponse)
@router.get("/{full_path:path}", response_class=HTMLResponse)
async def serve_spa(request: Request, full_path: str = ""):
    """
    Serve the single-page application (SPA) with nonce injection
    
    This replaces static file serving for index.html, all other 
    static assets (JS, CSS, images) are served normally
    """
    
    # Read index.html template rom the 'frontend' or 'dist' directory relative to the script
    index_path = BASE_DIR / "frontend" / "dist" / "index.html" # Vite build output
    if not index_path.exists():
        # Development fallback
        index_path = BASE_DIR / "frontend" / "index.html"

    if not index_path.exists():
        # Fallback if neither works (e.g., just in the root of the project)
        index_path = BASE_DIR / "index.html"
    
    html_content = index_path.read_text()
    
    # Inject nonce into HTML
    nonce = request.state.csp_nonce
    
    # Replace placeholder with actual nonce
    # Method 1: Template placeholder
    html_content = html_content.replace("{{CSP_NONCE}}", nonce)
    
    if 'rel="stylesheet"' in html_content: # for the auto-generated Link tag from Vite
        # In production, the 'dist/index.html' WILL have the link tag, and this line WILL inject the nonce.
        html_content = html_content.replace('<link rel="stylesheet"', f'<link nonce="{nonce}" rel="stylesheet"')

    # # Method 2: Blind Tag Replacement
    # # Inject into all script/style tags, more aggressive 
    # # but needed for style injections during build process
    # html_content = html_content.replace("<script", f'<script nonce="{nonce}"')
    # html_content = html_content.replace("<style", f'<style nonce="{nonce}"')
    
    return HTMLResponse(content=html_content)