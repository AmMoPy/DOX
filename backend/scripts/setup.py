#!/usr/bin/env python3
"""
DOX - Basic Setup Script
Handles virtual environment creation, dependency installation, and models setup
"""
import venv
import shutil
import tempfile
import platform
import webbrowser
import subprocess
from pathlib import Path


class Color:
    WHITE = '\033[97m'
    GREEN = '\033[92m'
    YELLOW = '\033[93m'
    RED = '\033[91m'
    BLUE = '\033[94m'
    CYAN = '\033[96m'
    MAGENTA = '\033[95m'
    RESET = '\033[0m'
    BOLD = '\033[1m'


def print_color(text, color):
    print(f"{color}{text}{Color.RESET}")


def print_header(text):
    print()
    print_color("╔" + "═" * 68 + "╗", Color.CYAN)
    print_color(f"║ {text:66} ║", Color.CYAN)
    print_color("╚" + "═" * 68 + "╝", Color.CYAN)
    print()


def print_step(step, message):
    print_color(f"{step}. {message}", Color.BLUE)


def print_success(message):
    print_color(f"✅ {message}", Color.GREEN)


def print_warning(message):
    print_color(f"⚠️  {message}", Color.YELLOW)


def print_error(message):
    print_color(f"❌ {message}", Color.RED)


def run_command(command, check=True, capture_output=False, cwd=None):
    """Run a shell command and return the result"""
    try:
        result = subprocess.run(
            command,
            shell=True,
            check=check,
            capture_output=capture_output,
            text=True,
            cwd=cwd
        )
        return result.returncode == 0, result.stdout if capture_output else None
    except subprocess.CalledProcessError as e:
        return False, e.output if capture_output else None


def prompt_yes_no(question, default=True):
    """Prompt user for yes/no input"""
    choices = "Y/n" if default else "y/N"
    response = input(f"{Color.YELLOW}{question} [{choices}]: {Color.RESET}").strip().lower()
    
    if response == '':
        return default
    return response in ['y', 'yes', '1', 'true']


class BasicSetup:
    def __init__(self):
        self.project_root = Path(__file__).parent.parent.parent
        self.backend_dir = self.project_root / "backend"
        self.frontend_dir = self.project_root / "frontend"
        self.venv_dir = ""
        self.is_windows = platform.system() == "Windows"
        self.backend_deps_installed = False
        self.model_validated = False
        self._OLLAMA_MODEL = "gemma3:270m"
        

    def check_prerequisites(self):
        """Check if basic prerequisites are installed"""
        print_header("PREREQUISITE CHECK")
        
        # Check Python
        python_ok, version = run_command("python --version", capture_output=True)
        if not python_ok:
            python_ok, version = run_command("python3 --version", capture_output=True)
        
        if python_ok:
            print_success(f"Python found: {version.strip()}")
        else:
            print_error("Python not found. Please install Python 3.10+ from https://python.org")
            return False
        
        # Check Node.js
        node_ok, version = run_command("node --version", capture_output=True)
        if node_ok:
            print_success(f"Node.js found: {version.strip()}")
        else:
            print_error("Node.js not found. Please install Node.js 16+ from https://nodejs.org")
            return False
        
        # Check npm
        npm_ok, version = run_command("npm --version", capture_output=True)
        if npm_ok:
            print_success(f"npm found: {version.strip()}")
        else:
            print_error("npm not found. Please install Node.js which includes npm")
            return False
        
        return True


    def create_directories(self):
        """Create necessary directories"""
        print_header("DIRECTORY SETUP")
        
        directories = [
            self.backend_dir / "models",
            self.backend_dir / "data" / "uploads",
            self.backend_dir / "data" / "chroma_db",
            self.backend_dir / "data" / "sqlite3_db"
        ]
        
        for directory in directories:
            try:
                directory.mkdir(parents=True, exist_ok=True)
                print_success(f"Created: {directory}")
            except Exception as e:
                print_error(f"Failed to create {directory}: {e}")
                return False
        
        # Create models README
        models_readme = self.backend_dir / "models" / "README.md"
        models_readme.write_text("""# Model Files Directory

This directory contains:
- Sentence-transformers embedding models (auto-downloaded)
- Other model files

Models are automatically downloaded when the application first runs.

**Note:** Large model files are not committed to Git.
""")
        
        return True


    def create_virtual_environment(self):
        """Create Python virtual environment"""
        print_header("PYTHON VIRTUAL ENVIRONMENT")
        
        if prompt_yes_no("Create virtual environment?", True):
            env_name = input(f"{Color.YELLOW}Environment name (default: venv): {Color.RESET}").strip() or "venv"
            self.venv_dir = self.backend_dir / env_name
            
            if self.venv_dir.exists():
                if prompt_yes_no("Virtual environment already exists. Recreate it?", False):
                    print_step("1", "Removing existing virtual environment...")
                    shutil.rmtree(self.venv_dir)
                else:
                    print_success("Using existing virtual environment")
                    return True
            
            print_step("1", "Creating virtual environment...")
            try:
                venv.create(self.venv_dir, with_pip=True)
                print_success("Virtual environment created successfully")
                return True
            except Exception as e:
                print_error(f"Failed to create virtual environment: {e}")
                return False
        else:
            print_warning("Skipping virtual environment creation")
            return True
    

    def get_python_executable(self):
        """Get the path to the Python executable"""
        if self.venv_dir and Path(self.venv_dir).exists():
            if self.is_windows:
                venv_python = self.venv_dir / "Scripts" / "python.exe"
            else:
                venv_python = self.venv_dir / "bin" / "python"
            
            if venv_python.exists():
                return str(venv_python)
         
        return None


    def install_backend_dependencies(self):
        """Install Python dependencies"""
        print_header("BACKEND DEPENDENCIES")

        python_exec = self.get_python_executable()
        
        if not python_exec:
            print_error("No Python executable found")
            return False

        print_step("1", f"Using Python: {python_exec}")
        
        # upgrade pip
        print_step("2", "Upgrading pip...")
    
        success, _ = run_command(f'"{python_exec}" -m pip install --upgrade pip')
        if not success:
            print_error("Failed to upgrade pip")
            return False
        print_success("pip upgraded successfully")
        
        # Install dependencies
        print_step("3", "Installing backend dependencies...")
        requirements_file = self.backend_dir / "requirements.txt"
        
        if not requirements_file.exists():
            print_error("requirements.txt not found")
            return False
        
        success, output = run_command(
            f'"{python_exec}" -m pip install -r "{requirements_file}"',
            capture_output=False
        )
        
        if success:
            print_success("Backend dependencies installed successfully")
            self.backend_deps_installed = True
            return True
        else:
            print_error("Failed to install backend dependencies")
            if output:
                print_color(output, Color.RED)
            self.backend_deps_installed = False
            return False


    def download_embedding_model(self):
        """Download and validate the SentenceTransformer model using temporary script"""
        print_header("EMBEDDING MODEL SETUP")
        
        # Skip if backend dependencies failed
        if not self.backend_deps_installed:
            print_warning("Skipping model download - backend dependencies not installed")
            return True
        
        models_dir = self.backend_dir / "models"
        cache_dir = models_dir / "cache"
        cache_dir.mkdir(parents=True, exist_ok=True)
        
        python_exec = self.get_python_executable()
        if not python_exec:
            print_error("Virtual environment not found")
            return False
        
        print_step("1", "Checking for existing embedding model...")
        
        # Create comprehensive script that checks and downloads if needed
        script_content = f'''
import sys
import os
from pathlib import Path

try:
    from sentence_transformers import SentenceTransformer
except ImportError:
    print("sentence-transformers not available")
    sys.exit(1)

# Check if model already exists
cache_dir = Path("{cache_dir}")
model_name = "all-MiniLM-L6-v2"

try:
    # Try to load existing model
    print(f"Checking for existing model in {{cache_dir}}...")
    model = SentenceTransformer(
        model_name,
        cache_folder=str(cache_dir),
        local_files_only=True
    )
    
    # Quick test to ensure model works
    embeddings = model.encode(["validation test"])
    print(f"EXISTS_VALID:{{len(embeddings[0])}}")
    sys.exit(0)
    
except Exception as e:
    print(f"No existing model found: {{e}}")
    print("Downloading model...")
    
    try:
        # Download the model
        model = SentenceTransformer(
            model_name,
            cache_folder=str(cache_dir),
            local_files_only=False
        )
        
        # Test the newly downloaded model
        embeddings = model.encode(["test sentence"])
        print(f"DOWNLOADED_VALID:{{len(embeddings[0])}}")
        sys.exit(0)
        
    except Exception as download_error:
        print(f"ERROR:{{download_error}}")
        sys.exit(1)
'''
        
        # Write to temporary file and execute
        try:
            with tempfile.NamedTemporaryFile(mode='w', suffix='.py', delete=False) as temp_file:
                temp_file.write(script_content)
                temp_script_path = temp_file.name
            
            print_step("2", "Running model setup...")
            success, output = run_command(
                f'"{python_exec}" "{temp_script_path}"',
                capture_output=True
            )
            
            # Clean up temp file
            Path(temp_script_path).unlink()
            
            if success and output:
                if "EXISTS_VALID" in output:
                    dimension = output.split(":")[-1].strip()
                    print_success(f"Existing model validated - dimension: {dimension}")
                    self.model_validated = True
                    return True
                elif "DOWNLOADED_VALID" in output:
                    dimension = output.split(":")[-1].strip()
                    print_success(f"Model downloaded and validated - dimension: {dimension}")
                    self.model_validated = True
                    return True
            
            print_error("Model setup failed")
            if output:
                print_color(output, Color.RED)
            return False
                
        except Exception as e:
            print_error(f"Failed to create temporary script: {e}")
            return False


    def install_frontend_dependencies(self):
        """Install Node.js dependencies"""
        print_header("FRONTEND DEPENDENCIES")
        
        if not self.frontend_dir.exists():
            print_error("Frontend directory not found")
            return False
        
        print_step("1", "Installing frontend dependencies...")
        success, output = run_command(
            "npm install",
            cwd=self.frontend_dir,
            capture_output=False
        )
        
        if success:
            print_success("Frontend dependencies installed successfully")
            return True
        else:
            print_error("Failed to install frontend dependencies")
            if output:
                print_color(output, Color.RED)
            return False
    

    def mfa_key_gen(self):
        """Run initial setup for keys and admin creation instructions"""
        print_header("INITIAL ADMIN CONFIGURATION")
        
        if prompt_yes_no("Generate security keys and initial admin instructions?", True):
            python_exec = self.get_python_executable()
            if python_exec:
                print_step("1", "Generating MFA Key...")
                # MFA key generation script
                script_content = f'''
from cryptography.fernet import Fernet

try:
    key = Fernet.generate_key().decode()
    
    print("=" * 60)
    print("MFA ENCRYPTION KEY GENERATED")
    print("=" * 60)
    print("Add this to your .env file:")
    print(f"MFA_ENCRYPTION_KEY={{key}}")
    print("=" * 60)
    print("IMPORTANT: Keep this key secret and backed up!")
    print("If you lose this key, users will need to re-setup MFA.")
    print("=" * 60)
except Exception as e:
    print(f"KEY GEN ERROR:{{e}}")
    sys.exit(1)
'''
                # Write to temporary file and execute
                try:
                    with tempfile.NamedTemporaryFile(mode='w', suffix='.py', delete=False) as temp_file:
                        temp_file.write(script_content)
                        temp_script_path = temp_file.name

                    success, output = run_command(
                        f'"{python_exec}" "{temp_script_path}"',
                        capture_output=False
                    )

                    # Clean up temp file
                    Path(temp_script_path).unlink()
                    
                    if success:
                        print_success("MFA key generated successfully")
                        # Admin creation instructions
                        print_step("2", "Initial Admin Account Creation Instructions:")
                        print_color("Admin account will be created on first application launch.\n", Color.YELLOW)
                        
                        print_color("Option A: Environment Variables (Recommended for Production)", Color.CYAN)
                        print("Add these to your .env file:")
                        print_color("INITIAL_ADMIN_EMAIL=admin@your-company.com", Color.YELLOW)
                        print_color("INITIAL_ADMIN_PASSWORD=<strong-password>\n", Color.YELLOW)
                        
                        print_color("Option B: Interactive Setup", Color.CYAN)
                        print("Leave environment variables unset.")
                        print("On first launch, visit: http://dox_url/setup")
                        print("Create admin through web interface.\n")
                        
                        print_color("Option C: API Call", Color.CYAN)
                        print("After starting the server, run:")
                        print_color('curl -X POST "http://dox_url/auth/setup" \\', Color.YELLOW)
                        print_color('  -H "Content-Type: application/json" \\', Color.YELLOW)
                        print_color('  -d \'{"email":"admin@your-company.com","password":"YourStrongPassword123!","role":"admin"}\'\n', Color.YELLOW)
                        
                        print_color("Next steps:", Color.GREEN)
                        print("1. Choose an admin creation method (A, B, or C above)")
                        print("2. If using Option A, update .env with INITIAL_ADMIN_EMAIL and INITIAL_ADMIN_PASSWORD")
                        print("3. Run: python main.py")
                        print("4. Create your admin account\n")
                        return True
                    else:
                        print_error(
                            "Initial admin configuration failed "
                            "Do manual MFA key generation and admin setup"
                            )
                        return False
                except Exception as e:
                    print_error(f"Failed to create temporary script: {e}")
                    return False
            else:
                print_error("Python executable not found")
                return False
        else:
            print_warning("Skipping initial configuration")
            return True


    def setup_ollama(self):
        """Setup Ollama and download the model"""
        print_header("OLLAMA SETUP")
        
        # Check if Ollama is installed
        ollama_installed, _ = run_command("ollama --version", check=False)
        
        if not ollama_installed:
            print_step("1", "Ollama not found. Installation required.\n")

            print_color(f"Ollama is needed to run the {self._OLLAMA_MODEL} model locally.", Color.YELLOW)
            print_color("Please download and install it from: https://ollama.com\n", Color.YELLOW)
            
            if prompt_yes_no("Open Ollama download page in your browser?"):
                webbrowser.open("https://ollama.com")
            
            print()
            print_color("After installing Ollama, please:", Color.YELLOW)
            print_color("1. Run 'ollama serve' in a terminal", Color.YELLOW)
            print_color("2. Run this setup script again\n", Color.YELLOW)
            
            if prompt_yes_no("Continue setup without Ollama? (AI features will be limited)", False):
                return True
            else:
                print_error("Ollama installation required for full functionality")
                return False
        else:
            print_success("Ollama is installed")
        
        # Download the model
        print_step("2", f"Downloading {self._OLLAMA_MODEL}...")
        print_color("This may take several minutes depending on your internet speed...", Color.YELLOW)
        
        success, output = run_command(
            f"ollama pull {self._OLLAMA_MODEL}",
            capture_output=False
        )
        
        if success:
            print_success("Gemma model downloaded successfully")
            return True
        else:
            print_error("Failed to download Gemma model")
            if output:
                print_color(output, Color.RED)
            
            if prompt_yes_no("Continue setup without the AI model?", False):
                return True
            return False
    

    def run_health_check(self):
        """Run comprehensive health check including model validation"""
        print_header("HEALTH CHECK")
        
        checks = []
        
        # Check Python executable
        python_exec = self.get_python_executable()
        if python_exec:
            # Test if the executable actually works
            test_success, _ = run_command(f'"{python_exec}" --version', check=False)
            checks.append(("Python Environment", test_success))
        else:
            checks.append(("Python Environment", False))
        
        # Check backend dependencies
        if self.backend_deps_installed:
            print_step("1", "Testing backend dependencies...")
            
            # Create temporary script for dependency check
            dep_check_script = '''
try:
    import fastapi
    import chromadb
    import sqlite3
    import sentence_transformers
    print("DEPS_OK")
    sys.exit(0)
except ImportError as e:
    print(f"DEPS_MISSING:{e}")
    sys.exit(1)
'''
            
            try:
                with tempfile.NamedTemporaryFile(mode='w', suffix='.py', delete=False) as temp_file:
                    temp_file.write(f"import sys\n{dep_check_script}")
                    temp_script_path = temp_file.name
                
                success, output = run_command(
                    f'"{python_exec}" "{temp_script_path}"',
                    capture_output=True
                )
                
                Path(temp_script_path).unlink()
                
                if success and output and "DEPS_OK" in output:
                    checks.append(("Backend Dependencies", True))
                else:
                    checks.append(("Backend Dependencies", False))
                    
            except Exception as e:
                print_error(f"Failed to check dependencies: {e}")
                checks.append(("Backend Dependencies", False))
        else:
            checks.append(("Backend Dependencies", False))
        
        # Check embedding model - simplified since it was validated during download
        if self.model_validated:
            checks.append(("Embedding Model", True))
        else:
            # Only check if model files exist (no re-validation)
            cache_dir = self.backend_dir / "models" / "cache"
            model_files_exist = cache_dir.exists() and any(cache_dir.iterdir())
            checks.append(("Embedding Model", model_files_exist))
        
        # Check frontend dependencies
        node_modules = self.frontend_dir / "node_modules"
        checks.append(("Frontend Dependencies", node_modules.exists()))
        
        # Check Ollama
        ollama_ok, _ = run_command("ollama --version", check=False)
        checks.append(("Ollama Installed", ollama_ok))
        
        # Check model (if Ollama is installed)
        if ollama_ok:
            model_success, model_output = run_command("ollama list", check=False, capture_output=True)
            if model_success and model_output:
                model_available = self._OLLAMA_MODEL in model_output
                checks.append(("Ollama Model", model_available))
            else:
                checks.append(("Ollama Model", False))
        else:
            checks.append(("Ollama Model", False))
        
        # Check directories
        directories_ok = all([
            (self.backend_dir / "models").exists(),
            (self.backend_dir / "data" / "uploads").exists(),
            (self.backend_dir / "data" / "chroma_db").exists(),
            (self.backend_dir / "data" / "sqlite3_db").exists()
        ])
        checks.append(("Project Directories", directories_ok))

        # Display results
        print()
        all_ok = True
        for check_name, status in checks:
            if status:
                print_success(f"{check_name}: OK")
            else:
                print_error(f"{check_name}: Missing")
                all_ok = False
        
        return all_ok
    

    def show_next_steps(self):
        """Display next steps after setup"""
        print_header("SETUP COMPLETE!")
        
        python_exec = self.get_python_executable()
        activate_cmd = ""
        if self.venv_dir and Path(self.venv_dir).exists():
            if self.is_windows:
                activate_cmd = f"{self.venv_dir}\\Scripts\\activate"
            else:
                activate_cmd = f"source {self.venv_dir}/bin/activate"
        
        print_color("🎉 Setup completed GZ!\n", Color.GREEN)

        print_color("Next steps to run DOX in dev mode:\n", Color.CYAN)

        print_color("1. Start Ollama (in a separate terminal):", Color.YELLOW)
        print_color("   ollama serve\n", Color.WHITE)

        print_step("2", "Start the backend server:")
        print_color(f"   cd backend", Color.WHITE)
        if self.venv_dir and Path(self.venv_dir).exists():
            print_color(f"   {activate_cmd}", Color.WHITE)
        else:
            print_color("   # (Using system Python - no virtual environment)", Color.WHITE)
        print_color("   python main.py\n", Color.WHITE)

        print_color("3. Start the frontend (in another terminal):", Color.YELLOW)
        print_color("   cd frontend", Color.WHITE)
        print_color("   npm run dev\n", Color.WHITE)

        print_color("4. Open your browser to: http://localhost:PORT_N\n", Color.YELLOW)

        print_color("The backend API will be available at: http://localhost:PORT_N", Color.CYAN)
        print_color("API documentation: http://localhost:PORT_N/docs", Color.CYAN)
        
        if not self.backend_deps_installed:
            print()
            print_warning("Note: Backend dependencies were not installed successfully")
            print_warning("You may need to install them manually or resolve dependency conflicts")
    

    def run_setup(self):
        """Run the complete setup process"""
        print_header("DOX - COMPLETE SETUP")
        print_color("This script will set up basic requirements need to run DOX using chroma/sqlite3 version\n", Color.YELLOW)
        
        if not prompt_yes_no("Do you want to continue with the setup?"):
            print_color("Setup cancelled.", Color.YELLOW)
            return
        
        # Run all setup steps
        steps = [
            ("Checking prerequisites", self.check_prerequisites),
            ("Creating directories", self.create_directories),
            ("Creating virtual environment", self.create_virtual_environment),
            ("Installing backend dependencies", self.install_backend_dependencies),
            ("Downloading embedding model", self.download_embedding_model),
            ("Installing frontend dependencies", self.install_frontend_dependencies),
            ("Initial configuration", self.mfa_key_gen),
            ("Setting up Ollama and models", self.setup_ollama),
            ("Health check", self.run_health_check),
        ]
        
        for step_name, step_func in steps:
            print()
            if not step_func():
                print_error(f"Setup failed at: {step_name}")
                if not prompt_yes_no("Continue anyway?"):
                    print_color("Setup cancelled.", Color.YELLOW)
                    return
        
        self.show_next_steps()


def main():
    """Main entry point"""
    try:
        setup = BasicSetup()
        setup.run_setup()
        
    except KeyboardInterrupt:
        print()
        print_color("Setup cancelled by user.", Color.YELLOW)
    except Exception as e:
        print_error(f"Unexpected error during setup: {e}")
        print_color("Please check the error message and try again.", Color.YELLOW)


if __name__ == "__main__":
    main()