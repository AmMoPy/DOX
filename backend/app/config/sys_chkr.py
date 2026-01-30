import subprocess

class SystemChecker:
    """Handles external system checks"""
    
    @staticmethod
    def check_ollama(ollama_model: str) -> dict:
        """Check Ollama availability and model status"""
        try:
            result = subprocess.run(
                ['ollama', '--version'],
                capture_output=True,
                text=True,
                timeout=3
            )
            
            if result.returncode != 0:
                return {"available": False, "reason": "ollama_not_responding"}
            
            # Check if model is available
            model_check = subprocess.run(
                ['ollama', 'list'],
                capture_output=True, 
                text=True,
                timeout=5
            )
            
            model_available = ollama_model in model_check.stdout
            
            return {
                "available": True,
                "version": result.stdout.strip(),
                "model_available": model_available,
                "model_name": ollama_model
            }
            
        except (FileNotFoundError, subprocess.TimeoutExpired):
            return {"available": False, "reason": "ollama_not_found"}
        except Exception as e:
            return {"available": False, "reason": str(e)}