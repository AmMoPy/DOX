import logging
import requests
from typing import Optional
from app.config.setting import settings

logger = logging.getLogger(__name__)


class EmailService:
    """Email service using SendGrid"""
    
    def __init__(self):
        self.api_key = settings.email.SENDGRID_API_KEY
        self.from_email = settings.email.FROM_EMAIL
        self.frontend_url = settings.email.FRONTEND_URL


    async def send_password_reset_email(
        self,
        to_email: str,
        reset_token: str,
        user_name: str
    ) -> bool:
        """
        Send password reset email with secure token link.
        
        Args:
            to_email: Recipient email
            reset_token: Secure reset token (never expose in client)
            user_name: User name for personalization
            
        Returns:
            True if sent successfully
        """
        reset_url = f"{self.frontend_url}/reset-password?token={reset_token}&email={to_email}"

        html_content = f'''
        <!DOCTYPE html>
        <html>
        <head>
            <style>
                body {{ font-family: Arial, sans-serif; line-height: 1.6; }}
                .container {{ max-width: 600px; margin: 0 auto; padding: 20px; }}
                .button {{ 
                    display: inline-block;
                    padding: 12px 24px;
                    background-color: #007bff;
                    color: white !important;
                    text-decoration: none;
                    border-radius: 4px;
                    margin: 20px 0;
                }}
                .footer {{ color: #666; font-size: 12px; margin-top: 30px; }}
            </style>
        </head>
        <body>
            <div class="container">
                <h2>Password Reset Request</h2>
                <p>Hello{" " + user_name},</p>
                <p>You requested to reset your password. Click the button below to proceed:</p>
                <a href="{reset_url}" class="button">Reset Password</a>
                <p><strong>This link expires in 1 hour.</strong></p>
                <p>If you didn't request this, please ignore this email. Your password will remain unchanged.</p>
                <div class="footer">
                    <p>This is an automated email. Please do not reply.</p>
                </div>
            </div>
        </body>
        </html>
        '''

        # SendGrid API endpoint
        url = "https://api.brevo.com/v3/smtp/email"

        payload = {
            "htmlContent": html_content,
            "sender": {
                "email": self.from_email,
                "name": "DOX"
            },
            "subject": "PwdR",
            "to": [
                {
                    "email": to_email,
                    "name": user_name
                }
            ]
        }

        headers = {
            "api-key": self.api_key,
            "Content-Type": "application/json"
        }

        try:
            response = requests.post(url, json=payload, headers=headers)

            if response.status_code == 201:
                logger.info(f"Password reset email sent to {to_email}")
                return True
            else:
                logger.error(f"SendGrid returned status {response.status_code}")
                return False
                
        except Exception as e:
            logger.error(f"Failed to send password reset email to {to_email}: {e}")
            return False
    

    async def send_welcome_email(self, to_email: str, user_name: str) -> bool:
        """Send welcome email to new users"""
        # Similar pattern for other email types
        pass


# Global instance
email_service = EmailService()