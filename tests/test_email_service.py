import pytest
import os
from unittest.mock import AsyncMock, MagicMock, patch, mock_open
from app.email_service import EmailService

# Suponiendo que el archivo está en app/services/email_service.py
# Ajusta la importación según tu estructura real

@pytest.fixture
def mock_settings_complete():
    with patch("app.email_service.settings") as mock_settings:
        mock_settings.smtp_host = "smtp.example.com"
        mock_settings.smtp_port = 587
        mock_settings.smtp_username = "user@example.com"
        mock_settings.smtp_password = "password123"
        mock_settings.from_email = "sender@example.com"
        mock_settings.from_name = "Test Sender"
        yield mock_settings

@pytest.fixture
def mock_settings_incomplete():
    with patch("app.email_service.settings") as mock_settings:
        mock_settings.smtp_host = None
        mock_settings.smtp_port = None
        mock_settings.smtp_username = None
        mock_settings.smtp_password = None
        mock_settings.from_email = "sender@example.com"
        mock_settings.from_name = "Test Sender"
        yield mock_settings

class TestEmailService:

    def test_init_incomplete_config(self, mock_settings_incomplete):
        """Prueba inicialización con configuración incompleta (warning log)."""
        with patch("app.email_service.logger") as mock_logger:
            service = EmailService()
            mock_logger.warning.assert_called_with(
                "SMTP configuration incomplete. Email notifications will be logged instead of sent."
            )

    def test_init_complete_config(self, mock_settings_complete):
        """Prueba inicialización con configuración completa."""
        with patch("app.email_service.logger") as mock_logger:
            service = EmailService()
            mock_logger.warning.assert_not_called()

    @pytest.mark.asyncio
    async def test_send_email_simulated(self, mock_settings_incomplete):
        """Prueba envío simulado cuando falta configuración SMTP."""
        service = EmailService()
        
        with patch("app.email_service.logger") as mock_logger:
            result = await service.send_email(
                "recipient@test.com", "Subject", "<h1>Hello</h1>"
            )
            
            assert result is True
            mock_logger.info.assert_called()
            mock_logger.debug.assert_called()
            assert "recipient@test.com" in mock_logger.info.call_args[0][0]

    @pytest.mark.asyncio
    async def test_send_email_success(self, mock_settings_complete):
        """Prueba envío exitoso real mockeando aiosmtplib."""
        service = EmailService()
        
        # Mockeamos aiosmtplib.SMTP
        mock_smtp = AsyncMock()
        mock_smtp.connect = AsyncMock()
        mock_smtp.login = AsyncMock()
        mock_smtp.send_message = AsyncMock()
        mock_smtp.quit = AsyncMock()

        with patch("aiosmtplib.SMTP", return_value=mock_smtp) as mock_smtp_cls:
            result = await service.send_email(
                "recipient@test.com", 
                "Subject", 
                "<h1>Hello</h1>", 
                text_content="Hello"
            )
            
            assert result is True
            mock_smtp_cls.assert_called_with(
                hostname="smtp.example.com",
                port=587,
                use_tls=True,
                validate_certs=True
            )
            mock_smtp.connect.assert_called_once()
            mock_smtp.login.assert_called_with("user@example.com", "password123")
            mock_smtp.send_message.assert_called_once()
            mock_smtp.quit.assert_called_once()

    @pytest.mark.asyncio
    async def test_send_email_auto_text_generation(self, mock_settings_complete):
        """Prueba que se genera texto plano desde HTML si no se provee."""
        service = EmailService()
        
        mock_smtp = AsyncMock()
        with patch("aiosmtplib.SMTP", return_value=mock_smtp):
            await service.send_email(
                "recipient@test.com", "Subject", "<p>Hello<br>World</p>"
            )
            
            # Verificar el contenido del mensaje enviado
            call_args = mock_smtp.send_message.call_args
            message = call_args[0][0]  # El objeto MIMEMultipart
            
            # Buscar la parte de texto plano
            text_part = next(
                part for part in message.walk() 
                if part.get_content_type() == "text/plain"
            )
            payload = text_part.get_payload()
            
            # Verificar que se eliminaron tags y se convirtieron saltos
            assert "Hello" in payload
            assert "World" in payload
            assert "<p>" not in payload

    @pytest.mark.asyncio
    async def test_send_email_exception(self, mock_settings_complete):
        """Prueba manejo de error durante el envío SMTP."""
        service = EmailService()
        
        mock_smtp = AsyncMock()
        mock_smtp.connect.side_effect = Exception("Connection failed")
        
        with patch("aiosmtplib.SMTP", return_value=mock_smtp), \
             patch("app.email_service.logger") as mock_logger:
            
            result = await service.send_email(
                "recipient@test.com", "Subject", "Body"
            )
            
            assert result is False
            mock_logger.error.assert_called()
            assert "Failed to send email" in mock_logger.error.call_args[0][0]

    @pytest.mark.asyncio
    async def test_plan_notification_template_fallback(self, mock_settings_incomplete):
        """Prueba que usa el template fallback si falla carga de archivo."""
        service = EmailService()
        
        # Forzar fallo al abrir archivo de template
        with patch("builtins.open", side_effect=Exception("File not found")), \
             patch.object(service, "send_email", new_callable=AsyncMock) as mock_send:
            
            mock_send.return_value = True
            
            await service.send_plan_change_notification(
                "user@test.com", "FREE", "PREMIUM"
            )
            
            mock_send.assert_called_once()
            # Verificar que el HTML enviado contiene partes del fallback
            html_sent = mock_send.call_args[0][2]
            assert "Email Validation API" in html_sent
            assert "FREE" in html_sent
            assert "PREMIUM" in html_sent

    @pytest.mark.asyncio
    async def test_plan_notification_template_file(self, mock_settings_incomplete):
        """Prueba que carga y renderiza correctamente el template desde archivo."""
        service = EmailService()
        
        dummy_template = "<html><body>From {{ old_plan }} to {{ new_plan }}</body></html>"
        
        with patch("builtins.open", mock_open(read_data=dummy_template)), \
             patch.object(service, "send_email", new_callable=AsyncMock) as mock_send:
            
            mock_send.return_value = True
            
            await service.send_plan_change_notification(
                "user@test.com", "FREE", "PREMIUM"
            )
            
            html_sent = mock_send.call_args[0][2]
            assert "From FREE to PREMIUM" in html_sent
