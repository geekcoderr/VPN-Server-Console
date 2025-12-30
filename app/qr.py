"""
QR code generation module.
Generates QR codes compatible with WireGuard mobile apps.
"""
import base64
import io
import qrcode
from qrcode.image.pil import PilImage


def generate_qr_code(config_content: str) -> str:
    """
    Generate a QR code PNG from WireGuard config content.
    
    Args:
        config_content: The complete WireGuard client config
        
    Returns:
        Base64-encoded PNG image string
    """
    # Create QR code
    qr = qrcode.QRCode(
        version=None,  # Auto-determine size
        error_correction=qrcode.constants.ERROR_CORRECT_M,
        box_size=10,
        border=4,
    )
    qr.add_data(config_content)
    qr.make(fit=True)
    
    # Generate image
    img = qr.make_image(fill_color="black", back_color="white")
    
    # Convert to base64
    buffer = io.BytesIO()
    img.save(buffer, format="PNG")
    buffer.seek(0)
    
    return base64.b64encode(buffer.getvalue()).decode()


def generate_qr_data_uri(config_content: str) -> str:
    """
    Generate a data URI for embedding QR code directly in HTML.
    
    Args:
        config_content: The complete WireGuard client config
        
    Returns:
        Data URI string (data:image/png;base64,...)
    """
    b64 = generate_qr_code(config_content)
    return f"data:image/png;base64,{b64}"
