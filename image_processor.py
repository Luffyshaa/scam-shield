from __future__ import annotations

from io import BytesIO

from PIL import Image, ImageEnhance, ImageFilter, ImageOps
import pytesseract


class OCRProcessingError(RuntimeError):
    """Raised when text cannot be extracted from an uploaded image."""


def _prepare_image(image: Image.Image) -> Image.Image:
    """Improve contrast and readability before sending the image to OCR."""
    image = ImageOps.exif_transpose(image)
    image = image.convert("L")

    # Upscale smaller screenshots/photos so text is easier for OCR to read.
    min_width = 1400
    if image.width < min_width:
        scale = min_width / image.width
        image = image.resize(
            (int(image.width * scale), int(image.height * scale)),
            Image.Resampling.LANCZOS,
        )

    image = ImageEnhance.Contrast(image).enhance(1.6)
    image = image.filter(ImageFilter.SHARPEN)
    return image


def extract_text_from_image(uploaded_file) -> str:
    """Extract readable English text from a Streamlit uploaded image."""
    try:
        raw = uploaded_file.getvalue()
        image = Image.open(BytesIO(raw))
        prepared = _prepare_image(image)
        text = pytesseract.image_to_string(prepared, lang="eng", config="--psm 6")
    except Exception as exc:  # surfaced to the UI as a friendly message
        raise OCRProcessingError(
            "Scam Shield could not read this image. Try a clearer screenshot or photo."
        ) from exc

    cleaned = "\n".join(line.strip() for line in text.splitlines() if line.strip()).strip()
    if len(cleaned) < 4:
        raise OCRProcessingError(
            "Very little text was detected. Try a sharper image with the message filling most of the frame."
        )

    return cleaned
