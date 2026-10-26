from io import BytesIO
from pathlib import Path
import shutil

import pytest
from PIL import Image, ImageDraw, ImageFont
from streamlit.testing.v1 import AppTest

from image_processor import OCRProcessingError, extract_text_from_image


def test_text_submission_and_low_risk_warning():
    app = AppTest.from_file(Path(__file__).resolve().parents[1] / 'app.py').run()
    assert not app.exception
    app.text_area[0].input('Pay immediately with gift cards.')
    app.button[0].click().run()
    assert not app.exception
    assert 'LIKELY SCAM' in app.text_area[1].value
    assert any('Do not use phone numbers' in warning.value for warning in app.warning)
    app.text_area[0].input('Your prescription is ready for pickup at your usual store.')
    app.button[0].click().run()
    assert not app.exception
    assert 'NO OBVIOUS RED FLAGS' in app.text_area[1].value
    assert not app.warning


def test_empty_message_prompts_for_input():
    app = AppTest.from_file(Path(__file__).resolve().parents[1] / 'app.py').run()
    app.button[0].click().run()
    assert not app.exception
    assert any('Please paste a message' in item.value for item in app.warning)


def test_invalid_image_has_friendly_error():
    with pytest.raises(OCRProcessingError, match='could not read this image'):
        extract_text_from_image(BytesIO(b'not an image'))


@pytest.mark.skipif(not shutil.which('tesseract'), reason='Tesseract required for OCR integration')
def test_screenshot_ocr():
    image = Image.new('RGB', (1400, 200), 'white')
    font = ImageFont.truetype('DejaVuSans.ttf', 48)
    ImageDraw.Draw(image).text((30, 60), 'Pay immediately with gift cards.', font=font, fill='black')
    uploaded = BytesIO()
    image.save(uploaded, format='PNG')
    assert 'gift cards' in extract_text_from_image(uploaded).lower()
