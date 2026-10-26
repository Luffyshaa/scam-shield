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


def test_phone_context_and_risk_levels_without_numeric_scores():
    app = AppTest.from_file(Path(__file__).resolve().parents[1] / 'app.py').run()
    app.selectbox[0].select('Phone call')
    app.text_area[0].input('Please pay with gift cards.')
    app.button[0].click().run()
    assert not app.exception
    rendered = '\n'.join(item.value for item in app.markdown)
    assert 'Risk level: High' in rendered
    assert 'Hang up now' in rendered
    assert 'Risk score:' not in rendered
    assert 'Risk score:' not in app.text_area[1].value
    assert all('(+' not in item.label for item in app.expander)


def test_upload_mode_and_recovery_help_available_without_analysis():
    app = AppTest.from_file(Path(__file__).resolve().parents[1] / 'app.py').run()
    app.radio[0].set_value('📷 Upload screenshot/photo').run()
    assert not app.exception
    assert len(app.get('file_uploader')) == 1
    labels = [item.label for item in app.expander]
    assert 'I already paid or shared information. What do I do now?' in labels
    assert 'Reporting and help' in labels


@pytest.mark.skipif(not shutil.which('tesseract'), reason='Tesseract required for OCR integration')
def test_uploaded_image_can_be_corrected_before_analysis(monkeypatch):
    image = Image.new('RGB', (1400, 200), 'white')
    ImageDraw.Draw(image).text((30, 60), 'Lunch tomorrow?', font=ImageFont.truetype('DejaVuSans.ttf', 48), fill='black')
    uploaded = BytesIO()
    image.save(uploaded, format='PNG')
    # AppTest cannot populate file_uploader; inject its returned file while running real OCR.
    monkeypatch.setattr('streamlit.file_uploader', lambda *args, **kwargs: uploaded)
    app = AppTest.from_file(Path(__file__).resolve().parents[1] / 'app.py').run()
    app.radio[0].set_value('📷 Upload screenshot/photo').run()
    assert not app.exception
    assert 'Lunch' in app.text_area[0].value
    app.text_area[0].input('Pay immediately with gift cards.')
    app.button[0].click().run()
    assert not app.exception
    assert 'LIKELY SCAM' in app.text_area[1].value
