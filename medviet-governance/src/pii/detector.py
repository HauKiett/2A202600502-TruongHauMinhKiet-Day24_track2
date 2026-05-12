# src/pii/detector.py
from presidio_analyzer import AnalyzerEngine, PatternRecognizer, Pattern
from presidio_analyzer.nlp_engine import NlpEngineProvider

SUPPORTED_LANGUAGE = "vi"


def _build_nlp_engine():
    """
    Thử load model spaCy theo thứ tự ưu tiên.
    `vi_core_news_lg` được spec yêu cầu, nhưng nếu chưa có thì fallback
    sang `xx_ent_wiki_sm` (multilingual) — vẫn detect được PERSON.

    Lưu ý: `xx_ent_wiki_sm` tag tên người tiếng Việt là `MISC` (không phải
    `PERSON`). Ta map `MISC → PERSON` để Presidio nhận diện đúng.
    """
    import spacy

    ner_mapping = {
        "model_to_presidio_entity_mapping": {
            "PER": "PERSON",
            "PERSON": "PERSON",
            "MISC": "PERSON",  # xx_ent_wiki_sm tag tên VN là MISC
            "ORG": "ORGANIZATION",
            "LOC": "LOCATION",
            "GPE": "LOCATION",
            "DATE": "DATE_TIME",
            "TIME": "DATE_TIME",
            "NORP": "NRP",
        },
        "low_confidence_score_multiplier": 0.4,
        "low_score_entity_names": [],
        "labels_to_ignore": ["O"],
    }

    candidates = [
        ("vi", "vi_core_news_lg"),
        ("vi", "xx_ent_wiki_sm"),
    ]
    load_errors = []
    for lang_code, model_name in candidates:
        try:
            spacy.load(model_name)
            provider = NlpEngineProvider(nlp_configuration={
                "nlp_engine_name": "spacy",
                "models": [{"lang_code": lang_code, "model_name": model_name}],
                "ner_model_configuration": ner_mapping,
            })
            return provider.create_engine()
        except Exception as exc:
            load_errors.append(f"{model_name}: {exc}")

    raise RuntimeError(
        "Không tìm thấy model spaCy nào hỗ trợ tiếng Việt. "
        "Hãy chạy: python -m spacy download xx_ent_wiki_sm"
    )


def build_vietnamese_analyzer() -> AnalyzerEngine:
    """
    Xây dựng AnalyzerEngine với các recognizer tùy chỉnh cho VN.
    """

    # --- TASK 2.2.1 ---
    # CCCD VN: đúng 12 chữ số liên tiếp
    cccd_pattern = Pattern(
        name="cccd_pattern",
        regex=r"\b\d{12}\b",
        score=0.9,
    )
    cccd_recognizer = PatternRecognizer(
        supported_entity="VN_CCCD",
        patterns=[cccd_pattern],
        context=["cccd", "căn cước", "chứng minh", "cmnd"],
        supported_language=SUPPORTED_LANGUAGE,
    )

    # --- TASK 2.2.2 ---
    # Số điện thoại VN: 0[3|5|7|8|9] + 8 chữ số
    phone_recognizer = PatternRecognizer(
        supported_entity="VN_PHONE",
        patterns=[Pattern(
            name="vn_phone",
            regex=r"\b0[35789]\d{8}\b",
            score=0.85,
        )],
        context=["điện thoại", "sdt", "phone", "liên hệ"],
        supported_language=SUPPORTED_LANGUAGE,
    )

    # Custom recognizer cho tên người Việt — bắt 2–4 từ viết hoa liên tiếp
    # (kèm dấu tiếng Việt). Bổ trợ cho NER khi model VN không đầy đủ.
    vn_person_recognizer = PatternRecognizer(
        supported_entity="PERSON",
        patterns=[Pattern(
            name="vn_person",
            regex=r"\b[A-ZÀ-Ỵ][a-zà-ỹ]+(?:\s+[A-ZÀ-Ỵ][a-zà-ỹ]+){1,3}\b",
            score=0.6,
        )],
        context=["bệnh nhân", "bác sĩ", "họ tên", "ông", "bà"],
        supported_language=SUPPORTED_LANGUAGE,
    )

    # Email recognizer (built-in EMAIL_ADDRESS của Presidio chỉ hỗ trợ "en",
    # nên ta thêm pattern riêng cho language "vi").
    email_recognizer = PatternRecognizer(
        supported_entity="EMAIL_ADDRESS",
        patterns=[Pattern(
            name="email_pattern",
            regex=r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b",
            score=0.9,
        )],
        context=["email", "mail", "thư điện tử"],
        supported_language=SUPPORTED_LANGUAGE,
    )

    # --- TASK 2.2.3 ---
    nlp_engine = _build_nlp_engine()

    # --- TASK 2.2.4 ---
    analyzer = AnalyzerEngine(
        nlp_engine=nlp_engine,
        supported_languages=[SUPPORTED_LANGUAGE],
    )
    analyzer.registry.add_recognizer(cccd_recognizer)
    analyzer.registry.add_recognizer(phone_recognizer)
    analyzer.registry.add_recognizer(vn_person_recognizer)
    analyzer.registry.add_recognizer(email_recognizer)

    return analyzer


def detect_pii(text: str, analyzer: AnalyzerEngine) -> list:
    """
    Detect PII trong text tiếng Việt.
    Trả về list các RecognizerResult.
    Entities: PERSON, EMAIL_ADDRESS, VN_CCCD, VN_PHONE
    """
    results = analyzer.analyze(
        text=text,
        language=SUPPORTED_LANGUAGE,
        entities=["PERSON", "EMAIL_ADDRESS", "VN_CCCD", "VN_PHONE"],
    )
    return results
