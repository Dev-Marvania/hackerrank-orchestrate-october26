"""
Unit tests for request intent classification.
Covers multilingual deletion authorization across EN, ES, FR, PT, JA, KO,
non-deletion requests (access, export, marketing opt-out, rectification),
negated deletions, compound requests, and whitespace/formatting edge cases.
"""

from __future__ import annotations

import unittest

from code.policy.deterministic_solver import classify_request_intent


class TestEnglishIntent(unittest.TestCase):
    """Test English request intent parsing."""

    def test_english_explicit_deletion(self) -> None:
        """Explicit deletion keywords authorize deletion."""
        samples = [
            "Please delete my account and erase all my personal data.",
            "I want to close my account and remove my profile.",
            "Kindly wipe my account records and purge my details.",
            "Please destroy all my customer records permanently.",
            "Cancel my account and wipe all personal info.",
        ]
        for text in samples:
            with self.subTest(text=text):
                self.assertTrue(classify_request_intent(text), f"Failed to classify deletion: {text}")

    def test_english_access_and_export_non_deletion(self) -> None:
        """Access, copy, and export requests without deletion must not authorize deletion."""
        samples = [
            "Please send me a copy of all my data.",
            "I would like to export my personal data.",
            "Provide a copy of my records.",
            "Download my data archive.",
            "Give me access to all my account records.",
            "I want an export of my account history.",
        ]
        for text in samples:
            with self.subTest(text=text):
                self.assertFalse(classify_request_intent(text), f"Falsely classified non-deletion as deletion: {text}")

    def test_english_marketing_opt_out(self) -> None:
        """Marketing opt-out and newsletter unsubscribe requests are not deletion requests."""
        samples = [
            "Please unsubscribe me from marketing emails.",
            "I want to opt-out of newsletter communications.",
            "Marketing opt-out request for my profile.",
            "Unsubscribe from promotional emails.",
        ]
        for text in samples:
            with self.subTest(text=text):
                self.assertFalse(classify_request_intent(text), f"Falsely classified opt-out as deletion: {text}")

    def test_english_rectification_non_deletion(self) -> None:
        """Rectification / data correction requests are not deletion requests."""
        samples = [
            "Please update my registered phone number and correct my name.",
            "I need to rectify my mailing address.",
            "Correct my email address on file.",
            "Rectification request: update my billing details.",
        ]
        for text in samples:
            with self.subTest(text=text):
                self.assertFalse(classify_request_intent(text), f"Falsely classified rectification as deletion: {text}")

    def test_english_negated_deletion(self) -> None:
        """Negated deletion requests must NOT authorize deletion."""
        samples = [
            "Do not delete my account, please just send me a copy of my records.",
            "Please don't delete my account, I only want to download my data.",
            "I want to export my data instead of deleting my account.",
            "Do not wipe or erase my profile, just send an archive.",
        ]
        for text in samples:
            with self.subTest(text=text):
                self.assertFalse(classify_request_intent(text), f"Falsely classified negated deletion as deletion: {text}")

    def test_english_compound_deletion(self) -> None:
        """Compound requests authorizing export AND deletion must authorize deletion."""
        samples = [
            "Please export my data and then delete my account permanently.",
            "Send me a copy of my records before closing and wiping my profile.",
            "Give me a copy of my data and delete my account.",
        ]
        for text in samples:
            with self.subTest(text=text):
                self.assertTrue(classify_request_intent(text), f"Failed to classify compound deletion: {text}")

    def test_english_deletion_noun_forms(self) -> None:
        """Requests containing noun forms 'deletion' and 'deletions' must authorize deletion."""
        samples = [
            "Please treat this message as a request for permanent account deletion.",
            "I am requesting deletion of the account registered to this email address.",
            "Please begin the deletion process for the account using this email address.",
            "Please process a permanent account-deletion request for this email address.",
            "Kindly proceed with account deletions for all records under my name.",
            "This is a formal request for profile erasure and permanent deletion.",
        ]
        for text in samples:
            with self.subTest(text=text):
                self.assertTrue(classify_request_intent(text), f"Failed to classify noun form deletion: {text}")

    def test_english_correct_treatment_boilerplate_with_deletion(self) -> None:
        """Requests containing boilerplate 'apply the correct treatment' alongside deletion must authorize deletion."""
        samples = [
            "Please treat this message as a request for permanent account deletion. Please apply the correct treatment to records covered by the request. Let me know when the request has been completed.",
            "I am requesting deletion of the account registered to this email address. Please apply the correct treatment to records covered by the request. A short confirmation when the process is complete is sufficient.",
            "Please begin the deletion process for the account using this email address. Please apply the correct treatment to records covered by the request. Let me know when the request has been completed.",
            "Please process a permanent account-deletion request for this email address. Please apply the correct treatment to records covered by the request. Let me know when the request has been completed.",
            "Please delete my account immediately. Please apply the correct treatment to records covered by the request.",
        ]
        for text in samples:
            with self.subTest(text=text):
                self.assertTrue(classify_request_intent(text), f"Falsely classified deletion with boilerplate as non-deletion: {text}")

    def test_english_not_asking_for_deletion_negation(self) -> None:
        """Requests explicitly stating 'not asking for deletion' must NOT authorize deletion."""
        samples = [
            "Please stop the promotional emails. I still need the account and my order history, so I am not asking for deletion.",
            "I am not requesting a deletion of my records, only an export of my data.",
            "Please unsubscribe me from marketing emails. I am not seeking deletion of my account.",
        ]
        for text in samples:
            with self.subTest(text=text):
                self.assertFalse(classify_request_intent(text), f"Falsely classified negated deletion phrasing as deletion: {text}")



class TestSpanishIntent(unittest.TestCase):
    """Test Spanish request intent parsing."""

    def test_spanish_deletion(self) -> None:
        """Explicit Spanish deletion requests authorize deletion."""
        samples = [
            "Solicito la eliminación permanente de mi cuenta y mis datos.",
            "Por favor borrar mi cuenta y suprimir mis datos personales.",
            "Deseo cancelar cuenta y eliminar todos los registros.",
        ]
        for text in samples:
            with self.subTest(text=text):
                self.assertTrue(classify_request_intent(text), f"Failed Spanish deletion: {text}")

    def test_spanish_non_deletion_access_export(self) -> None:
        """Spanish access/export requests do not authorize deletion."""
        samples = [
            "Solicito una copia de mis datos personales.",
            "Deseo descargar de mis datos personales.",
            "Exportar de mis registros por favor.",
            "Acceso de mis datos guardados.",
        ]
        for text in samples:
            with self.subTest(text=text):
                self.assertFalse(classify_request_intent(text), f"Falsely classified Spanish non-deletion: {text}")

    def test_spanish_marketing_and_rectification(self) -> None:
        """Spanish opt-out and rectification requests do not authorize deletion."""
        samples = [
            "Quiero cancelar la suscripción al boletín informativo.",
            "Deseo rectificar mi dirección postal y modificar mi teléfono.",
            "Solicito la rectificación de mis datos de contacto.",
        ]
        for text in samples:
            with self.subTest(text=text):
                self.assertFalse(classify_request_intent(text), f"Falsely classified Spanish opt-out/rectification: {text}")

    def test_spanish_negated_and_compound(self) -> None:
        """Spanish negated vs compound requests."""
        negated = "No eliminar mi cuenta, solo quiero descargar una copia de mis datos."
        compound = "Descargar mis datos y luego eliminar mi cuenta por completo."
        self.assertFalse(classify_request_intent(negated), f"Falsely classified Spanish negated deletion: {negated}")
        self.assertTrue(classify_request_intent(compound), f"Failed Spanish compound deletion: {compound}")


class TestFrenchIntent(unittest.TestCase):
    """Test French request intent parsing."""

    def test_french_deletion(self) -> None:
        """Explicit French deletion requests authorize deletion."""
        samples = [
            "Je demande la suppression définitive de mon compte.",
            "Veuillez effacer mes données et clôturer mon profil.",
            "Supprimer toutes mes informations personnelles.",
        ]
        for text in samples:
            with self.subTest(text=text):
                self.assertTrue(classify_request_intent(text), f"Failed French deletion: {text}")

    def test_french_non_deletion_access_export(self) -> None:
        """French access/export requests do not authorize deletion."""
        samples = [
            "Donnez-moi une copie de mes données personnelles.",
            "Envoyez-moi mes données s'il vous plaît.",
            "Accéder à mes données personnelles.",
        ]
        for text in samples:
            with self.subTest(text=text):
                self.assertFalse(classify_request_intent(text), f"Falsely classified French access: {text}")

    def test_french_marketing_and_rectification(self) -> None:
        """French opt-out and rectification requests do not authorize deletion."""
        samples = [
            "Veuillez me désabonner des newsletters.",
            "Je souhaite rectifier mon adresse e-mail et corriger mes coordonnées.",
            "Demande de rectification de mes informations personnelles.",
        ]
        for text in samples:
            with self.subTest(text=text):
                self.assertFalse(classify_request_intent(text), f"Falsely classified French opt-out/rectification: {text}")

    def test_french_negated_and_compound(self) -> None:
        """French negated vs compound requests."""
        negated = "Ne supprimez pas mon compte, envoyez-moi seulement mes données."
        compound = "Donnez-moi une copie de mes données et ensuite supprimez mon compte."
        self.assertFalse(classify_request_intent(negated), f"Falsely classified French negated deletion: {negated}")
        self.assertTrue(classify_request_intent(compound), f"Failed French compound deletion: {compound}")


class TestPortugueseIntent(unittest.TestCase):
    """Test Portuguese request intent parsing."""

    def test_portuguese_deletion(self) -> None:
        """Explicit Portuguese deletion requests authorize deletion."""
        samples = [
            "Solicito a exclusão permanente da minha conta e dados pessoais.",
            "Por favor apagar todos os meus dados e excluir perfil.",
            "Quero cancelar conta e apagar registros.",
        ]
        for text in samples:
            with self.subTest(text=text):
                self.assertTrue(classify_request_intent(text), f"Failed Portuguese deletion: {text}")

    def test_portuguese_non_deletion_access_export(self) -> None:
        """Portuguese access/export requests do not authorize deletion."""
        samples = [
            "Solicito uma cópia dos meus dados pessoais.",
            "Gostaria de exportar meus dados cadastrais.",
            "Acesso aos meus registros e informações.",
            "Baixar cópia dos meus dados.",
        ]
        for text in samples:
            with self.subTest(text=text):
                self.assertFalse(classify_request_intent(text), f"Falsely classified Portuguese non-deletion: {text}")

    def test_portuguese_marketing_and_rectification(self) -> None:
        """Portuguese opt-out and rectification requests do not authorize deletion."""
        samples = [
            "Cancelar inscrição nas mensagens de marketing e newsletter.",
            "Preciso corrigir meus dados cadastrais e retificar meu e-mail.",
            "Solicito a retificação do meu endereço cadastrado.",
        ]
        for text in samples:
            with self.subTest(text=text):
                self.assertFalse(classify_request_intent(text), f"Falsely classified Portuguese opt-out/rectification: {text}")

    def test_portuguese_negated_and_compound(self) -> None:
        """Portuguese negated vs compound requests."""
        negated = "Não exclua minha conta, apenas envie uma cópia dos meus registros."
        compound = "Envie uma cópia dos meus registros e exclua minha conta."
        self.assertFalse(classify_request_intent(negated), f"Falsely classified Portuguese negated deletion: {negated}")
        self.assertTrue(classify_request_intent(compound), f"Failed Portuguese compound deletion: {compound}")


class TestJapaneseIntent(unittest.TestCase):
    """Test Japanese request intent parsing."""

    def test_japanese_deletion(self) -> None:
        """Explicit Japanese deletion requests authorize deletion."""
        samples = [
            "このアカウントの完全な削除を依頼します。",
            "アカウントの消去と解約をお願いします。",
            "個人情報の削除を申請します。",
        ]
        for text in samples:
            with self.subTest(text=text):
                self.assertTrue(classify_request_intent(text), f"Failed Japanese deletion: {text}")

    def test_japanese_non_deletion_access_export(self) -> None:
        """Japanese access/export requests do not authorize deletion."""
        samples = [
            "私の個人データのエクスポートをお願いします。",
            "登録情報の開示請求をいたします。",
            "個人データのコピーを提供してください。",
            "アカウント情報の閲覧を希望します。",
        ]
        for text in samples:
            with self.subTest(text=text):
                self.assertFalse(classify_request_intent(text), f"Falsely classified Japanese non-deletion: {text}")

    def test_japanese_marketing_and_rectification(self) -> None:
        """Japanese opt-out and rectification requests do not authorize deletion."""
        samples = [
            "メルマガの配信停止をお願いします。",
            "登録情報の訂正をお願いします。",
            "住所の修正を希望します。",
        ]
        for text in samples:
            with self.subTest(text=text):
                self.assertFalse(classify_request_intent(text), f"Falsely classified Japanese opt-out/rectification: {text}")

    def test_japanese_negated_and_compound(self) -> None:
        """Japanese negated vs compound requests."""
        negated = "アカウントは削除しないでください、データのコピーのみ送ってください。"
        compound = "データをコピーした後にアカウントを削除してください。"
        self.assertFalse(classify_request_intent(negated), f"Falsely classified Japanese negated deletion: {negated}")
        self.assertTrue(classify_request_intent(compound), f"Failed Japanese compound deletion: {compound}")


class TestKoreanIntent(unittest.TestCase):
    """Test Korean request intent parsing."""

    def test_korean_deletion(self) -> None:
        """Explicit Korean deletion requests authorize deletion."""
        samples = [
            "이 이메일 주소에 연결된 계정의 영구 삭제를 요청합니다.",
            "회원 탈퇴 및 개인정보 제거를 요청합니다.",
            "모든 개인정보 삭제를 신청합니다.",
        ]
        for text in samples:
            with self.subTest(text=text):
                self.assertTrue(classify_request_intent(text), f"Failed Korean deletion: {text}")

    def test_korean_non_deletion_access_export(self) -> None:
        """Korean access/export requests do not authorize deletion."""
        samples = [
            "내 개인정보 사본을 내보내기 해주세요.",
            "개인정보 열람 및 데이터 사본을 요청합니다.",
            "데이터 다운로드를 요청합니다.",
            "보관 중인 개인정보 내역을 열람하고자 합니다.",
        ]
        for text in samples:
            with self.subTest(text=text):
                self.assertFalse(classify_request_intent(text), f"Falsely classified Korean non-deletion: {text}")

    def test_korean_marketing_and_rectification(self) -> None:
        """Korean opt-out and rectification requests do not authorize deletion."""
        samples = [
            "뉴스레터 수신 거부 요청합니다.",
            "마케팅 정보 수신 동의 철회합니다.",
            "등록된 전화번호를 수정 및 정정해 주세요.",
            "개인정보 정정 요청서 제출합니다.",
        ]
        for text in samples:
            with self.subTest(text=text):
                self.assertFalse(classify_request_intent(text), f"Falsely classified Korean opt-out/rectification: {text}")

    def test_korean_negated_and_compound(self) -> None:
        """Korean negated vs compound requests."""
        negated = "계정을 삭제하지 말고 데이터 사본만 보내주세요."
        compound = "내 데이터를 다운로드한 후 계정을 삭제해 주세요."
        self.assertFalse(classify_request_intent(negated), f"Falsely classified Korean negated deletion: {negated}")
        self.assertTrue(classify_request_intent(compound), f"Failed Korean compound deletion: {compound}")


class TestIntentFormattingAndEdgeCases(unittest.TestCase):
    """Test whitespace, casing, and formatting edge cases."""

    def test_mixed_casing(self) -> None:
        """Intent classification is case-insensitive."""
        self.assertTrue(classify_request_intent("pLeAsE DeLeTe mY aCcoUnT"))
        self.assertFalse(classify_request_intent("sEnD mE a CoPy Of My DaTa"))

    def test_multiline_and_punctuation(self) -> None:
        """Newlines and surrounding punctuation do not break intent detection."""
        multiline_del = "\n\nHello,\n\tPlease delete my account immediately.\nThank you!\n"
        self.assertTrue(classify_request_intent(multiline_del))

        multiline_non = "\n\nHello,\n\tPlease send me a copy of my records.\nThank you!\n"
        self.assertFalse(classify_request_intent(multiline_non))


class TestBenchmarkNonDeletionAndNegationCases(unittest.TestCase):
    """Test explicit benchmark evaluation requests and adversarial negation fuzzing."""

    def test_benchmark_non_deletion_cases(self) -> None:
        """All 10 benchmark non-deletion requests in dataset/deletion_requests.csv must evaluate to False."""
        cases = {
            "case_533": "The mobile number on my profile is out of date. Please replace it with the new one and leave the account active.",
            "case_534": "Please stop the promotional emails. I still need the account and my order history, so I am not asking for deletion.",
            "case_535": "I'd like to download my account information in a portable format. Please keep the account as it is.",
            "case_536": "I can't access my profile and need help resetting the login. Do not close the account.",
            "case_537": "My surname is misspelled on the account. Can you correct it without removing any of my records?",
            "case_538": "Please remove me from marketing lists only. I still want receipts and service messages for this account.",
            "case_539": "Can you tell me what personal information you hold about me? This is an information request, not a request to erase it.",
            "case_540": "I need a copy of last year's invoices for my records. Please leave my profile and purchase history in place.",
            "case_541": "Please change the email address used for this account. I want to continue using the service.",
            "case_542": "Could you send me a copy of the information held on my account? I still use it, so please don't delete or change anything.",
        }
        for cid, text in cases.items():
            with self.subTest(case_id=cid, text=text):
                self.assertFalse(
                    classify_request_intent(text),
                    f"{cid} was falsely classified as authorizing deletion: {text}"
                )

    def test_benchmark_boilerplate_deletion_cases(self) -> None:
        """All 10 benchmark boilerplate deletion requests must evaluate to True."""
        cases = {
            "case_90": "Please treat this message as a request for permanent account deletion. Please apply the correct treatment to records covered by the request. Let me know when the request has been completed.",
            "case_103": "I am requesting deletion of the account registered to this email address. Please apply the correct treatment to records covered by the request. A short confirmation when the process is complete is sufficient.",
            "case_192": "Please treat this message as a request for permanent account deletion. Please apply the correct treatment to records covered by the request. Please contact me if you need information to verify the request.",
            "case_289": "Please begin the deletion process for the account using this email address. Please apply the correct treatment to records covered by the request. Let me know when the request has been completed.",
            "case_320": "Please process a permanent account-deletion request for this email address. Please apply the correct treatment to records covered by the request. Let me know when the request has been completed.",
            "case_331": "Please process a permanent account-deletion request for this email address. Please apply the correct treatment to records covered by the request. A short confirmation when the process is complete is sufficient.",
            "case_348": "Please treat this message as a request for permanent account deletion. Please apply the correct treatment to records covered by the request. Let me know when the request has been completed.",
            "case_431": "Please treat this message as a request for permanent account deletion. Please apply the correct treatment to records covered by the request. Please confirm the result after completing the required checks.",
            "case_514": "Please begin the deletion process for the account using this email address. Please apply the correct treatment to records covered by the request. Let me know when the request has been completed.",
            "case_543": "Please process a permanent account-deletion request for this email address. Please apply the correct treatment to records covered by the request. I would appreciate confirmation of the final outcome.",
        }
        for cid, text in cases.items():
            with self.subTest(case_id=cid, text=text):
                self.assertTrue(
                    classify_request_intent(text),
                    f"{cid} failed to be classified as authorizing deletion: {text}"
                )

    def test_fuzzy_auxiliary_negation_variants(self) -> None:
        """Fuzzy negation phrasing and auxiliary verbs must NOT authorize deletion."""
        samples = [
            "I do not want deletion",
            "I don't want deletion",
            "I do not want to delete",
            "I do not request deletion",
            "I don't seek deletion of my data",
            "without removing any records",
            "without deleting my personal details",
            "not a request to erase it",
            "not a request to delete my profile",
            "leave the account active",
            "leave my profile and purchase history in place",
            "keep the account as it is",
            "want to continue using the service",
            "remove me from marketing lists only",
        ]
        for text in samples:
            with self.subTest(text=text):
                self.assertFalse(
                    classify_request_intent(text),
                    f"Falsely classified fuzzy negation variant as deletion: {text}"
                )

    def test_multilingual_fuzzy_negations(self) -> None:
        """Multilingual explicit negation expressions must NOT authorize deletion."""
        samples = [
            "No deseo la eliminación de mis datos",
            "No quiero la supresión de mis registros",
            "Je ne veux pas la suppression de mes données",
            "Ne souhaite pas la suppression de mon compte",
            "Não quero a exclusão dos meus dados",
            "Não desejo a eliminação da minha conta",
            "削除を希望しません",
            "削除は希望しません",
            "消去を希望しません",
            "삭제를 원하지 않습니다",
            "삭제는 원하지 않습니다",
            "제거를 원하지 않습니다",
        ]
        for text in samples:
            with self.subTest(text=text):
                self.assertFalse(
                    classify_request_intent(text),
                    f"Falsely classified multilingual negation as deletion: {text}"
                )


if __name__ == "__main__":
    unittest.main()

