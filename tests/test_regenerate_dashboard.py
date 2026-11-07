import importlib.util
import unittest
from pathlib import Path


MODULE_PATH = Path(__file__).parents[1] / "scripts" / "regenerate_dashboard.py"
SPEC = importlib.util.spec_from_file_location("regenerate_dashboard", MODULE_PATH)
dashboard = importlib.util.module_from_spec(SPEC)
assert SPEC.loader is not None
SPEC.loader.exec_module(dashboard)


class SensitiveTitleTest(unittest.TestCase):
    def test_attack_class_titles_are_sensitive(self):
        titles = [
            "Fix RCE in parser",
            "Prevent SQLi in search",
            "Stop path traversal in export",
            "Guard prototype pollution",
            "Avoid command execution via args",
            "Fix open redirect",
            "Fix request smuggling",
            "Fix race condition",
            "Fix TOCTOU",
            "Fix LFI",
            "Fix SSTI",
            "Fix ReDoS",
            "Fix zip slip",
            "Fix cross-site scripting in comments",
            "Prevent cross-site request forgery in forms",
            "ディレクトリトラバーサルを修正",
            "バッファオーバーフローを修正",
            "プロトタイプ汚染を修正",
            "安全でないデシリアライゼーションを修正",
            "任意コード実行を修正",
            "コマンド実行を修正",
            "クロスサイトスクリプティングを修正",
            "クロスサイトリクエストフォージェリを修正",
        ]
        for title in titles:
            with self.subTest(title=title):
                self.assertRegex(title, dashboard.SENSITIVE_TITLE)

    def test_benign_titles_are_not_sensitive(self):
        titles = [
            "Add the MIT license",
            "Let testers mark notes as bug, question, idea or next",
            "Record the page that is open when a recording starts",
            "README を手順書形式の how-to に書き直す",
        ]
        for title in titles:
            with self.subTest(title=title):
                self.assertNotRegex(title, dashboard.SENSITIVE_TITLE)


if __name__ == "__main__":
    unittest.main()
