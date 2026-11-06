"""Quiz grading: what counts as a right answer.

Run with: python -m unittest test_quiz_grading
"""
import os
import unittest

os.environ.setdefault('JWT_SECRET', 'test-secret-' + 'x' * 40)
os.environ.setdefault('MONGO_HOST', 'localhost')

from main import grade_answer  # noqa: E402

VERANTWORTUNG = "responsibility\nVerantwortung übernehmen = to take responsibility"
UMSETZEN = "to implement, put into practice\nIdeen umsetzen = to put ideas into practice"
KNAPP = ("1) tight: Die Zeit ist knapp.\n"
         "2) brief: kurz und knapp\n"
         "3) just under: knapp fünf Jahre = almost five years")


class LineBreaksTestCase(unittest.TestCase):
    def test_line_breaks_never_count_against_an_answer(self):
        self.assertEqual(grade_answer(VERANTWORTUNG.replace("\n", " "), VERANTWORTUNG)[0], "correct")
        self.assertEqual(grade_answer(VERANTWORTUNG, VERANTWORTUNG)[0], "correct")
        self.assertEqual(grade_answer(KNAPP.replace("\n", "  "), KNAPP)[0], "correct")


class MeaningsTestCase(unittest.TestCase):
    def assertGrade(self, answer, definition, expected):
        self.assertEqual(grade_answer(answer, definition)[0], expected, answer)

    def test_the_meaning_alone_is_right(self):
        self.assertGrade("responsibility", VERANTWORTUNG, "correct")
        self.assertGrade("Responsibility.", VERANTWORTUNG, "correct")

    def test_each_comma_alternative_is_right(self):
        self.assertGrade("to implement", UMSETZEN, "correct")
        self.assertGrade("put into practice", UMSETZEN, "correct")
        self.assertGrade("to implement, put into practice", UMSETZEN, "correct")

    def test_each_numbered_meaning_is_right(self):
        for answer in ("tight", "brief", "just under"):
            self.assertGrade(answer, KNAPP, "correct")

    def test_the_translation_of_an_example_is_right(self):
        self.assertGrade("to take responsibility", VERANTWORTUNG, "correct")

    def test_copying_the_german_example_is_not_a_meaning(self):
        self.assertNotEqual(grade_answer("Verantwortung übernehmen", VERANTWORTUNG)[0], "correct")

    def test_a_note_in_brackets_is_optional(self):
        back = "1) interface (tech): eine Schnittstelle zum CRM\n2) link between teams: an der Schnittstelle"
        self.assertGrade("interface", back, "correct")
        self.assertGrade("interface (tech)", back, "correct")
        self.assertGrade("lever", "lever (lit. adjusting screw)\nan den richtigen Stellschrauben drehen = to pull the right levers", "correct")

    def test_a_typo_is_still_forgiven(self):
        self.assertGrade("responsibilty", VERANTWORTUNG, "correct")

    def test_a_wrong_answer_stays_wrong(self):
        self.assertGrade("freedom", VERANTWORTUNG, "incorrect")
        self.assertGrade("loose", KNAPP, "incorrect")
        self.assertGrade("", VERANTWORTUNG, "incorrect")

    def test_a_plain_one_line_back_works_as_before(self):
        self.assertGrade("hello", "hello", "correct")
        self.assertGrade("helo", "hello", "correct")
        self.assertGrade("goodbye", "hello", "incorrect")


if __name__ == '__main__':
    unittest.main(verbosity=2)
