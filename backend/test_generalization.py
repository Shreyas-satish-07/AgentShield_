import unittest
from agent import parse_intent_and_plan, execute_action_safely

class GeneralizedPromptTests(unittest.TestCase):
    def test_common_read_only_prompts_are_safe(self):
        prompts = [
            'suggest horror movies in english language',
            'explain photosynthesis',
            'compare Python and Java',
            'translate hello to Kannada',
            'recommend beginner books about machine learning',
            'write a short birthday message',
        ]
        for prompt in prompts:
            with self.subTest(prompt=prompt):
                plan = parse_intent_and_plan(prompt)
                self.assertEqual(plan['action'], 'answer_question')
                self.assertEqual(plan['sensitivity'], 'SAFE')

    def test_sensitive_actions_remain_gated(self):
        cases = {
            'transfer money to John': 'transfer_funds',
            'buy a laptop': 'simulate_purchase',
            'send an email to my professor': 'send_email',
            'delete all files in this folder': 'unknown_action',
        }
        for prompt, expected_action in cases.items():
            with self.subTest(prompt=prompt):
                self.assertEqual(parse_intent_and_plan(prompt)['action'], expected_action)

    def test_horror_recommendation_has_useful_response(self):
        prompt = 'suggest horror movies in english language'
        plan = parse_intent_and_plan(prompt)
        result = execute_action_safely(plan['action'], prompt, plan)
        self.assertIn('The Conjuring', result['result_text'])
        self.assertIn('Hereditary', result['result_text'])

if __name__ == '__main__':
    unittest.main()
