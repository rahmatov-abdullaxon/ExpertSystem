"""
Expert System for E-commerce Fraud Detection - FINAL PRODUCTION VERSION
"""
import operator
from typing import Dict, List, Tuple, Set, Any


class Rule:
    def __init__(self, rule_id, conditions, conclusion, strength, description=""):
        self.id = rule_id
        self.conditions = conditions
        self.conclusion = conclusion
        self.strength = strength
        self.description = description

    def __repr__(self):
        return f"[{self.id}] {self.conclusion} ({self.strength})"


QUESTION_MAP = {
    "user_confirmed_transaction": "Was this transaction made by you? (yes/no)",
    "otp_passed": "Did the OTP/3DS verification succeed? (yes/no)",
    "user_confirmed_travel": "Are you currently traveling? (yes/no)",
    "shipping_address_changed_recently": "Is this shipping address new for you? (yes/no)",
    "device_seen_before": "Have you used this device before? (yes/no)",
}

ALL_RULES = [
    Rule("O1", [("amount", ">", 500)], "high_amount", 0.60),
    Rule("O2", [("amount", ">", 1500)], "very_high_amount", 0.80),
    Rule("O3", [("account_age_days", "<", 7)], "new_account", 0.80),
    Rule("O4", [("account_age_days", "<", 30)], "young_account", 0.50),
    Rule("O5", [("failed_logins_24h", ">=", 3)], "suspicious_login_activity", 0.70),
    Rule("O6", [("failed_logins_24h", ">=", 8)], "many_failed_logins", 0.85),
    Rule("O7", [("transactions_last_hour", ">=", 3)], "high_velocity", 0.70),
    Rule("O8", [("transactions_last_hour", ">=", 6)], "very_high_velocity", 0.85),
    Rule("O9", [("device_seen_before", "==", False)], "new_device", 0.70),
    Rule("O10", [("device_seen_before", "==", True)], "known_device", 0.60),
    Rule("O11", [("ip_risk_score", ">=", 80)], "high_ip_risk", 0.90),
    Rule("O12", [("ip_risk_score", ">=", 50)], "medium_ip_risk", 0.60),
    Rule("O13", [("country_mismatch", "==", True)], "location_mismatch", 0.70),
    Rule(
        "O14",
        [("billing_shipping_mismatch", "==", True)],
        "billing_shipping_mismatch_flag",
        0.75,
    ),
    Rule(
        "O15",
        [("shipping_address_changed_recently", "==", True)],
        "recent_address_change",
        0.65,
    ),
    Rule("O16", [("email_age_days", "<", 30)], "new_email", 0.55),
    Rule("O17", [("phone_verified", "==", False)], "unverified_phone", 0.60),
    Rule("O18", [("vpn_detected", "==", True)], "anonymous_connection", 0.65),
    Rule(
        "T1",
        [("location_mismatch", "==", True), ("new_device", "==", True)],
        "account_takeover_risk",
        0.75,
    ),
    Rule(
        "T2",
        [("suspicious_login_activity", "==", True), ("new_device", "==", True)],
        "account_takeover_risk",
        0.80,
    ),
    Rule("T3", [("many_failed_logins", "==", True)], "account_takeover_risk", 0.70),
    Rule(
        "T4",
        [("billing_shipping_mismatch_flag", "==", True), ("high_amount", "==", True)],
        "payment_fraud_risk",
        0.75,
    ),
    Rule(
        "T5",
        [("high_ip_risk", "==", True), ("anonymous_connection", "==", True)],
        "payment_fraud_risk",
        0.70,
    ),
    Rule(
        "T6",
        [("location_mismatch", "==", True), ("high_amount", "==", True)],
        "payment_fraud_risk",
        0.60,
    ),
    Rule(
        "T7",
        [("new_account", "==", True), ("unverified_phone", "==", True)],
        "fake_account_risk",
        0.75,
    ),
    Rule(
        "T8",
        [("new_email", "==", True), ("unverified_phone", "==", True)],
        "fake_account_risk",
        0.70,
    ),
    Rule(
        "T9",
        [("young_account", "==", True), ("high_velocity", "==", True)],
        "fake_account_risk",
        0.60,
    ),
    Rule("T10", [("very_high_velocity", "==", True)], "automation_risk", 0.80),
    Rule(
        "T11",
        [("high_velocity", "==", True), ("medium_ip_risk", "==", True)],
        "automation_risk",
        0.65,
    ),
    Rule(
        "T12",
        [("recent_address_change", "==", True), ("location_mismatch", "==", True)],
        "suspicious_delivery_risk",
        0.70,
    ),
    Rule(
        "T13",
        [("suspicious_delivery_risk", "==", True), ("high_amount", "==", True)],
        "reshipping_risk",
        0.70,
    ),
    Rule("C1", [("user_confirmed_transaction", "==", True)], "legitimate_user", 0.90),
    Rule("C2", [("otp_passed", "==", True)], "legitimate_user", 0.95),
    Rule(
        "C3", [("user_confirmed_travel", "==", True)], "expected_location_change", 0.90
    ),
    Rule(
        "C4",
        [("location_mismatch", "==", True), ("expected_location_change", "==", True)],
        "location_explained",
        0.95,
    ),
    Rule("C5", [("known_device", "==", True)], "trusted_device", 0.60),
    Rule(
        "C6",
        [("account_age_days", ">", 180), ("past_chargebacks", "==", 0)],
        "trusted_history",
        0.70,
    ),
    Rule(
        "D1",
        [("account_takeover_risk", "==", True), ("very_high_amount", "==", True)],
        "DECLINE_recommended",
        0.85,
    ),
    Rule(
        "D2",
        [("account_takeover_risk", "==", True)],
        "STEP_UP_VERIFY_recommended",
        0.70,
    ),
    Rule(
        "D3",
        [("payment_fraud_risk", "==", True), ("high_amount", "==", True)],
        "MANUAL_REVIEW_recommended",
        0.70,
    ),
    Rule(
        "D4",
        [("fake_account_risk", "==", True), ("high_amount", "==", True)],
        "MANUAL_REVIEW_recommended",
        0.75,
    ),
    Rule("D5", [("automation_risk", "==", True)], "DECLINE_recommended", 0.85),
    Rule("D6", [("reshipping_risk", "==", True)], "MANUAL_REVIEW_recommended", 0.75),
    Rule(
        "D7",
        [("high_ip_risk", "==", True), ("very_high_amount", "==", True)],
        "STEP_UP_VERIFY_recommended",
        0.60,
    ),
    Rule("D8", [("legitimate_user", "==", True)], "APPROVE_recommended", 0.95),
    Rule("D9", [("location_explained", "==", True)], "APPROVE_recommended", 0.85),
    Rule("D10", [("trusted_history", "==", True)], "APPROVE_recommended", 0.60),
]


class InferenceEngine:
    MAX_CONFIDENCE = 1.0
    MIN_CONFIDENCE = 0.0

    def __init__(self, rules: List[Rule]):
        self.rules = rules
        self.values: Dict[str, any] = {}
        self.inferred_facts: Dict[str, float] = {}
        self.trace: List[str] = []
        self.fired_rules: Set[str] = set()
        self.asked_questions: Set[str] = set()

    # Replace the existing load_data method with the following:
    def load_data(self, data: Dict[str, Any]) -> None:
        data = dict(data)  # defensive copy; do NOT mutate caller's dict
        defaults = {
            "email_age_days": 180,
            "vpn_detected": False,
            "shipping_address_changed_recently": False,
            "past_chargebacks": 0,
        }
        for k, v in defaults.items():
            data.setdefault(k, v)
        # merge into internal values (preserve previously-loaded values if needed)
        self.values.update(data)

    def _eval_condition(self, condition: Tuple) -> Tuple[bool, float]:
        fact_name, op_str, target_val = condition

        # Prefer explicit input values, but if the fact was derived we must use its inferred confidence.
        if fact_name in self.values:
            current_val = self.values[fact_name]
            if fact_name in self.inferred_facts:
                confidence = float(self.inferred_facts[fact_name])
            else:
                confidence = self.MAX_CONFIDENCE
        elif fact_name in self.inferred_facts:
            confidence = float(self.inferred_facts[fact_name])
            if isinstance(target_val, bool):
                current_val = True if confidence > 0.0 else False
            else:
                current_val = confidence
        else:
            return False, self.MIN_CONFIDENCE

        ops = {
            ">": operator.gt,
            "<": operator.lt,
            ">=": operator.ge,
            "<=": operator.le,
            "==": operator.eq,
            "!=": operator.ne,
        }

        # Boolean target: return inferred confidence (not 1.0) when fact was derived.
        if isinstance(target_val, bool):
            result = bool(current_val) == target_val
            return (result, confidence if result else self.MIN_CONFIDENCE)

        # Numeric/comparison target: try to compare using current_val
        try:
            if op_str not in ops:
                return False, self.MIN_CONFIDENCE
            if ops[op_str](current_val, target_val):
                return True, confidence
            return False, self.MIN_CONFIDENCE
        except Exception:
            return False, self.MIN_CONFIDENCE

    def _combine_confidence(self, c1: float, c2: float) -> float:
        combined = c1 + c2 - (c1 * c2)
        return min(max(combined, self.MIN_CONFIDENCE), self.MAX_CONFIDENCE)

    def forward_chain(self):
        max_iterations = max(50, len(self.rules) * 3)
        iteration = 0
        changed = True

        while changed and iteration < max_iterations:
            changed = False
            iteration += 1

            for rule in self.rules:
                if rule.id in self.fired_rules:
                    continue

                premises_met = True
                min_premise_confidence = self.MAX_CONFIDENCE

                # Evaluate premises with debug printing
                for cond in rule.conditions:
                    ok, conf = self._eval_condition(cond)
                    # cond is tuple like (fact, op, val)
                    if not ok:
                        premises_met = False
                        break
                    min_premise_confidence = min(min_premise_confidence, conf)

                if not premises_met:
                    continue

                inferred_conf = min_premise_confidence * rule.strength
                prev_conf = self.inferred_facts.get(
                    rule.conclusion, self.MIN_CONFIDENCE
                )
                self.fired_rules.add(rule.id)

                if rule.conclusion not in self.inferred_facts:
                    self.inferred_facts[rule.conclusion] = inferred_conf
                    self.values[rule.conclusion] = True
                    self.trace.append(
                        f"Fired {rule.id}: '{rule.conclusion}' = {inferred_conf:.2f}"
                    )
                    changed = True
                else:
                    combined = self._combine_confidence(prev_conf, inferred_conf)
                    if combined > prev_conf + 1e-12:
                        self.inferred_facts[rule.conclusion] = combined
                        self.trace.append(
                            f"Updated '{rule.conclusion}': {prev_conf:.2f} -> {combined:.2f} via {rule.id}"
                        )
                        changed = True

    def get_active_risk_indicators(self) -> List[str]:
        risk_facts = [
            "new_device",
            "location_mismatch",
            "high_amount",
            "very_high_amount",
            "suspicious_login_activity",
            "many_failed_logins",
            "high_velocity",
            "very_high_velocity",
            "high_ip_risk",
            "medium_ip_risk",
            "billing_shipping_mismatch_flag",
            "recent_address_change",
            "new_account",
            "young_account",
            "unverified_phone",
            "new_email",
            "anonymous_connection",
        ]
        active = []
        for fact in risk_facts:
            conf = self.inferred_facts.get(fact, 0.0)
            if conf > 0.5:
                active.append(fact)
        return active

    def calculate_risk_level(self) -> float:
        active = self.get_active_risk_indicators()

        high_severity = {
            "high_ip_risk",
            "many_failed_logins",
            "very_high_velocity",
            "very_high_amount",
            "anonymous_connection",
        }
        medium_severity = {
            "location_mismatch",
            "new_device",
            "suspicious_login_activity",
            "high_amount",
            "billing_shipping_mismatch_flag",
            "recent_address_change",
            "high_velocity",
        }
        low_severity = {
            "medium_ip_risk",
            "new_account",
            "young_account",
            "unverified_phone",
            "new_email",
        }

        score = 0.0
        for r in active:
            conf = self.inferred_facts.get(r, 0.0)
            if r in high_severity:
                score += conf * 0.35
            elif r in medium_severity:
                score += conf * 0.20
            elif r in low_severity:
                score += conf * 0.10
        return min(score, 1.0)

    def has_explainable_anomalies(self) -> bool:
        if (
            "location_mismatch" in self.inferred_facts
            and "location_explained" not in self.inferred_facts
        ):
            return True
        if (
            "recent_address_change" in self.inferred_facts
            and "shipping_address_changed_recently" not in self.asked_questions
        ):
            return True
        return False

    def find_relevant_questions(self) -> List[Tuple[str, float, str]]:
        questions_scored = {}
        active_risks = self.get_active_risk_indicators()
        overall_risk = self.calculate_risk_level()

        if (
            "location_mismatch" in active_risks
            and "location_explained" not in self.inferred_facts
        ):
            q = "user_confirmed_travel"
            if q not in self.asked_questions:
                questions_scored[q] = (1.00, "Explain location anomaly")

        if "recent_address_change" in active_risks:
            q = "shipping_address_changed_recently"
            if q not in self.asked_questions and q not in questions_scored:
                questions_scored[q] = (0.90, "Confirm address change")

        # low-risk, no explainable anomalies → return what's already queued (consistent tuple shape)
        if overall_risk < 0.12 and not self.has_explainable_anomalies():
            return [
                (q, score, reason) for q, (score, reason) in questions_scored.items()
            ]

        risk_to_questions = {
            "new_device": ["device_seen_before", "user_confirmed_transaction"],
        }

        for risk in active_risks:
            if risk in risk_to_questions:
                for q in risk_to_questions[risk]:
                    if q in QUESTION_MAP and q not in self.asked_questions:
                        if q not in questions_scored:
                            risk_conf = self.inferred_facts.get(risk, 0.5)
                            questions_scored[q] = (risk_conf * 0.80, f"Address {risk}")

        if overall_risk > 0.45 or self.values.get("amount", 0) > 1500:
            for q in ["user_confirmed_transaction", "otp_passed"]:
                if q not in self.asked_questions and q not in questions_scored:
                    questions_scored[q] = (0.65, "High-risk verification")

        recs = self.get_recommendations()
        if len(recs) >= 2:
            top_conf, second_conf = recs[0][1], recs[1][1]
            if abs(top_conf - second_conf) < 0.20:
                for q in ["user_confirmed_transaction", "otp_passed"]:
                    if q not in self.asked_questions:
                        if q in questions_scored:
                            score, reason = questions_scored[q]
                            questions_scored[q] = (
                                score * 1.2,
                                f"{reason} + disambiguate",
                            )
                        else:
                            questions_scored[q] = (0.70, "Close decision")

        result = [(q, score, reason) for q, (score, reason) in questions_scored.items()]
        result.sort(key=lambda x: x[1], reverse=True)
        return result

    def get_recommendations(self) -> List[Tuple[str, float]]:
        actions = [
            "DECLINE_recommended",
            "MANUAL_REVIEW_recommended",
            "STEP_UP_VERIFY_recommended",
            "APPROVE_recommended",
        ]

        results = []
        for act in actions:
            if act in self.inferred_facts:
                results.append((act, self.inferred_facts[act]))

        if not results:
            risk_level = self.calculate_risk_level()
            if risk_level < 0.12:
                results.append(("APPROVE_recommended", 0.92))
            elif risk_level < 0.30:
                results.append(("APPROVE_recommended", 0.70))
            else:
                results.append(("STEP_UP_VERIFY_recommended", 0.55))

        return sorted(results, key=lambda x: x[1], reverse=True)

    def should_continue_asking(self) -> bool:
        recs = self.get_recommendations()
        if not recs:
            return False

        top_action, top_conf = recs[0]
        risk_level = self.calculate_risk_level()

        if self.has_explainable_anomalies():
            return True

        if top_conf >= 0.92:
            return False

        if risk_level < 0.12 and top_conf >= 0.80:
            return False

        if top_conf >= 0.88 and top_action in [
            "DECLINE_recommended",
            "MANUAL_REVIEW_recommended",
        ]:
            return False

        if len(recs) >= 2 and (top_conf - recs[1][1] < 0.15):
            return True

        return risk_level > 0.25 and top_conf < 0.80


def run_expert_system(initial_data: Dict, auto_answer: Dict[str, bool] = None):
    engine = InferenceEngine(ALL_RULES)
    engine.load_data(initial_data)

    print("\n" + "=" * 60)
    print("FRAUD DETECTION EXPERT SYSTEM")
    print("=" * 60 + "\n")

    print("Transaction Data:")
    for key, value in sorted(initial_data.items()):
        print(f"  {key}: {value}")

    max_questions = 5
    questions_asked = 0

    while questions_asked < max_questions:
        print(f"\n[Step {questions_asked + 1}] Analyzing...")
        engine.forward_chain()

        active_risks = engine.get_active_risk_indicators()
        risk_level = engine.calculate_risk_level()

        print(f"\nRisk Level: {risk_level:.2f}")
        if active_risks:
            print(f"Active Indicators: {', '.join(active_risks)}")
        else:
            print("Active Indicators: None")

        recs = engine.get_recommendations()
        print("\nCurrent Assessment:")
        for action, conf in recs[:3]:
            action_label = action.replace("_recommended", "").replace("_", " ").upper()
            print(f"  {action_label}: {conf:.2f}")

        if not engine.should_continue_asking():
            top_action, top_conf = recs[0]
            print(
                f"\n>>> FINAL: {top_action.replace('_recommended', '').replace('_', ' ').upper()} ({top_conf:.2f})"
            )
            break

        relevant_questions = engine.find_relevant_questions()

        if not relevant_questions:
            top_action, top_conf = recs[0]
            print(
                f"\n>>> FINAL: {top_action.replace('_recommended', '').replace('_', ' ').upper()} ({top_conf:.2f})"
            )
            break

        question_fact, score, reason = relevant_questions[0]
        engine.asked_questions.add(question_fact)

        print(f"\n[?] {QUESTION_MAP[question_fact]}")
        print(f"    ({reason})")

        if auto_answer and question_fact in auto_answer:
            val = auto_answer[question_fact]
            ans_text = "yes" if val else "no"
            print(f"    Auto-answer: {ans_text}")
        else:
            ans = input("    Answer: ").strip().lower()
            val = ans in ["yes", "y", "1", "true"]

        engine.load_data({question_fact: val})

        questions_asked += 1

    print("\n" + "=" * 60)
    print("REASONING TRACE")
    print("=" * 60)
    for line in engine.trace:
        print(f"  {line}")
    print()


if __name__ == "__main__":
    test_12 = {
        "amount": 1,
        "ip_risk_score": 0,
        "account_age_days": 1,
        "country_mismatch": True,
        "device_seen_before": True,
        "failed_logins_24h": 0,
        "transactions_last_hour": 4,
        "billing_shipping_mismatch": False,
        "phone_verified": True,
    }
    run_expert_system(test_12)
