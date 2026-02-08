import copy
import pytest

from expert_system import InferenceEngine, Rule, ALL_RULES


def make_engine(rules=None):
    return InferenceEngine(rules if rules is not None else ALL_RULES)


def test_load_data_does_not_mutate_input():
    engine = make_engine()
    data = {"amount": 100}
    data_copy = copy.deepcopy(data)
    engine.load_data(data)
    # The original caller dict must not be mutated by load_data
    assert data == data_copy, "load_data should not mutate the caller's dict"


def test_forward_chain_single_rule_triggers():
    rules = [Rule("R1", [("amount", ">", 10)], "high_amount", 0.6)]
    engine = make_engine(rules)
    engine.load_data({"amount": 20})
    engine.forward_chain()
    assert "high_amount" in engine.inferred_facts
    assert engine.inferred_facts["high_amount"] == pytest.approx(0.6)


def test_confidence_combination_properties():
    engine = make_engine([Rule("noop", [], "x", 0.0)])
    # direct access to method: check associative-like behavior for given inputs
    c1 = engine._combine_confidence(0.2, 0.3)
    assert c1 == pytest.approx(0.2 + 0.3 - 0.2 * 0.3)
    # combining with 0 should return the other
    assert engine._combine_confidence(0.0, 0.45) == pytest.approx(0.45)
    # combining with 1.0 should return 1.0
    assert engine._combine_confidence(1.0, 0.5) == pytest.approx(1.0)


def test_known_device_prevents_new_device():
    # Using ALL_RULES, set device_seen_before True -> known_device should infer and new_device must not be inferred
    engine = make_engine()
    engine.load_data({"device_seen_before": True})
    engine.forward_chain()
    assert "known_device" in engine.inferred_facts
    assert "new_device" not in engine.inferred_facts


def test_circular_rules_terminate_and_produce_expected_facts():
    # Create a circular dependency A -> B, B -> A. Engine must not loop infinitely.
    rules = [
        Rule("A1", [("fact_a", "==", True)], "fact_b", 0.8),
        Rule("B1", [("fact_b", "==", True)], "fact_a", 0.7),
    ]
    engine = make_engine(rules)
    # seed fact_a
    engine.load_data({"fact_a": True})
    engine.forward_chain()
    assert "fact_a" in engine.inferred_facts
    assert "fact_b" in engine.inferred_facts
    # fired rules should contain both rules
    assert {"A1", "B1"}.issubset(engine.fired_rules)


def test_recommendations_default_for_low_risk():
    engine = make_engine()
    engine.load_data({"amount": 1, "ip_risk_score": 0, "account_age_days": 400})
    engine.forward_chain()
    recs = engine.get_recommendations()
    assert len(recs) >= 1
    top = recs[0]
    assert "APPROVE_recommended" in top[0] or top[0] == "APPROVE_recommended"


def test_find_relevant_questions_high_amount_triggers_verification_questions():
    engine = make_engine()
    engine.load_data({"amount": 2000, "ip_risk_score": 10, "account_age_days": 400})
    engine.forward_chain()
    questions = engine.find_relevant_questions()
    keys = {q for q, s, r in questions}
    assert "user_confirmed_transaction" in keys or "otp_passed" in keys


def test_should_continue_asking_honors_confidence_thresholds():
    engine = make_engine()
    # Construct scenario where recommended top action has very high confidence
    engine.inferred_facts["APPROVE_recommended"] = 0.95
    # since top_conf >= 0.92, should not continue asking
    assert engine.should_continue_asking() is False


def test_trace_populated_on_rule_fire():
    engine = make_engine()
    engine.load_data({"amount": 2000})
    engine.forward_chain()
    # At least one rule should fire for amount-based conditions
    assert len(engine.trace) > 0
    # trace entries should be human-readable strings
    assert any("Fired" in t or "Updated" in t for t in engine.trace)
