"""Safe evaluation and attenuation checks for declarative capability predicates."""

import json
from collections.abc import Mapping
from typing import Any, ClassVar


class PredicateError(ValueError):
    """A capability predicate is malformed or cannot be evaluated safely."""


class PredicateEngine:
    """Evaluate a small, deterministic predicate language without executing code."""

    _OPERATORS: ClassVar[set[str]] = {
        "eq",
        "ne",
        "lt",
        "lte",
        "gt",
        "gte",
        "in",
        "not_in",
        "exists",
    }

    @classmethod
    def validate(cls, expression: dict[str, Any]) -> None:
        cls._validate_expression(expression)

    @classmethod
    def evaluate(cls, expression: dict[str, Any], environment: dict[str, Any]) -> bool:
        cls.validate(expression)
        return cls._evaluate(expression, environment)

    @classmethod
    def is_attenuated(
        cls,
        child: dict[str, Any] | None,
        parent: dict[str, Any] | None,
    ) -> bool:
        """Prove narrowing for conjunctions by requiring every parent clause in the child."""
        if child is not None:
            cls.validate(child)
        if parent is None:
            return True

        cls.validate(parent)
        if child is None:
            return False

        parent_clauses = cls._conjunctive_clauses(parent)
        child_clauses = cls._conjunctive_clauses(child)
        if parent_clauses is None or child_clauses is None:
            return False

        child_keys = {cls._canonical(clause) for clause in child_clauses}
        return all(cls._canonical(clause) in child_keys for clause in parent_clauses)

    @classmethod
    def combine(
        cls,
        parent: dict[str, Any] | None,
        child: dict[str, Any] | None,
    ) -> dict[str, Any] | None:
        parent_clauses = cls._conjunctive_clauses(parent or {"all": []}) or []
        child_clauses = cls._conjunctive_clauses(child or {"all": []}) or []
        clauses = [*parent_clauses, *child_clauses]
        if not clauses:
            return None
        unique_clauses = {cls._canonical(clause): clause for clause in clauses}
        return {"all": list(unique_clauses.values())}

    @classmethod
    def _validate_expression(cls, expression: Any) -> None:
        if not isinstance(expression, dict):
            raise PredicateError("predicate must be a single operator or a path/operator object")

        if "all" in expression or "any" in expression:
            if len(expression) != 1:
                raise PredicateError("logical predicates cannot contain extra fields")
            key = "all" if "all" in expression else "any"
            items = expression[key]
            if not isinstance(items, list):
                raise PredicateError(f"{key} predicate must contain a list")
            for item in items:
                cls._validate_expression(item)
            return

        if "not" in expression:
            if len(expression) != 1:
                raise PredicateError("not predicate cannot contain extra fields")
            cls._validate_expression(expression["not"])
            return

        if (
            "path" not in expression
            or "op" not in expression
            or not set(expression).issubset({"path", "op", "value"})
        ):
            raise PredicateError("predicate requires path and op")
        if not isinstance(expression["path"], str) or not expression["path"]:
            raise PredicateError("predicate path must be a non-empty string")
        if not isinstance(expression["op"], str) or expression["op"] not in cls._OPERATORS:
            raise PredicateError(f"unsupported predicate operator: {expression['op']}")
        if expression["op"] != "exists" and "value" not in expression:
            raise PredicateError("predicate requires a value")
        if expression["op"] == "exists" and not isinstance(expression.get("value"), bool):
            raise PredicateError("exists predicate value must be boolean")
        if expression["op"] in {"in", "not_in"} and not isinstance(expression["value"], list):
            raise PredicateError(f"{expression['op']} predicate value must be a list")

    @classmethod
    def _evaluate(cls, expression: dict[str, Any], environment: dict[str, Any]) -> bool:
        if "all" in expression:
            return all(cls._evaluate(item, environment) for item in expression["all"])
        if "any" in expression:
            return any(cls._evaluate(item, environment) for item in expression["any"])
        if "not" in expression:
            return not cls._evaluate(expression["not"], environment)

        found, actual = cls._resolve(environment, expression["path"])
        operator = expression["op"]
        expected = expression.get("value")
        if operator == "exists":
            return found is expected
        if not found:
            return False
        if operator == "eq":
            return bool(actual == expected)
        if operator == "ne":
            return bool(actual != expected)
        if operator == "in":
            if not isinstance(expected, list):
                raise PredicateError("in predicate value must be a list")
            return actual in expected
        if operator == "not_in":
            if not isinstance(expected, list):
                raise PredicateError("not_in predicate value must be a list")
            return actual not in expected

        try:
            if operator == "lt":
                return bool(actual < expected)
            if operator == "lte":
                return bool(actual <= expected)
            if operator == "gt":
                return bool(actual > expected)
            return bool(actual >= expected)
        except TypeError as exc:
            raise PredicateError(
                f"incompatible values for predicate at {expression['path']}"
            ) from exc

    @staticmethod
    def _resolve(environment: Mapping[str, Any], path: str) -> tuple[bool, Any]:
        current: Any = environment
        for segment in path.split("."):
            if not isinstance(current, Mapping) or segment not in current:
                return False, None
            current = current[segment]
        return True, current

    @classmethod
    def _conjunctive_clauses(cls, expression: dict[str, Any]) -> list[dict[str, Any]] | None:
        if "all" in expression:
            clauses: list[dict[str, Any]] = []
            for item in expression["all"]:
                if "path" not in item:
                    return None
                clauses.append(item)
            return clauses
        if "path" in expression:
            return [expression]
        return None

    @staticmethod
    def _canonical(value: dict[str, Any]) -> str:
        return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True)
