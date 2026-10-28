"""Basic DDF CLI tests."""

from click.testing import CliRunner

from ddf.cli.main import cli


def test_cli_help():
    result = CliRunner().invoke(
        cli,
        ["--help"],
    )

    assert result.exit_code == 0
    assert "Dynamic Delegation Fabric" in result.output


def test_cli_has_core_commands():
    result = CliRunner().invoke(
        cli,
        ["--help"],
    )

    for command in (
        "server",
        "identity",
        "grant",
        "delegate",
        "authorize",
        "revoke",
        "chain",
        "explain",
        "demo",
    ):
        assert command in result.output


def test_v02_cli_uses_assertion_json_and_exposes_no_legacy_options():
    runner = CliRunner()
    grant = runner.invoke(cli, ["grant", "--help"])
    delegate = runner.invoke(cli, ["delegate", "--help"])
    authorize = runner.invoke(cli, ["authorize", "--help"])

    assert grant.exit_code == delegate.exit_code == authorize.exit_code == 0
    assert "--assertion-json" in grant.output
    assert "--assertion-json" in delegate.output
    assert "--request-json" in authorize.output
    for output in (grant.output, delegate.output, authorize.output):
        assert "--purpose" not in output
        assert "--amount" not in output
        assert "--actions" not in output
