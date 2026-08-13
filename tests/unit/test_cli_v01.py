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
