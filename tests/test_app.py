from .context import blueprint


def test_app(capsys, example_fixture):
    # pylint: disable=W0612,W0613
    blueprint.Lsassy.run()
    captured = capsys.readouterr()

    assert "Hello World..." in captured.out
