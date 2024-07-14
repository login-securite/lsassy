import nox


@nox.session(python=["3.9", "3.7"])
def tests(session):
    session.run("poetry", "install", external=True)
    session.run("poetry", "run", "pytest", "--cov")
