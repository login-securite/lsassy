clean:
	rm -f -r build/
	rm -f -r dist/
	rm -f -r *.egg-info
	find . -name '*.pyc' -exec rm -f {} +
	find . -name '*.pyo' -exec rm -f {} +
	find . -name '*~' -exec rm -f  {} +
	find . -name '__pycache__' -exec rm -rf  {} +

publish: clean build
	poetry publish

testpublish: clean build
	poetry config repositories.testpypi https://test.pypi.org/legacy/
	poetry publish --repository testpypi

rebuild: clean
	poetry install

build: clean
	poetry build

install:
	poetry install

test:
	nox -r
