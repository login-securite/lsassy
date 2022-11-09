clean:
	rm -f -r build/
	rm -f -r dist/
	rm -f -r *.egg-info
	find . -name '*.pyc' -exec rm -f {} +
	find . -name '*.pyo' -exec rm -f {} +
	find . -name '*~' -exec rm -f  {} +
	find . -name '__pycache__' -exec rm -rf  {} +

publish: clean
	python setup.py sdist bdist_wheel
	python -m twine upload dist/*

testpublish: clean
	python setup.py sdist bdist_wheel
	python -m twine upload --repository-url https://test.pypi.org/legacy/ dist/*

linux: clean
	python setup.py install
	pyinstaller ./lsassy/console.py --onefile --clean -n lsassy_linux_amd64 --additional-hooks-dir=hooks

windows: clean
	python setup.py install
	pyinstaller ./lsassy/console.py --onefile --clean -n lsassy_windows_amd64 --additional-hooks-dir=hooks

rebuild: clean
	python setup.py install

build: clean
	python setup.py install

install: build

test:
	python setup.py test
