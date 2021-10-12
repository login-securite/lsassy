clean:
	rm -f -r build/
	rm -f -r dist/
	rm -f -r *.egg-info
	find . -name '*.pyc' -exec rm -f {} +
	find . -name '*.pyo' -exec rm -f {} +
	find . -name '*~' -exec rm -f  {} +
	find . -name '__pycache__' -exec rm -rf  {} +

publish: clean
	python3.7 setup.py sdist bdist_wheel
	python3.7 -m twine upload dist/*

testpublish: clean
	python3.7 setup.py sdist bdist_wheel
	python3.7 -m twine upload --repository-url https://test.pypi.org/legacy/ dist/*

package: clean
	python setup.py install
	pyinstaller ./lsassy/console.py --onefile --clean -n lsassy --additional-hooks-dir=hooks

rebuild: clean
	python3.7 setup.py install

build: clean
	python3.7 setup.py install

install: build

test:
	python3.7 setup.py test