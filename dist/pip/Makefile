PYTHON?=python3

all:
	$(PYTHON) setup.py build

pub:
	$(PYTHON) setup.py build sdist
	twine check dist/*
	twine upload -u __token__ --repository-url https://upload.pypi.org/legacy/ --verbose dist/*
