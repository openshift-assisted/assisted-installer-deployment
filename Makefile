SERVICE := $(or ${SERVICE},quay.io/ocpmetal/assisted-installer-deployment:latest)


all: pycodestyle pylint image

lint: pycodestyle

image: build
	skipper build assisted-installer-deployment

local-update: image
	docker build -t assisted-installer-deployment:local -f Dockerfile.assisted-installer-deployment .

build:
	python setup.py sdist

pycodestyle:
	pycodestyle .

autopep8:
	autopep8 --recursive --in-place .

pylint:
	mkdir -p reports
	PYLINTHOME=reports/ pylint release

clean:
	rm -rf build dist *egg-info ./__pycache__
	find -name *.pyc -delete
