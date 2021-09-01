all: pycodestyle pylint

clean:
	rm -rf build dist *egg-info ./__pycache__
	find -name *.pyc -delete

##########
# Verify #
##########

lint: pycodestyle

pycodestyle:
	pycodestyle .

autopep8:
	autopep8 --recursive --in-place .

pylint:
	mkdir -p reports
	PYLINTHOME=reports/ pylint release/

###########
# Release #
###########

snapshot:
	skipper run python3 tools/update_assisted_installer_yaml.py --full

tag_images:
	skipper run python3 tools/assisted_installer_stable_promotion.py --tag ${TAG} --version-tag
