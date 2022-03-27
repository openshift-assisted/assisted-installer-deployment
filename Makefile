all: lint

clean:
	rm -rf build dist *egg-info ./__pycache__
	find -name *.pyc -delete

##########
# Verify #
##########

lint: flake8 pylint

flake8:
	flake8 .

unit-test:
	pytest tools/

autopep8:
	autopep8 --recursive --in-place .

pylint:
	pylint release/ tools/check_ai_images.py

###########
# Release #
###########

snapshot:
	skipper run python3 tools/update_assisted_installer_yaml.py --full
	$(MAKE) verify_snapshot

verify_snapshot:
	skipper run python3 tools/check_ai_images.py

tag_images:
	skipper run python3 tools/assisted_installer_stable_promotion.py --tag ${TAG} --version-tag
