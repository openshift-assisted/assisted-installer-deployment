.PHONY: all clean lint flake8 unit-test autopep8 isort pylint snapshot verify_snapshot tag_images release

all: lint

clean:
	rm -rf build dist *egg-info ./__pycache__
	find -name *.pyc -delete

###############
# Development #
###############

# This affects the message at the top of the auto-generated files,
# instruction users how they should be updated
CUSTOM_COMPILE_COMMAND = "make pip-freeze"

.PHONY: pip-freeze requirements.txt dev-requirements.txt

requirements.txt: requirements.in
	CUSTOM_COMPILE_COMMAND=$(CUSTOM_COMPILE_COMMAND) pip-compile $<

dev-requirements.txt: dev-requirements.in
	CUSTOM_COMPILE_COMMAND=$(CUSTOM_COMPILE_COMMAND) pip-compile $<

# Compiles the input requirement files into a frozen requirement file
pip-freeze: requirements.txt dev-requirements.txt

##########
# Verify #
##########

lint: flake8 pylint isort black

black:
	black --check --diff tools/

format:
	black tools/
	isort --profile black tools/ tests/

flake8:
	flake8 .

unit-test:
	pytest --disable-warnings tests/

autopep8:
	autopep8 --recursive --in-place .

pylint:
	pylint release/ tools/check_ai_images.py tools/jira_client tests/

isort:
	isort --profile black --check-only release/ tools/ tests/

###########
# Release #
###########

snapshot:
	skipper run python3 tools/update_assisted_installer_yaml.py --full
	$(MAKE) verify_snapshot

verify_snapshot:
	skipper run python3 tools/check_ai_images.py

tag_images:
	skipper run -i python3 tools/assisted_installer_stable_promotion.py --tag ${TAG} --version-tag

release:
	skipper run -i release -- --tag ${TAG}
