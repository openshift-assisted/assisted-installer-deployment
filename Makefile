SERVICE := $(or ${SERVICE},quay.io/ocpmetal/assisted-installer-deployment:latest)


all: pycodestyle pylint image

image: build
	skipper build assisted-installer-deployment

local-update: image
	docker build -t assisted-installer-deployment:local -f Dockerfile.assisted-installer-deployment .

.DEFAULT:
	skipper -v $(MAKE) $@
