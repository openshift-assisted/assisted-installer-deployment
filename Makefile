SERVICE := $(or ${SERVICE},quay.io/ocpmetal/assisted-installer-deployment:latest)


all: pep8 pylint image

image: build
	skipper build assisted-installer-deployment

#update: image
#	GIT_REVISION=${GIT_REVISION} docker build --build-arg GIT_REVISION -t $(SERVICE) -f Dockerfile.ignition-manifests-and-kubeconfig-generate .
#	docker push $(SERVICE)

local-update: image
	docker build -t assisted-installer-deployment:local -f Dockerfile.assisted-installer-deployment .

.DEFAULT:
	skipper -v $(MAKE) $@
