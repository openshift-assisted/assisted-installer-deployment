#!/usr/bin/env bash

set -o nounset
set -o pipefail
set -o errexit
set -o xtrace

function print_help() {
  ALL_FUNCS="assisted_service|print_help"
  echo "Usage: bash ${0} (${ALL_FUNCS})"
}

function kustomize() {
  if which kustomize; then
    return
  fi

  # We tried using "official" install_kustomize.sh script, but it used too much rate-limited APIs of GitHub
  curl -L --retry 5 "https://github.com/kubernetes-sigs/kustomize/releases/download/kustomize%2Fv4.3.0/kustomize_v4.3.0_linux_amd64.tar.gz" | \
    tar -zx -C /usr/bin/
}

function butane() {
  echo "Installing butane..."
  curl https://mirror.openshift.com/pub/openshift-v4/clients/butane/latest/butane-${ARCH} --output /usr/local/bin/butane
  chmod +x /usr/local/bin/butane
}

function assisted_service() {
  ARCH=$(case $(arch) in x86_64) echo -n amd64 ;; aarch64) echo -n arm64 ;; *) echo -n $(arch) ;; esac)
  OS=$(uname | awk '{print tolower($0)}')
  OPERATOR_SDK_DL_URL=https://github.com/operator-framework/operator-sdk/releases/download/v1.10.1
  curl --retry 5 -LO ${OPERATOR_SDK_DL_URL}/operator-sdk_${OS}_${ARCH}
  chmod +x operator-sdk_${OS}_${ARCH}
  install operator-sdk_${OS}_${ARCH} /usr/local/bin/operator-sdk

  go get github.com/onsi/ginkgo/ginkgo@v1.16.4 \
    golang.org/x/tools/cmd/goimports@v0.1.5 \
    github.com/golang/mock/mockgen@v1.5.0 \
    github.com/vektra/mockery/.../@v1.1.2 \
    gotest.tools/gotestsum@v1.6.3 \
    github.com/axw/gocov/gocov \
    sigs.k8s.io/controller-tools/cmd/controller-gen@v0.6.2 \
    github.com/AlekSi/gocov-xml@v0.0.0-20190121064608-3a14fb1c4737

  butane
  kustomize
}

declare -F $@ || (print_help && exit 1)

"$@"
