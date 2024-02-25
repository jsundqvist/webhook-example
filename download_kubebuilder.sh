#!/bin/sh
rm -rf _test/kubebuilder && mkdir -p _test/kubebuilder
curl -L https://github.com/kubernetes-sigs/kubebuilder/releases/download/v2.3.2/kubebuilder_2.3.2_linux_amd64.tar.gz | tar xvz --strip-components=1 -C _test/kubebuilder
