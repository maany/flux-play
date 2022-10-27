#!/bin/bash
#
# Setup for Node servers

set -euxo pipefail

sudo -i -u vagrant bash << EOF
sudo apt-get install -y nfs-common
EOF
