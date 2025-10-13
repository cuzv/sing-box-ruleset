#!/bin/bash

set -e -o pipefail

wget https://github.com/SagerNet/sing-box/releases/download/v${VERSION}/sing-box-${VERSION}-linux-amd64.tar.gz
tar -zxvf sing-box-${VERSION}-linux-amd64.tar.gz
mv sing-box-${VERSION}-linux-amd64/sing-box .

curl -fsSL https://adguardteam.github.io/AdGuardSDNSFilter/Filters/filter.txt -o filter.txt

./sing-box rule-set convert --type adguard --output output/AdGuardSDNSFilterSingBox.srs filter.txt
