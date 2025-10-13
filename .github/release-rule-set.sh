# https://github.com/SagerNet/sing-geosite/blob/main/.github/release-rule-set.sh

#!/bin/bash

set -e -o pipefail


for file in output/*.json; do
    ./sing-box rule-set compile "$file"
done


cd output
git init
git config --local user.email "github-action@users.noreply.github.com"
git config --local user.name "GitHub Action"
git remote add origin https://github-action:$GITHUB_TOKEN@github.com/xmdhs/sing-box-ruleset.git
git branch -M rule-set
git add .
git commit -m "Update rule-set"
git push -f origin rule-set
