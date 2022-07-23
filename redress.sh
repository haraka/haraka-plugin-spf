#!/bin/sh

if [ -z "$1" ]; then
  echo "$0 something"
  exit
fi

sed -i '' -e "s/template/${1}/g" README.md

sed -i '' \
    -e "s/template/${1}/g" \
    -e "s/template\.ini/$1.ini/" \
    test/index.js

sed -i '' -e "s/template/${1}/g" package.json
sed -i '' \
    -e "s/_template/_${1}/g" \
    -e "s/template\.ini/$1.ini/" \
    index.js

tee Changes.md <<EO_CHANGE
## 1.0.0 - $(date +%Y-%m-%d)

- Initial release
EO_CHANGE
git mv config/template.ini "config/$1.ini"
git add package.json Changes.md README.md index.js test config
git commit -m "renamed template to $1"
npm install
npm run lint && npm test || exit 1
git rm redress.sh

echo "success!"
echo ""
echo "Next Steps: update package.json and force push this onto your repo:"
echo ""
echo "    \$EDITOR package.json"
echo "    git push --set-upstream origin master -f"
echo ""
