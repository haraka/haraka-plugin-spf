[![CI Test Status][ci-img]][ci-url]
[![Code Climate][clim-img]][clim-url]
[![NPM][npm-img]][npm-url]

# haraka-plugin-spf

Clone me, to create a new Haraka plugin!

# Template Instructions

These instructions will not self-destruct after use. Use and destroy.

See also, [How to Write a Plugin](https://github.com/haraka/Haraka/wiki/Write-a-Plugin) and [Plugins.md](https://github.com/haraka/Haraka/blob/master/docs/Plugins.md) for additional plugin writing information.

## Create a new repo for your plugin

Haraka plugins are named like `haraka-plugin-something`. All the namespace after `haraka-plugin-` is yours for the taking. Please check the [Plugins](https://github.com/haraka/Haraka/blob/master/Plugins.md) page and a Google search to see what plugins already exist.

Once you've settled on a name, create the GitHub repo. On the repo's main page, click the _Clone or download_ button and copy the URL. Then paste that URL into a local ENV variable with a command like this:

```sh
export MY_GITHUB_ORG=haraka
export MY_PLUGIN_NAME=haraka-plugin-SOMETHING
```

Clone and rename the spf repo:

```sh
git clone git@github.com:haraka/haraka-plugin-spf.git
mv haraka-plugin-spf $MY_PLUGIN_NAME
cd $MY_PLUGIN_NAME
git remote rm origin
git remote add origin "git@github.com:$MY_GITHUB_ORG/$MY_PLUGIN_NAME.git"
```

Now you'll have a local git repo to begin authoring your plugin

## rename boilerplate

Replaces all uses of the word `spf` with your plugin's name.

./redress.sh [something]

You'll then be prompted to update package.json and then force push this repo onto the GitHub repo you've created earlier.


# Add your content here

## INSTALL

```sh
cd /path/to/local/haraka
npm install haraka-plugin-spf
echo "spf" >> config/plugins
service haraka restart
```

### Configuration

If the default configuration is not sufficient, copy the config file from the distribution into your haraka config dir and then modify it:

```sh
cp node_modules/haraka-plugin-spf/config/spf.ini config/spf.ini
$EDITOR config/spf.ini
```

## USAGE


<!-- leave these buried at the bottom of the document -->
[ci-img]: https://github.com/haraka/haraka-plugin-spf/actions/workflows/ci.yml/badge.svg
[ci-url]: https://github.com/haraka/haraka-plugin-spf/actions/workflows/ci.yml
[clim-img]: https://codeclimate.com/github/haraka/haraka-plugin-spf/badges/gpa.svg
[clim-url]: https://codeclimate.com/github/haraka/haraka-plugin-spf
[npm-img]: https://nodei.co/npm/haraka-plugin-spf.png
[npm-url]: https://www.npmjs.com/package/haraka-plugin-spf
