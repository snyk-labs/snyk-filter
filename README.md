[![Snyk logo](https://snyk.io/style/asset/logo/snyk-print.svg)](https://snyk.io)

***

# Snyk Custom Filtering of SNYK CLI JSON output
The Snyk-filter module takes the json outputted from `snyk test --json` and adds custom filtering for results filtering as well as breaking options for CI usage.

# How do I use it?

## Install or clone

First, Install the Snyk Filter using npm:

`npm install snyk-filter -g`

Alternatively, you can skip this step, clone the repo and run the script locally (using `node ./snyk-filter.js`)

## Usage

1. Implement your custom JQ filters in a json file (see sample in sample-filters and tweak things from there)

2. Then pipe you snyk test json output into snyk-filter or use the -i argument to input a json file. Use the -f argument to point to the json file containing your custom filters.

### License

[License: Apache License, Version 2.0](LICENSE)
