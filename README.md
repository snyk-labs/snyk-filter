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

1. Implement your custom JQ filters in a .snyk/snyk.yml file (see sample in sample-filters and tweak things from there - use [![JQPlay]](https://jqplay.org/) )

2. Place the snyk.yml file in .snyk folder

2. Then pipe you snyk test json output into snyk-filter or use the -i argument to input a json file. Use the -f argument to point to the yml file containing your custom filters if you are not using the default location (<working_folder>/.snyk/snyk.yml).

### Example with Snyk CLI (using .snyk/snyk.yml by default)
snyk test --json | snyk-filter

### Example with Snyk CLI and custom yml file location
snyk test --json | snyk-filter -f ../myfolder/snyk.yml

### Example
snyk-filter -i snyk_results.json

### Example with custom yml file location
snyk-filter -i snyk_results.json -f ../myfolder/snyk.yml

## Options
`--json` to output json

### License

[License: Apache License, Version 2.0](LICENSE)
