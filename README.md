[![Snyk logo](https://snyk.io/style/asset/logo/snyk-print.svg)](https://snyk.io)

***

# Snyk Custom Filtering of SNYK CLI JSON output
The Snyk-filter module takes the json outputted from `snyk test --json` and adds custom filtering for results filtering as well as breaking options for CI usage.

[![Known Vulnerabilities](https://snyk.io//test/github/aarlaud-snyk/snyk-filter/badge.svg?targetFile=package.json)](https://snyk.io//test/github/aarlaud-snyk/snyk-filter?targetFile=package.json)
[![CircleCI](https://circleci.com/gh/snyk-tech-services/snyk-filter.svg?style=svg)](https://circleci.com/gh/snyk-tech-services/snyk-filter)

# How do I use it?

## Clone & Install

First, clone the repo.
Then run

`npm install -g`

`jq` is required to be installed on your machine

## Usage

1. Implement your custom JQ filters in a .snyk-filter/snyk.yml file relative to your current working directory where you will be running snyk test from (see sample in sample-filters and tweak things from there - use [JQPlay](https://jqplay.org/) )

2. Then pipe your snyk test json output into snyk-filter or use the -i argument to input a json file. Use the -f argument to point to the yml file containing your custom filters if you are not using the default location (.snyk-filter/snyk.yml).

### Example with Snyk CLI (using .snyk-filter/snyk.yml by default)
snyk test --json | snyk-filter

### Example with Snyk CLI and custom yml file location
snyk test --json | snyk-filter -f $HOME/myfolder/high-upgradeable-vulns.yml

### Example
snyk-filter -i snyk_results.json

### Example with custom yml file location
snyk-filter -i snyk_results.json -f $HOME/myfolder/high-upgradeable-vulns.yml

## Options
`--json` to output json

### License

[License: Apache License, Version 2.0](LICENSE)
