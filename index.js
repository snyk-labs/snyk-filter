#!/usr/bin/env node

var debug = require('debug')('index')
var fs = require('fs');
var snykFilter = require('./lib/snyk-filter.js');
var argv = require('minimist')(process.argv.slice(2));
var os = require('os');
var path = require('path');
var template, source, output;
var options = {};

if (argv.i) { // input source
  source = argv.i; // grab the next item
  if (typeof source === 'boolean') {
    source = undefined;
  }
}
if (argv.o) { // output destination
  output = argv.o; // grab the next item
  if (typeof output === 'boolean') {
    output = undefined;
  }
}
if (argv.json) { // output destination
  options = {"json": true};
}
if (argv.f) { // output destination

  filters = argv.f;

  if (typeof output === 'boolean') {
    output = undefined;
  }
} else {
  filters = path.join(process.cwd(), "/.snyk-filter/snyk.yml");
}



snykFilter.run(source, onReportOutput, filters, options);

function onReportOutput(report) {
  if (output) {
    fs.writeFile(output, report, function (err) {
      if (err) {
        return console.log(err);
      }
      console.log('Vulnerability snapshot saved at ' + output);
    });
  } else {
    console.log(report);
  }
}
