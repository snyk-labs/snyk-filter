#!/usr/bin/env node

const yaml = require('js-yaml');
const fs = require('fs');
const path = require('path');
const jq = require('node-jq');

var snykDisplay = require('./snyk-display.js');
var customFilters;// = require('../sample-filters/filters.json');

module.exports = {run: run, processResults:processResults, filter:filter, pass:pass };
var options = {"showVulnPaths": true, "path": path.dirname(__dirname).split(path.sep).pop()};


function onDataCallback(data, reportCallback) {
  

  const jqFilterString = customFilters.filter;
  const jqPassString = customFilters.pass;
  const failMsg = customFilters.msg;

    data = JSON.parse(data);
    if(Array.isArray(data)){
      data.map((dataItem) => {
        processResults(dataItem, jqFilterString, jqPassString, failMsg);
      });
    } else {
      processResults(data,jqFilterString, jqPassString, failMsg);
    }

}


function readInputFromFile(source, reportCallback) {
  fs.readFile(source, 'utf8', function (err, data) {
    if (err) {
      throw err;
    }
    onDataCallback(data, reportCallback);
  });
}

function readInputFromStdin(reportCallback) {
  var data = '';
  process.stdin.setEncoding('utf8');
  process.stdin.on('readable', function () {
    var chunk = process.stdin.read();
    if (chunk !== null) {
      data += chunk;
    }
  });
  process.stdin.on('end', function () {
    onDataCallback(data, reportCallback);
  });
}

function run(source, reportCallback, filters, cliOptions = null) {
  //options = options;

  try {
    var ymlFileInJSON = yaml.safeLoad(fs.readFileSync(filters, 'utf8'));
    customFilters = ymlFileInJSON.customFilters;
  } catch (e) {
    console.log("Error loading yml file" + e);
  }

  if(cliOptions && cliOptions.json) options.json = cliOptions.json;

  try {
    if (source) {
      readInputFromFile(source, reportCallback);
    } else {
      readInputFromStdin(reportCallback);
    }
  } catch (error) {
    console.log('out');
  }
}

function processResults(data, filterString, passString, failMsg){
  filter(data, filterString)
  //.then((filteredData) => aggregate(filteredData))
  //.then((processedData) => {reportCallback(processedData)})
  .then((processedData) => {

    //console.log(processedData);
    if(options && options.json){
      console.log("json");
      console.log(processedData);
    } else {
      var response = snykDisplay.displayResult(processedData, options);
      console.log(response);
    }

  })
  .catch((error) => {
    console.error("filter failed");
  })
  .then(() => pass(data, passString, failMsg))
  .then(()=> {
      return 0;
   })
  .catch((error) => {
    console.error(error);
    throw new Error(error);
  });
}


function filter(data, filterString) {
  return new Promise((resolve,reject) => {
    //const filter = '[.vulnerabilities[] | select(.isUpgradable == true and .severity == "high") | {"vulns": .title, "sev":.severity, "upgradable":.isUpgradable, "link": ("https://snyk.io/vuln/"+.id), "module": .moduleName }]';
    //const filter = 'select(.vulnerabilities | map( select(.packageName | contains("bson") | not)))';
    const filter = filterString;
    const options = { input: 'json', output: 'json' };

    jq.run(filter, data, options)
      .then((output) => {
        resolve(output);
      })
      .catch((err) => {
        console.error(err)
        reject(err);
      })
  });
}

// function aggregate(data) {
//   return new Promise((resolve,reject) => {
//     const aggregate = '. | unique | group_by(.module)';
//     const options = { input: 'json', output: 'json' };
//
//     jq.run(aggregate, data, options)
//       .then((output) => {
//         resolve(output);
//       })
//       .catch((err) => {
//         console.error(err)
//         reject(err);
//       })
//   });
// }

function pass(data, passString, passFailMsg) {
  return new Promise((resolve,reject) => {
    const query = passString;
    const options = { input: 'json', output: 'json' };
    jq.run(query, data, options)
      .then((output) => {
        if(output == 0){
          console.log("No issues found after custom filtering");
          resolve(true);
        } else {
          reject(passFailMsg);
        }

      })
      .catch((err) => {
        console.error("err")
        reject(err);
      })
  });
}


process.on('unhandledRejection', error => {
  // Prints "unhandledRejection woops!"
  console.log('Snyk Test Failed');
  process.exit(1);
});
