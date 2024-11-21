#!/usr/bin/env node
var debug = require("debug")("snyk-filter");
const yaml = require("js-yaml");
const fs = require("fs");
const path = require("path");
const jq = require("node-jq");
const chalk = require("chalk");

var snykDisplay = require("./snyk-display.js");
var customFilters; // = require('../sample-filters/filters.json');

module.exports = {
  run: run,
  processResults: processResults,
  filter: filter,
  pass: pass,
};
var options = {
  showVulnPaths: true,
  path: path.dirname(__dirname).split(path.sep).pop(),
};

var results = [];

function onDataCallback(data, reportCallback) {
  const jqFilterString = customFilters.filter;
  const jqPassString = customFilters.pass;
  const failMsg = customFilters.msg;
  data = JSON.parse(data);
  const inputLen = data.length;
  if (Array.isArray(data)) {
    data.map((dataItem) => {
      processResults(dataItem, jqFilterString, jqPassString, failMsg, inputLen);
    });
  } else {
    processResults(data, jqFilterString, jqPassString, failMsg, inputLen);
  }
}

function readInputFromFile(source, reportCallback) {
  fs.readFile(source, "utf8", function (err, data) {
    if (err) {
      throw err;
    }
    onDataCallback(data, reportCallback);
  });
}

function readInputFromStdin(reportCallback) {
  var data = "";
  process.stdin.setEncoding("utf8");
  process.stdin.on("readable", function () {
    var chunk = process.stdin.read();
    if (chunk !== null) {
      data += chunk;
    }
  });
  process.stdin.on("end", function () {
    onDataCallback(data, reportCallback);
  });
}

function run(source, reportCallback, filters, cliOptions = null) {
  //options = options;

  try {
    var ymlFileInJSON = yaml.load(fs.readFileSync(filters, "utf8"));
    customFilters = ymlFileInJSON.customFilters;
    debug(customFilters);
  } catch (e) {
    console.log("Error loading yml file" + e);
  }

  if (cliOptions && cliOptions.json) options.json = cliOptions.json;

  try {
    if (source) {
      readInputFromFile(source, reportCallback);
    } else {
      readInputFromStdin(reportCallback);
    }
  } catch (error) {
    debug("error reading input: " + error);
  }
}

function processResults(data, filterString, passString, failMsg, inputLen) {
  filter(data, filterString)
    //.then((filteredData) => aggregate(filteredData))
    //.then((processedData) => {reportCallback(processedData)})
    .then((processedData) => {
      if (options && options.json) {
        console.warn("json output enabled");
        // console.log(JSON.stringify(processedData, null, 2));
        results.push(processedData);
        if (results.length == inputLen || !inputLen) {
          console.log(JSON.stringify(results));
        }
      } else if (data.infrastructureAsCodeIssues) {
        var response = snykDisplay.displayIACResult(
          processedData,
          options,
          data
        );
        console.log(response);
      } else {
        var response = snykDisplay.displayResult(processedData, options);
        console.log(response);
      }
    })
    .catch((error) => {
      console.error("filter failed");
    })
    .then(() => pass(data, passString, failMsg))
    .then(() => {
      return 0;
    })
    .catch((error) => {
      console.error(error);
      throw new Error(error);
    });
}

function filter(data, filterString) {
  return new Promise((resolve, reject) => {
    //const filter = '[.vulnerabilities[] | select(.isUpgradable == true and .severity == "high") | {"vulns": .title, "sev":.severity, "upgradable":.isUpgradable, "link": ("https://snyk.io/vuln/"+.id), "module": .moduleName }]';
    //const filter = 'select(.vulnerabilities | map( select(.packageName | contains("bson") | not)))';
    const filter = filterString;
    const options = { input: "json", output: "json" };
    jq.run(filter, data, options)
      .then((output) => {
        resolve(output);
      })
      .catch((err) => {
        console.error(err);
        reject(err);
      });
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
  return new Promise((resolve, reject) => {
    const query = passString;
    const options = { input: "json", output: "json" };
    jq.run(query, data, options)
      .then((output) => {
        if (output == 0) {
          console.warn(
            `${chalk.yellow(
              data.projectName || data.path
            )} - No issues found after custom filtering.`
          );
          resolve(true);
        } else {
          console.warn(
            `${chalk.yellow(data.projectName || data.path)} - ${passFailMsg}`
          );
          resolve(true);
        }
      })
      .catch((err) => {
        console.error("err");
        reject(err);
      });
  });
}

process.on("unhandledRejection", (error) => {
  // Prints "unhandledRejection woops!"
  console.error("Snyk Test Failed");
  process.exit(1);
});
