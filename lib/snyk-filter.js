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

function onDataCallback(data, reportCallback) {
  const jqFilterString = customFilters.filter;
  const jqPassString = customFilters.pass;
  const failMsg = customFilters.msg;
  data = JSON.parse(data);
  const promises = Array.isArray(data)
    ? data.map((dataItem) =>
        processResults(dataItem, jqFilterString, jqPassString, failMsg)
      )
    : [processResults(data, jqFilterString, jqPassString, failMsg)];

  return Promise.allSettled(promises).then((results) => {
    if (options && options.json) {
      const successful = results
        .filter((r) => r.status === "fulfilled")
        .map((r) => r.value);

      const outputValue = Array.isArray(data)
        ? successful
        : successful.length > 0
        ? successful[0]
        : null;

      console.log(JSON.stringify(outputValue, null, 2));
    }

    const rejected = results.filter((r) => r.status === "rejected");
    if (rejected.length > 0) {
      rejected.forEach((result) => {
        const reason = result.reason;
        console.error(
          reason instanceof Error ? reason.message : String(reason)
        );
      });
      process.exitCode = 1;
      return Promise.reject(
        new Error("One or more projects failed custom filtering")
      );
    }
  });
}

function readInputFromFile(source, reportCallback) {
  return new Promise((resolve, reject) => {
    fs.readFile(source, "utf8", function (err, data) {
      if (err) {
        return reject(err);
      }
      resolve(onDataCallback(data, reportCallback));
    });
  });
}

function readInputFromStdin(reportCallback) {
  return new Promise((resolve, reject) => {
    var data = "";
    process.stdin.setEncoding("utf8");
    process.stdin.on("readable", function () {
      var chunk = process.stdin.read();
      if (chunk !== null) {
        data += chunk;
      }
    });
    process.stdin.on("error", reject);
    process.stdin.on("end", function () {
      resolve(onDataCallback(data, reportCallback));
    });
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
    return Promise.reject(e);
  }

  if (cliOptions && cliOptions.json) options.json = cliOptions.json;

  try {
    if (source) {
      return readInputFromFile(source, reportCallback);
    } else {
      return readInputFromStdin(reportCallback);
    }
  } catch (error) {
    debug("error reading input: " + error);
    return Promise.reject(error);
  }
}

function processResults(data, filterString, passString, failMsg) {
  return filter(data, filterString)
    .then((processedData) => {
      if (options && options.json) {
        return processedData;
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
      return processedData;
    })
    .then((processedData) =>
      pass(data, passString, failMsg).then(
        () => processedData,
        (err) => {
          console.error(err);
          process.exitCode = 1;
          return processedData;
        }
      )
    )
    .catch((error) => {
      console.error("filter failed");
      throw error;
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
    const jqOptions = { input: "json", output: "json" };
    jq.run(query, data, jqOptions)
      .then((output) => {
        if (output == 0) {
          if (!options.json) {
            console.info(
              `${chalk.yellow(
                data.projectName || data.path
              )} - No issues found after custom filtering`
            );
          }
          resolve(true);
        } else {
          reject(
            `${chalk.yellow(data.projectName || data.path)} - ${passFailMsg}`
          );
        }
      })
      .catch((err) => {
        console.error("err");
        reject(err);
      });
  });
}

process.on("unhandledRejection", (error) => {
  console.error("Snyk Test Failed");
  process.exitCode = 1;
});
