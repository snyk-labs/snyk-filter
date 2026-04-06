var assert = require("assert");
var _ = require("lodash");

var snykFilter = require("../lib/snyk-filter.js");
var filterFixtures = require("./fixtures/test_filters.json");
var resultFixtures = require("./fixtures/test_results.json");

describe("Filtering", function () {
  it("Filter only medium and upgradable", function (done) {
    snykFilter
      .filter(
        resultFixtures.sample_input,
        filterFixtures.filters.medium_and_upgradable
      )
      .then((res) => {
        if (
          _.isEqual(res, resultFixtures.sample_output_medium_and_upgradable)
        ) {
          done();
        } else {
          done("filtered results do not match expected results");
        }
      })
      .catch((err) => {
        done(err);
      });
  });

  it("Filter only low and upgradable", function (done) {
    snykFilter
      .filter(
        resultFixtures.sample_input,
        filterFixtures.filters.low_and_upgradable
      )
      .then((res) => {
        if (_.isEqual(res, resultFixtures.sample_output_low_and_upgradable)) {
          done();
        } else {
          done("filtered results do not match expected results");
        }
      })
      .catch((err) => {
        done(err);
      });
  });

  it("Filter only low and non upgradable", function (done) {
    snykFilter
      .filter(
        resultFixtures.sample_input,
        filterFixtures.filters.low_and_non_upgradable
      )
      .then((res) => {
        if (
          _.isEqual(res, resultFixtures.sample_output_low_and_non_upgradable)
        ) {
          done();
        } else {
          done("filtered results do not match expected results");
        }
      })
      .catch((err) => {
        done(err);
      });
  });

  it("Filter only medium and non upgradable", function (done) {
    snykFilter
      .filter(
        resultFixtures.sample_input,
        filterFixtures.filters.medium_and_non_upgradable
      )
      .then((res) => {
        if (
          _.isEqual(res, resultFixtures.sample_output_medium_and_non_upgradable)
        ) {
          done();
        } else {
          done("filtered results do not match expected results");
        }
      })
      .catch((err) => {
        done(err);
      });
  });
});

describe("Passing", function () {
  it("Pass only if no medium and upgradable - Pass Expected", function (done) {
    snykFilter
      .pass(
        resultFixtures.sample_input,
        filterFixtures.passFilters.medium_and_upgradable,
        filterFixtures.failMessages.medium_and_upgradable
      )
      .then((res) => {
        if (res) {
          done();
        } else {
          done(res);
        }
      })
      .catch((err) => {
        done(err);
      });
  });

  it("Pass only if no low and upgradable - Break Expected", function (done) {
    snykFilter
      .pass(
        resultFixtures.sample_input,
        filterFixtures.passFilters.low_and_upgradable,
        filterFixtures.failMessages.low_and_upgradable
      )
      .then((res) => {
        if (res) {
          done();
        } else {
          done(res);
        }
      })
      .catch((err) => {
        // Test
        done();
      });
  });

  it("Pass only if no low and non upgradable - Pass Expected", function (done) {
    snykFilter
      .pass(
        resultFixtures.sample_input,
        filterFixtures.passFilters.low_and_non_upgradable,
        filterFixtures.failMessages.low_and_non_upgradable
      )
      .then((res) => {
        if (res) {
          done();
        } else {
          done(res);
        }
      })
      .catch((err) => {
        done(err);
      });
  });

  it("Pass only if no medium and non upgradable - Break Expected", function (done) {
    snykFilter
      .pass(
        resultFixtures.sample_input,
        filterFixtures.passFilters.medium_and_non_upgradable,
        filterFixtures.failMessages.medium_and_non_upgradable
      )
      .then((res) => {
        if (res) {
          done();
        } else {
          done(res);
        }
      })
      .catch((err) => {
        done();
      });
  });
});

describe("JSON output regression", function () {
  const os = require("os");
  const path = require("path");
  const fs = require("fs");
  const yaml = require("js-yaml");

  it("Emits a valid JSON array for multi-project input and includes all filtered results", function (done) {
    const tempDir = fs.mkdtempSync(path.join(os.tmpdir(), "snyk-filter-test-"));
    const filterFile = path.join(tempDir, "test-snyk.yml");
    const inputFile = path.join(tempDir, "input.json");
    const testData = [
      {
        projectName: "proj1",
        vulnerabilities: [
          {
            id: "A",
            severity: "low",
          },
        ],
      },
      {
        projectName: "proj2",
        vulnerabilities: [
          {
            id: "B",
            severity: "high",
          },
        ],
      },
    ];

    fs.writeFileSync(inputFile, JSON.stringify(testData));
    fs.writeFileSync(
      filterFile,
      yaml.dump({
        customFilters: {
          filter: '.vulnerabilities |= map(select(.severity == "high"))',
          pass: '[.vulnerabilities[] | select(.severity == "high")] | length',
          msg: "Issues detected",
        },
      })
    );

    const originalLog = console.log;
    const originalError = console.error;
    const logs = [];
    console.log = (...args) => logs.push(args.join(" "));
    console.error = () => {};

    snykFilter
      .run(inputFile, function () {}, filterFile, { json: true })
      .then(() => {
        console.log = originalLog;
        console.error = originalError;

        assert.strictEqual(logs.length, 1, "Expected one JSON output call");

        const output = JSON.parse(logs[0]);
        assert(Array.isArray(output), "Expected JSON output to be an array");
        assert.strictEqual(output.length, 2);
        assert.strictEqual(output[0].projectName, "proj1");
        assert.strictEqual(output[1].projectName, "proj2");
        assert.deepStrictEqual(output[0].vulnerabilities, []);
        assert.deepStrictEqual(output[1].vulnerabilities, [
          {
            id: "B",
            severity: "high",
          },
        ]);

        done();
      })
      .catch((err) => {
        console.log = originalLog;
        console.error = originalError;
        done(err);
      });
  });
});
