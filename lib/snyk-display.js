#!/usr/bin/env node
var debug = require('debug')('snyk-display')

const chalk = require('chalk');

var SEVERITIES = ['low', 'medium', 'high'];
var ROOT = "https://snyk.io";

module.exports = {displayResult: displayResult };

function displayResult(res, options) {

  debug('options: ' + options)

  var meta = metaForDisplay(res, options) + '\n\n';
  var packageManager = options.packageManager;
  var summary = 'Tested ';


  // handle errors by extracting their message
  if (res instanceof Error) {
    return res.message;
  }

  // real `test` result object, let's describe it
  if (res.hasOwnProperty('dependencyCount')) {
    summary += res.dependencyCount + ' dependencies';
  } else {
    summary += options.path;
  }
  var issues = res.licensesPolicy ? 'issues' : 'vulnerabilities';
  summary += ' for known ' + issues;

  if (res.ok && res.vulnerabilities.length === 0) {
    var vulnPaths = options.showVulnPaths ?
          ', no vulnerable paths found.' :
          ', none were found.';
    summary = chalk.green('✓ ' + summary + vulnPaths);

    if(options.severityThreshold){
      summary += chalk.yellow('\n\nCAUTION! Your severity setting might have hidden some vulnerabilities below the threshold chosen. Make sure to review the unfiltered results.');
    }

    return chalk.bold('\nTesting ' + options.path + '...\n') + meta + summary;
  }

  var vulnLength = res.vulnerabilities && res.vulnerabilities.length;
  var count = 'found ' + res.uniqueCount;
  if (res.uniqueCount === 1) {
    var issue = res.licensesPolicy ? 'issue' : 'vulnerability';
    count += ' ' + issue + ', ';
  } else {
    count += ' ' + (res.licensesPolicy ? 'issues' : 'vulnerabilities') + ', ';
  }
  if (options.showVulnPaths) {
    count += vulnLength + ' vulnerable ';

    if (res.vulnerabilities && res.vulnerabilities.length === 1) {
      count += 'path.';
    } else {
      count += 'paths.';
    }
  } else {
    count = count.slice(0, -2) + '.'; // replace ', ' with dot
  }
  //summary = summary + ', ' + chalk.red.bold(count);

  if (packageManager === 'npm' || packageManager === 'yarn') {
    summary += '\n\nRun `snyk wizard` to address these issues.';
  }

  var sep = '\n\n';

  var reportedVulns = {};
  var body = (res.vulnerabilities || []).map(function (vuln) {
    if (!options.showVulnPaths && reportedVulns[vuln.id]) { return; }
    reportedVulns[vuln.id] = true;

    var res = '';
    var name = vuln.name + '@' + vuln.version;
    var severity = vuln.severity[0].toUpperCase() + vuln.severity.slice(1);
    var issue = vuln.type === 'license' ? 'issue' : 'vulnerability';
    res += chalk.red('✗ ' + severity + ' severity ' + issue + ' found on ' +
      name + '\n');
    res += '- desc: ' + vuln.title + '\n';
    res += '- info: ' + ROOT + '/vuln/' + vuln.id + '\n';
    if (options.showVulnPaths) {
      res += '- from: ' + vuln.from.join(' > ') + '\n';
    }
    if (vuln.note) {
      res += vuln.note + '\n';
    }

    // none of the output past this point is relevant if we're not displaying
    // vulnerable paths
    if (!options.showVulnPaths) {
      return res.trim();
    }

    var upgradeSteps = (vuln.upgradePath || []).filter(Boolean);

    // Remediation instructions (if we have one)
    if (upgradeSteps.length) {

      // Create upgrade text
      var upgradeText = upgradeSteps.shift();
      upgradeText += (upgradeSteps.length) ?
          ' (triggers upgrades to ' + upgradeSteps.join(' > ') + ')' : '';

      var fix = ''; // = 'Fix:\n';
      for (var idx = 0; idx < vuln.upgradePath.length; idx++) {
        var elem = vuln.upgradePath[idx];

        if (elem) {
          // Check if we're suggesting to upgrade to ourselves.
          if (vuln.from.length > idx && vuln.from[idx] === elem) {
            // This ver should get the not-vuln dependency, suggest refresh
            fix += 'Your dependencies are out of date, otherwise you would ' +
              'be using a newer ' + vuln.name + ' than ' + vuln.name + '@' +
              vuln.version + '.\n';
            if (packageManager === 'npm') {
              fix += 'Try deleting node_modules, reinstalling ' +
              'and running `snyk test` again.\nIf the problem persists, ' +
              'one of your dependencies may be bundling outdated modules.';
            } else if (packageManager === 'rubygems') {
              fix += 'Try running `bundle update ' + vuln.name + '` ' +
              'and running `snyk test` again.';
            }
            break;
          }
          if (idx === 0) {
            // This is an outdated version of yourself
            fix += 'You\'ve tested an outdated version of the project. ' +
              'Should be upgraded to ' + upgradeText;
          } else if (idx === 1) {
            // A direct dependency needs upgrade. Nothing to add.
            fix += 'Upgrade direct dependency ' + vuln.from[idx] +
              ' to ' + upgradeText;
          } else {
            // A deep dependency needs to be upgraded
            res += 'No direct dependency upgrade can address this issue.\n' +
              chalk.bold('Run `snyk wizard` to explore remediation options.');
          }
          break;
        }

      }
      res += chalk.bold(fix);
    } else {
      if (vuln.type === 'license') {
        // do not display fix (there isn't any), remove newline
        res = res.slice(0, -1);
      } else if (packageManager === 'npm') {
        res += chalk.magenta(
          'Fix: None available. Consider removing this dependency.');
      }
    }

    return res;
  }).filter(Boolean).join(sep) + sep + meta + summary;

  return chalk.bold('\nTesting ' + options.path + '...\n') + body;
}



function metaForDisplay(res, options) {
  var meta = [
    chalk.bold('Organisation: ') + res.org,
    // chalk.bold('Package manager: ') +
    //   (options.packageManager | res.packageManager),
    //chalk.bold('Target file: ') + options.file,
    //chalk.bold('Open source: ') + (res.isPrivate ? 'no' : 'yes'),
  ];
  if (res.filesystemPolicy) {
    meta.push('Local Snyk policy found');
    if (res.ignoreSettings && res.ignoreSettings.disregardFilesystemIgnores) {
      meta.push('Local Snyk policy ignores disregarded');
    }
  }
  if (res.licensesPolicy) {
    meta.push('Licenses enabled');
  }

  return meta.join('\n');
}



function validateSeverityThreshold(severityThreshold) {
  return SEVERITIES.indexOf(severityThreshold) > -1;
}
