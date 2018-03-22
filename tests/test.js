var assert = require('assert');
var _ = require('lodash');

var snykFilter = require('../lib/snyk-filter.js');
var filterFixtures = require('./fixtures/test_filters.json');
var resultFixtures = require('./fixtures/test_results.json');


describe('Filtering', function() {
	it('Filter only medium and upgradable', function(done) {
    snykFilter.filter(resultFixtures.sample_input,filterFixtures.filters.medium_and_upgradable)
    .then((res) => {
      if(_.isEqual(res, resultFixtures.sample_output_medium_and_upgradable)){
        done();
      } else {
        done("filtered results do not match expected results");
      }
    })
    .catch((err) => {
      done(err);
    });
	});

	it('Filter only low and upgradable', function(done) {
    snykFilter.filter(resultFixtures.sample_input,filterFixtures.filters.low_and_upgradable)
    .then((res) => {
      if(_.isEqual(res, resultFixtures.sample_output_low_and_upgradable)){
        done();
      } else {
        done("filtered results do not match expected results");
      }
    })
    .catch((err) => {
      done(err);
    });
	});

	it('Filter only low and non upgradable', function(done) {
    snykFilter.filter(resultFixtures.sample_input,filterFixtures.filters.low_and_non_upgradable)
    .then((res) => {
      if(_.isEqual(res, resultFixtures.sample_output_low_and_non_upgradable)){
        done();
      } else {
        done("filtered results do not match expected results");
      }
    })
    .catch((err) => {
      done(err);
    });
	});

	it('Filter only medium and non upgradable', function(done) {
    snykFilter.filter(resultFixtures.sample_input,filterFixtures.filters.medium_and_non_upgradable)
    .then((res) => {
      if(_.isEqual(res, resultFixtures.sample_output_medium_and_non_upgradable)){
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


describe('Passing', function() {
	it('Pass only if no medium and upgradable - Pass Expected', function(done) {
    snykFilter.pass(resultFixtures.sample_input,filterFixtures.passFilters.medium_and_upgradable, filterFixtures.failMessages.medium_and_upgradable)
    .then((res) => {
      if(res){
        done();
      } else {
        done(res);
      }
    })
    .catch((err) => {
      done(err);
    });
	});

	it('Pass only if no low and upgradable - Break Expected', function(done) {
    snykFilter.pass(resultFixtures.sample_input,filterFixtures.passFilters.low_and_upgradable, filterFixtures.failMessages.low_and_upgradable)
    .then((res) => {

      if(res){
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

	it('Pass only if no low and non upgradable - Pass Expected', function(done) {
    snykFilter.pass(resultFixtures.sample_input,filterFixtures.passFilters.low_and_non_upgradable, filterFixtures.failMessages.low_and_non_upgradable)
    .then((res) => {
      if(res){
        done();
      } else {
        done(res);
      }
    })
    .catch((err) => {
      done(err);
    });
	});

	it('Pass only if no medium and non upgradable - Break Expected', function(done) {
    snykFilter.pass(resultFixtures.sample_input,filterFixtures.passFilters.medium_and_non_upgradable,  filterFixtures.failMessages.medium_and_non_upgradable)
    .then((res) => {
      if(res){
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
