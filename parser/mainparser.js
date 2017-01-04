var request = require('requestretry');
var cheerio = require('cheerio');
var config = require('../config');
var fs = require('fs');
var mongoose = require('mongoose');
var Schema = mongoose.Schema;
var starProject_model = mongoose.model('starProjects');
var chalk = require('chalk');


var arr = [];

var sendrequest = function (config) {
	var url = config.url;
	console.log('send the request for: ' + config.url);
	// for (var i = 0; i < websites.length; i++) {
	// 	console.log(websites[i].url);
	// }
	request({url: url,
		method: 'GET',
		maxAttempt: 5, 
		form: null
		}, (e, r, body) => {
			if (e) {
				console.log('error');
				console.log(e);
			} else {
				if (body) {
					console.log('I have got the body responsed.');
				}
				parser(body);
			}
		})
}

exports.sendrequest = sendrequest;

var getLocalDate = function() {
	var date = new Date();
	var year = date.getFullYear();
	var month = date.getMonth() + 1;
	var day = date.getDay();
	var hour = date.getHours();
	var min = date.getMinutes();
	var sec = date.getSeconds();
	return year + '-' + month + 'day' + ' ' + hour + ':' + min + ':' + 'sec';
};

var saveModel = function(result) {
	for (var i = 0; i < result.length; i++) {
		result[i].updateTime = getLocalDate();
		starProject_model.update(
			result[i], {
				upsert: true
			}, function(err, res) {
				if (err) {
					console.log(err);
				}
			}
		)
	}
	// console.dir(result);
	// fs.writeFile('result.json', {result: result});
	// result = {result: result};
	// fs.writeFile('result.json', result);
}

/**
 * @param  {[string] the response}
 * @return {[object] an object}
 */
var parser = function (body) {
	var $ = cheerio.load(body);
	var that = $;
	var result = $('.js-repo-filter .col-12');
	var i = 0;
	var arr_mongo = [];
	result.each(function(i, elem) {
			$ = cheerio.load($(this).html());

			//obtain owner and project name
			var ownerAndName = $('.d-inline-block a').text().trim();
			var owner;
			var projectName;
			if (ownerAndName) {
				owner = ownerAndName.split(' / ')[0] || '';
				projectName = ownerAndName.split(' / ')[1] || '';
			}

			// obtain star and fork number string
			var str = $('.f6 a').text();
			if (str) {
				str = str.trim().replace(/\s+/g,' ');
				var starNum = str.split(' ')[0].replace(/\,/g, '') || '';
				var forkNum = str.split(' ')[1] && str.split(' ')[1].replace(/\,/g, '') || '';
				var lan = $('.f6 span').text().trim() || '';
			}
			var obj = {
				owner,
				projectName,
				lan,
				starNum,
				forkNum,
			};
			console.dir(obj);
			arr.push(obj);
			arr_mongo.push(obj);
			saveModel(arr_mongo);
	});
	chalk.green('first finished:');
	var github_url = 'https://github.com';
	var next_url = that('.next_page').attr('href');
	console.log('next_url is : ' + next_url);
	if (next_url) {
		config.url = github_url + next_url;
		sendrequest(config);
	} else {
		var result = {result: arr};
		fs.writeFile('result.json', JSON.stringify(result));
		console.log('The process finished!!');
	}
};





sendrequest(config);
