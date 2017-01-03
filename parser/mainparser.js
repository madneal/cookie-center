var request = require('requestretry');
var cheerio = require('cheerio');
var config = require('../config');
var fs = require('fs');
var mongoose = require('mongoose');
var Schema = mongoose.Schema;
var starProject_model = mongoose.model('starProjects');


var arr = [];

var sendrequest = function (config) {
	var websites = config.websites;
	for (var i = 0; i < websites.length; i++) {
		console.log(websites[i].url);
		request({url: websites[i].url,
			method: 'GET',
			maxAttempt: 5, 
			form: null
			}, (e, r, body) => {
				if (e) {
					console.log('error');
					console.log(e);
				} else {
					parser(body);
				}
			})
	}
}

exports.sendrequest = sendrequest;

/**
 * @param  {[string] the response}
 * @return {[object] an object}
 */
var parser = function (body) {
	var $ = cheerio.load(body);
	var that = $;
	var result = $('.js-repo-filter .col-12');
	var i = 0;
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
				var starNum = str.split(' ')[0].replace(/\,/g,'');
				var forkNum = str.split(' ')[1];
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
	});
	var github_url = 'https://github.com';
	var next_url = that('.next_page').attr('href');
	if (next_url) {
		config.url = github_url + next_url;
		sendrequest(config);
	}
};

var getLocalDate = function() {
	var year = this.getFullYear();
	var month = this.getMonth() + 1;
	var day = this.getDay();
	var hour = this.getHours();
	var min = this.getMinutes();
	var sec = this.getSeconds();
	return year + '-' + month + 'day' + ' ' + hour + ':' + min + ':' + 'sec';
};

var saveModel = function(result) {
	// for (var i = 0; i < result.length; i++) {
	// 	result[i].updateTime = getLocalDate();
	// 	starProject_model.update(
	// 		result[i], {
	// 			upsert: true
	// 		}, function(err, res) {
	// 			if (err) {
	// 				console.log(err);
	// 			}
	// 		}
	// 	)
	// }
	result = {result: result};
	fs.writeFile('result.json', result);
}



sendrequest(config);