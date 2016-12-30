var request = require('requestretry');
var cheerio = require('cheerio');
// var config = require('../config');
console.log('is problem here');
var config = require('../config');
console.log('is there execute');
var fs = require('fs');



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
	fs.writeFile('1.html', body);
}

sendrequest(config);