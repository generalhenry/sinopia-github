/**
 * TODO err - user deletes Sinopia token
 */
var GitHubApi = require("github");
var userCache = Object.create(null);


function Auth(config, stuff) {
	if (!(this instanceof Auth)) {
		return new Auth(config, stuff);
	}

	this._org = config.org;
	this._clientID = config.client_id;
	this._clientSecret = config.client_secret;
	this._ttl = config.ttl * 1000; // sec -> ms
	
	this._logger = stuff.logger;
}

Auth.prototype.authenticate = function(username, password, done) {
	var org = this._org;
	var logger = this._logger;
	var ttl = this._ttl;
	var cache = getCache(username, password);

	if (cache.groups && Date.now() < cache.expires) {
		return done(null, cache.groups);
	} else {
		getTeams(username, password, function (err, teams) {
			if (err) {
				logger.warn({
					user: username,
					err: err,
				}, 'GITHUB error @{err}');
				return done(null, false);
			} else {
				var groups;
				cache.expires = Date.now() + ttl;
				cache.etag = teams.meta.etag;
				if (teams.meta.status === '304 Not Modified') {
					done(null, cache.groups);
				} else {
					groups = cache.groups = teams.reduce(function(groups, team) {
						return team.organization.login === org ? groups.concat(team.name) : groups;
					}, []);

					if (groups.length) {
						groups.unshift(username);
						done(null, groups);
					} else {
						done(null, false);
					}
				}
			}
		});
	}
};

Auth.prototype.add_user = function(username, password, done) {
	getTeams(username, password, function (err) {
		if (err) {
			done(err);
		} else {
			done(null, true);
		}
	});
};

function getCache (username, password) {
	var token = JSON.stringify({
		username: username,
		password: password
	});
	return userCache[token] = userCache[token] || {}; 
}

function getTeams (username, password, done) {
	var cache = getCache(username, password);
	var github = cache.github = cache.github || new GitHubApi({
		version: "3.0.0"
	});

	github.authenticate({
		type: "basic",
		username: username,
		password: password
	});

	github.user.getTeams({
		headers: {
			'If-None-Match': cache.etag
		}
	}, done);
}

module.exports = Auth;
