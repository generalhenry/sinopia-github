/**
 * TODO err - user deletes Sinopia token
 */
var crypto = require('crypto');
var GitHubApi = require('github');


function Auth(config, stuff) {
	if (!(this instanceof Auth)) {
		return new Auth(config, stuff);
	}

	this._org = config.org;
	this._clientID = config.client_id;
	this._clientSecret = config.client_secret;
	this._ttl = config.ttl * 1000; // sec -> ms
	
	this._logger = stuff.logger;
	this._userCache = Object.create(null);
}

Auth.prototype.authenticate = function(username, password, done) {
	this._getTeams(username, password, done);
};

Auth.prototype.add_user = function(username, password, done) {
	this._getTeams(username, password, function (err) {
		if (err) {
			return done(err);
		}
		done(null, true);
	});
};

Auth.prototype._getCache = function (username, password) {
	var shasum = crypto.createHash('sha1');
	shasum.update(JSON.stringify({
		username: username,
		password: password
	}));
	var token = shasum.digest('hex');
	if (!this._userCache[token]) {
		this._userCache[token] = Object.create(null);
	}
	return this._userCache[token]; 
}

Auth.prototype._getTeams = function (username, password, done) {
	var org = this._org;
	var logger = this._logger;
	var ttl = this._ttl;
	var cache = this._getCache(username, password);
	if (cache.groups && Date.now() < cache.expires) {
		return done(null, cache.groups);
	}
	if (!cache.github) {
		cache.github = new GitHubApi({
			version: "3.0.0"
		});
		cache.github.authenticate({
			type: "basic",
			username: username,
			password: password
		});
	}
	cache.github.user.getTeams({
		headers: {
			'If-None-Match': cache.etag
		}
	}, function (err, teams) {
		if (err) {
			logger.warn({
				username: username,
				err: err,
			}, 'GITHUB error @{err} for user @{username}');
			return done(err, false);
		}
		var groups;
		cache.expires = Date.now() + ttl;
		cache.etag = teams.meta.etag;
		if (teams.meta.status === '304 Not Modified') {
			return done(null, cache.groups);
		}
		groups = cache.groups = teams.filter(function(team) {
			return team.organization.login === org;
		}).map(function(team) {
			return team.name;
		});

		if (groups.length) {
			groups.unshift(username);
			return done(null, groups);
		}
		done(null, false);
	});
}

module.exports = Auth;
