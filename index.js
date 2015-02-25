/**
 * TODO err - user deletes Sinopia token
 * TODO err - informative when user cannot access or publish
 * TODO err - connection issues
 */
var request = require('request');
var async = require('async');
var pkg = require('./package');

var userCache = {};
var logger;

var reqLogMsg = 'user: @{user}, req: @{method} @{url}';

function github(user, path, opts, cb) {
	var url = 'https://api.github.com' + path;
	if (!opts.headers) opts.headers = {};
	opts.headers['User-Agent'] = 'sinopia-github v' + pkg.version;
	logger.warn({
		user: user,
		level: 35, // http
		url: url,
		method: opts.method || 'GET'
	}, reqLogMsg);
	return request(url, opts, cb);
}

function Auth(config, stuff) {
	if (!(this instanceof Auth)) {
		return new Auth(config, stuff);
	}

	this._org = config.org;
	this._clientID = config.client_id;
	this._clientSecret = config.client_secret;
	this._ttl = config.ttl * 1000; // sec -> ms
	
	logger = stuff.logger;
}

Auth.prototype.authenticate = function(user, pass, done) {
	var org = this._org;

	if (!userCache[user]) userCache[user] = {};

	async.waterfall([
		this.getToken.bind(this, user, pass),
		this.listTeams.bind(this, user)
	], function(err, teams) {
		if (err) return done(err);

		var groups = teams.reduce(function(groups, team) {
			if (team.organization.login === org) groups.push(team);
			return groups;
		}, []);

		if (groups.length) {
			groups.unshift(user);
			done(null, groups);
		} else {
			done(null, false);
		}
	});
};

Auth.prototype.getToken = function(user, pass, done) {
	var cache = userCache[user];
	if (cache.token) {
		return done(null, cache.token);
	}

	github(user, '/authorizations/clients/' + this._clientID, {
		auth: {user: user, pass: pass},
		method: 'PUT',
		json: {
			client_secret: this._clientSecret,
			scopes: ['read:org']
		}
	}, function(err, res, res) {
		if (err) return done(err);
		cache.token = res.token;
		done(null, res.token);
	}).auth(user, pass);
};

Auth.prototype.listTeams = function(user, token, done) {
	var cache = userCache[user],
		ttl = this._ttl;

	if (cache.teams && Date.now() < cache.expires) {
		return done(null, cache.teams);
	}

	github(user, '/user/teams', {
		qs: {access_token: token},
		json: true,
		headers: {'If-None-Match': cache.etag} // if resource is unchanged, request does not count against rate limit
	}, function(err, res, teams) {
		if (err) return done(err);

		if (res.statusCode === 304) { teams = cache.teams; }
		else if (cache.etag) { logger.warn({user: user}, 'github teams resource modified for @{user} since cache'); }
		
		cache.teams = teams;
		cache.expires = Date.now() + ttl;
		cache.etag = res.headers.etag;
		done(null, teams);
	})
};

module.exports = Auth;
