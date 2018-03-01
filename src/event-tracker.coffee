Promise = require 'bluebird'
_ = require 'lodash'
mixpanel = require 'mixpanel'
mask = require 'json-mask'

mixpanelMask = [
	'appId'
	'delay'
	'error'
	'interval'
	'image'
	'app(appId,name)'
	'service(appId,serviceId,serviceName,commit,releaseId,image,labels)'
	'stateDiff/local(os_version,superisor_version,ip_address,apps/*/services)'
].join(',')

module.exports = class EventTracker
	constructor: ->
		@_client = null
		@_properties = null

	_logEvent: ->
		console.log(arguments...)

	track: (ev, properties = {}) =>
		# Allow passing in an error directly and having it assigned to the error property.
		if properties instanceof Error
			properties = error: properties

		properties = _.cloneDeep(properties)
		# If the properties has an error argument that is an Error object then it treats it nicely,
		# rather than letting it become `{}`
		if properties.error instanceof Error
			properties.error =
				message: properties.error.message
				stack: properties.error.stack

		# Don't log private env vars (e.g. api keys) or other secrets - use a whitelist to mask what we send
		properties = mask(properties, mixpanelMask)
		@_logEvent('Event:', ev, JSON.stringify(properties))
		if !@_client?
			return
		# Mutation is bad, and it should feel bad
		properties = _.assign(properties, @_properties)
		@_client.track(ev, properties)

	init: ({ offlineMode, mixpanelToken, uuid, mixpanelHost }) ->
		Promise.try =>
			@_properties =
				distinct_id: uuid
				uuid: uuid
			if offlineMode
				return
			@_client = mixpanel.init(mixpanelToken, { host: mixpanelHost })
