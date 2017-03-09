exports.checkInt = (s, options = {}) ->
	# Make sure `s` exists and is not an empty string.
	if !s
		return
	i = parseInt(s, 10)
	if isNaN(i)
		return
	if options.positive && i <= 0
		return
	return i

exports.checkString = (s) ->
	# Make sure `s` exists and is not an empty string, or 'null' or 'undefined'.
	# This might happen if the parsing of config.json on the host using jq is wrong (it is buggy in some versions).
	if !s? or s == 'null' or s == 'undefined' or s == ''
		return
	return s

exports.checkTruthy = (v) ->
	if v == '1' or v == 'true' or v == true or v == 'on'
		return true
	if v == '0' or v == 'false' or v == false or v == 'off'
		return false
	return