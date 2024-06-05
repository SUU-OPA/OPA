package httpapi.authz

import rego.v1

options := {"quick-trip": ["Marek"], "survey": [], "file": []}

methods = ["GET", "POST"]

default allow := false

# Allow all users to get trip with survey.
allow if {
	methods[_] == input.method
	input.option == "survey"
}

# Allow selected office workers to generate quick trip
allow if {
	methods[_] == input.method
	input.option == "quick-trip"
	options[input.option][_] == input.user
}
