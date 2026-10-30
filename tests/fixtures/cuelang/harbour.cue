// Saltmere Harbour configuration
package harbour

import "strings"

#Berth: {
	id:       int & >0
	length_m: float
	occupied: *false | bool
}

name:   "Saltmere Harbour"
code:   strings.ToUpper("smh")
berths: [...#Berth] & [{id: 4, length_m: 12.5}, {id: 7, length_m: 9.0, occupied: true}]
