// Saltmere Harbour configuration
local defaults = import 'defaults.libsonnet';
local berth(id, length) = { id: id, length_m: length };

defaults {
  harbour: 'Saltmere Harbour',
  berths: [berth(4, 12.5), berth(7, 9.0)],
  high_water: importstr 'high_water.txt',
}
