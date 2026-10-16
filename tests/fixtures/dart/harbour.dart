// Harbour app in Dart
import 'dart:async';
import 'package:http/http.dart' as http;

class Boat {
  final String name;
  Boat(this.name);
}

enum Tide { high, low }

Future<int> countBoats() async {
  final r = await http.get(Uri.parse('https://api.example.org/boats'));
  return r.body.length;
}
