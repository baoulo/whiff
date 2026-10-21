% A score for whiff's tests.
\version "2.24.0"
\include "english.ly"

\header {
  title = "The Harbour Wall"
  subtitle = "for flute"
  composer = \markup { \italic "Ana Lighthouse" }
  poet = "Ben Gull"
  copyright = "CC0 1.0"
  tagline = ##f
}

melody = \relative c'' {
  \key d \major
  \time 6/8
  \tempo 4. = 100
  a4 fs8 a4 d8 | b4 g8 b4 d8 | a4 fs8 e4 d8 | fs4. d4. \bar "|."
}

\score {
  <<
    \new Staff \with { instrumentName = "Flute" } \melody
    \addlyrics { Har -- bour wall at dawn, the fer -- ry waits for gulls and men }
  >>
  \layout { }
  \midi { }
}
