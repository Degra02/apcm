#import "@preview/minimal-note:0.10.0": *
#show: style-algorithm
#import "@preview/note-me:0.5.0": *
#import "@preview/showybox:2.0.4": showybox

#show: minimal-note.with(
  title: [APCM Notes],
  author: [Filippo De Grandi],
  date: datetime.today().display("[month repr:long], [year]")
)


#include "hashing.typ"
#pagebreak()

#include "symmetric.typ"
#pagebreak()
