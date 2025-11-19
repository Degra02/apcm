#let _background_logo(img, color) = layout(bounds => {
  let size = measure(img, ..bounds)
  img
  place(top, block(..size, fill: color))
})

#let unitn_cover = (course, title, students, academic_year: none, examination_day: none, watermark: true) => [
  #set text(font: "Fira Sans")

  #if watermark {
    let bkg_img = image("./unitn-cover/unitn_bw.png", height: 500pt)
    set page(
      background: move(
        dy: 200pt, dx: 100pt,
        rotate(-20deg, layout(bounds => {
          let size = measure(bkg_img, ..bounds)
          bkg_img
          place(top, block(..size, fill: rgb(255,255,255,240)))
        })),
      )
    )
  }

  #figure(
    image("./unitn-cover/unitn.svg", width: 30%),
    // prevent conflict with default figure numbering
    kind: "cover-backgroud",
    supplement: "",
  )

  #set align(center)

  #set text(size: 20pt)
  #v(1em)
  #smallcaps[University of Trento]
  #v(1.5em)

  #set text(size: 15pt)
  #smallcaps[#course]

  // #set text(size: 13pt)
  //
  // #if academic_year == none {
  //   let today = datetime.today()
  //   // here you go studenti fuori corso
  //   academic_year = if today.month() < 3 { today.year() - 2 } else { today.year() - 1 }
  // }
  // #let academic_year = str(academic_year) + "-" + str(academic_year + 1)
  // #smallcaps[
  //   #pad(top: 15pt, bottom: 40pt)[Academic Year #academic_year]
  // ]

  #set text(size: 20pt)

  #v(.5fr)

  #par(justify: false, smallcaps(title))

  #v(1fr)

  #columns(1)[
    // #set text(size: 13pt)
    // #set align(top+start)
    // #set par(spacing: 10pt)
    //
    // #if type(supervisors) != array {
    //   supervisors = (supervisors, )
    // }
    //
    // #text(size: 13pt)[*Supervisor#if supervisors.len() == 1 [] else [s]*]
    //
    // #for s in supervisors [
    //   #par(first-line-indent: 0pt, s)
    // ]
    //
    // #colbreak()

    #set text(size: 13pt)
    #set par(spacing: 6pt)

    #if type(students) != array {
      students = (students, )
    } else if students.len() == 0 {
      students = ()
    } else if students.len() == 2 and type(students.at(0)) != array and type(students.at(0)) in (content, str) and type(students.at(1)) == int {
      students = (students, )
    }
    #if students.len() != 0 {
      text(size: 13pt)[*Graduate Student#if students.len() == 1 [] else [s]*]
    }

    // #students

    #let display-student(s, inline: false) = {
      if type(s) == array and s.len() == 2 {
        if inline [
          #par[#s.at(0) -- #s.at(1)]
        ] else [
          #par[#s.at(0)]
          #par[#s.at(1)]
        ]
      } else [
        #s
      ]
    }

    #if students.len() == 1 {
      display-student(students.at(0))
    } else {
      for s in students {
        display-student(s, inline: true)
      }
    }

    // #for s in students {
    //   if type(s) == array [
    //     #s.at(0)
    //
    //     #s.at(1)
    //
    //   ] else [
    //     #s
    //   ]
    // }
  ]

  #v(.5fr)

  #if examination_day != none [
    #set text(size: 12pt)
    #smallcaps[Date: #examination_day]
  ]
  #line(length: 100%)
  #pagebreak()
]
