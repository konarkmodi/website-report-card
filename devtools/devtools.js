browser.devtools.panels.create(
	"Neerikshan",                      // title
	"../icons/sheriff.png",                // icon
	"panel/panel.html"      // content
  ).then((newPanel) => {
		console.log(">>> Inside pannel", newPanel);
  });
