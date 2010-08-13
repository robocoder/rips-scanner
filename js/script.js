/** 

RIPS - A static source code analyser for vulnerabilities in PHP scripts 
	by Johannes Dahse (johannesdahse@gmx.de)
			
			
**/

/* CODE STYLE */	

function setActiveStyleSheet(title)
{
	var i, a;
	for(i=0; (a = document.getElementsByTagName("link")[i]); i++)
	{
		if(a.getAttribute("rel").indexOf("style") != -1 && a.getAttribute("title")) 
		{
			a.disabled = true;
			if(a.getAttribute("title") == title) a.disabled = false;
		}
	}
}

function hide(tag)
{
	if(document.getElementById(tag).style.display != "none")
	{
		document.getElementById(tag).style.display="none";
		document.getElementById("pic"+tag).className='plusico';
	}
	else
	{
		document.getElementById(tag).style.display="block";
		document.getElementById("pic"+tag).className='minusico';
	}
}

function markVariable(variable)
{
	var i, a;
	for(i=0; (a = document.getElementsByName("phps-var-"+variable)[i]); i++)
	{
		if(a.style.backgroundColor == '')
			a.style.backgroundColor = 'darkred';
		else
			a.style.backgroundColor = '';
	}
	
}
	
function getFuncCode(hoveritem, file, start, end)
{
	var codediv = document.getElementById("funccode");
	codediv.style.display="block"; 
	codediv.style.zIndex = 3;
	
	if(file.length > 50)
		title = '...'+file.substr(file.length-50,50);
	else
		title = file;
	document.getElementById("funccodetitle").innerHTML=title;
	
	var tmp = hoveritem.offsetParent;
	codediv.style.top = tmp.offsetParent.offsetTop; 
	codediv.style.left = hoveritem.offsetLeft;
	
	var a = true;
	var client = new XMLHttpRequest();
	client.onreadystatechange = function () 
	{ 
		if(this.readyState == 4 && this.status == 200 && a) 
		{
			document.getElementById("funccodecontent").innerHTML=(this.responseText);
			a=false;
		} 
		else if (this.readyState == 4 && this.status != 200) 
		{
			alert("Please copy 'getfunc.php' to the same directory.");
		}
	}
	client.open("GET", "getfunc.php?file="+file+"&start="+start+"&end="+end);
	client.send();
}

function closeFuncCode()
{
	document.getElementById("funccode").style.display = "none";
}

/* MANAGE WINDOWS */	

function closeWindow(id)
{
	document.getElementById("window"+id).style.display="none";
}

function top(wid)
{
	var windows = document.getElementsByName("window");
	for(var i=0; i<windows.length; i++)
	{
		if(windows[i].id == "window"+wid)
			windows[i].style.zIndex = 3;
		else
			windows[i].style.zIndex = 1;
	}
}

function openFunctions()
{
	var style = document.getElementById("window3").style;

	if(style.display == "" || style.display == "none") {
		style.display = "block";
		style.zIndex = 3;
	}	
	else {
		style.display = "none";
	}	
}

function openUserinput()
{
	var style = document.getElementById("window4").style;

	if(style.display == "" || style.display == "none") {
		style.display = "block";
		style.zIndex = 3;
	}	
	else {
		style.display = "none";
	}	
}

function openCodeViewer(hoveritem, file, lines)
{
	var linenrs = lines.split(",");
	var title = 'CodeViewer - ';
	if(file.length > 50)
		title+= '...'+file.substr(file.length-50,50);
	else
		title+= file;
		
	var mywindow = document.getElementById("window1");	
	mywindow.style.display="block";
	
	if(hoveritem != 3 && hoveritem != 4)
		var tmp = hoveritem.offsetParent;
	else	
		var tmp = document.getElementById("windowtitle"+hoveritem);
		
	mywindow.style.top = tmp.offsetParent.offsetTop - 100; 
	mywindow.style.right = 200; 
	
	document.getElementById("windowtitle1").innerHTML=title;
	
	var a = true;
	var client = new XMLHttpRequest();
	client.onreadystatechange = function () 
	{ 
		if(this.readyState == 4 && this.status == 200 && a) 
		{
			document.getElementById("windowcontent1").innerHTML=(this.responseText);
					
			document.getElementById(linenrs[0]).scrollIntoView();
		
			document.body.scrollTop = tmp.offsetParent.offsetTop - 200;
			
			a=false;
		} 
		else if (this.readyState == 4 && this.status != 200) 
		{
			alert("Please copy 'code.php' to the same directory.");
		}
	}
	client.open("GET", "code.php?file="+file+"&lines="+lines);
	client.send();
}

function openExploitCreator(hoveritem, file, get, post, cookie, files, server)
{
	var title = 'ExploitCreator - ';
	if(file.length > 50)
		title+= '...'+file.substr(file.length-50,50);
	else
		title+= file;
		
	var mywindow = document.getElementById("window2");	
	mywindow.style.display="block";
	
	var tmp = hoveritem.offsetParent;
	
	mywindow.style.top = tmp.offsetParent.offsetTop - 100; 
	mywindow.style.right = 200; 
	
	document.getElementById("windowtitle2").innerHTML=title;
	
	var a = true;
	var client = new XMLHttpRequest();
	client.onreadystatechange = function () 
	{ 
		if(this.readyState == 4 && this.status == 200 && a) 
		{
			document.getElementById("windowcontent2").innerHTML=(this.responseText);
					
			document.getElementById("windowcontent2").scrollIntoView();
		
			document.body.scrollTop = tmp.offsetParent.offsetTop - 200;
			
			a=false;
		} 
		else if (this.readyState == 4 && this.status != 200) 
		{
			alert("Please copy 'exploit.php' to the same directory.");
		}
	}
	client.open("GET", 
		"exploit.php?file="+file+"&get="+get+"&post="+post+"&cookie="+cookie+"&files="+files+"&server="+server);
	client.send();
}
	

/* DRAG WINDOW */	
	
var dragobjekt = null;

var dragx = 0;
var dragy = 0;

var posx = 0;
var posy = 0;

function draginit() {
  document.onmousemove = drag;
  document.onmouseup = dragstop;
}

function dragstart(id) {
  dragobjekt = document.getElementById("window"+id);
  dragx = posx - dragobjekt.offsetLeft;
  dragy = posy - dragobjekt.offsetTop;
}

function dragstop() {
  dragobjekt=null;
}

function drag(ereignis) {
  posx = document.all ? window.event.clientX : ereignis.pageX;
  posy = document.all ? window.event.clientY : ereignis.pageY;
  if(dragobjekt != null) {
    dragobjekt.style.left = (posx - dragx) + "px";
    dragobjekt.style.top = (posy - dragy) + "px";
  }
}			   
