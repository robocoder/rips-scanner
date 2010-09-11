/** 

RIPS - A static source code analyser for vulnerabilities in PHP scripts 
	by Johannes Dahse (johannesdahse@gmx.de)
			
			
**/

/* SCAN */

function scanAnimation(div)
{
	if(div)
	{
		var pixel = div.style.height.split("px");
		var newpixel = Number(pixel[0])+5;
		div.style.height = newpixel+"px";
		if(newpixel >= 75)
			div.style.height = "0px";
	}	
}

function scan(ignore_warning)
{
	var location = encodeURIComponent(document.getElementById("location").value);
	var subdirs = Number(document.getElementById("subdirs").checked);
	var	verbosity = document.getElementById("verbosity").value;
	var vector = document.getElementById("vector").value;
	var treestyle = document.getElementById("treestyle").value;
	
	var params = "loc="+location+"&subdirs="+subdirs+"&verbosity="+verbosity+"&vector="+vector+"&treestyle="+treestyle;

	if(ignore_warning)
		params+="&ignore_warning=1";
	
	document.getElementById("scanning").style.backgroundImage="url(css/scanning.gif)";
	document.getElementById("scanning").innerHTML='scanning ...<div class="scanned" id="scanned"></div>';
	document.getElementById("scanning").style.display="block";
	var animation = window.setInterval("scanAnimation(document.getElementById('scanned'))", 300);
	
	var a = true;
	var client = new XMLHttpRequest();
	client.onreadystatechange = function () 
	{ 
		if(this.readyState == 4 && this.status == 200 && a) 
		{
			if(!this.responseText.match(/^\s*warning:/))
			{
				document.getElementById("scanning").style.display="none";
				window.clearInterval(animation);
				document.getElementById("options").style.display="";
				document.getElementById("result").innerHTML=(this.responseText);
			}
			else
			{
				var amount = this.responseText.split(':')[1];
				var warning = "<div class=\"warning\">";
				warning+="<h2>warning</h2>";
				warning+="<p>You are about to scan " + amount + " files. ";
				warning+="Depending on the amount of codelines and includes this may take a very long time. ";
				warning+="The author of RIPS recommends to scan only a few files once.</p>";
				warning+="<p>Do you want to continue anyway?</p>";	
				warning+="<input type=\"button\" class=\"Button\" value=\"continue\" onClick=\"scan(true);\"/>&nbsp;";
				warning+="<input type=\"button\" class=\"Button\" value=\"cancel\" onClick=\"document.getElementById('scanning').style.display='none';\"/>";
				warning+="</div>";
				document.getElementById("scanning").style.backgroundImage="none";
				document.getElementById("scanning").innerHTML=warning;
			}
			a=false;
		} 
		else if (this.readyState == 4 && this.status != 200) 
		{
			alert("Network error ("+this.status+").");
		}
	}
	client.open("POST", "main.php", true);
	client.setRequestHeader("Content-type", "application/x-www-form-urlencoded");
	client.setRequestHeader("Content-length", params.length);
	client.setRequestHeader("Connection", "close");
	client.send(params);
}

/* SEARCH */

function search()
{
	var location = encodeURIComponent(document.getElementById("location").value);
	var subdirs = Number(document.getElementById("subdirs").checked);
	var regex = encodeURIComponent(document.getElementById("search").value);
	var params = 'loc='+location+'&subdirs='+subdirs+'&search=1&regex='+regex+'&ignore_warning=1&treestyle=1';

	document.getElementById("scanning").style.backgroundImage="url(css/scanning.gif)";
	document.getElementById("scanning").innerHTML='searching ...<div class="scanned" id="scanned"></div>';
	document.getElementById("scanning").style.display="block";
	var animation = window.setInterval("scanAnimation(document.getElementById('scanned'))", 300);
	
	var a = true;
	var client = new XMLHttpRequest();
	client.onreadystatechange = function () 
	{ 
		if(this.readyState == 4 && this.status == 200 && a) 
		{
			document.getElementById("scanning").style.display="none";
			window.clearInterval(animation);
			document.getElementById("options").style.display="none";
			document.getElementById("result").innerHTML=(this.responseText);
			a=false;
		}
		else if (this.readyState == 4 && this.status != 200) 
		{
			alert("Network error ("+this.status+").");
		}
	}
	client.open("POST", "main.php", true);
	client.setRequestHeader("Content-type", "application/x-www-form-urlencoded");
	client.setRequestHeader("Content-length", params.length);
	client.setRequestHeader("Connection", "close");
	client.send(params);
}


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

function mouseFunction(name, item)
{
	if(document.getElementById('fol_'+name) != null)
	{
		item.style.cursor='pointer';
		item.style.textDecoration='underline';
		item.title='jump to function code';
	}	
}

var stack = new Array(); 

function openFunction(name, linenr)
{
	if(document.getElementById('fol_'+name) != null)
	{
		var code = String(document.getElementById('fol_'+name).onclick).split("\n");
		eval(code[1]);
		var save = new Array(document.getElementById('windowcontent1').innerHTML, linenr);
		stack.push(save);
		document.getElementById('return').style.display='block';
	}	
}

function returnLastCode()
{
	var recover = stack.pop();
	if(stack.length < 1)
		document.getElementById('return').style.display='none';
	document.getElementById('windowcontent1').innerHTML = recover[0];
	document.getElementById(recover[1]).scrollIntoView();
	document.body.scrollTop = document.body.scrollTop - 100;
}

/* MANAGE WINDOWS */

function closeFuncCode()
{
	document.getElementById("funccode").style.display = "none";
}

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

/* LOAD WINDOWS */

function openWindow(id)
{
	var style = document.getElementById("window"+id).style;

	if(style.display == "" || style.display == "none") {
		style.display = "block";
		style.zIndex = 3;
	}	
	else {
		style.display = "none";
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
			alert("Network error ("+this.status+").");
		}
	}
	client.open("GET", "windows/function.php?file="+file+"&start="+start+"&end="+end);
	client.send();
}

function openHelp(hoveritem, type, thefunction, get, post, cookie, files, server)
{
	var title = 'Help - ';
	if(type.length > 50)
		title+= type.substr(0,80)+'...';
	else
		title+=type;
	
	var mywindow = document.getElementById("window2");	
	mywindow.style.display="block";
	
	if(hoveritem != 3 && hoveritem != 4)
		var tmp = hoveritem.offsetParent;
	else	
		var tmp = document.getElementById("windowtitle"+hoveritem);
		
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
			alert("Network error ("+this.status+").");
		}
	}
	client.open("GET", 
		"windows/help.php?type="+type+"&function="+thefunction+"&get="+get+"&post="+post+"&cookie="+cookie+"&files="+files+"&server="+server);
	client.send();
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
		
	if(tmp.offsetParent != null)	
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
					
			if(document.getElementById(linenrs[0]) != null)	
				document.getElementById(linenrs[0]).scrollIntoView();
		
			if(tmp.offsetParent != null)
				document.body.scrollTop = tmp.offsetParent.offsetTop - 200;
			else
				document.body.scrollTop = document.body.scrollTop - 100;
			
			a=false;
		} 
		else if (this.readyState == 4 && this.status != 200) 
		{
			alert("Network error ("+this.status+").");
		}
	}
	client.open("GET", "windows/code.php?file="+file+"&lines="+lines);
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
			alert("Network error ("+this.status+").");
		}
	}
	client.open("GET", 
		"windows/exploit.php?file="+file+"&get="+get+"&post="+post+"&cookie="+cookie+"&files="+files+"&server="+server);
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

/* RESIZE WINDOW */

var curWidth = 0;
var curHeight = 0;
var curX = 0;
var curY = 0;
var newX = 0;
var newY = 0;
var mouseButtonPos = "up";
var windowid = 1;

function resizeStart(e, id)
{
	windowid = id;
	curEvent = ((typeof event == "undefined")? e: event);
	mouseButtonPos = "down";	
	curX = curEvent.clientX;
	curY = curEvent.clientY;
	
	var tempWidth = document.getElementById("window"+id).style.width;
	var tempHeight = document.getElementById("window"+id).style.height;

	var widthArray = tempWidth.split("p");
	curWidth = parseInt(widthArray[0]);
	var heightArray=tempHeight.split("p");
	curHeight=parseInt(heightArray[0]);
}

function getPos(e)
{
	if( mouseButtonPos == "down" )
	{
		curEvent = ((typeof event == "undefined")? e: event);
		newY = curEvent.clientY;
		newX = curEvent.clientX;
		var pxMoveY = parseInt(newY - curY);
		var pxMoveX = parseInt(newX - curX);

		var newWidth = parseInt(curWidth + pxMoveX);
		var newHeight = parseInt(curHeight + pxMoveY);

		newWidth = ((newWidth < 200)? 200: newWidth);
		newHeight=(newHeight<5?5:newHeight);

		document.getElementById("window"+windowid).style.width = newWidth + "px";
		document.getElementById("window"+windowid).style.height = newHeight + "px";
	}
}