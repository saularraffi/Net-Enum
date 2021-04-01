var btn = document.getElementById('target-ip-btn')
var ipInput = document.getElementById('target-ip')

var data = {
	ip: '10.0.2.9'
}

btn.addEventListener('click', function(){
	alert('hello')
})

fetch(`${window.origin}/`, {
	method: 'POST',
	cache: "no-cache",
	headers: {
	    'Content-Type': 'application/json',
	  },
	body: JSON.stringify(data)
})