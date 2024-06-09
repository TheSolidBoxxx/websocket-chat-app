const usrname = prompt("Enter your username");

const socket = new WebSocket('ws://' + window.location.href.split("/")[2]);
socket.onopen = function(event) {
    socket.send(usrname);
};

socket.onmessage = function(event) {
    const serverMessage = event.data.split(":");

    switch(serverMessage[0]){
        case "USERNAME":
            AddUser(serverMessage[1]);
            break;

        case "LOGOUT":
            RemoveUser(serverMessage[1])
            break;

        case "MSG":
            AddMessage(serverMessage[1], serverMessage[2])
            break
    }
};

socket.onclose = function(event) {
    console.log('WebSocket is closed now.');
};

socket.onerror = function(error) {
    console.error('WebSocket error:', error);
};


function Send(){
    socket.send(document.getElementById("inp").value);
}

function AddUser(user){
    const para = document.createElement("li");
    para.appendChild(document.createTextNode(user));
    document.getElementById("users").querySelector("ul").appendChild(para);
}

function RemoveUser(user){
    const element = document.getElementById("users").querySelector("ul");
    for (const child of element.children) {
        if(child.innerHTML == user){
            child.remove();
        }
    }
}

function AddMessage(user, msg){
    const msg_box = document.createElement("li");

    if(user == usrname)
        msg_box.appendChild(document.createTextNode(user + ": " + msg + " [SELF]"));
    else
        msg_box.appendChild(document.createTextNode(user + ": " + msg));
    document.getElementById("messages").querySelector("ul").appendChild(msg_box);
}

window.onbeforeunload = function() {
    socket.onclose = function () {};
    socket.close();
};
