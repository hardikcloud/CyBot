let currentSessionId = null;

const chatBox = document.getElementById("chatBox");
const userInput = document.getElementById("userInput");
const sendBtn = document.getElementById("sendBtn");
const newChatBtn = document.getElementById("newChatBtn");
const historyList = document.getElementById("historyList");

/* ================= SEND MESSAGE ================= */

function sendMessage() {

    const message = userInput.value.trim();
    if (!message) return;

    chatBox.innerHTML += `<div class="msg user">${message}</div>`;
    userInput.value = "";

    chatBox.innerHTML += `<div class="msg bot typing" id="typing">Cybot is analyzing...</div>`;
    chatBox.scrollTop = chatBox.scrollHeight;

    fetch("/chat", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
            message: message,
            session_id: currentSessionId
        })
    })
    .then(res => res.json())
    .then(data => {

        document.getElementById("typing")?.remove();

        if (!currentSessionId) {
            currentSessionId = data.session_id;
        }

        chatBox.innerHTML += `<div class="msg bot">${data.reply.replace(/\n/g, "<br>")}</div>`;
        chatBox.scrollTop = chatBox.scrollHeight;

        loadSessions();
    });
}

sendBtn.addEventListener("click", sendMessage);

userInput.addEventListener("keypress", function(e) {
    if (e.key === "Enter") sendMessage();
});

/* ================= NEW CHAT ================= */

newChatBtn.addEventListener("click", function() {
    currentSessionId = null;
    chatBox.innerHTML = "";
    loadSessions();
});

/* ================= LOAD SESSIONS ================= */

function loadSessions() {

    fetch("/sessions")
    .then(res => res.json())
    .then(data => {

        historyList.innerHTML = "";

        data.forEach(session => {

            const item = document.createElement("div");
            item.className = "session-item";
            if (session.id === currentSessionId) {
                item.classList.add("active");
            }

            const title = document.createElement("span");
            title.textContent = session.title;
            title.onclick = () => loadChat(session.id);

            const dots = document.createElement("span");
            dots.className = "menu-dots";
            dots.innerHTML = `<i class="fa-solid fa-ellipsis-vertical"></i>`;
            dots.onclick = (e) => {
                e.stopPropagation();
                toggleMenu(session.id);
            };

            const menu = document.createElement("div");
            menu.className = "session-menu";
            menu.id = `menu-${session.id}`;

            const deleteBtn = document.createElement("button");
            deleteBtn.textContent = "Delete";
            deleteBtn.onclick = () => deleteSession(session.id);

            const cancelBtn = document.createElement("button");
            cancelBtn.textContent = "Cancel";
            cancelBtn.onclick = () => closeMenu(session.id);

            menu.appendChild(deleteBtn);
            menu.appendChild(cancelBtn);

            item.appendChild(title);
            item.appendChild(dots);
            item.appendChild(menu);

            historyList.appendChild(item);
        });
    });
}

/* ================= LOAD CHAT ================= */

function loadChat(sessionId) {

    currentSessionId = sessionId;

    fetch(`/messages/${sessionId}`)
    .then(res => res.json())
    .then(data => {

        chatBox.innerHTML = "";

        data.forEach(msg => {
            chatBox.innerHTML += `
                <div class="msg ${msg.role}">
                    ${msg.content.replace(/\n/g, "<br>")}
                </div>`;
        });

        chatBox.scrollTop = chatBox.scrollHeight;
        loadSessions();
    });
}

/* ================= MENU LOGIC ================= */

function toggleMenu(sessionId) {
    closeAllMenus();
    const menu = document.getElementById(`menu-${sessionId}`);
    if (menu) menu.style.display = "block";
}

function closeMenu(sessionId) {
    const menu = document.getElementById(`menu-${sessionId}`);
    if (menu) menu.style.display = "none";
}

function closeAllMenus() {
    document.querySelectorAll(".session-menu").forEach(menu => {
        menu.style.display = "none";
    });
}

document.addEventListener("click", closeAllMenus);

/* ================= DELETE SESSION ================= */

function deleteSession(sessionId) {

    fetch(`/delete_session/${sessionId}`)
    .then(res => res.json())
    .then(data => {

        if (currentSessionId === sessionId) {
            currentSessionId = null;
            chatBox.innerHTML = "";
        }

        loadSessions();
    });
}

/* ================= INIT ================= */

window.onload = loadSessions;