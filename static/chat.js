let currentSessionId = null;

// Load sessions when page loads
window.onload = function () {
    loadSessions();
};

// Send message
document.getElementById("sendBtn").addEventListener("click", function () {

    const userInput = document.getElementById("userInput");
    const chatBox = document.getElementById("chatBox");

    const userMessage = userInput.value.trim();
    if (!userMessage) return;

    // Show user message
    chatBox.innerHTML += `
        <div class="msg user">
            ${userMessage}
        </div>
    `;

    userInput.value = "";

    fetch("/chat", {
        method: "POST",
        headers: {
            "Content-Type": "application/json"
        },
        body: JSON.stringify({
            message: userMessage,
            session_id: currentSessionId
        })
    })
    .then(res => res.json())
    .then(data => {

        // Save session id after first message
        if (!currentSessionId) {
            currentSessionId = data.session_id;
            loadSessions(); // refresh sidebar
        }

        chatBox.innerHTML += `
            <div class="msg bot">
                ${data.reply}
            </div>
        `;

        chatBox.scrollTop = chatBox.scrollHeight;
    })
    .catch(err => console.error(err));
});


// New Chat button
document.querySelector(".btn-primary").addEventListener("click", function () {
    currentSessionId = null;
    document.getElementById("chatBox").innerHTML = "";
});


// Load all sessions (sidebar)
function loadSessions() {
    fetch("/sessions")
    .then(res => res.json())
    .then(data => {

        const historyDiv = document.querySelector(".history");
        historyDiv.innerHTML = "<span>History</span>";

        data.forEach(session => {
            historyDiv.innerHTML += `
                <div class="session-item" onclick="loadChat(${session.id})">
                    Chat ${session.id}
                </div>
            `;
        });
    });
}


// Load specific session messages
function loadChat(sessionId) {

    fetch(`/messages/${sessionId}`)
    .then(res => res.json())
    .then(data => {

        currentSessionId = sessionId;

        const chatBox = document.getElementById("chatBox");
        chatBox.innerHTML = "";

        data.forEach(msg => {
            chatBox.innerHTML += `
                <div class="msg ${msg.role}">
                    ${msg.content}
                </div>
            `;
        });

        chatBox.scrollTop = chatBox.scrollHeight;
    });
}