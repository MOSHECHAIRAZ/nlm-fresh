document.getElementById('extractBtn').addEventListener('click', async () => {
    const outputArea = document.getElementById('output');
    outputArea.value = "Extracting...";

    try {
        const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });

        if (!tab) {
            throw new Error("No active tab found");
        }

        // 1. שליפת הטוקן (נשאר אותו דבר, זה ספציפי ל-NotebookLM)
        const injectionResults = await chrome.scripting.executeScript({
            target: { tabId: tab.id },
            world: 'MAIN',
            func: () => {
                return window.WIZ_global_data?.SNlM0e || null;
            }
        });

        const token = injectionResults[0].result;

        if (!token) {
            outputArea.value = "Error: Token not found. Please refresh the NotebookLM page.";
            return;
        }

        // 2. === שליפת Cookies מה-URL הנוכחי ===
        // כדי לקבל קוקיס רלוונטיים ל-NotebookLM
        const cookies = await chrome.cookies.getAll({ url: tab.url });
        
        // סינון כפילויות ואיחוד
        const cookieString = cookies.map(c => `${c.name}=${c.value}`).join('; ');

        // 3. יצירת הפלט
        const result = {
            NLM_AUTH_TOKEN: token,
            NLM_COOKIES: cookieString
        };

        outputArea.value = JSON.stringify(result, null, 2);
        outputArea.value += "\n\nSending to nlm software...";
        
        // 4. שליחה לשרת המקומי
        try {
            const response = await fetch("http://127.0.0.1:36400", {
                method: "POST",
                headers: { "Content-Type": "application/json" },
                body: JSON.stringify(result)
            });

            if (response.ok) {
                outputArea.value = "✅ SUCCESS! Credentials automatically saved to nlm.";
            } else {
                outputArea.value += "\n❌ Server received but returned error.";
            }
        } catch (netErr) {
            outputArea.value += "\n⚠️ Could not connect to nlm software.\nMake sure you ran 'nlm auth -server' in your terminal!";
        }

    } catch (err) {
        outputArea.value = "Error: " + err.message;
        console.error(err);
    }
});