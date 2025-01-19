document.addEventListener('DOMContentLoaded', () => {
    const apiKeyInput = document.getElementById('apiKey');
    const saveButton = document.getElementById('saveButton');
    const statusMessage = document.getElementById('statusMessage');

    // Load saved API key hash (if exists)
    chrome.storage.local.get(['apiKeyHash'], (result) => {
        if (result.apiKeyHash) {
            apiKeyInput.placeholder = '••••••••••••••••';
        }
    });

    // Hash function using SHA-256
    async function hashString(str) {
        const encoder = new TextEncoder();
        const data = encoder.encode(str);
        const hashBuffer = await crypto.subtle.digest('SHA-256', data);
        const hashArray = Array.from(new Uint8Array(hashBuffer));
        return hashArray.map(byte => byte.toString(16).padStart(2, '0')).join('');
    }

    // Save API key with hashing
    async function saveApiKey() {
        try {
            const apiKey = apiKeyInput.value.trim();
            
            if (!apiKey) {
                showStatus('Please enter an API key', 'error');
                return;
            }

            // Hash the API key
            const apiKeyHash = await hashString(apiKey);

            // Save the hashed API key
            chrome.storage.local.set({ apiKeyHash }, () => {
                showStatus('Settings saved successfully!', 'success');
                apiKeyInput.value = '';
                apiKeyInput.placeholder = '••••••••••••••••';
            });

        } catch (error) {
            showStatus('Error saving settings: ' + error.message, 'error');
        }
    }

    function showStatus(message, type) {
        statusMessage.textContent = message;
        statusMessage.className = 'status-message ' + type;
        statusMessage.style.display = 'block';
        
        setTimeout(() => {
            statusMessage.style.display = 'none';
        }, 3000);
    }

    saveButton.addEventListener('click', saveApiKey);
}); 