document.addEventListener('DOMContentLoaded', () => {
  const chatMessages = document.getElementById('chat-messages');
  const userInput = document.getElementById('user-input');
  const sendButton = document.getElementById('send-button');
  const settingsLink = document.getElementById('settings-link');
  const backToChat = document.getElementById('back-to-chat');
  const mainView = document.getElementById('main-view');
  const settingsView = document.getElementById('settings-view');
  const apiKeyInput = document.getElementById('apiKey');
  const customPromptInput = document.getElementById('customPrompt');
  const saveButton = document.getElementById('saveButton');
  const statusMessage = document.getElementById('statusMessage');
  const newChatButton = document.getElementById('new-chat');
  const copyApiKeyButton = document.getElementById('copyApiKey');
  const toggleApiKeyButton = document.getElementById('toggleApiKey');

  // Default system prompt
  const DEFAULT_SYSTEM_PROMPT = `
You are a assistant. Your name is Lyar.
Your personality traits:
- Helpful and supportive
- Creative and innovative
- Clever and intelligent
- Very friendly and approachable
- Always try to help users solve their problems in the best way possible

Web3 Integration:
When user requests any action to blockchain/web3, you should:
1.You can clarify the format if user request action with web3. 
If you don't know it is nft or token you can ask user to clarify. type nft is erc721 or erc1155.
2. Use the appropriate smart contract ABI
3. Encode the function call data
4. Reply with the following format if you enough information, if not you can ask user to clarify:
{{action: 'web3',
  method: 'function_name',
  params: ['param1', 'param2'],
  data: 'encoded_function_data',
  value: 'eth_value_in_wei',
  to: 'contract_address'
}}
`.trim();

  // Merge default and custom prompts
  function getMergedPrompt(customPrompt) {
    if (!customPrompt) return DEFAULT_SYSTEM_PROMPT;
    
    return `
${DEFAULT_SYSTEM_PROMPT}

Custom Instructions:
${customPrompt}
`.trim();
  }

  // Handle web3 action
  async function handleWeb3Action(actionData) {
    try {
      // Check if MetaMask is installed
      if (typeof window.ethereum === 'undefined') {
        throw new Error('MetaMask is not installed');
      }

      // Request account access
      const accounts = await window.ethereum.request({ method: 'eth_requestAccounts' });
      const from = accounts[0];

      // Parse action data
      const match = actionData.match(/{{action: 'web3'.*?}}/s);
      if (!match) return null;

      try {
        // Convert the matched string to a valid JSON format
        const jsonStr = match[0]
          .replace(/{{/g, '{')
          .replace(/}}/g, '}')
          .replace(/'/g, '"');
        
        const action = JSON.parse(jsonStr);

        // Prepare transaction parameters
        const txParams = {
          from,
          to: action.to,
          value: action.value ? action.value : '0x0',
          data: action.data ? action.data : '0x'
        };

        // Send transaction
        const txHash = await window.ethereum.request({
          method: 'eth_sendTransaction',
          params: [txParams],
        });

        return `Transaction sent! Hash: ${txHash}`;
      } catch (e) {
        console.error('Error parsing action:', e);
        throw new Error('Invalid web3 action format');
      }
    } catch (error) {
      console.error('Web3 error:', error);
      throw error;
    }
  }

  // Handle API key visibility toggle
  toggleApiKeyButton.addEventListener('click', async () => {
    const isPassword = apiKeyInput.type === 'password';
    apiKeyInput.type = isPassword ? 'text' : 'password';
    toggleApiKeyButton.textContent = isPassword ? 'Hide' : 'Show';
  });

  // Handle API key copy
  copyApiKeyButton.addEventListener('click', async () => {
    try {
      const result = await chrome.storage.local.get(['apiKey']);
      if (result.apiKey) {
        await navigator.clipboard.writeText(result.apiKey);
        showStatus('API Key copied to clipboard!', 'success');
      } else {
        showStatus('No API Key saved', 'error');
      }
    } catch (error) {
      showStatus('Failed to copy API Key', 'error');
    }
  });

  // Handle new chat button
  newChatButton.addEventListener('click', () => {
    // Clear chat messages from UI
    chatMessages.innerHTML = '';
    // Clear chat history from storage
    chrome.storage.local.set({ chatHistory: [] });
  });

  // Handle view switching
  settingsLink.addEventListener('click', (e) => {
    e.preventDefault();
    mainView.style.display = 'none';
    settingsView.style.display = 'block';
  });

  backToChat.addEventListener('click', (e) => {
    e.preventDefault();
    settingsView.style.display = 'none';
    mainView.style.display = 'block';
  });

  // Settings functionality
  // Load saved settings
  chrome.storage.local.get(['apiKeyHash', 'apiKey', 'customPrompt'], (result) => {
    if (result.apiKeyHash) {
      apiKeyInput.placeholder = '••••••••••••••••';
      if (result.apiKey) {
        apiKeyInput.value = result.apiKey;
      }
    }
    if (result.customPrompt) {
      customPromptInput.value = result.customPrompt;
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

  // Save settings
  async function saveSettings() {
    try {
      const apiKey = apiKeyInput.value.trim();
      const customPrompt = customPromptInput.value.trim();
      
      if (!apiKey) {
        showStatus('Please enter an API key', 'error');
        return;
      }

      // Save settings
      const apiKeyHash = await hashString(apiKey);
      chrome.storage.local.set({ 
        apiKeyHash,
        apiKey,
        customPrompt
      }, () => {
        showStatus('Settings saved successfully!', 'success');
        apiKeyInput.value = apiKey;
        apiKeyInput.type = 'password';
        toggleApiKeyButton.textContent = 'Show';
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

  saveButton.addEventListener('click', saveSettings);

  // Chat functionality
  // Load chat history from storage
  chrome.storage.local.get(['chatHistory'], (result) => {
    if (result.chatHistory) {
      result.chatHistory.forEach(message => {
        appendMessage(message.text, message.type);
      });
    }
  });

  // Handle send button click
  sendButton.addEventListener('click', handleSendMessage);

  // Handle enter key press
  userInput.addEventListener('keypress', (e) => {
    if (e.key === 'Enter' && !e.shiftKey) {
      e.preventDefault();
      handleSendMessage();
    }
  });

  async function getGeminiResponse(message) {
    try {
      // Get API key, chat history, and custom prompt from storage
      const result = await chrome.storage.local.get(['apiKey', 'chatHistory', 'customPrompt']);
      const apiKey = result.apiKey;
      const chatHistory = result.chatHistory || [];
      const customPrompt = result.customPrompt;

      if (!apiKey) {
        appendMessage('Please set your API key in settings first', 'assistant');
        return;
      }

      // Prepare conversation history
      const contents = [];

      // Add system instruction as first message
      contents.push({
        role: "model",
        parts: [{
          text: getMergedPrompt(customPrompt)
        }]
      });

      // Add chat history
      chatHistory.forEach(msg => {
        contents.push({
          role: msg.type === 'user' ? 'user' : 'model',
          parts: [{ text: msg.text }]
        });
      });

      // Add current message
      contents.push({
        role: 'user',
        parts: [{ text: message }]
      });

      const response = await fetch(`https://generativelanguage.googleapis.com/v1beta/models/gemini-1.5-flash:generateContent?key=${apiKey}`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
        },
        body: JSON.stringify({ contents })
      });

      if (!response.ok) {
        throw new Error('API request failed');
      }

      const data = await response.json();
      if (data.candidates && data.candidates[0] && data.candidates[0].content) {
        return data.candidates[0].content.parts[0].text;
      } else {
        throw new Error('Invalid response format');
      }
    } catch (error) {
      console.error('Error:', error);
      return 'Sorry, I encountered an error. Please try again later.';
    }
  }

  async function handleSendMessage() {
    const message = userInput.value.trim();
    if (!message) return;

    // Add user message to chat
    appendMessage(message, 'user');
    saveMessage(message, 'user');

    // Clear input
    userInput.value = '';

    // Show loading message
    const loadingMessage = 'Thinking...';
    appendMessage(loadingMessage, 'assistant');

    // Get response from Gemini
    const response = await getGeminiResponse(message);

    // Remove loading message
    chatMessages.removeChild(chatMessages.lastChild);

    // Check for web3 action in response
    if (response.includes("{{action: 'web3'")) {
      try {
        // Handle web3 action
        const txResult = await handleWeb3Action(response);
        
        // Show both AI response and transaction result
        appendMessage(response, 'assistant');
        if (txResult) {
          appendMessage(txResult, 'assistant');
        }
        
        // Save messages
        saveMessage(response, 'assistant');
        if (txResult) {
          saveMessage(txResult, 'assistant');
        }
      } catch (error) {
        // Show error message
        appendMessage(response, 'assistant');
        appendMessage(`Web3 Error: ${error.message}`, 'assistant');
        
        // Save messages
        saveMessage(response, 'assistant');
        saveMessage(`Web3 Error: ${error.message}`, 'assistant');
      }
    } else {
      // Normal response without web3 action
      appendMessage(response, 'assistant');
      saveMessage(response, 'assistant');
    }
  }

  function appendMessage(text, type) {
    const messageDiv = document.createElement('div');
    messageDiv.classList.add('message', `${type}-message`);
    messageDiv.textContent = text;
    chatMessages.appendChild(messageDiv);
    chatMessages.scrollTop = chatMessages.scrollHeight;
  }

  function saveMessage(text, type) {
    chrome.storage.local.get(['chatHistory'], (result) => {
      const chatHistory = result.chatHistory || [];
      chatHistory.push({ text, type });
      chrome.storage.local.set({ chatHistory });
    });
  }
}); 