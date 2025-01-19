document.addEventListener('DOMContentLoaded', async () => {
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

  // Wallet elements
  const walletInfo = document.getElementById('walletInfo');
  const createWalletButton = document.getElementById('createWallet');
  const importWalletButton = document.getElementById('importWallet');
  const importSection = document.getElementById('importSection');
  const exportSection = document.getElementById('exportSection');
  const privateKeyInput = document.getElementById('privateKey');
  const confirmImportButton = document.getElementById('confirmImport');
  const exportKeyInput = document.getElementById('exportKey');
  const copyPrivateKeyButton = document.getElementById('copyPrivateKey');
  const removeWalletButton = document.getElementById('removeWallet');

  // Chain elements
  const chainSelect = document.getElementById('chainSelect');
  const walletBalance = document.getElementById('walletBalance');
  const tokenSymbol = document.getElementById('tokenSymbol');
  const refreshBalance = document.getElementById('refreshBalance');

  // Wallet functionality
  let wallet = null;
  const walletButtons = document.querySelector('.wallet-buttons');

  function showWalletActions(hasWallet) {
    if (hasWallet) {
      // Hide create/import buttons when wallet exists
      walletButtons.style.display = 'none';
      importSection.style.display = 'none';
    } else {
      // Show create/import buttons when no wallet
      walletButtons.style.display = 'flex';
    }
  }

  // Initialize chain selector
  function initializeChainSelector() {
    // Clear existing options
    chainSelect.innerHTML = '';
    
    // Add chains from config
    Object.entries(CHAINS).forEach(([chainId, chain]) => {
      const option = document.createElement('option');
      option.value = chainId;
      option.textContent = `${chain.icon} ${chain.name}`;
      chainSelect.appendChild(option);
    });

    // Load saved chain
    chrome.storage.local.get(['selectedChainId'], (result) => {
      if (result.selectedChainId) {
        chainSelect.value = result.selectedChainId;
      } else {
        // Default to Ethereum Mainnet
        chainSelect.value = '1';
        chrome.storage.local.set({ selectedChainId: '1' });
      }
      updateTokenSymbol();
    });
  }

  // Update token symbol based on selected chain
  function updateTokenSymbol() {
    const chainId = chainSelect.value;
    const chain = CHAINS[chainId];
    if (chain) {
      tokenSymbol.textContent = chain.symbol;
    }
  }

  // Get provider for current chain
  function getProvider() {
    const chainId = chainSelect.value;
    const chain = CHAINS[chainId];
    if (!chain) return null;
    return new ethers.JsonRpcProvider(chain.rpc);
  }

  // Update wallet balance
  async function updateBalance() {
    try {
      if (!wallet) return;

      const provider = getProvider();
      if (!provider) return;

      const balance = await provider.getBalance(wallet.address);
      const formattedBalance = ethers.formatEther(balance);
      walletBalance.textContent = (+formattedBalance).toFixed(4);
    } catch (error) {
      console.error('Balance update error:', error);
      walletBalance.textContent = '0.00';
    }
  }

  // Chain change handler
  chainSelect.addEventListener('change', async () => {
    const chainId = chainSelect.value;
    chrome.storage.local.set({ selectedChainId: chainId });
    updateTokenSymbol();
    await updateBalance();
  });

  // Refresh balance handler
  refreshBalance.addEventListener('click', updateBalance);

  // Update wallet info with balance
  async function updateWalletInfo(address) {
    walletInfo.innerHTML = `
      <p><strong>Address:</strong></p>
      <p>${address}</p>
    `;
    await updateBalance();
  }

  // Initialize chain selector
  initializeChainSelector();

  // Load wallet if exists
  chrome.storage.local.get(['walletAddress', 'encryptedPrivateKey'], async (result) => {
    if (result.walletAddress) {
      wallet = new ethers.Wallet(result.encryptedPrivateKey);
      await updateWalletInfo(result.walletAddress);
      showWalletActions(true);
    } else {
      showWalletActions(false);
    }
  });

  // Create new wallet
  createWalletButton.addEventListener('click', async () => {
    try {
      const randomWallet = ethers.Wallet.createRandom();
      wallet = randomWallet;
      const address = await wallet.getAddress();

      chrome.storage.local.set({
        walletAddress: address,
        encryptedPrivateKey: wallet.privateKey
      });

      await updateWalletInfo(address);
      showStatus('Wallet created successfully!', 'success');
      showWalletActions(true);

      exportKeyInput.value = wallet.privateKey;
      exportSection.style.display = 'block';
    } catch (error) {
      console.error('Wallet creation error:', error);
      showStatus('Error creating wallet: ' + error.message, 'error');
    }
  });

  // Import wallet
  importWalletButton.addEventListener('click', () => {
    importSection.style.display = importSection.style.display === 'none' ? 'block' : 'none';
    exportSection.style.display = 'none';
  });

  // Confirm import
  confirmImportButton.addEventListener('click', async () => {
    try {
      const privateKey = privateKeyInput.value.trim();
      if (!privateKey) {
        throw new Error('Please enter a private key');
      }

      wallet = new ethers.Wallet(privateKey);
      const address = await wallet.getAddress();

      chrome.storage.local.set({
        walletAddress: address,
        encryptedPrivateKey: privateKey
      });

      await updateWalletInfo(address);
      showStatus('Wallet imported successfully!', 'success');
      showWalletActions(true);
      importSection.style.display = 'none';
      privateKeyInput.value = '';
    } catch (error) {
      console.error('Wallet import error:', error);
      showStatus('Error importing wallet: ' + error.message, 'error');
    }
  });

  // Copy private key
  copyPrivateKeyButton.addEventListener('click', async () => {
    try {
      await navigator.clipboard.writeText(exportKeyInput.value);
      showStatus('Private key copied to clipboard!', 'success');
    } catch (error) {
      showStatus('Error copying private key', 'error');
    }
  });

  // Remove wallet
  removeWalletButton.addEventListener('click', async () => {
    try {
      chrome.storage.local.remove(['walletAddress', 'encryptedPrivateKey'], () => {
        wallet = null;
        walletBalance.textContent = '0.00';
        updateWalletInfo('No wallet connected');
        showWalletActions(false);
        exportSection.style.display = 'none';
        showStatus('Wallet removed successfully!', 'success');
      });
    } catch (error) {
      console.error('Wallet removal error:', error);
      showStatus('Error removing wallet: ' + error.message, 'error');
    }
  });

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
When user requests any blockchain/web3 action, you should:
1. Use the appropriate smart contract ABI
2. Encode the function call data
3. Reply with the following format:
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