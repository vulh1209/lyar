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

  // Wallet functionality
  let wallet = null;
  const walletButtons = document.querySelector('.wallet-buttons');

  // Auth elements
  const userInfo = document.getElementById('userInfo');
  const googleSignIn = document.getElementById('googleSignIn');
  const googleSignOut = document.getElementById('googleSignOut');
  const createPasskey = document.getElementById('createPasskey');
  const recoverWithPasskey = document.getElementById('recoverWithPasskey');
  const passkeyInfo = document.getElementById('passkeyInfo');

  // Theme elements
  const themeToggle = document.getElementById('settings-theme-toggle');

  function showWalletActions(hasWallet) {
    if (hasWallet) {
      // Hide create/import buttons when wallet exists
      walletButtons.style.display = 'none';
      importSection.style.display = 'none';
    } else {
      // Only show create/import buttons when logged in
      chrome.storage.local.get(['isLoggedIn'], (result) => {
        walletButtons.style.display = result.isLoggedIn ? 'flex' : 'none';
        if (!result.isLoggedIn) {
          walletInfo.innerHTML = '<p>Please sign in to manage wallet</p>';
        }
      });
    }
  }

  // Initialize chain selector
  function initializeChainSelector() {
    if (!chainSelect) {
      console.error('Chain select element not found');
      return;
    }

    // Clear existing options
    chainSelect.innerHTML = '';
    
    // Add chains from config
    if (typeof CHAINS !== 'undefined') {
      Object.entries(CHAINS).forEach(([chainId, chain]) => {
        const option = document.createElement('option');
        option.value = chainId;
        option.textContent = `${chain.icon} ${chain.name}`;
        chainSelect.appendChild(option);
      });

      // Load saved chain or default to Sepolia
      chrome.storage.local.get(['selectedChainId'], (result) => {
        if (result.selectedChainId) {
          chainSelect.value = result.selectedChainId;
        } else {
          // Default to Sepolia
          chainSelect.value = '11155111';
          chrome.storage.local.set({ selectedChainId: '11155111' });
        }
        updateTokenSymbol();
      });

      // Add chain change handler
      chainSelect.addEventListener('change', async () => {
        const chainId = chainSelect.value;
        chrome.storage.local.set({ selectedChainId: chainId });
        updateTokenSymbol();
        await updateBalance();
      });
    } else {
      console.error('CHAINS configuration not found');
    }
  }

  // Update token symbol based on selected chain
  function updateTokenSymbol() {
    if (!chainSelect || !tokenSymbol) return;
    
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
      // Check login status first
      const result = await chrome.storage.local.get(['isLoggedIn']);
      if (!result.isLoggedIn) {
        walletBalance.textContent = '*****';
        return;
      }

      if (!wallet) {
        walletBalance.textContent = '0.00';
        return;
      }

      const provider = getProvider();
      if (!provider) {
        walletBalance.textContent = '0.00';
        return;
      }

      const balance = await provider.getBalance(wallet.address);
      const formattedBalance = ethers.formatEther(balance);
      walletBalance.textContent = (+formattedBalance).toFixed(4);
    } catch (error) {
      console.error('Balance update error:', error);
      walletBalance.textContent = '0.00';
    }
  }

  // Update wallet info with balance
  async function updateWalletInfo(address) {
    // Check login status
    chrome.storage.local.get(['isLoggedIn'], async (result) => {
      if (!result.isLoggedIn) {
        walletInfo.innerHTML = '<p>********************</p>';
      } else {
        if (!address || address === 'No wallet connected') {
          walletInfo.innerHTML = '<p>No wallet connected</p>';
        } else {
          walletInfo.innerHTML = `
            <p><strong>Address:</strong></p>
            <p>${address}</p>
          `;
        }
      }
      await updateBalance();
    });
    
    // Update passkey section visibility
    const passkeySection = document.querySelector('.passkey-section');
    if (wallet) {
      passkeySection.style.display = 'block';
    } else {
      passkeySection.style.display = 'none';
    }
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
      // Check login status first
      const result = await chrome.storage.local.get(['isLoggedIn']);
      if (!result.isLoggedIn) {
        throw new Error('Please sign in first');
      }

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
  importWalletButton.addEventListener('click', async () => {
    // Check login status first
    const result = await chrome.storage.local.get(['isLoggedIn']);
    if (!result.isLoggedIn) {
      showStatus('Please sign in first', 'error');
      return;
    }
    
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

  // Default system prompt
  const DEFAULT_SYSTEM_PROMPT = `
You are a assistant. Your name is Lyar.
Your personality traits:
- Helpful and supportive
- Creative and innovative
- Clever and intelligent
- Very friendly and approachable
- Always try to help users solve their problems in the best way possible
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

  // Google Sign In
  async function handleGoogleSignIn() {
    try {
      const auth = await chrome.identity.getAuthToken({ interactive: true });
      if (!auth) throw new Error('Authentication failed');

      const response = await fetch('https://www.googleapis.com/oauth2/v3/userinfo', {
        headers: { Authorization: `Bearer ${auth.token}` }
      });
      
      if (!response.ok) throw new Error('Failed to get user info');
      
      const userProfile = await response.json();
      
      // Save user info
      chrome.storage.local.set({ 
        userProfile,
        isLoggedIn: true 
      });

      updateUserInfo(userProfile);
      showStatus('Signed in successfully!', 'success');
    } catch (error) {
      console.error('Google Sign In error:', error);
      showStatus('Sign in failed: ' + error.message, 'error');
    }
  }

  // Google Sign Out
  async function handleGoogleSignOut() {
    try {
      // Get current token
      chrome.identity.getAuthToken({ interactive: false }, function(token) {
        if (token) {
          // Remove token
          chrome.identity.removeCachedAuthToken({ token: token }, function() {
            // Clear user data from storage
            chrome.storage.local.remove(['userProfile', 'isLoggedIn'], function() {
              updateUserInfo(null);
              showStatus('Signed out successfully!', 'success');
            });
          });
        } else {
          // If no token found, just clear storage
          chrome.storage.local.remove(['userProfile', 'isLoggedIn'], function() {
            updateUserInfo(null);
            showStatus('Signed out successfully!', 'success');
          });
        }
      });
    } catch (error) {
      console.error('Google Sign Out error:', error);
      showStatus('Sign out failed: ' + error.message, 'error');
    }
  }

  // Update UI with user info
  function updateUserInfo(profile) {
    if (profile) {
      userInfo.innerHTML = `
        <p><strong>${profile.name}</strong></p>
        <p>${profile.email}</p>
      `;
      googleSignIn.style.display = 'none';
      googleSignOut.style.display = 'block';
      
      // Enable wallet section when logged in
      document.querySelector('.wallet-section').classList.remove('disabled');
      
      // Show wallet actions if no wallet exists
      if (!wallet) {
        walletButtons.style.display = 'flex';
        walletInfo.innerHTML = '<p>No wallet connected</p>';
      }
      
      // Show passkey section only when logged in and wallet exists
      const passkeySection = document.querySelector('.passkey-section');
      if (wallet) {
        passkeySection.style.display = 'block';
        chrome.storage.local.get(['passkeyCredential'], (result) => {
          if (result.passkeyCredential) {
            recoverWithPasskey.style.display = 'block';
            createPasskey.style.display = 'none';
          } else {
            createPasskey.style.display = 'block';
            recoverWithPasskey.style.display = 'none';
          }
        });
      } else {
        passkeySection.style.display = 'none';
      }
    } else {
      userInfo.innerHTML = '<p>Not signed in</p>';
      googleSignIn.style.display = 'block';
      googleSignOut.style.display = 'none';
      
      // Disable wallet section when logged out
      const walletSection = document.querySelector('.wallet-section');
      walletSection.classList.add('disabled');
      walletInfo.innerHTML = '<p>*** *** *** ***</p>';
      walletButtons.style.display = 'none';
      
      // Hide wallet sections and passkey section
      importSection.style.display = 'none';
      exportSection.style.display = 'none';
      document.querySelector('.passkey-section').style.display = 'none';
    }
  }

  // Create Passkey
  async function handleCreatePasskey() {
    try {
      if (!wallet) {
        throw new Error('Please create or import a wallet first');
      }

      const publicKey = {
        challenge: crypto.getRandomValues(new Uint8Array(32)),
        rp: {
          name: 'Lyar Assistant',
          id: window.location.hostname
        },
        user: {
          id: crypto.getRandomValues(new Uint8Array(16)),
          name: wallet.address,
          displayName: 'Wallet Owner'
        },
        pubKeyCredParams: [{
          type: 'public-key',
          alg: -7 // ES256
        }],
        authenticatorSelection: {
          authenticatorAttachment: 'platform',
          userVerification: 'required'
        }
      };

      const credential = await navigator.credentials.create({
        publicKey
      });

      // Convert ArrayBuffer to Base64
      const credentialId = btoa(String.fromCharCode(...new Uint8Array(credential.rawId)));
      const publicKeyBytes = new Uint8Array(credential.response.getPublicKey());
      const publicKeyBase64 = btoa(String.fromCharCode(...publicKeyBytes));

      // Save credential ID and public key
      chrome.storage.local.set({
        passkeyCredential: {
          id: credentialId,
          publicKey: publicKeyBase64,
          walletAddress: wallet.address,
          encryptedPrivateKey: wallet.privateKey
        }
      });

      updatePasskeyInfo(true);
      showStatus('Passkey created successfully!', 'success');
    } catch (error) {
      console.error('Create passkey error:', error);
      showStatus('Failed to create passkey: ' + error.message, 'error');
    }
  }

  // Recover with Passkey
  async function handleRecoverWithPasskey() {
    try {
      // Check login status first
      const result = await chrome.storage.local.get(['isLoggedIn', 'passkeyCredential']);
      if (!result.isLoggedIn) {
        throw new Error('Please sign in first');
      }
      if (!result.passkeyCredential) {
        throw new Error('No passkey found');
      }

      const challenge = crypto.getRandomValues(new Uint8Array(32));
      
      // Convert Base64 credential ID back to ArrayBuffer
      const credentialId = Uint8Array.from(atob(result.passkeyCredential.id), c => c.charCodeAt(0));

      const assertionOptions = {
        challenge,
        allowCredentials: [{
          type: 'public-key',
          id: credentialId,
          transports: ['internal']
        }],
        userVerification: 'required'
      };

      const assertion = await navigator.credentials.get({
        publicKey: assertionOptions
      });

      if (assertion) {
        // Restore wallet using saved data
        wallet = new ethers.Wallet(result.passkeyCredential.encryptedPrivateKey);
        await updateWalletInfo(result.passkeyCredential.walletAddress);
        showStatus('Wallet recovered successfully!', 'success');
        showWalletActions(true);
        
        // Show export section with private key
        exportKeyInput.value = result.passkeyCredential.encryptedPrivateKey;
        exportSection.style.display = 'block';
      }
    } catch (error) {
      console.error('Recover with passkey error:', error);
      showStatus('Failed to recover wallet: ' + error.message, 'error');
    }
  }

  // Update passkey info
  function updatePasskeyInfo(hasPasskey) {
    chrome.storage.local.get(['isLoggedIn', 'walletAddress'], (result) => {
      if (!result.isLoggedIn) {
        // Khi chưa login
        passkeyInfo.innerHTML = '<p>Please sign in to manage passkey</p>';
        createPasskey.style.display = 'none';
        recoverWithPasskey.style.display = 'block';
        recoverWithPasskey.disabled = true;
        recoverWithPasskey.classList.add('disabled');
      } else if (result.walletAddress) {
        // Đã login và đã có ví
        if (hasPasskey) {
          passkeyInfo.innerHTML = '<p> Wallet is secured with passkey</p>';
          createPasskey.style.display = 'none';
          recoverWithPasskey.style.display = 'none';
        } else {
          passkeyInfo.innerHTML = '<p>Secure your wallet with a passkey</p>';
          createPasskey.style.display = 'block';
          recoverWithPasskey.style.display = 'none';
        }
      } else {
        // Đã login nhưng chưa có ví
        if (hasPasskey) {
          passkeyInfo.innerHTML = '<p> Recover your wallet with passkey</p>';
          createPasskey.style.display = 'none';
          recoverWithPasskey.style.display = 'block';
          recoverWithPasskey.disabled = false;
          recoverWithPasskey.classList.remove('disabled');
        } else {
          passkeyInfo.innerHTML = '<p>Create a wallet first to use passkey</p>';
          createPasskey.style.display = 'none';
          recoverWithPasskey.style.display = 'none';
        }
      }
    });
  }

  // Check for existing passkey
  chrome.storage.local.get(['passkeyCredential'], (result) => {
    updatePasskeyInfo(!!result.passkeyCredential);
  });

  // Check for existing login
  chrome.storage.local.get(['userProfile', 'isLoggedIn'], (result) => {
    if (result.isLoggedIn && result.userProfile) {
      updateUserInfo(result.userProfile);
    }
  });

  // Event listeners
  googleSignIn.addEventListener('click', handleGoogleSignIn);
  googleSignOut.addEventListener('click', handleGoogleSignOut);
  createPasskey.addEventListener('click', handleCreatePasskey);
  recoverWithPasskey.addEventListener('click', handleRecoverWithPasskey);

  // Theme handling
  function toggleTheme() {
    const html = document.documentElement;
    const currentTheme = html.getAttribute('data-theme');
    const newTheme = currentTheme === 'dark' ? 'light' : 'dark';
    
    html.setAttribute('data-theme', newTheme);
    chrome.storage.local.set({ theme: newTheme });
    themeToggle.checked = newTheme === 'dark';
  }

  // Load saved theme
  chrome.storage.local.get(['theme'], (result) => {
    if (result.theme) {
      document.documentElement.setAttribute('data-theme', result.theme);
      themeToggle.checked = result.theme === 'dark';
    }
  });

  themeToggle.addEventListener('change', toggleTheme);
}); 