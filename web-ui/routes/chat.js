const express = require('express');
const router = express.Router();
const http = require('http');
const https = require('https');
const path = require('path');
const os = require('os');

const OLLAMA_HOST = (process.env.OLLAMA_HOST || 'http://localhost:11434').replace(/\/$/, '');
const OLLAMA_MODEL = process.env.OLLAMA_MODEL || 'llama3.1:8b';

// Helper: POST to Ollama HTTP API
function ollamaGenerate(prompt, options = {}) {
  return new Promise((resolve, reject) => {
    const body = JSON.stringify({
      model: OLLAMA_MODEL,
      prompt,
      stream: false,
      options: { temperature: 0.4, top_p: 0.9, ...options }
    });

    const url = new URL(`${OLLAMA_HOST}/api/generate`);
    const lib = url.protocol === 'https:' ? https : http;

    const req = lib.request({
      hostname: url.hostname,
      port: url.port || (url.protocol === 'https:' ? 443 : 80),
      path: url.pathname,
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'Content-Length': Buffer.byteLength(body)
      }
    }, (res) => {
      let data = '';
      res.on('data', (chunk) => { data += chunk; });
      res.on('end', () => {
        try {
          resolve(JSON.parse(data).response || '');
        } catch (e) {
          reject(new Error('Failed to parse Ollama response'));
        }
      });
    });

    req.on('error', reject);
    req.setTimeout(60000, () => { req.destroy(); reject(new Error('Request timeout')); });
    req.write(body);
    req.end();
  });
}

// Helper: GET Ollama tags (list models)
function ollamaTags() {
  return new Promise((resolve, reject) => {
    const url = new URL(`${OLLAMA_HOST}/api/tags`);
    const lib = url.protocol === 'https:' ? https : http;

    const req = lib.request({
      hostname: url.hostname,
      port: url.port || (url.protocol === 'https:' ? 443 : 80),
      path: url.pathname,
      method: 'GET'
    }, (res) => {
      let data = '';
      res.on('data', (chunk) => { data += chunk; });
      res.on('end', () => {
        try {
          resolve(JSON.parse(data));
        } catch (e) {
          reject(new Error('Failed to parse Ollama tags response'));
        }
      });
    });

    req.on('error', reject);
    req.setTimeout(10000, () => { req.destroy(); reject(new Error('Request timeout')); });
    req.end();
  });
}

// Chat with AI assistant
router.post('/message', async (req, res) => {
  const { message } = req.body;

  if (!message) {
    return res.status(400).json({ error: 'Message is required' });
  }

  try {
    const prompt = `You are a cybersecurity expert assistant. Answer the following security question concisely and accurately:\n\n${message}\n`;
    const response = await ollamaGenerate(prompt);

    res.json({
      success: true,
      response: response.trim(),
      timestamp: new Date().toISOString()
    });
  } catch (error) {
    console.error('Chat error:', error);
    const isTimeout = error.message === 'Request timeout';
    res.status(isTimeout ? 504 : 500).json({
      error: isTimeout ? 'Request timeout' : 'Failed to process message',
      message: error.message
    });
  }
});

// Check if AI model is available
router.get('/status', async (req, res) => {
  try {
    const data = await ollamaTags();
    const models = (data.models || []).map((m) => ({
      name: m.name,
      id: m.digest ? m.digest.slice(0, 12) : '',
      size: m.size ? `${(m.size / 1e9).toFixed(1)} GB` : '',
      modified: m.modified_at || ''
    }));

    res.json({
      available: true,
      models,
      recommended: models.find(m => m.name.includes('llama3.1:8b')) ? 'llama3.1:8b' :
                   models.find(m => m.name.includes('llama3.2:3b')) ? 'llama3.2:3b' :
                   models[0]?.name || 'none'
    });
  } catch (error) {
    res.json({
      available: false,
      error: error.message || 'Ollama not responding'
    });
  }
});

module.exports = router;
