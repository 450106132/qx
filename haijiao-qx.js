/**
 * 海角 Quantumult X 单文件修复版
 *
 * 功能：
 * 1. 处理 banner、attachment、topic API 响应。
 * 2. 解出 HLS AES-128 真实 Key。
 * 3. 通过 script-echo-response 返回 HTTPS 二进制 Key，避免 Safari 使用 data: Key。
 * 4. 将 .ts 响应的 Content-Type 修正为 video/mp2t。
 */

'use strict';

const KEY_ROUTE = '/__qx_hj_key__/';
const SCRIPT_NAME = '海角 QX 修复版';

function info(message) {
  if (typeof console !== 'undefined') console.log(`[${SCRIPT_NAME}] ${message}`);
}

function warn(message) {
  if (typeof console !== 'undefined') console.log(`[${SCRIPT_NAME}] ⚠️ ${message}`);
}

function getHeader(headers, wantedName) {
  const wanted = wantedName.toLowerCase();
  for (const [name, value] of Object.entries(headers || {})) {
    if (name.toLowerCase() === wanted) return value;
  }
  return undefined;
}

function removeHeaders(headers, names) {
  const blocked = new Set(names.map((name) => name.toLowerCase()));
  const result = {};
  for (const [name, value] of Object.entries(headers || {})) {
    if (!blocked.has(name.toLowerCase())) result[name] = value;
  }
  return result;
}

function normalizeTsHeaders(headers) {
  const result = removeHeaders(headers, ['content-type']);
  result['Content-Type'] = 'video/mp2t';
  return result;
}

function normalizePlaylistHeaders(headers) {
  const result = removeHeaders(headers, [
    'content-type',
    'content-encoding',
    'content-length',
    'transfer-encoding',
  ]);
  result['Content-Type'] = 'application/vnd.apple.mpegurl';
  return result;
}

function normalizeBodyHeaders(headers) {
  return removeHeaders(headers, [
    'content-encoding',
    'content-length',
    'transfer-encoding',
  ]);
}

function resolveUrl(resource, baseUrl) {
  if (/^https?:\/\//i.test(resource)) return resource;
  const originMatch = baseUrl.match(/^(https?:\/\/[^/]+)/i);
  if (resource.startsWith('/')) {
    return originMatch ? `${originMatch[1]}${resource}` : resource;
  }
  return baseUrl.replace(/[^/?#]*(?:[?#].*)?$/, '') + resource;
}

function deriveSecretUrl(playlistUrl) {
  return playlistUrl.replace(/\.m3u8(?=\?|$)/i, '.jpg');
}

function syntheticKeyUrl(playlistUrl, keyHex) {
  const origin = playlistUrl.match(/^(https?:\/\/[^/]+)/i);
  if (!origin) throw new Error('无法从 m3u8 地址解析域名');
  return `${origin[1]}${KEY_ROUTE}${keyHex}.key`;
}

function replaceKeyUri(playlist, originalUri, replacementUri) {
  return playlist.split(`URI="${originalUri}"`).join(`URI="${replacementUri}"`);
}

function utf8ToBase64(value) {
  return btoa(unescape(encodeURIComponent(value)));
}

function base64ToUtf8(value) {
  return decodeURIComponent(escape(atob(value)));
}

function encodeTripleBase64(value) {
  let result = value;
  for (let i = 0; i < 3; i += 1) result = utf8ToBase64(result);
  return result;
}

function decodeTripleBase64(value) {
  let result = value;
  for (let i = 0; i < 3; i += 1) result = base64ToUtf8(result);
  return result;
}

function parseDataField(value) {
  return JSON.parse(decodeTripleBase64(value));
}

function encodeDataField(value) {
  return encodeTripleBase64(JSON.stringify(value));
}

function binaryStringToBytes(value) {
  const bytes = new Uint8Array(value.length);
  for (let i = 0; i < value.length; i += 1) bytes[i] = value.charCodeAt(i) & 0xff;
  return bytes;
}

function toUint8Array(value) {
  if (value instanceof Uint8Array) return value;
  if (value instanceof ArrayBuffer) return new Uint8Array(value);
  if (ArrayBuffer.isView(value)) {
    return new Uint8Array(value.buffer, value.byteOffset, value.byteLength);
  }
  if (typeof value === 'string') return binaryStringToBytes(value);
  throw new TypeError(`无法转换为 Uint8Array: ${typeof value}`);
}

function responseBytes(response) {
  if (response && response.bodyBytes !== undefined) return toUint8Array(response.bodyBytes);
  if (response && typeof response.body === 'string') return binaryStringToBytes(response.body);
  throw new Error('响应中没有二进制内容');
}

function responseText(response) {
  if (response && typeof response.body === 'string') return response.body;
  if (response && response.bodyBytes !== undefined) {
    return new TextDecoder('utf-8').decode(toUint8Array(response.bodyBytes));
  }
  return '';
}

function decodeBase64Bytes(value) {
  return binaryStringToBytes(atob(value.trim()));
}

function decryptContentKey(encryptedKey, secretBase64Text) {
  const encrypted = toUint8Array(encryptedKey);
  const secret = decodeBase64Bytes(secretBase64Text);
  if (encrypted.byteLength < 16) throw new Error(`加密 Key 长度不足: ${encrypted.byteLength}`);
  if (secret.byteLength < 16) throw new Error(`secret 长度不足: ${secret.byteLength}`);

  const realKey = new Uint8Array(16);
  for (let i = 0; i < 16; i += 1) realKey[i] = encrypted[i] ^ secret[i];
  return realKey;
}

function bytesToHex(bytes) {
  return Array.from(toUint8Array(bytes), (value) => value.toString(16).padStart(2, '0')).join('');
}

function hexToBytes(hex) {
  if (!/^[0-9a-f]{32}$/i.test(hex)) throw new Error('真实 Key 必须是 32 位十六进制');
  const bytes = new Uint8Array(16);
  for (let i = 0; i < bytes.length; i += 1) {
    bytes[i] = Number.parseInt(hex.slice(i * 2, i * 2 + 2), 16);
  }
  return bytes;
}

function keyBytesFromUrl(url) {
  const match = url.match(/\/__qx_hj_key__\/([0-9a-f]{32})\.key(?:\?|$)/i);
  if (!match) throw new Error('虚拟 Key 地址格式不正确');
  return hexToBytes(match[1]);
}

function markPurchased(value) {
  if (!value || typeof value !== 'object') return value;
  if (Object.prototype.hasOwnProperty.call(value, 'is_buy')) value.is_buy = true;
  if (Object.prototype.hasOwnProperty.call(value, 'buy_index')) value.buy_index = 9999;
  if (Object.prototype.hasOwnProperty.call(value, 'currentUserPurchased')) {
    value.currentUserPurchased = true;
  }
  if (Array.isArray(value)) {
    value.forEach(markPurchased);
  } else {
    Object.values(value).forEach(markPurchased);
  }
  return value;
}

function parseJson(value) {
  if (value && typeof value === 'object') return value;
  try {
    return JSON.parse(String(value || '').replace(/^\uFEFF/, '').trim());
  } catch {
    return null;
  }
}

function qxFetch(options) {
  const request = { ...options };
  request.timeout = request.timeout || 15000;
  return $task.fetch(request).then((response) => {
    const status = Number(response.statusCode || response.status || 0);
    if (status < 200 || status >= 300) throw new Error(`HTTP ${status}`);
    return response;
  });
}

function apiHeaders(request) {
  const token = getHeader(request.headers, 'x-user-token');
  if (!token) return null;
  return {
    'Content-Type': 'application/json',
    pcver: getHeader(request.headers, 'pcver') || '2',
    'User-Agent':
      getHeader(request.headers, 'user-agent') ||
      'Mozilla/5.0 (iPhone; CPU iPhone OS like Mac OS X) AppleWebKit/605.1.15',
    'x-user-token': token,
    'x-user-id': getHeader(request.headers, 'x-user-id') || '',
    'X-HJ-Internal': '1',
  };
}

async function fetchAttachment(attachmentId, request) {
  const headers = apiHeaders(request);
  if (!headers) {
    warn('没有检测到 x-user-token，请先登录海角');
    return null;
  }
  const origin = request.url.match(/^(https?:\/\/[^/]+)/i);
  if (!origin) return null;

  const response = await qxFetch({
    url: `${origin[1]}/api/attachment`,
    method: 'POST',
    headers,
    body: JSON.stringify({
      id: attachmentId,
      resource_id: 2174028,
      resource_type: 'topic',
      line: 'normal1',
    }),
  });
  const json = parseJson(responseText(response));
  if (!json || !json.data) return null;
  const attachment = parseDataField(json.data);
  return attachment && /^https?:\/\//i.test(attachment.remoteUrl || '')
    ? attachment.remoteUrl
    : null;
}

function injectVideoLink(content, videoUrl) {
  const button =
    `<div style="margin:12px 0">` +
    `<a href="${videoUrl}" style="display:inline-block;background:#3d7eff;color:#fff;` +
    `padding:10px 18px;border-radius:6px;text-decoration:none;font-size:14px">` +
    `立即观看完整视频</a></div>`;
  const value = String(content || '');
  if (value.includes(videoUrl)) return value;
  if (value.includes('<body>')) return value.replace('<body>', `<body>${button}`);
  return button + value;
}

async function handleBanner(response) {
  const json = parseJson(response.body);
  if (!json) return {};
  json.data = 'WW01V2MySkJQVDA9';
  return {
    body: JSON.stringify(json),
    headers: normalizeBodyHeaders(response.headers),
  };
}

async function handleAttachment(request, response) {
  const json = parseJson(response.body);
  if (!json || !json.data) return {};
  const attachment = parseDataField(json.data);
  const remoteUrl = attachment && attachment.remoteUrl ? attachment.remoteUrl : '';
  if (attachment && attachment.id && (!/^https?:\/\//i.test(remoteUrl) || /preview/i.test(remoteUrl))) {
    const fullUrl = await fetchAttachment(attachment.id, request);
    if (fullUrl) attachment.remoteUrl = fullUrl;
  }
  json.data = encodeDataField(attachment);
  return {
    body: JSON.stringify(json),
    headers: normalizeBodyHeaders(response.headers),
  };
}

async function handleTopic(request, response) {
  if (!getHeader(request.headers, 'x-user-token')) {
    warn('帖子请求没有登录信息，保持原响应');
    return {};
  }
  const json = parseJson(response.body);
  if (!json || !json.data) return {};
  const topic = parseDataField(json.data);
  markPurchased(topic);
  if (topic.sale) {
    topic.sale.is_buy = true;
    topic.sale.buy_index = 9999;
  }
  topic.currentUserPurchased = true;

  const video = Array.isArray(topic.attachments)
    ? topic.attachments.find((item) => item && item.category === 'video' && item.id)
    : null;
  if (video) {
    const videoUrl = await fetchAttachment(video.id, request);
    if (videoUrl) {
      video.remoteUrl = videoUrl;
      topic.content = injectVideoLink(topic.content, videoUrl);
      info(`已注入视频链接: ${videoUrl}`);
    }
  }

  json.data = encodeDataField(topic);
  return {
    body: JSON.stringify(json),
    headers: normalizeBodyHeaders(response.headers),
  };
}

function playlistKeyUris(playlist) {
  const result = [];
  const pattern = /^#EXT-X-KEY:[^\r\n]*URI="([^"]+)"[^\r\n]*$/gim;
  let match;
  while ((match = pattern.exec(playlist)) !== null) {
    if (!result.includes(match[1])) result.push(match[1]);
  }
  return result;
}

async function handlePlaylist(request, response) {
  let playlist = responseText(response);
  if (!playlist || playlist.includes('#EXT-X-STREAM-INF')) return {};

  const keyUris = playlistKeyUris(playlist);
  if (keyUris.length === 0) {
    info('m3u8 没有 AES Key，保持原响应');
    return {};
  }

  const secretUrl = deriveSecretUrl(request.url);
  info(`secret: ${secretUrl}`);
  const secretResponse = await qxFetch({ url: secretUrl, method: 'GET', timeout: 15000 });
  const secretText = responseText(secretResponse).trim();
  if (!secretText) throw new Error('secret 内容为空');

  for (const keyUri of keyUris) {
    const encryptedKeyUrl = resolveUrl(keyUri, request.url);
    info(`加密 Key: ${encryptedKeyUrl}`);
    const keyResponse = await qxFetch({
      url: encryptedKeyUrl,
      method: 'GET',
      headers: { Accept: 'application/octet-stream' },
      timeout: 15000,
    });
    const realKey = decryptContentKey(responseBytes(keyResponse), secretText);
    const keyHex = bytesToHex(realKey);
    const qxKeyUrl = syntheticKeyUrl(request.url, keyHex);
    playlist = replaceKeyUri(playlist, keyUri, qxKeyUrl);
    info(`真实 Key: ${keyHex}`);
  }

  info('m3u8 已改为 HTTPS 虚拟 Key');
  return {
    body: playlist,
    headers: normalizePlaylistHeaders(response.headers),
  };
}

function echoRealKey(requestUrl) {
  const bytes = keyBytesFromUrl(requestUrl);
  info(`返回 16 字节真实 Key: ${bytesToHex(bytes)}`);
  return {
    status: 'HTTP/1.1 200 OK',
    headers: {
      'Content-Type': 'application/octet-stream',
      'Cache-Control': 'no-store',
      'Access-Control-Allow-Origin': '*',
    },
    bodyBytes: bytes.buffer.slice(bytes.byteOffset, bytes.byteOffset + bytes.byteLength),
  };
}

async function runQuantumultX() {
  const request = typeof $request !== 'undefined' ? $request : { url: '', headers: {} };
  const response = typeof $response !== 'undefined' ? $response : null;
  const url = request.url || '';

  try {
    if (url.includes(KEY_ROUTE)) {
      $done(echoRealKey(url));
      return;
    }

    if (/\.ts(?:\?|$)/i.test(url)) {
      $done({ headers: normalizeTsHeaders((response && response.headers) || {}) });
      return;
    }

    if (!response) {
      $done({});
      return;
    }

    if (getHeader(request.headers, 'x-hj-internal') === '1') {
      $done({});
      return;
    }

    let result = {};
    if (/\/api\/banner\/banner_list(?:\?|$)/i.test(url)) {
      result = await handleBanner(response);
    } else if (/\/api\/attachment(?:\?|$)/i.test(url)) {
      result = await handleAttachment(request, response);
    } else if (/\/api\/topic\/\d+(?:\?|$)/i.test(url)) {
      result = await handleTopic(request, response);
    } else if (/\.m3u8(?:\?|$)/i.test(url)) {
      result = await handlePlaylist(request, response);
    }
    $done(result);
  } catch (error) {
    warn(error && error.stack ? error.stack : String(error));
    $done({});
  }
}

const exported = {
  bytesToHex,
  decodeTripleBase64,
  decryptContentKey,
  deriveSecretUrl,
  encodeTripleBase64,
  hexToBytes,
  keyBytesFromUrl,
  markPurchased,
  normalizePlaylistHeaders,
  normalizeTsHeaders,
  replaceKeyUri,
  resolveUrl,
  syntheticKeyUrl,
};

if (typeof module !== 'undefined' && module.exports) {
  module.exports = exported;
} else {
  runQuantumultX();
}

