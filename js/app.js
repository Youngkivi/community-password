/**
 * 密码查询系统 - 前端应用
 *
 * 安全设计（共享密码 + 白名单模式）：
 * - 共享密码使用 AES-256-GCM 加密存储，每人的密钥独立
 * - 加密密钥由 PBKDF2(学号|手机号, salt, 100000次迭代) 派生
 * - 每条白名单记录使用独立的随机 salt 和 IV
 * - 非白名单用户即使下载了数据文件也无法解密
 *
 * 浏览器兼容性：需要支持 Web Crypto API (所有现代浏览器均支持)
 */

(function () {
    'use strict';

    // ============ 配置 ============
    const CONFIG = {
        dataUrl: 'data/passwords.json',
        pbkdf2Iterations: 100000,
        keyLengthBits: 256,
        hashAlgorithm: 'SHA-256',
        passwordDisplayTimeout: 60, // 秒，超过后自动隐藏密码
        rateLimitMax: 20,           // 时间窗口内最大尝试次数
        rateLimitWindow: 60,        // 时间窗口（秒）
    };

    // ============ DOM 元素 ============
    const form = document.getElementById('lookupForm');
    const studentIdInput = document.getElementById('studentId');
    const phoneNumberInput = document.getElementById('phoneNumber');
    const submitBtn = document.getElementById('submitBtn');
    const btnText = document.getElementById('btnText');
    const btnSpinner = document.getElementById('btnSpinner');
    const resultDiv = document.getElementById('result');
    const loadingHint = document.getElementById('loadingHint');

    // ============ 状态 ============
    let passwordData = null;    // 加载的加密数据
    let isDataLoaded = false;   // 数据是否加载完成
    let isLoading = false;      // 是否正在查询中
    let clearTimer = null;      // 自动清除计时器

    // ============ 工具函数 ============

    /**
     * 将标准 Base64 字符串解码为 ArrayBuffer
     * 兼容 Node.js crypto 模块的 Base64 输出
     */
    function base64ToArrayBuffer(base64) {
        try {
            const binary = atob(base64);
            const bytes = new Uint8Array(binary.length);
            for (let i = 0; i < binary.length; i++) {
                bytes[i] = binary.charCodeAt(i);
            }
            return bytes.buffer;
        } catch (e) {
            throw new Error('Base64 解码失败：数据格式错误');
        }
    }

    /**
     * ArrayBuffer 转为 Base64（用于调试，非核心功能）
     */
    function arrayBufferToBase64(buffer) {
        const bytes = new Uint8Array(buffer);
        let binary = '';
        for (let i = 0; i < bytes.length; i++) {
            binary += String.fromCharCode(bytes[i]);
        }
        return btoa(binary);
    }

    // ============ 速率限制 ============

    /**
     * 检查是否超过速率限制
     * 使用 localStorage 记录请求时间戳，窗口内超过上限则拒绝
     * @returns {{ allowed: boolean, remaining: number, resetIn: number }}
     */
    function checkRateLimit() {
        const now = Date.now();
        const windowMs = CONFIG.rateLimitWindow * 1000;
        const cutoff = now - windowMs;

        // 读取历史时间戳
        let timestamps = [];
        try {
            const raw = localStorage.getItem('_rate_limit_timestamps');
            if (raw) {
                timestamps = JSON.parse(raw);
                if (!Array.isArray(timestamps)) timestamps = [];
            }
        } catch (e) {
            timestamps = [];
        }

        // 清除窗口外的时间戳
        timestamps = timestamps.filter(t => t > cutoff);

        // 持久化清理后的数据
        try {
            localStorage.setItem('_rate_limit_timestamps', JSON.stringify(timestamps));
        } catch (e) { /* 存储满时忽略 */ }

        const count = timestamps.length;
        const remaining = Math.max(0, CONFIG.rateLimitMax - count);
        const allowed = count < CONFIG.rateLimitMax;
        const oldest = timestamps.length > 0 ? timestamps[0] : now;
        const resetIn = Math.max(0, Math.ceil((oldest + windowMs - now) / 1000));

        return { allowed, remaining, resetIn };
    }

    /**
     * 记录一次请求尝试
     */
    function recordAttempt() {
        let timestamps = [];
        try {
            const raw = localStorage.getItem('_rate_limit_timestamps');
            if (raw) {
                timestamps = JSON.parse(raw);
                if (!Array.isArray(timestamps)) timestamps = [];
            }
        } catch (e) {
            timestamps = [];
        }

        timestamps.push(Date.now());

        try {
            localStorage.setItem('_rate_limit_timestamps', JSON.stringify(timestamps));
        } catch (e) { /* 存储满时忽略 */ }
    }

    // ============ 哈希操作 ============

    /**
     * 使用 Web Crypto API 计算 SHA-256 哈希，输出小写 hex 字符串
     * 与 Node.js crypto.createHash('sha256').digest('hex') 输出一致
     * @param {string} input
     * @returns {Promise<string>}
     */
    async function sha256Hex(input) {
        const encoder = new TextEncoder();
        const data = encoder.encode(input);
        const hashBuffer = await crypto.subtle.digest('SHA-256', data);
        const hashArray = Array.from(new Uint8Array(hashBuffer));
        return hashArray.map(b => b.toString(16).padStart(2, '0')).join('');
    }

    // ============ 加密操作 ============

    /**
     * 使用 PBKDF2 从学号和手机号派生 AES 密钥
     * @param {string} keyMaterial - 格式: "学号|手机号"
     * @param {Uint8Array} salt - 16字节随机盐值
     * @returns {Promise<CryptoKey>} AES-GCM 解密密钥
     */
    async function deriveKey(keyMaterial, salt) {
        const encoder = new TextEncoder();
        const keyBytes = encoder.encode(keyMaterial);

        // 导入为 PBKDF2 密钥材料
        const pbkdf2Key = await crypto.subtle.importKey(
            'raw',
            keyBytes,
            'PBKDF2',
            false,
            ['deriveBits']
        );

        // 派生密钥位
        const derivedBits = await crypto.subtle.deriveBits(
            {
                name: 'PBKDF2',
                salt: salt,
                iterations: CONFIG.pbkdf2Iterations,
                hash: CONFIG.hashAlgorithm,
            },
            pbkdf2Key,
            CONFIG.keyLengthBits
        );

        // 导入为 AES-GCM 密钥
        const aesKey = await crypto.subtle.importKey(
            'raw',
            derivedBits,
            { name: 'AES-GCM' },
            false,
            ['decrypt']
        );

        return aesKey;
    }

    /**
     * 使用 AES-GCM 解密密码
     * @param {ArrayBuffer} encryptedData - 密文 + 16字节认证标签
     * @param {CryptoKey} key - AES 密钥
     * @param {Uint8Array} iv - 12字节初始化向量
     * @returns {Promise<string|null>} 解密后的密码，失败返回 null
     */
    async function decryptPassword(encryptedData, key, iv) {
        try {
            const decrypted = await crypto.subtle.decrypt(
                {
                    name: 'AES-GCM',
                    iv: iv,
                    tagLength: 128, // 128-bit 认证标签
                },
                key,
                encryptedData
            );
            const decoder = new TextDecoder();
            return decoder.decode(decrypted);
        } catch (e) {
            // AES-GCM 认证失败 = 密钥错误（手机号不对）
            return null;
        }
    }

    // ============ 数据加载 ============

    /**
     * 加载加密的密码数据
     */
    async function loadPasswordData() {
        try {
            // 添加时间戳参数防止浏览器缓存
            const url = `${CONFIG.dataUrl}?t=${Date.now()}`;
            const response = await fetch(url);
            if (!response.ok) {
                throw new Error(`HTTP ${response.status}: ${response.statusText}`);
            }
            const data = await response.json();

            if (!Array.isArray(data)) {
                throw new Error('数据格式错误：期望 JSON 数组');
            }

            if (data.length === 0) {
                throw new Error('数据文件为空');
            }

            // 基本验证每条记录的结构
            for (const entry of data) {
                if (!entry.id || !entry.salt || !entry.iv || !entry.data) {
                    throw new Error(`数据格式错误：记录缺少必要字段 (id=${entry.id || 'unknown'})`);
                }
            }

            passwordData = data;
            isDataLoaded = true;
            loadingHint.classList.add('hidden');
            submitBtn.disabled = false;

            console.log(`✅ 密码数据加载完成，共 ${data.length} 条记录`);
        } catch (e) {
            loadingHint.innerHTML = `
                <div style="color: var(--color-error);">
                    ❌ 数据加载失败<br>
                    <small>${escapeHtml(e.message)}</small>
                </div>
            `;
            console.error('数据加载失败:', e);
        }
    }

    // ============ 查询逻辑 ============

    /**
     * 查询密码
     * @param {string} studentId - 学号
     * @param {string} phoneNumber - 手机号
     */
    async function lookupPassword(studentId, phoneNumber) {
        // 对输入的学号做 SHA-256 哈希后再匹配
        const hashedId = await sha256Hex(studentId);
        const entry = passwordData.find(e => e.id === hashedId);

        if (!entry) {
            showError('未找到该学号，请检查后重试');
            return;
        }

        try {
            // 解码存储的盐值、IV 和加密数据
            const salt = new Uint8Array(base64ToArrayBuffer(entry.salt));
            const iv = new Uint8Array(base64ToArrayBuffer(entry.iv));
            const encryptedBytes = new Uint8Array(base64ToArrayBuffer(entry.data));

            if (salt.length !== 16) {
                throw new Error('盐值长度异常');
            }
            if (iv.length !== 12) {
                throw new Error('IV 长度异常');
            }

            // 构造密钥材料并派生密钥
            const keyMaterial = `${studentId}|${phoneNumber}`;
            const key = await deriveKey(keyMaterial, salt);

            // 尝试解密
            const password = await decryptPassword(encryptedBytes.buffer, key, iv);

            if (password === null) {
                showError('手机号不匹配，请检查后重试');
            } else {
                showPassword(password);
            }
        } catch (e) {
            console.error('解密过程出错:', e);
            showError('数据处理出错，请稍后重试');
        }
    }

    // ============ UI 更新 ============

    /**
     * 显示密码结果
     */
    function showPassword(password) {
        clearAutoClearTimer();

        resultDiv.className = 'result';
        resultDiv.innerHTML = `
            <div class="result-success">
                <div class="result-title">✅ 验证通过，共享密码如下</div>
                <div class="password-display">
                    <span class="password-text" id="passwordText">${escapeHtml(password)}</span>
                    <button class="copy-btn" id="copyBtn" title="复制密码">📋 复制</button>
                </div>
                <div class="result-meta">
                    密码将在 <span id="countdown">${CONFIG.passwordDisplayTimeout}</span> 秒后自动隐藏
                    · <a href="#" id="clearNow" style="color: var(--color-text-secondary);">立即清除</a>
                </div>
            </div>
        `;

        // 绑定复制按钮
        document.getElementById('copyBtn').addEventListener('click', function () {
            copyToClipboard(password, this);
        });

        // 绑定立即清除
        document.getElementById('clearNow').addEventListener('click', function (e) {
            e.preventDefault();
            clearResult();
        });

        // 自动清除倒计时
        startAutoClearTimer(CONFIG.passwordDisplayTimeout);
    }

    /**
     * 显示错误信息
     */
    function showError(message) {
        clearAutoClearTimer();

        resultDiv.className = 'result';
        resultDiv.innerHTML = `
            <div class="result-error">
                <span class="error-icon">⚠️</span>
                <span>${escapeHtml(message)}</span>
            </div>
        `;

        // 3秒后自动清除错误信息
        startAutoClearTimer(3);
    }

    /**
     * 清除结果
     */
    function clearResult() {
        clearAutoClearTimer();
        resultDiv.className = 'result hidden';
        resultDiv.innerHTML = '';
    }

    /**
     * 复制到剪贴板
     */
    async function copyToClipboard(text, btn) {
        try {
            await navigator.clipboard.writeText(text);
            btn.textContent = '✅ 已复制';
            btn.classList.add('copied');

            setTimeout(() => {
                btn.textContent = '📋 复制';
                btn.classList.remove('copied');
            }, 2000);
        } catch (e) {
            // 降级方案：使用传统方法
            try {
                const textarea = document.createElement('textarea');
                textarea.value = text;
                textarea.style.position = 'fixed';
                textarea.style.opacity = '0';
                document.body.appendChild(textarea);
                textarea.select();
                document.execCommand('copy');
                document.body.removeChild(textarea);

                btn.textContent = '✅ 已复制';
                btn.classList.add('copied');
                setTimeout(() => {
                    btn.textContent = '📋 复制';
                    btn.classList.remove('copied');
                }, 2000);
            } catch (fallbackErr) {
                btn.textContent = '❌ 复制失败';
                setTimeout(() => {
                    btn.textContent = '📋 复制';
                }, 2000);
            }
        }
    }

    /**
     * 启动自动清除计时器
     */
    function startAutoClearTimer(seconds) {
        clearAutoClearTimer();

        if (seconds <= 0) return;

        const countdownEl = document.getElementById('countdown');
        let remaining = seconds;

        const updateCountdown = () => {
            if (countdownEl) {
                countdownEl.textContent = remaining;
            }
        };

        clearTimer = setInterval(() => {
            remaining--;
            if (remaining <= 0) {
                clearResult();
            } else {
                updateCountdown();
            }
        }, 1000);
    }

    /**
     * 清除计时器
     */
    function clearAutoClearTimer() {
        if (clearTimer) {
            clearInterval(clearTimer);
            clearTimer = null;
        }
    }

    /**
     * HTML 转义
     */
    function escapeHtml(str) {
        const div = document.createElement('div');
        div.textContent = str;
        return div.innerHTML;
    }

    /**
     * 设置加载状态
     */
    function setLoading(loading) {
        isLoading = loading;
        if (loading) {
            submitBtn.disabled = true;
            btnText.classList.add('hidden');
            btnSpinner.classList.remove('hidden');
        } else {
            submitBtn.disabled = false;
            btnText.classList.remove('hidden');
            btnSpinner.classList.add('hidden');
        }
    }

    // ============ 事件处理 ============

    /**
     * 表单提交
     */
    form.addEventListener('submit', async function (e) {
        e.preventDefault();

        if (isLoading || !isDataLoaded) return;

        // 速率限制检查
        const rateLimit = checkRateLimit();
        if (!rateLimit.allowed) {
            showError(
                `请求过于频繁，请 ${rateLimit.resetIn} 秒后再试。` +
                `（每分钟最多 ${CONFIG.rateLimitMax} 次）`
            );
            return;
        }

        const studentId = studentIdInput.value.trim();
        const phoneNumber = phoneNumberInput.value.trim();

        // 基本校验
        if (!studentId) {
            showError('请输入学号');
            studentIdInput.focus();
            return;
        }
        if (!phoneNumber) {
            showError('请输入手机号');
            phoneNumberInput.focus();
            return;
        }
        if (!/^\d+$/.test(studentId)) {
            showError('学号格式不正确（仅包含数字）');
            studentIdInput.focus();
            return;
        }
        if (!/^\d{11}$/.test(phoneNumber)) {
            showError('手机号格式不正确（11位数字）');
            phoneNumberInput.focus();
            return;
        }

        // 记录本次尝试
        recordAttempt();

        // 清除之前的结果
        clearResult();

        // 开始查询
        setLoading(true);

        try {
            // 使用 setTimeout 让 UI 有时间更新（显示加载动画）
            await new Promise(resolve => setTimeout(resolve, 50));
            await lookupPassword(studentId, phoneNumber);
        } catch (e) {
            console.error('查询出错:', e);
            showError('查询过程出错，请稍后重试');
        } finally {
            setLoading(false);
        }
    });

    /**
     * 输入框实时校验
     */
    phoneNumberInput.addEventListener('input', function () {
        // 限制只能输入数字
        this.value = this.value.replace(/\D/g, '');
    });

    studentIdInput.addEventListener('input', function () {
        // 限制只能输入数字和字母
        this.value = this.value.replace(/[^\w]/g, '');
    });

    // ============ 初始化 ============

    function init() {
        // 页面加载时即开始加载数据
        loadPasswordData();
    }

    // 页面就绪后初始化
    if (document.readyState === 'loading') {
        document.addEventListener('DOMContentLoaded', init);
    } else {
        init();
    }
})();
