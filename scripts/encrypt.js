/**
 * 密码数据加密脚本 — 共享密码 + 白名单模式
 *
 * 用法:
 *   node scripts/encrypt.js --password "共享密码" [csv文件路径]
 *   node scripts/encrypt.js -p "共享密码" [csv文件路径]
 *
 * 功能：
 *   1. 读取访问控制 CSV（格式: 学号,手机号）
 *   2. 对每一条记录，用 (学号+手机号) 派生的独立密钥加密同一个共享密码
 *   3. 输出 data/passwords.json（可安全提交到 Git）
 *
 * 安全设计：
 *   - 每条记录使用独立的随机 salt 和 IV
 *   - 密钥 = PBKDF2(学号+"|"+手机号, salt, 100000次, SHA-256)
 *   - 只有名单内的人输入正确的学号+手机号才能解密得到共享密码
 *   - 即使下载了完整数据文件，不知道学号+手机号也无法解密
 *
 * 注意：
 *   - 需要 Node.js 16+
 *   - CSV 使用 UTF-8 编码，第一行为标题行会被跳过
 *   - 不要将原始 CSV 提交到 Git（已在 .gitignore 中）
 */

const fs = require('fs');
const path = require('path');
const crypto = require('crypto');

// ============ 配置 ============
const DEFAULT_CSV_PATH = path.join(__dirname, '..', 'data.csv');
const OUTPUT_PATH = path.join(__dirname, '..', 'data', 'passwords.json');
const PBKDF2_ITERATIONS = 100000;
const KEY_LENGTH = 32;      // 256 bits
const SALT_LENGTH = 16;     // 128 bits
const IV_LENGTH = 12;       // 96 bits (GCM 推荐)

// ============ 工具函数 ============

/**
 * 计算 SHA-256 哈希，输出小写 hex 字符串
 * 与 Web Crypto API crypto.subtle.digest('SHA-256', ...) 输出一致
 */
function sha256Hex(input) {
    return crypto.createHash('sha256').update(input, 'utf8').digest('hex');
}

// ============ 管理员配置 ============
const ADMIN_CONFIG_PATH = path.join(__dirname, 'admin-config.json');

function loadAdminConfig() {
    if (!fs.existsSync(ADMIN_CONFIG_PATH)) {
        console.error('\n❌ 错误: 找不到管理员配置文件');
        console.log(`\n💡 请创建 ${ADMIN_CONFIG_PATH}，格式参考 admin-config.example.json:`);
        console.log('   {');
        console.log('     "studentId": "管理员学号",');
        console.log('     "phone": "管理员手机号"');
        console.log('   }');
        process.exit(1);
    }

    try {
        const raw = fs.readFileSync(ADMIN_CONFIG_PATH, 'utf8');
        const config = JSON.parse(raw);

        if (!config.studentId || !config.phone) {
            console.error('\n❌ 错误: 管理员配置文件缺少 studentId 或 phone 字段');
            process.exit(1);
        }

        return config;
    } catch (e) {
        console.error(`\n❌ 错误: 管理员配置文件解析失败 — ${e.message}`);
        process.exit(1);
    }
}

// ============ 参数解析 ============

function parseArgs() {
    const args = process.argv.slice(2);
    let password = null;
    let csvPath = DEFAULT_CSV_PATH;

    for (let i = 0; i < args.length; i++) {
        if (args[i] === '--password' || args[i] === '-p') {
            password = args[i + 1];
            i++;
        } else if (!args[i].startsWith('-')) {
            csvPath = args[i];
        }
    }

    return { password, csvPath };
}

// ============ 主逻辑 ============

function main() {
    const { password, csvPath } = parseArgs();
    const admin = loadAdminConfig();

    console.log('🔐 密码数据加密工具（白名单模式）\n');
    console.log(`📄 CSV 白名单: ${csvPath}`);
    console.log(`📤 输出文件:   ${OUTPUT_PATH}`);

    // 参数校验
    if (!password) {
        console.error('\n❌ 错误: 请使用 --password 指定共享密码');
        console.log('\n💡 用法:');
        console.log('   node scripts/encrypt.js --password "你的共享密码"');
        console.log('   node scripts/encrypt.js -p "你的共享密码" /path/to/data.csv');
        console.log('\n💡 示例:');
        console.log('   node scripts/encrypt.js -p "MySecret2024"');
        process.exit(1);
    }

    if (password.length < 4) {
        console.error('\n❌ 错误: 密码长度至少为 4 个字符');
        process.exit(1);
    }

    console.log(`🔑 共享密码:   ${'*'.repeat(password.length)} (${password.length} 字符)`);

    // 检查 CSV
    if (!fs.existsSync(csvPath)) {
        console.error(`\n❌ 错误: 找不到 CSV 文件 "${csvPath}"`);
        console.log('\n💡 CSV 格式（每行一条记录，不含密码列）:');
        console.log('   学号,手机号');
        console.log('   2024001,13800138000');
        console.log('   2024002,13900139000');
        process.exit(1);
    }

    // 读取 CSV
    const csvContent = fs.readFileSync(csvPath, 'utf8').trim();
    if (!csvContent) {
        console.error('\n❌ 错误: CSV 文件为空');
        process.exit(1);
    }

    const lines = csvContent.split('\n')
        .map(line => line.trim())
        .filter(line => line && !line.startsWith('#'));

    if (lines.length < 2) {
        console.error('\n❌ 错误: CSV 至少需要标题行 + 1 条数据');
        process.exit(1);
    }

    const header = lines[0];
    const dataLines = lines.slice(1);

    console.log(`\n📊 标题: ${header}`);
    console.log(`📊 白名单人数: ${dataLines.length}\n`);

    // 处理每条记录
    let results = [];
    const seenIds = new Set();
    let successCount = 0;
    let errorCount = 0;

    for (let i = 0; i < dataLines.length; i++) {
        const line = dataLines[i];
        const lineNum = i + 2; // CSV 行号（1-based + 标题行）

        const parts = line.split(',').map(s => s.trim());

        if (parts.length < 2) {
            console.error(`⚠️  第 ${lineNum} 行: 格式错误（需要 学号,手机号），跳过`);
            errorCount++;
            continue;
        }

        const [studentId, phoneNumber] = parts;

        // 校验
        if (!studentId) {
            console.error(`⚠️  第 ${lineNum} 行: 学号为空，跳过`);
            errorCount++;
            continue;
        }
        if (!phoneNumber || !/^\d+$/.test(phoneNumber)) {
            console.error(`⚠️  第 ${lineNum} 行: 手机号格式不正确 (${phoneNumber || '空'})，跳过`);
            errorCount++;
            continue;
        }
        if (seenIds.has(studentId)) {
            console.error(`⚠️  第 ${lineNum} 行: 学号 "${studentId}" 重复，跳过`);
            errorCount++;
            continue;
        }
        seenIds.add(studentId);

        try {
            const encrypted = encryptRecord(studentId, phoneNumber, password);
            results.push(encrypted);
            successCount++;
            console.log(`✅ 第 ${lineNum} 行: ${studentId}`);
        } catch (e) {
            console.error(`❌ 第 ${lineNum} 行: 加密失败 — ${e.message}`);
            errorCount++;
        }
    }

    // 确保管理员记录始终存在（管理员优先，CSV 中重复则跳过）
    const adminHash = sha256Hex(admin.studentId);
    const beforeDedup = results.length;
    results = results.filter(r => {
        if (r.id === adminHash) {
            console.warn(`⚠️  管理员学号已在 CSV 中，自动跳过 (${admin.studentId})`);
            return false;
        }
        return true;
    });
    results.push(encryptRecord(admin.studentId, admin.phone, password));
    if (results.length === beforeDedup + 1) {
        console.log(`🔧 已添加管理员记录 (${admin.studentId})`);
    }

    // 汇总
    console.log(`\n${'═'.repeat(45)}`);
    console.log(`📊 总计 ${dataLines.length} 条 | ✅ 成功 ${successCount} | ❌ 失败 ${errorCount}`);

    if (successCount === 0) {
        console.error('\n❌ 没有成功加密任何记录，已退出');
        process.exit(1);
    }

    // 写入
    const outDir = path.dirname(OUTPUT_PATH);
    if (!fs.existsSync(outDir)) {
        fs.mkdirSync(outDir, { recursive: true });
    }

    fs.writeFileSync(OUTPUT_PATH, JSON.stringify(results, null, 2), 'utf8');
    const fileSizeKB = (fs.statSync(OUTPUT_PATH).size / 1024).toFixed(1);
    console.log(`\n✅ 已写入: ${OUTPUT_PATH} (${fileSizeKB} KB)`);

    // 提醒
    console.log('\n⚠️  提交前请确认:');
    console.log('   1. data.csv（白名单明文）已在 .gitignore 中 ➜ 不会被提交');
    console.log('   2. passwords.json（加密数据）可以安全提交到 Git');
    console.log('   3. 共享密码请通过私密渠道告知所有授权用户');
}

// ============ 加密函数 ============

/**
 * 加密一条白名单记录
 * @param {string} studentId - 学号
 * @param {string} phoneNumber - 手机号
 * @param {string} sharedPassword - 共享密码（所有人相同）
 * @returns {{ id: string, salt: string, iv: string, data: string }}
 */
function encryptRecord(studentId, phoneNumber, sharedPassword) {
    // 1. 随机盐值
    const salt = crypto.randomBytes(SALT_LENGTH);

    // 2. 从 (学号 + 手机号) 派生 256 位密钥
    const keyMaterial = `${studentId}|${phoneNumber}`;
    const key = crypto.pbkdf2Sync(
        keyMaterial,
        salt,
        PBKDF2_ITERATIONS,
        KEY_LENGTH,
        'sha256'
    );

    // 3. 随机 IV
    const iv = crypto.randomBytes(IV_LENGTH);

    // 4. AES-256-GCM 加密共享密码
    const cipher = crypto.createCipheriv('aes-256-gcm', key, iv);
    const encrypted = Buffer.concat([
        cipher.update(sharedPassword, 'utf8'),
        cipher.final(),
    ]);
    const authTag = cipher.getAuthTag();          // 16 字节
    const combined = Buffer.concat([encrypted, authTag]);

    // 5. Base64 编码
    return {
        id: sha256Hex(studentId),
        salt: salt.toString('base64'),
        iv: iv.toString('base64'),
        data: combined.toString('base64'),
    };
}

// ============ 启动 ============
main();
