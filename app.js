const crypto = require('crypto');
const axios = require('axios');
const uuid = require('uuid');

const RAA_APP_ID = ''; //接口调用唯一凭证
const RAA_BIZ_ID = ''; //业务权限标识
const RAA_SECRET_KEY = ''; //接口签名

const TEST_CODE_1 = 'pn7WMb'; //测试码  testcase01 - 实名认证接口
const TEST_CODE_2 = 'dxou8P'; //测试码  testcase02 - 实名认证接口
const TEST_CODE_3 = 'MXDvjT'; //测试码  testcase03 - 实名认证接口
const TEST_CODE_4 = '3VDVaw'; //测试码  testcase04 - 实名认证结果查询接口
const TEST_CODE_5 = 'h9748e'; //测试码  testcase05 - 实名认证结果查询接口
const TEST_CODE_6 = '32dhz4'; //测试码  testcase06 - 实名认证结果查询接口
const TEST_CODE_7 = 'tWh5Bv'; //测试码  testcase07 - 游戏用户行为数据上报接口
const TEST_CODE_8 = 'bdjgnw'; //测试码  testcase08 - 游戏用户行为数据上报接口

const RAA_CHECK_URL = 'https://wlc.nppa.gov.cn/test/authentication/check/'; //实名认证接口
const RAA_QUERY_URL = 'https://wlc.nppa.gov.cn/test/authentication/query/'; //实名认证结果查询接口
const RAA_LOGINOUT_URL = 'https://wlc.nppa.gov.cn/test/collection/loginout/'; //游戏用户行为数据上报接口

/**
 * 实名认证接口
 * @param {*} ai 游戏内部成员标识
 * @param {*} name 用户姓名
 * @param {*} idNum 用户身份证号码
 * @param {*} test_code 测试码
 */
async function check(ai, name, idNum, test_code) {

    let body_params = {
        ai: ai,
        name: name,
        idNum: idNum
    };

    let body = getBody(body_params);
    let sign = getSign(body);
    let headers = getHeaders(sign);

    let url = `${RAA_CHECK_URL}${test_code}`;
    console.log(`[testcase] 请求URL:${url}`);

    let ret_data = await axios.post(url, body, { headers: headers });

    return ret_data.data;
}

/**
 * 实名认证结果查询接口
 * @param {*} ai 游戏内部成员标识
 * @param {*} test_code 测试码
 */
async function query(ai, test_code) {

    let body_params = {
        ai: ai
    };

    let body = getBody(body_params);
    let sign = getSign(body, body_params);
    let headers = getHeaders(sign);

    let url = `${RAA_QUERY_URL}${test_code}?ai=${ai}`;
    console.log(`[testcase] 请求URL:${url}`);

    let ret_data = await axios.get(url, { headers: headers });

    return ret_data.data;
}

/**
 * 游戏用户行为数据上报接口
 * @param {*} pi 用户唯一标识
 * @param {*} si 游戏内部会话标识
 * @param {*} bt 用户行类型
 * @param {*} ct 上报类型
 * @param {*} di 设备标识
 * @param {*} test_code 测试码 
 */
async function loginout(pi, si, bt, ct, di, test_code) {

    let body_params = {
        collections: [{
            no: 1,
            si: si,
            bt: bt,
            ot: getCurTimestamp(),
            ct: ct,
            di: di,
            pi: pi
        }]
    };

    let body = getBody(body_params);
    let sign = getSign(body);
    let headers = getHeaders(sign);

    let url = `${RAA_LOGINOUT_URL}${test_code}`;
    console.log(`[testcase] 请求URL:${url}`);

    let ret_data = await axios.post(url, body, { headers: headers });

    return ret_data.data;
}

/**
 * 得到报文消息体
 * @param {*} body_params 业务参数
 * @returns 报文消息体
 */
function getBody(body_params) {

    console.log(`[明文] 报文消息体（Body）:${JSON.stringify(body_params)} \n`);

    let body_data = aes_gcm_encrypt(JSON.stringify(body_params), RAA_SECRET_KEY);
    console.log(`[调试] 解密 body_paras: ${aes_ecb_decrypt(body_data, RAA_SECRET_KEY)}`);

    let body = {
        "data": body_data
    }

    console.log(`[密文] 报文消息体: ${JSON.stringify(body)} \n`);

    return body;
}

/**
 * 得到签名
 * @param {*} body 报文消息体
 * @param {*} query_data get参数
 * @returns 签名
 */
function getSign(body, query_data = null) {
    let data = getHeaders();

    let arr = [];
    for (let key in data) {
        arr.push({
            key: key,
            value: data[key]
        });
    }

    if (query_data) {
        for (let key in query_data) {
            arr.push({
                key: key,
                value: query_data[key]
            });
        }
    }

    arr.sort(function(item_1, item_2) {
        return (item_1.key + '') > (item_2.key + '');
    });

    let sign_str = RAA_SECRET_KEY;

    for (let i = 0; i < arr.length; i++) {
        if (arr[i].key != 'sign' && arr[i].key != 'Content-Type') {
            sign_str += `${arr[i].key}${arr[i].value}`;
        }
    }

    if (!query_data) {
        sign_str += JSON.stringify(body);
    }

    console.log(`[明文] sign：${sign_str} \n`);

    let sign = crypto.createHash('sha256').update(sign_str).digest('hex');

    console.log(`[密文] sign：${sign} \n`);

    return sign;
}

/**
 * 得到请求headers
 * @param {*} sign 签名
 * @returns headers
 */
function getHeaders(sign = null) {
    let headers = {
        'Content-Type': 'application/json; charset=utf-8',
        'appId': RAA_APP_ID,
        "bizId": RAA_BIZ_ID,
        "timestamps": new Date().getTime(),
        "sign": sign
    };

    if (sign) {
        console.log(`[密文] 报文消息头（Headers）: ${JSON.stringify(headers)} \n`);
    }

    return headers;
}

/**
 * 加密
 * @param {*} plaintext 明文
 * @param {*} key 密钥
 * @returns 密文
 */
function aes_gcm_encrypt(plaintext, key) {
    try {
        let key_bytes = Buffer.from(key, 'hex');
        let iv = crypto.randomBytes(12);
        let cipher_iv = crypto.createCipheriv('aes-128-gcm', key_bytes, iv);

        let ciphertext = cipher_iv.update(plaintext, 'utf8', 'base64')
        ciphertext += cipher_iv.final('base64');
        ciphertext = Buffer.from(ciphertext, 'base64');

        let tags = cipher_iv.getAuthTag();

        //对应JAVA AES/GCM/PKCS5Padding模式
        let total_length = iv.length + ciphertext.length + tags.length;
        let buf_msg = Buffer.concat([iv, ciphertext, tags], total_length);

        return buf_msg.toString('base64');
    } catch (ex) {
        console.log(`[aes_gcm_encrypt] error=${ex.message}`);
        return null;
    }
}

/**
 * 解密
 * @param {*} ciphertext 密文
 * @param {*} key 密钥
 * @returns 明文
 */
function aes_ecb_decrypt(ciphertext, key) {

    try {
        var ciphertext_bytes = Buffer.from(ciphertext, 'base64');
        let key_bytes = Buffer.from(key, 'hex');

        var iv = ciphertext_bytes.slice(0, 12);
        var cipher_iv = crypto.createDecipheriv('aes-128-gcm', key_bytes, iv);

        //去除头iv12位 去除尾tags16位
        var buf_msg = cipher_iv.update(ciphertext_bytes.slice(12, ciphertext_bytes.length - 16));

        return buf_msg.toString('utf8');

    } catch (e) {
        console.log(`[aes_ecb_decrypt] error=${ex.message}`);
        return null;
    }
}

/**
 * 得到当前时间戳（秒）
 * @returns 当前时间秒数
 */
function getCurTimestamp() {
    return parseInt(Date.parse(new Date()) / 1000);
};


const test_case = async() => {
    console.log(`=================================实名认证接口[BEGIN]=================================`);

    // 测试数据
    // 认证成功 {"ai":"100000000000000001", "name":"某一一", "idNum":"110000190101010001"}
    // 认证中 {"ai":"200000000000000001", "name":"某二一", "idNum":"110000190201010009"}
    // 认证失败 所有非“认证成功”或“认证中”预置的数据

    let test_case_1_result = await check("100000000000000001", "某一一", "110000190101010001", TEST_CODE_1);
    console.log(`[testcase] 01-实名认证接口：${JSON.stringify(test_case_1_result)}`);
    console.log(`------------------------------------------------------------------------------------`);

    let test_case_2_result = await check("200000000000000001", "某二一", "110000190201010009", TEST_CODE_2);
    console.log(`[testcase] 02-实名认证接口：${JSON.stringify(test_case_2_result)}`);
    console.log(`------------------------------------------------------------------------------------`);

    let test_case_3_result = await check("200000000000000015", "某二一", "110000190201010009", TEST_CODE_3);
    console.log(`[testcase] 03-实名认证接口：${JSON.stringify(test_case_3_result)}`);

    console.log(`=================================实名认证接口[END]===================================\n\n`);

    console.log(`=================================实名认证结果查询接口[BEGIN]==========================`);

    // 测试数据
    // 认证成功 {"ai":"100000000000000001"}
    // 认证中 {"ai":"200000000000000001"}
    // 认证失败 {"ai":"300000000000000001"}

    let test_case_4_result = await query("100000000000000001", TEST_CODE_4);
    console.log(`[testcase] 04-实名认证结果查询接口：${JSON.stringify(test_case_4_result)}`);
    console.log(`------------------------------------------------------------------------------------`);

    let test_case_5_result = await query("200000000000000001", TEST_CODE_5);
    console.log(`[testcase] 05-实名认证结果查询接口：${JSON.stringify(test_case_5_result)}`);
    console.log(`------------------------------------------------------------------------------------`);

    let test_case_6_result = await query("300000000000000001", TEST_CODE_6);
    console.log(`[testcase] 06-实名认证结果查询接口：${JSON.stringify(test_case_6_result)}`);
    console.log(`------------------------------------------------------------------------------------`);

    console.log(`=================================实名认证结果查询接口[END]============================\n\n`);

    console.log(`=================================游戏用户行为数据上报接口[BEGIN]=======================`);

    //测试数据
    // {"pi":"1fffbjzos82bs9cnyj1dna7d6d29zg4esnh99u"}

    let pi = "1fffbjzos82bs9cnyj1dna7d6d29zg4esnh99u";
    let si = uuid.v4().toUpperCase().replace(/-/g, '');
    let bt = 0; // 0:下线 1:上线
    let ct = 2; // 0:已认证通过用户 2：游客用户
    let di = uuid.v4().toUpperCase().replace(/-/g, '');

    let test_case_7_result = await loginout(pi, si, bt, ct, di, TEST_CODE_7);
    console.log(`[testcase] 07-游戏用户行为数据上报接口：${JSON.stringify(test_case_7_result)}`);
    console.log(`------------------------------------------------------------------------------------`);

    ct = 0;

    let test_case_8_result = await loginout(pi, si, bt, ct, di, TEST_CODE_8);
    console.log(`[testcase] 08-游戏用户行为数据上报接口：${JSON.stringify(test_case_8_result)}`);
    console.log(`------------------------------------------------------------------------------------`);

    console.log(`=================================游戏用户行为数据上报接口[END]=========================\n\n`);
}

test_case();