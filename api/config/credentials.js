// process 是 Node.js 提供的全局对象，包含当前进程的信息和控制方法
// 读取 .env 文件中的环境变量，加载至 process.env
require('dotenv').config();

const { bootstrapCredentials } = require('@librechat/api/credentials');

module.exports = bootstrapCredentials();
