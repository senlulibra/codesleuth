# codesleuth(PHP Static Code Audit Script)
一款面向CTF场景的PHP静态代码审计工具，支持清洗网页高亮污染的源码，基于正则特征识别文件包含、反序列化、命令执行等高危漏洞，控制台分组展示漏洞信息，支持导出Markdown审计报告。

> ⚠️ 免责声明：本工具仅用于个人学习、CTF授权靶场审计，严禁在未获得授权的系统上使用，违规使用后果自行承担。

## Demo说明
- `test.htm`：模拟CTF网页高亮后的污染源码，带有HTML标签与样式代码，用来测试脚本的HTML清洗、过滤干扰并识别漏洞的能力。

## 使用示例
```bash

python/py codesleuth.py -p test.htm
