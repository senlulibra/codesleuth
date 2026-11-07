import os
import re
import argparse
from datetime import datetime

# ===================== 漏洞规则库 =====================
RULES = [
    # 高危
    {
        "pattern": r'unserialize\s*\(',
        "desc": "PHP反序列化漏洞入口，CTF高频",
        "level": "高危"
    },
    {
        "pattern": r'(include|require|include_once|require_once)\s*\(\s*[$]',
        "desc": "文件包含，参数可控",
        "level": "高危"
    },
    {
        "pattern": r'file_get_contents\s*\(\s*[$]',
        "desc": "file_get_contents传入变量，可利用伪协议",
        "level": "高危"
    },
    {
        "pattern": r'(system|exec|passthru|popen|proc_open|shell_exec)\s*\(\s*[$]',
        "desc": "命令执行函数，参数可控",
        "level": "高危"
    },
    {
        "pattern": r'(eval|assert|create_function)\s*\(\s*[$]',
        "desc": "动态代码执行，风险极高",
        "level": "高危"
    },
    {
        "pattern": r'(fopen|fwrite|file_put_contents)\s*\(\s*[$]',
        "desc": "文件操作写入，可能造成任意文件写入",
        "level": "高危"
    },
    # 中危
    {
        "pattern": r'\$_GET\[[^\]]+\]',
        "desc": "GET可控参数",
        "level": "中危"
    },
    {
        "pattern": r'\$_POST\[[^\]]+\]',
        "desc": "POST可控参数",
        "level": "中危"
    },
    {
        "pattern": r'\$_REQUEST\[[^\]]+\]',
        "desc": "REQUEST可控参数",
        "level": "中危"
    },
    {
        "pattern": r'(mysql_query|mysqli_query)\s*\(\s*[$]',
        "desc": "SQL查询传入变量，存在SQL注入风险",
        "level": "中危"
    },
    {
        "pattern": r'preg_match\s*\(',
        "desc": "正则校验，存在绕过可能性",
        "level": "中危"
    },
    {
        "pattern": r'echo\s*[$]',
        "desc": "直接输出变量，存在XSS风险",
        "level": "中危"
    },
    # 低危
    {
        "pattern": r'highlight_file\s*\(|show_source\s*\(',
        "desc": "源码泄露函数",
        "level": "低危"
    },
    {
        "pattern": r'var_dump\s*\(|print_r\s*\(',
        "desc": "调试打印，信息泄露风险",
        "level": "低危"
    },
]


def clean_html(raw_text: str) -> str:
    """清洗HTML标签与html实体，适配highlight_file导出页面"""
    text = re.sub(r'<.*?>', '', raw_text)
    text = text.replace("&nbsp;", " ")
    text = text.replace("&amp;", "&")
    text = text.replace("&lt;", "<")
    text = text.replace("&gt;", ">")
    return text

def remove_comment(line: str) -> str:
    """剔除单行注释 // 之后内容，避免注释误报"""
    line = re.sub(r'//.*$', '', line)
    line = re.sub(r'#.*$', '', line)
    return line

def scan_file(file_path: str):
    result_list = []
    try:
        with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
            lines = f.readlines()
    except Exception as e:
        return [{"error": f"读取失败：{str(e)}"}]

    for lineno, raw_line in enumerate(lines, start=1):
        clean_line = clean_html(raw_line)
        check_line = remove_comment(clean_line)
        for rule in RULES:
            pat = rule["pattern"]
            desc = rule["desc"]
            level = rule["level"]
            if re.search(pat, check_line, re.IGNORECASE):
                exist = any(
                    item["line"] == lineno and item["desc"] == desc
                    for item in result_list
                )
                if not exist:
                    result_list.append({
                        "line": lineno,
                        "level": level,
                        "desc": desc,
                        "code": clean_line.strip()
                    })
    return result_list

def save_md_report(all_results, report_path="scan_report.md"):
    """导出Markdown报告（保持原样不变）"""
    now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    total_risk = 0
    stat = {"高危":0, "中危":0, "低危":0}
    for _, risk_items in all_results.items():
        for r in risk_items:
            if "error" not in r:
                stat[r["level"]] +=1
                total_risk +=1

    md = f"""# 源码审计扫描报告
> 扫描时间：{now}
> 扫描文件总数：{len(all_results)}
> 风险汇总：高危 {stat['高危']} | 中危 {stat['中危']} | 低危 {stat['低危']}
> 风险条目总计：{total_risk}

> ⚠️ 说明：本工具为特征匹配轻量审计工具，**仅为风险告警，不代表一定可以利用，需要人工复核数据流、过滤逻辑**

---
"""
    for filename, risk_list in all_results.items():
        md += f"## 📄 {filename}\n"
        if len(risk_list) == 0:
            md += "> ✅ 未发现风险\n\n"
            continue
        md += "| 行号 | 风险等级 | 风险描述 | 代码片段 |\n"
        md += "| ---- | -------- | -------- | -------- |\n"
        for item in risk_list:
            if "error" in item:
                md += f"| - | ❌ 读取异常 | {item['error']} | - |\n"
            else:
                snippet = item["code"].replace("|", "\\|")
                md += f"| {item['line']} | {item['level']} | {item['desc']} | {snippet} |\n"
        md += "\n"
    with open(report_path, "w", encoding="utf-8") as f:
        f.write(md)
    print(f"\n📋 Markdown报告已保存至：{report_path}")

def main():
    parser = argparse.ArgumentParser(description="轻量PHP源码审计工具｜控制台分组打印版，MD完整保留")
    parser.add_argument("-p", "--path", required=True, help="扫描单个文件或者文件夹路径")
    args = parser.parse_args()
    target = args.path
    all_scan_result = {}

    def print_group(items):
        # 按desc分组
        group = {}
        for it in items:
            if "error" in it:
                print(f"[ERROR] {it['error']}")
                continue
            key = it["desc"]
            if key not in group:
                group[key] = {"level": it["level"], "lines": []}
            group[key]["lines"].append((it["line"], it["code"]))
        # 分组输出
        for desc, info in group.items():
            print(f"[{info['level']}] {desc}")
            for ln, code in info["lines"]:
                print(f"  L{ln}: {code}")
            print()  # 重点！这一句就是每组漏洞后面打空一行

    if os.path.isdir(target):
        for root, _, files in os.walk(target):
            for fname in files:
                suffix = (".php", ".htm", ".html", ".txt")
                if fname.lower().endswith(suffix):
                    fullpath = os.path.join(root, fname)
                    res = scan_file(fullpath)
                    all_scan_result[fullpath] = res
                    if res:
                        print(f"\n==== 文件：{fullpath} ====")
                        print_group(res)
    else:
        res = scan_file(target)
        all_scan_result[target] = res
        print(f"\n==== 文件：{target} ====")
        print_group(res)

    save_md_report(all_scan_result)
    total = sum(len(v) for v in all_scan_result.values())
    print(f"\n[*] 扫描完成！一共找到 {total} 条风险特征️\n说明：本工具为特征匹配轻量审计工具，仅为风险告警，不代表一定可以利用，需要人工复核数据流、过滤逻辑")

if __name__ == "__main__":
    main()
