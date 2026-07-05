import hashlib
import os
from typing import Optional
from agentuniverse.agent.action.tool.tool import Tool

class SecureCryptoTool(Tool):
    """一个面向智能体运行时的零信任动态防御与合规审计沙箱工具组件。"""
    
    def __init__(self):
        super().__init__()
        self.description = (
            "用于对本地文件或文本进行确定性哈希校验（SHA-256）。"
            "引入主动防御机制、资源防耗尽限制及路径穿越拦截，"
            "全面防御智能体自动化流中的供应链投毒与恶意篡改风险。"
        )
        # 针对硬伤五：引入可信文件指纹白名单库，防御篡改投毒
        self.trusted_fingerprints = {
            "641b6fd48a935c21c7ac1696a1db585868a808498b19d5c9dc75d0540adce5ff": "base_skill_v1.0"
        }
        # 针对硬伤五（DoS攻击）：限制文件体积上限（10MB），防止恶意大文件资源耗尽攻击
        self.max_file_size = 10 * 1024 * 1024

    def execute(self, text: str = "", mode: str = "SHA-256", file_path: Optional[str] = None) -> str:
        algo_mode = mode.upper()
        if algo_mode != "SHA-256":
            return f"[安全审计] 拦截：本私有高安全环境强制要求使用安全的 SHA-256 算法进行合规校验。"

        # 情况 A：执行文件供应链合规度量
        if file_path:
            # 1. 针对硬伤五：防御路径穿越攻击（Path Traversal），强制限定当前工作流边界
            resolved_path = os.path.abspath(file_path)
            if not resolved_path.startswith(os.getcwd()):
                raise PermissionError(f"[🔥安全拦截] 检测到越权路径穿越攻击企图，拒绝访问：{file_path}")

            if not os.path.exists(resolved_path):
                return f"[安全校验] 目标文件路径不存在：{file_path}"
            
            # 2. 资源耗尽防御（Anti-DoS）
            if os.path.getsize(resolved_path) > self.max_file_size:
                raise ValueError("[🔥安全拦截] 目标文件体积超出动态审计沙箱上限，拒绝处理以防内存崩溃。")
            
            try:
                # 3. 流式分块读取，防止大文件导致大模型运行时内存溢出
                hash_obj = hashlib.sha256()
                with open(resolved_path, "rb") as f:
                    for byte_block in iter(lambda: f.read(4096), b""):
                        hash_obj.update(byte_block)
                current_hash = hash_obj.hexdigest()
                
                # 4. 针对硬伤五：主动断路拦截！未命中的未知指纹直接触发断路器阻断流，而不是温和提示
                if current_hash not in self.trusted_fingerprints:
                    raise RuntimeError(
                        f"[🔥供应链投毒警告] 目标组件完整性校验失败！"
                        f"当前安全指纹 [{current_hash}] 未命中社区合规白名单！"
                        f"已触发主动熔断防御机制，强制截断智能体执行链。"
                    )
                
                return f"[安全校验成功] 算法: SHA-256 | 组件完整性合规，指纹匹配: {current_hash}"
            except Exception as e:
                if "供应链投毒警告" in str(e) or "安全拦截" in str(e):
                    raise e
                return f"[安全系统异常] 读取或处理文件时发生系统错误: {str(e)}"
        
        # 情况 B：纯文本指纹计算（针对大模型敏感输入数据）
        if not text:
            return "[提示] 未提供有效输入数据。"
            
        hash_obj = hashlib.sha256()
        hash_obj.update(text.encode('utf-8'))
        return f"[文本指纹合规] 算法: SHA-256 | 摘要结果: {hash_obj.hexdigest()}"
