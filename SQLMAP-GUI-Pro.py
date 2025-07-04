import tkinter as tk
from tkinter import ttk, messagebox
import os
import csv
from tkinter import filedialog, messagebox
import subprocess
import threading
import pandas as pd
import os
import shutil
from tkinter import scrolledtext
import socket
import select
import re
from http.server import HTTPServer, BaseHTTPRequestHandler
from http.client import HTTPResponse
from io import BytesIO
import time
from urllib.parse import urlparse, parse_qs

class ProxyRequestHandler(BaseHTTPRequestHandler):
    """代理请求处理器"""
    def __init__(self, *args, parent=None, **kwargs):
        self.parent = parent
        super().__init__(*args, **kwargs)

    def do_METHOD(self):
        """处理所有HTTP方法"""
        try:
            # 解析目标URL
            url = self.path
            if not url.startswith('http'):
                url = f'http://{self.headers.get("Host", "")}{url}'

            # 构建请求数据
            packet = {
                'time': time.strftime('%Y-%m-%d %H:%M:%S'),
                'method': self.command,
                'url': url,
                'headers': dict(self.headers),
                'raw': f'{self.command} {self.path} HTTP/1.1\r\n'
            }

            # 添加请求头
            for header, value in self.headers.items():
                packet['raw'] += f'{header}: {value}\r\n'

            # 读取请求体
            content_length = int(self.headers.get('Content-Length', 0))
            body = self.rfile.read(content_length) if content_length > 0 else b''
            packet['body'] = body.decode('utf-8', errors='ignore')
            packet['raw'] += f'\r\n{packet["body"]}'

            # 转发请求到目标服务器
            parsed_url = urlparse(url)
            conn = socket.create_connection((parsed_url.hostname, parsed_url.port or 80))
            conn.sendall(self._build_forward_request(parsed_url, body))

            # 接收目标服务器的响应
            response = self._receive_response(conn)
            conn.close()

            # 记录响应数据
            packet['response'] = response.decode('utf-8', errors='ignore')

            # 存储数据包
            if self.parent:
                self.parent.captured_packets.append(packet)
                self.parent.after(0, self.parent.update_packet_list, packet)

            # 将响应返回给客户端
            self._send_response_to_client(response)

        except Exception as e:
            print(f"Error processing request: {str(e)}")
            self.send_response(500)
            self.end_headers()
            self.wfile.write(b"Internal server error")

    def _build_forward_request(self, parsed_url, body):
        """构建转发到目标服务器的请求"""
        request_line = f"{self.command} {parsed_url.path or '/'} HTTP/1.1\r\n"
        headers = ''.join(f"{key}: {value}\r\n" for key, value in self.headers.items())
        return (request_line + headers + "\r\n").encode('utf-8') + body

    def _receive_response(self, conn):
        """接收目标服务器的响应"""
        response = b""
        while True:
            data = conn.recv(4096)
            if not data:
                break
            response += data
        return response

    def _send_response_to_client(self, response):
        """将目标服务器的响应返回给客户端"""
        self.wfile.write(response)

    def do_GET(self): self.do_METHOD()
    def do_POST(self): self.do_METHOD()
    def do_PUT(self): self.do_METHOD()
    def do_DELETE(self): self.do_METHOD()
    def do_HEAD(self): self.do_METHOD()
    def do_OPTIONS(self): self.do_METHOD()
    def do_PATCH(self): self.do_METHOD()

class CustomHTTPServer(HTTPServer):
    """自定义HTTP服务器"""
    def __init__(self, server_address, RequestHandlerClass, parent=None):
        self.parent = parent
        super().__init__(server_address, RequestHandlerClass)

    def finish_request(self, request, client_address):
        """完成请求处理"""
        handler = self.RequestHandlerClass(request, client_address, self, parent=self.parent)
        return handler
        
    def close(self):
        """关闭服务器"""
        self.server_close()

class SQLMapGUI(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("SQL注入测试工具")
        self.geometry("1000x800")

        # 初始化代理监听相关变量
        self.proxy_server = None
        self.is_listening = False
        self.captured_packets = []

        # 创建状态栏
        self.status_bar = tk.Label(self, text="就绪", bd=1, relief=tk.SUNKEN, anchor=tk.W)
        self.status_bar.pack(side=tk.BOTTOM, fill=tk.X)

        # 创建notebook用于选项卡
        self.notebook = ttk.Notebook(self)
        self.notebook.pack(fill="both", expand=True, padx=5, pady=5)

        # 先定义回调方法
        def dummy_callback(*args):
            pass
            
        # 临时设置所有回调
        self.on_search_change = dummy_callback
        self.refresh_packet_list = dummy_callback 
        self.apply_filter = dummy_callback
        self.show_result_context_menu = dummy_callback
        self.filter_results = dummy_callback
        self.export_test_results = dummy_callback
        self.on_closing = dummy_callback

        # 创建主页面和数据库结构页面
        self.create_main_page()
        self.create_database_structure_page()

        # 绑定关闭事件
        self.protocol("WM_DELETE_WINDOW", self.on_closing)

    def create_main_page(self):
        """创建主要功能页面"""
        main_frame = ttk.Frame(self.notebook)
        self.notebook.add(main_frame, text="主要功能")

        # 创建主面板
        main_panel = ttk.PanedWindow(main_frame, orient=tk.VERTICAL)
        main_panel.pack(fill="both", expand=True)

        # 上部面板 - 数据展示
        upper_panel = ttk.Frame(main_panel)
        main_panel.add(upper_panel)

        # 创建分割面板
        split_panel = ttk.PanedWindow(upper_panel, orient=tk.HORIZONTAL)
        split_panel.pack(fill="both", expand=True)

        # 左侧树形视图 (缩小为原来的1/2)
        left_frame = ttk.Frame(split_panel)
        split_panel.add(left_frame)

        self.columns = ("HTTP Data", "Injection", "Payload", "InjectionType")
        self.tree = ttk.Treeview(left_frame, columns=self.columns, show="headings")
        for col in self.columns:
            self.tree.heading(col, text=col)
            if col == "HTTP Data":
                self.tree.column(col, width=150, anchor="w")  # 缩小宽度
            elif col == "Injection":
                self.tree.column(col, width=40, anchor="center")
            elif col == "Payload":
                self.tree.column(col, width=125, anchor="w")
            elif col == "InjectionType":
                self.tree.column(col, width=75, anchor="center")

        # 添加滚动条
        tree_scroll = ttk.Scrollbar(left_frame, orient="vertical", command=self.tree.yview)
        self.tree.configure(yscrollcommand=tree_scroll.set)

        # 布局
        self.tree.pack(side="left", fill="both", expand=True)
        tree_scroll.pack(side="right", fill="y")

        # 绑定右键菜单
        self.tree.bind("<Button-3>", self.show_tree_context_menu)

        # 右侧HTTP数据包预览区域
        right_frame = ttk.Frame(split_panel)
        split_panel.add(right_frame)

        # HTTP数据包预览
        self.http_preview = scrolledtext.ScrolledText(right_frame, wrap=tk.WORD, height=10)
        self.http_preview.pack(fill="both", expand=True)

        # 绑定选择事件和右键菜单
        self.tree.bind('<<TreeviewSelect>>', self.show_http_detail)
        self.tree.bind("<Button-3>", self.show_tree_context_menu)

        # 下部面板 - 控制区域
        lower_panel = ttk.Frame(main_panel)
        main_panel.add(lower_panel)

        # 创建控制面板
        control_frame = ttk.LabelFrame(lower_panel, text="控制面板")
        control_frame.pack(fill="x", padx=5, pady=5)

        # 基本操作区域
        basic_frame = ttk.Frame(control_frame)
        basic_frame.pack(fill="x", padx=5, pady=5)

        ttk.Button(basic_frame, text="导入HTTP数据", 
                  command=self.import_data).pack(side="left", padx=5)
        
        ttk.Label(basic_frame, text="sqlmap参数:").pack(side="left", padx=5)
        self.params_entry = ttk.Entry(basic_frame, width=50)
        self.params_entry.pack(side="left", padx=5)
        
        self.run_btn = ttk.Button(basic_frame, text="运行", command=self.run_scan)
        self.run_btn.pack(side="left", padx=5)
        
        ttk.Button(basic_frame, text="导出报告", 
                  command=self.export_report).pack(side="left", padx=5)
        
        ttk.Button(basic_frame, text="打开日志文件夹", 
                  command=self.open_logs).pack(side="left", padx=5)

        # 代理劫持捕获HTTP数据包区域
        proxy_frame = ttk.LabelFrame(control_frame, text="代理劫持捕获HTTP数据包")
        proxy_frame.pack(fill="x", padx=5, pady=5)

        # IP配置
        ip_frame = ttk.Frame(proxy_frame)
        ip_frame.pack(fill="x", padx=5, pady=5)
        ttk.Label(ip_frame, text="监听IP:").pack(side="left", padx=5)
        self.listen_ip = ttk.Entry(ip_frame, width=15)
        self.listen_ip.insert(0, "0.0.0.0")
        self.listen_ip.pack(side="left", padx=5)

        # 端口配置
        ttk.Label(ip_frame, text="端口:").pack(side="left", padx=5)
        self.listen_port = ttk.Entry(ip_frame, width=6)
        self.listen_port.insert(0, "8080")
        self.listen_port.pack(side="left", padx=5)

        # 控制按钮
        btn_frame = ttk.Frame(proxy_frame)
        btn_frame.pack(fill="x", padx=5, pady=5)
        
        self.listen_start_button = ttk.Button(btn_frame, text="开始监听", 
                                            command=self.start_listening)
        self.listen_start_button.pack(side="left", padx=5)
        
        self.listen_stop_button = ttk.Button(btn_frame, text="停止监听", 
                                           command=self.stop_listening, state="disabled")
        self.listen_stop_button.pack(side="left", padx=5)

        # Tamper管理区域
        tamper_frame = ttk.LabelFrame(control_frame, text="Tamper管理")
        tamper_frame.pack(fill="x", padx=5, pady=5)

        # Tamper类型选择
        ttk.Label(tamper_frame, text="Tamper类型:").pack(side="left", padx=5)
        self.tamper_type = ttk.Combobox(tamper_frame, width=20, state="readonly")
        self.tamper_type['values'] = [
            "字符编码绕过", 
            "空格绕过",
            "注释绕过",
            "关键字绕过",
            "数据库特定绕过"
        ]
        self.tamper_type.pack(side="left", padx=5)
        self.tamper_type.bind('<<ComboboxSelected>>', self.update_tamper_list)

        # Tamper脚本选择
        ttk.Label(tamper_frame, text="Tamper脚本:").pack(side="left", padx=5)
        self.tamper_script = ttk.Combobox(tamper_frame, width=30, state="readonly")
        self.tamper_script.pack(side="left", padx=5)
        self.tamper_script.bind('<<ComboboxSelected>>', self.show_tamper_desc)

        # Tamper说明
        self.tamper_desc_label = ttk.Label(tamper_frame, text="", wraplength=400)
        self.tamper_desc_label.pack(side="left", padx=5)

        # 自定义Tamper按钮
        ttk.Button(tamper_frame, text="使用自定义Tamper", 
                  command=self.use_custom_tamper).pack(side="left", padx=5)
        ttk.Button(tamper_frame, text="应用选中Tamper", 
                  command=self.apply_tamper).pack(side="left", padx=5)

        # 创建数据库操作面板
        db_frame = ttk.LabelFrame(main_frame, text="数据库操作")
        db_frame.pack(fill="x", padx=5, pady=5)

        # 数据库名输入
        ttk.Label(db_frame, text="数据库名:").pack(side="left")
        self.database_name_entry = ttk.Entry(db_frame, width=30)
        self.database_name_entry.insert(0, "填写数据库名称")
        self.database_name_entry.pack(side="left", padx=5)

        ttk.Button(db_frame, text="获取指定数据库下表名称", 
                  command=self.get_tables).pack(side="left", padx=5)

        # 数据表名输入
        ttk.Label(db_frame, text="数据表名:").pack(side="left")
        self.table_name_entry = ttk.Entry(db_frame, width=30)
        self.table_name_entry.insert(0, "填写数据库表名")
        self.table_name_entry.pack(side="left", padx=5)

        ttk.Button(db_frame, text="获取指定表下字段名", 
                  command=self.get_columns).pack(side="left", padx=5)

        # 创建命令按钮面板
        command_frame = ttk.LabelFrame(main_frame, text="常用命令")
        command_frame.pack(fill="x", padx=5, pady=5)

        # 添加命令按钮
        ttk.Button(command_frame, text="枚举所有数据库名", 
                  command=self.enum_dbs).pack(side="left", padx=5)
        ttk.Button(command_frame, text="列出当前数据库名", 
                  command=self.current_db).pack(side="left", padx=5)
        ttk.Button(command_frame, text="枚举所有表名", 
                  command=self.enum_tables).pack(side="left", padx=5)
        ttk.Button(command_frame, text="枚举所有字段名", 
                  command=self.dump).pack(side="left", padx=5)
        ttk.Button(command_frame, text="一键脱库", 
                  command=self.dump_all).pack(side="left", padx=5)
        ttk.Button(command_frame, text="列出当前用户名", 
                  command=self.current_user).pack(side="left", padx=5)
        ttk.Button(command_frame, text="判断当前用户是否为DBA权限", 
                  command=self.is_dba).pack(side="left", padx=5)
        ttk.Button(command_frame, text="强制SSL通信——Https", 
                  command=self.force_ssl).pack(side="left", padx=5)

        # 线程控制
        thread_frame = ttk.Frame(command_frame)
        thread_frame.pack(side="left", padx=5)
        self.thread_var = tk.StringVar(value="1")
        ttk.Label(thread_frame, text="线程数:").pack(side="left")
        thread_option = ttk.Combobox(thread_frame, textvariable=self.thread_var, 
                                   values=list(range(1, 11)), state="readonly", width=5)
        thread_option.pack(side="left", padx=5)
        thread_option.bind("<<ComboboxSelected>>", self.update_threads)

        # 创建输出区域
        output_frame = ttk.LabelFrame(main_frame, text="输出")
        output_frame.pack(fill="both", expand=True, padx=5, pady=5)

        self.output_text = scrolledtext.ScrolledText(output_frame, height=10)
        self.output_text = scrolledtext.ScrolledText(output_frame, height=10)
        self.output_text.tag_configure("success", foreground="green")
        self.output_text.tag_configure("info", foreground="blue")
        self.output_text.tag_configure("error", foreground="red")
        self.output_text.pack(fill="both", expand=True)

    def update_status(self, message):
        """更新状态栏信息"""
        self.status_bar.config(text=message)
        self.update_idletasks()

    def import_data(self):
        """导入HTTP数据"""
        file_path = filedialog.askopenfilename(
            filetypes=[("Excel Files", "*.xlsx"), ("Text Files", "*.txt")]
        )
        if not file_path:
            return

        try:
            self.tree.delete(*self.tree.get_children())
            if file_path.endswith('.xlsx'):
                df = pd.read_excel(file_path)
                for http_data in df.iloc[:, 1]:
                    if isinstance(http_data, str) and http_data.strip():
                        self.tree.insert("", "end", values=(http_data.strip(), "", ""))
            else:
                with open(file_path, "r") as f:
                    for line in f:
                        line = line.strip()
                        if line:
                            self.tree.insert("", "end", values=(line, "", ""))
            self.update_status("数据导入成功")
        except Exception as e:
            messagebox.showerror("错误", f"导入数据失败: {str(e)}")

    def run_scan(self):
        """运行扫描"""
        if not self.tree.get_children():
            messagebox.showwarning("警告", "请先导入HTTP数据")
            return

        self.run_btn.config(state="disabled")
        self.update_status("正在执行扫描...")
        threading.Thread(target=self._run_scan_thread).start()

    def _run_scan_thread(self):
        """扫描线程"""
        params = self.params_entry.get().split()
        for item in self.tree.get_children():
            http_data = self.tree.item(item)["values"][0]
            
            # 保存HTTP数据到临时文件
            with open("temp_http.txt", "w") as f:
                f.write(http_data)
            
            # 执行sqlmap
            try:
                result = subprocess.run(
                    ['sqlmap', '-r', 'temp_http.txt', '--batch'] + params,
                    capture_output=True,
                    text=True
                )
                
                # 更新输出
                self.output_text.insert("end", result.stdout + result.stderr + "\n")
                self.output_text.see("end")
                
                # 更新结果
                result_output = result.stdout + result.stderr
                
                # 使用Parameter作为注入点检测的标志
                if "Parameter: " in result_output:
                    self.tree.set(item, "Injection", "Yes")
                    
                    # 提取注入类型
                    injection_type = "Unknown"
                    type_match = re.search(r"Type: ([^\n]+)", result_output)
                    if type_match:
                        injection_type = type_match.group(1)
                    self.tree.set(item, "InjectionType", injection_type)
                    
                    # 提取payload
                    if "Payload:" in result_output:
                        try:
                            payload_start = result_output.index("Payload:") + len("Payload:")
                            payload_end = result_output.index("\n", payload_start)
                            payload = result_output[payload_start:payload_end].strip()
                            self.tree.set(item, "Payload", payload)
                            
                            # 在输出中突出显示发现的注入点
                            self.output_text.insert("end", "\n[+] 发现注入点！\n", "success")
                            self.output_text.insert("end", f"[*] 注入类型: {injection_type}\n", "info")
                            self.output_text.insert("end", f"[*] Payload: {payload}\n", "info")
                        except ValueError:
                            self.output_text.insert("end", "警告: Payload提取失败\n", "error")
                else:
                    self.tree.set(item, "Injection", "No")
                    self.tree.set(item, "InjectionType", "N/A")
                
                # 更新输出
                self.output_text.insert("end", result_output + "\n")
                self.output_text.see("end")
                
            except Exception as e:
                self.output_text.insert("end", f"错误: {str(e)}\n", "error")
                self.tree.set(item, "Injection", "Error")
                self.tree.set(item, "InjectionType", "Error")
                self.output_text.see("end")
            
            self.update()

        # 清理临时文件
        if os.path.exists("temp_http.txt"):
            os.remove("temp_http.txt")
            
        self.run_btn.config(state="normal")
        self.update_status("扫描完成")

    def export_report(self):
        """导出报告"""
        if not self.tree.get_children():
            messagebox.showwarning("警告", "没有可导出的数据")
            return

        report_data = []
        for item in self.tree.get_children():
            values = self.tree.item(item)["values"]
            report_data.append(values)

        html_content = f'''
<!DOCTYPE html>
<html>
<head>
    <title>SQL注入测试报告</title>
    <style>
        body {{ 
            font-family: Arial, sans-serif;
            margin: 20px;
            background-color: #f5f5f5;
        }}
        .container {{
            max-width: 1200px;
            margin: 0 auto;
            background-color: white;
            padding: 20px;
            border-radius: 5px;
            box-shadow: 0 0 10px rgba(0,0,0,0.1);
        }}
        h1 {{
            color: #333;
            text-align: center;
            padding-bottom: 20px;
            border-bottom: 2px solid #eee;
        }}
        table {{
            width: 100%;
            border-collapse: collapse;
            margin: 20px 0;
            table-layout: fixed;
        }}
        th, td {{
            border: 1px solid #ddd;
            padding: 12px;
            text-align: left;
            word-wrap: break-word;
            overflow-wrap: break-word;
        }}
        th:nth-child(1), td:nth-child(1) {{ width: 35%; }} /* HTTP Data */
        th:nth-child(2), td:nth-child(2) {{ width: 10%; }} /* Injection */
        th:nth-child(3), td:nth-child(3) {{ width: 35%; }} /* Payload */
        th:nth-child(4), td:nth-child(4) {{ width: 20%; }} /* Injection Type */
        th {{
            background-color: #f8f9fa;
            font-weight: bold;
        }}
        tr:hover {{
            background-color: #f5f5f5;
        }}
        .summary {{
            margin-top: 30px;
            padding: 20px;
            background-color: #f8f9fa;
            border-radius: 5px;
        }}
        .success {{
            color: #28a745;
        }}
        .failure {{
            color: #dc3545;
        }}
    </style>
</head>
<body>
    <div class="container">
        <h1>SQL注入测试报告</h1>
        <table>
            <tr>
                <th>HTTP 数据</th>
                <th>注入情况</th>
                <th>有效载荷</th>
                <th>注入类型</th>
            </tr>
'''

        for http_data, injection, payload, injection_type in report_data:
            status_class = 'success' if injection == 'Yes' else 'failure'
            # 对HTTP数据进行HTML转义并保持格式
            escaped_http_data = http_data.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;").replace("\n", "<br>").replace(" ", "&nbsp;")
            # 如果注入类型为空，设置为未知
            if not injection_type:
                injection_type = "未知"
            html_content += f'''
                <tr>
                    <td style="white-space: pre-wrap; font-family: monospace;">{escaped_http_data}</td>
                    <td class="{status_class}">{injection}</td>
                    <td>{payload}</td>
                    <td>{injection_type}</td>
                </tr>'''

        success_count = sum(1 for _, inj, _, _ in report_data if inj == "Yes")
        html_content += f'''
            </table>
            <div class="summary">
                <h2>测试总结</h2>
                <p>测试时间: {pd.Timestamp.now().strftime('%Y-%m-%d %H:%M:%S')}</p>
                <p>总测试数: {len(report_data)}</p>
                <p>成功注入数: <span class="success">{success_count}</span></p>
                <p>失败数: <span class="failure">{len(report_data) - success_count}</span></p>
            </div>
        </div>
    </body>
</html>
'''

        try:
            with open("sql注入测试报告.html", "w", encoding="utf-8") as f:
                f.write(html_content)
            self.update_status("报告导出成功")
            messagebox.showinfo("成功", "报告已导出为 sql注入测试报告.html")
        except Exception as e:
            messagebox.showerror("错误", f"导出报告失败: {str(e)}")

    def open_logs(self):
        """打开日志文件夹"""
        log_path = os.path.expanduser("~/.local/share/sqlmap/output/")
        try:
            subprocess.run(['xdg-open', log_path])
            self.update_status("已打开日志文件夹")
        except Exception as e:
            messagebox.showerror("错误", f"无法打开日志文件夹: {str(e)}")

    def get_tables(self):
        """获取指定数据库的表"""
        db_name = self.database_name_entry.get().strip()
        if db_name:
            self.params_entry.insert("end", f"-D {db_name} --tables ")
            self.update_status(f"已添加获取数据库 {db_name} 的表命令")

    def get_columns(self):
        """获取指定表的列"""
        table_name = self.table_name_entry.get().strip()
        if table_name:
            self.params_entry.insert("end", f"-T {table_name} --dump ")
            self.update_status(f"已添加获取表 {table_name} 的列命令")

    def enum_dbs(self):
        """枚举所有数据库"""
        self.params_entry.insert("end", "--dbs ")
        self.update_status("已添加枚举数据库命令")

    def current_db(self):
        """获取当前数据库"""
        self.params_entry.insert("end", "--current-db ")
        self.update_status("已添加获取当前数据库命令")

    def enum_tables(self):
        """枚举所有表"""
        self.params_entry.insert("end", "--tables ")
        self.update_status("已添加枚举表命令")

    def dump(self):
        """导出所有字段"""
        self.params_entry.insert("end", "--dump ")
        self.update_status("已添加导出字段命令")

    def dump_all(self):
        """一键导出所有数据"""
        self.params_entry.insert("end", "--dump-all ")
        self.update_status("已添加一键导出命令")

    def current_user(self):
        """获取当前用户"""
        self.params_entry.insert("end", "--current-user ")
        self.update_status("已添加获取当前用户命令")

    def is_dba(self):
        """检查是否为DBA权限"""
        self.params_entry.insert("end", "--is-dba ")
        self.update_status("已添加检查DBA权限命令")

    def force_ssl(self):
        """强制使用SSL"""
        self.params_entry.insert("end", "--force-ssl ")
        self.update_status("已添加强制SSL命令")

    def update_tamper_list(self, event=None):
        """更新tamper列表"""
        tamper_dict = {
            "字符编码绕过": [
                ("apostrophemask", "使用UTF-8全角引号替换单引号，绕过对单引号的过滤"),
                ("base64encode", "对参数进行Base64编码，绕过WAF对特殊字符的检测"),
                ("chardoubleencode", "对字符进行双重URL编码，绕过WAF的解码检测"),
                ("unmagicquotes", "对引号进行转义，绕过magic_quotes类型的过滤")
            ],
            "空格绕过": [
                ("space2comment", "使用/**/ 替换空格，绕过对空格的过滤"),
                ("space2dash", "使用-替换空格，绕过对空格的过滤"),
                ("space2hash", "使用# 替换空格，绕过对空格的过滤"),
                ("space2mssqlblank", "使用MSSQL空白字符替换空格")
            ],
            "注释绕过": [
                ("randomcomments", "在SQL语句中添加随机注释"),
                ("charencode", "对SQL语句进行URL编码"),
                ("equaltolike", "将等号替换为LIKE，绕过等号过滤"),
                ("halfversionedmorekeywords", "在关键字前后添加MySQL注释")
            ],
            "关键字绕过": [
                ("between", "使用BETWEEN替换大于号和小于号"),
                ("bluecoat", "使用随机大小写绕过关键字过滤"),
                ("lowercase", "将SQL语句转换为小写"),
                ("uppercase", "将SQL语句转换为大写")
            ],
            "数据库特定绕过": [
                ("mysql", "MySQL数据库特定的绕过技术"),
                ("mssql", "MSSQL数据库特定的绕过技术"),
                ("oracle", "Oracle数据库特定的绕过技术"),
                ("postgresql", "PostgreSQL数据库特定的绕过技术")
            ]
        }
        
        selected_type = self.tamper_type.get()
        if selected_type in tamper_dict:
            self.tamper_script['values'] = [t[0] for t in tamper_dict[selected_type]]
            self.tamper_descriptions = dict(tamper_dict[selected_type])
            self.tamper_script.set('')
            self.tamper_desc_label.config(text='')

    def show_tamper_desc(self, event=None):
        """显示tamper描述"""
        selected_script = self.tamper_script.get()
        if selected_script in self.tamper_descriptions:
            self.tamper_desc_label.config(text=self.tamper_descriptions[selected_script])

    def use_custom_tamper(self):
        """使用自定义tamper"""
        file_path = filedialog.askopenfilename(
            title="选择Tamper脚本",
            filetypes=[("Python Files", "*.py")]
        )
        if file_path:
            try:
                # 复制tamper脚本到sqlmap的tamper目录
                tamper_dir = os.path.expanduser("~/.local/share/sqlmap/tamper/")
                if not os.path.exists(tamper_dir):
                    os.makedirs(tamper_dir)
                tamper_name = os.path.basename(file_path)
                shutil.copy2(file_path, os.path.join(tamper_dir, tamper_name))
                
                # 添加tamper参数
                script_name = os.path.splitext(tamper_name)[0]
                self.params_entry.insert("end", f" --tamper={script_name}")
                self.update_status(f"已添加自定义tamper: {script_name}")
            except Exception as e:
                messagebox.showerror("错误", f"添加自定义tamper失败: {str(e)}")

    def apply_tamper(self):
        """应用选中的tamper"""
        selected_script = self.tamper_script.get()
        if selected_script:
            self.params_entry.insert("end", f" --tamper={selected_script}")
            self.update_status(f"已应用tamper: {selected_script}")
        else:
            messagebox.showwarning("警告", "请先选择一个tamper脚本")

    def update_threads(self, event):
        """更新线程数"""
        selected_thread = self.thread_var.get()
        self.params_entry.insert("end", f"--threads={selected_thread} ")
        self.update_status(f"已设置线程数为 {selected_thread}")

    def create_database_structure_page(self):
        """创建数据库结构页面"""
        db_frame = ttk.Frame(self.notebook)
        self.notebook.add(db_frame, text="数据库结构")

        # 创建控制面板
        control_frame = ttk.Frame(db_frame)
        control_frame.pack(fill="x", padx=5, pady=5)

        # 添加刷新按钮
        ttk.Button(control_frame, text="刷新", 
                  command=self.update_database_structure).pack(side="left", padx=5)

        # 添加状态标签
        self.db_status_label = ttk.Label(control_frame, text="就绪")
        self.db_status_label.pack(side="left", padx=10)

        # 创建分割面板
        paned = ttk.PanedWindow(db_frame, orient=tk.HORIZONTAL)
        paned.pack(fill="both", expand=True, padx=5, pady=5)

        # 左侧树形视图
        tree_frame = ttk.Frame(paned)
        paned.add(tree_frame)

        # 创建树形视图
        self.db_tree = ttk.Treeview(tree_frame)
        self.db_tree.pack(fill="both", expand=True, padx=5, pady=5)

        # 添加滚动条
        scrollbar = ttk.Scrollbar(tree_frame, orient="vertical", command=self.db_tree.yview)
        self.db_tree.configure(yscrollcommand=scrollbar.set)
        scrollbar.pack(side="right", fill="y")

        # 初始化树形结构
        self.db_tree["columns"] = ("type")
        self.db_tree.column("#0", width=300, minwidth=300, stretch=tk.YES)
        self.db_tree.column("type", width=100, minwidth=100, stretch=tk.NO)
        self.db_tree.heading("#0", text="名称", anchor=tk.W)
        self.db_tree.heading("type", text="类型", anchor=tk.W)

        # 右侧表格视图
        self.table_frame = ttk.Frame(paned)
        paned.add(self.table_frame)

        # 创建表格视图
        self.data_table = ttk.Treeview(self.table_frame)
        self.data_table.pack(fill="both", expand=True, padx=5, pady=5)

        # 添加表格滚动条
        table_scroll = ttk.Scrollbar(self.table_frame, orient="vertical", command=self.data_table.yview)
        self.data_table.configure(yscrollcommand=table_scroll.set)
        table_scroll.pack(side="right", fill="y")

        # 初始加载数据
        self.update_database_structure()

        # 绑定右键菜单事件
        self.db_tree.bind("<Button-3>", self.show_db_tree_context_menu)
        
        # 绑定树形视图选择事件
        self.db_tree.bind("<<TreeviewSelect>>", self.on_db_tree_select)

    def show_db_tree_context_menu(self, event):
        """显示数据库树形视图的右键菜单"""
        item = self.db_tree.identify_row(event.y)
        if not item:
            return

        # 获取节点类型
        values = self.db_tree.item(item, "values")
        node_type = values[0] if values else ""

        # 创建菜单
        menu = tk.Menu(self, tearoff=0)
        
        # 添加通用菜单项
        menu.add_command(label="复制名称", 
                        command=lambda: self.copy_node_name(item))
        
        # 根据节点类型添加特定菜单项
        if node_type == "表":
            menu.add_command(label="导出表结构", 
                           command=lambda: self.export_table_structure(item))
        
        menu.add_separator()
        menu.add_command(label="刷新", 
                        command=lambda: self.refresh_node(item))

        # 显示菜单
        try:
            menu.tk_popup(event.x_root, event.y_root)
        finally:
            menu.grab_release()

    def copy_node_name(self, item):
        """复制节点名称到剪贴板"""
        text = self.db_tree.item(item, "text")
        self.clipboard_clear()
        self.clipboard_append(text)
        self.db_status_label.config(text=f"已复制: {text}")

    def export_table_structure(self, item):
        """导出表结构到文件"""
        # 获取表路径
        table_name = self.db_tree.item(item, "text")
        parent = self.db_tree.parent(item)
        db_name = self.db_tree.item(parent, "text")
        grandparent = self.db_tree.parent(parent)
        ip = self.db_tree.item(grandparent, "text")

        # 构建文件路径
        csv_path = os.path.expanduser(
            f"~/.local/share/sqlmap/output/{ip}/dump/{db_name}/{table_name}.csv"
        )

        # 选择保存位置
        filename = filedialog.asksaveasfilename(
            defaultextension=".csv",
            filetypes=[("CSV文件", "*.csv")],
            initialfile=f"{table_name}_structure.csv"
        )
        
        if filename:
            try:
                shutil.copy2(csv_path, filename)
                self.db_status_label.config(text=f"已导出: {filename}")
            except Exception as e:
                messagebox.showerror("错误", f"导出失败: {str(e)}")

    def refresh_node(self, item):
        """刷新选中节点"""
        values = self.db_tree.item(item, "values")
        node_type = values[0] if values else ""
        
        if node_type == "IP地址":
            # 刷新整个IP节点
            self.update_database_structure()
        else:
            # 刷新当前节点及其子节点
            parent = self.db_tree.parent(item)
            self.db_tree.delete(*self.db_tree.get_children(item))
            self.update_database_structure()

    def update_database_structure(self):
        """更新数据库结构树形视图"""
        self.db_status_label.config(text="正在扫描数据库结构...")
        try:
            # 清空现有树形结构
            self.clear_database_tree()
            
            # 扫描输出目录
            db_structure = self.scan_output_directory()
            
            # 构建树形视图
            self.build_database_tree(db_structure)
            
            self.db_status_label.config(text=f"已加载 {len(db_structure)} 个IP的数据库")
        except Exception as e:
            self.db_status_label.config(text=f"错误: {str(e)}")
            messagebox.showerror("错误", f"加载数据库结构失败: {str(e)}")

    def scan_output_directory(self):
        """扫描sqlmap输出目录，返回数据库结构字典"""
        output_dir = os.path.expanduser("~/.local/share/sqlmap/output")
        if not os.path.exists(output_dir):
            raise Exception("sqlmap输出目录不存在")
            
        db_structure = {}
        
        # 遍历IP目录
        for ip in os.listdir(output_dir):
            ip_path = os.path.join(output_dir, ip, "dump")
            if not os.path.isdir(ip_path):
                continue
                
            db_structure[ip] = {}
            
            # 遍历数据库目录
            for db_name in os.listdir(ip_path):
                db_path = os.path.join(ip_path, db_name)
                if not os.path.isdir(db_path):
                    continue
                
                db_structure[ip][db_name] = []
                
                # 遍历表CSV文件
                for table_file in os.listdir(db_path):
                    if not table_file.endswith(".csv"):
                        continue
                        
                    table_name = table_file[:-4]
                    table_path = os.path.join(db_path, table_file)
                    
                    # 读取CSV文件获取字段
                    try:
                        with open(table_path, "r") as f:
                            reader = csv.reader(f)
                            headers = next(reader)
                            db_structure[ip][db_name].append({
                                "name": table_name,
                                "fields": headers
                            })
                    except Exception as e:
                        print(f"读取表{table_name}失败: {str(e)}")
                        continue
                        
        return db_structure

    def build_database_tree(self, db_structure):
        """根据数据库结构字典构建树形视图"""
        root_node = self.db_tree.insert("", "end", text="数据库结构", open=True)
        
        for ip, databases in db_structure.items():
            ip_node = self.db_tree.insert(root_node, "end", text=ip, values=("IP地址"))
            
            for db_name, tables in databases.items():
                db_node = self.db_tree.insert(ip_node, "end", text=db_name, values=("数据库"))
                
                for table in tables:
                    table_node = self.db_tree.insert(db_node, "end", text=table["name"], values=("表"))
                    
                    for field in table["fields"]:
                        self.db_tree.insert(table_node, "end", text=field, values=("字段"))

    def clear_database_tree(self):
        """清空数据库树形视图"""
        for item in self.db_tree.get_children():
            self.db_tree.delete(item)

    def on_db_tree_select(self, event):
        """处理树形视图选择事件"""
        selected_item = self.db_tree.focus()
        if not selected_item:
            return
            
        # 获取节点类型
        values = self.db_tree.item(selected_item, "values")
        node_type = values[0] if values else ""
        
        if node_type == "表":
            # 获取表路径
            table_name = self.db_tree.item(selected_item, "text")
            parent = self.db_tree.parent(selected_item)
            db_name = self.db_tree.item(parent, "text")
            grandparent = self.db_tree.parent(parent)
            ip = self.db_tree.item(grandparent, "text")
            
            # 构建文件路径
            csv_path = os.path.expanduser(
                f"~/.local/share/sqlmap/output/{ip}/dump/{db_name}/{table_name}.csv"
            )
            
            # 加载并显示表数据
            self.load_table_data(csv_path)

    def load_table_data(self, csv_path):
        """加载并显示表数据"""
        try:
            # 清空现有表格
            for item in self.data_table.get_children():
                self.data_table.delete(item)
            self.data_table["columns"] = []
            
            if not os.path.exists(csv_path):
                return
                
            # 创建控制面板
            if hasattr(self, 'table_control_frame'):
                self.table_control_frame.destroy()
            self.table_control_frame = ttk.Frame(self.table_frame)
            self.table_control_frame.pack(fill="x", padx=5, pady=5)
            
            # 添加搜索框
            ttk.Label(self.table_control_frame, text="搜索:").pack(side="left")
            self.table_search_entry = ttk.Entry(self.table_control_frame, width=30)
            self.table_search_entry.pack(side="left", padx=5)
            self.table_search_entry.bind("<Return>", lambda e: self.filter_table_data())
            
            # 添加分页控制
            ttk.Button(self.table_control_frame, text="<", 
                      command=lambda: self.change_page(-1)).pack(side="left", padx=2)
            self.page_label = ttk.Label(self.table_control_frame, text="1/1")
            self.page_label.pack(side="left", padx=2)
            ttk.Button(self.table_control_frame, text=">", 
                      command=lambda: self.change_page(1)).pack(side="left", padx=2)
            
            # 添加导出按钮
            ttk.Button(self.table_control_frame, text="导出数据",
                      command=self.export_table_data).pack(side="right", padx=5)
            
            # 读取CSV文件
            with open(csv_path, "r") as f:
                reader = csv.reader(f)
                self.table_headers = next(reader)
                self.all_rows = list(reader)
                
            # 初始化分页
            self.current_page = 1
            self.rows_per_page = 100
            self.filtered_rows = self.all_rows
            self.total_pages = max(1, len(self.filtered_rows) // self.rows_per_page + 1)
            
            # 显示第一页数据
            self.display_page()
            
        except Exception as e:
            messagebox.showerror("错误", f"加载表数据失败: {str(e)}")
            
    def display_page(self):
        """显示当前页的数据"""
        # 清空表格
        for item in self.data_table.get_children():
            self.data_table.delete(item)
            
        # 设置表格列
        self.data_table["columns"] = self.table_headers
        for col in self.table_headers:
            self.data_table.column(col, width=120, minwidth=50)
            self.data_table.heading(col, text=col)
            
        # 计算当前页的数据范围
        start_idx = (self.current_page - 1) * self.rows_per_page
        end_idx = min(start_idx + self.rows_per_page, len(self.filtered_rows))
        
        # 添加当前页的数据行
        for row in self.filtered_rows[start_idx:end_idx]:
            self.data_table.insert("", "end", values=row)
            
        # 更新分页信息
        self.page_label.config(text=f"{self.current_page}/{self.total_pages}")
        
    def change_page(self, delta):
        """切换分页"""
        new_page = self.current_page + delta
        if 1 <= new_page <= self.total_pages:
            self.current_page = new_page
            self.display_page()
            
    def filter_table_data(self):
        """根据搜索条件过滤数据"""
        search_term = self.table_search_entry.get().lower()
        if not search_term:
            self.filtered_rows = self.all_rows
        else:
            self.filtered_rows = [
                row for row in self.all_rows 
                if any(search_term in str(cell).lower() for cell in row)
            ]
            
        # 重置分页
        self.current_page = 1
        self.total_pages = max(1, len(self.filtered_rows) // self.rows_per_page + 1)
        self.display_page()
        
    def export_table_data(self):
        """导出表格数据到CSV文件"""
        if not hasattr(self, 'table_headers') or not hasattr(self, 'all_rows'):
            return
            
        filename = filedialog.asksaveasfilename(
            defaultextension=".csv",
            filetypes=[("CSV文件", "*.csv")],
            initialfile="exported_data.csv"
        )
        
        if filename:
            try:
                with open(filename, "w", newline="") as f:
                    writer = csv.writer(f)
                    writer.writerow(self.table_headers)
                    writer.writerows(self.all_rows)
                messagebox.showinfo("成功", "数据导出成功")
            except Exception as e:
                messagebox.showerror("错误", f"导出失败: {str(e)}")

    def create_passive_scan_page(self):
        """创建被动扫描页面"""
        passive_frame = ttk.Frame(self.notebook)
        self.notebook.add(passive_frame, text="被动扫描")

        # 创建监听配置区域
        config_frame = ttk.LabelFrame(passive_frame, text="监听配置")
        config_frame.pack(fill="x", padx=5, pady=5)

        # IP配置
        ip_frame = ttk.Frame(config_frame)
        ip_frame.pack(fill="x", padx=5, pady=5)
        ttk.Label(ip_frame, text="监听IP:").pack(side="left", padx=5)
        self.listen_ip = ttk.Entry(ip_frame, width=15)
        self.listen_ip.insert(0, "0.0.0.0")
        self.listen_ip.pack(side="left", padx=5)

        # 端口配置
        ttk.Label(ip_frame, text="端口:").pack(side="left", padx=5)
        self.listen_port = ttk.Entry(ip_frame, width=6)
        self.listen_port.insert(0, "8080")
        self.listen_port.pack(side="left", padx=5)

        # 创建控制区域
        control_frame = ttk.Frame(passive_frame)
        control_frame.pack(fill="x", padx=5, pady=5)
        
        self.listen_start_button = ttk.Button(control_frame, text="开始监听", 
                                         command=self.start_listening)
        self.listen_start_button.pack(side="left", padx=5)
        
        self.listen_stop_button = ttk.Button(control_frame, text="停止监听", 
                                        command=self.stop_listening, state="disabled")
        self.listen_stop_button.pack(side="left", padx=5)
        
        self.inject_test_button = ttk.Button(control_frame, text="开始注入测试", 
                                        command=self.start_injection_test, state="disabled")
        self.inject_test_button.pack(side="left", padx=5)

        # 创建数据包显示区域
        packet_frame = ttk.LabelFrame(passive_frame, text="数据包信息")
        packet_frame.pack(fill="both", expand=True, padx=5, pady=5)

        # 创建左右分隔的面板
        paned = ttk.PanedWindow(packet_frame, orient="horizontal")
        paned.pack(fill="both", expand=True, padx=5, pady=5)

        # 左侧数据包列表
        list_frame = ttk.Frame(paned)
        paned.add(list_frame)

        # 创建数据包列表
        columns = ("时间", "方法", "URL", "状态")
        self.packet_tree = ttk.Treeview(list_frame, columns=columns, show="headings", selectmode="extended")
        for col in columns:
            self.packet_tree.heading(col, text=col, command=lambda c=col: self.sort_packets(c))
        
        # 设置列宽
        self.packet_tree.column("时间", width=150)
        self.packet_tree.column("方法", width=80)
        self.packet_tree.column("URL", width=300)
        self.packet_tree.column("状态", width=100)

        # 添加滚动条
        scrollbar = ttk.Scrollbar(list_frame, orient="vertical", 
                                    command=self.packet_tree.yview)
        self.packet_tree.configure(yscrollcommand=scrollbar.set)

        self.packet_tree.pack(side="left", fill="both", expand=True)
        scrollbar.pack(side="right", fill="y")

        # 在数据包列表中绑定右键菜单
        self.packet_tree.bind("<Button-3>", self.show_packet_context_menu)

        # 右侧数据包详情
        detail_frame = ttk.Frame(paned)
        paned.add(detail_frame)

        # 创建数据包详情显示区域
        self.packet_detail = scrolledtext.ScrolledText(detail_frame, wrap=tk.WORD, 
                                                         width=50, height=20)
        self.packet_detail.pack(fill="both", expand=True)

        # 绑定选择事件
        self.packet_tree.bind('<<TreeviewSelect>>', self.show_packet_detail)

        # 创建结果显示区域
        result_frame = ttk.LabelFrame(passive_frame, text="测试结果")
        result_frame.pack(fill="x", padx=5, pady=5)

        # 创建结果表格
        columns = ("URL", "参数", "注入类型", "Payload", "状态")
        self.result_tree = ttk.Treeview(result_frame, columns=columns, show="headings", height=5)
        for col in columns:
            self.result_tree.heading(col, text=col)
            self.result_tree.column(col, width=120)

        # 添加滚动条
        result_scroll = ttk.Scrollbar(result_frame, orient="vertical", 
                                        command=self.result_tree.yview)
        self.result_tree.configure(yscrollcommand=result_scroll.set)

        self.result_tree.pack(side="left", fill="x", expand=True)
        result_scroll.pack(side="right", fill="y")

    def start_listening(self):
        """开始监听"""
        try:
            ip = self.listen_ip.get()
            port = int(self.listen_port.get())
            
            # 这里将添加代理服务器的实现
            self.is_listening = True
            self.listen_start_button.config(state="disabled")
            self.listen_stop_button.config(state="normal")
            self.update_status("正在监听...")
            
            # 启动代理服务器线程
            threading.Thread(target=self._run_proxy_server, args=(ip, port), 
                           daemon=True).start()
            
        except ValueError:
            messagebox.showerror("错误", "端口必须是有效的数字")
        except Exception as e:
            messagebox.showerror("错误", f"启动监听失败: {str(e)}")

    def stop_listening(self):
        """停止监听"""
        self.is_listening = False
        if self.proxy_server:
            try:
                self.proxy_server.shutdown()
                self.proxy_server.server_close()
            except:
                pass
            self.proxy_server = None
        
        self.listen_start_button.config(state="normal")
        self.listen_stop_button.config(state="disabled")
        self.update_status("监听已停止")

    def _run_proxy_server(self, ip, port):
        """运行代理服务器"""
        try:
            # 设置socket选项以允许地址重用
            CustomHTTPServer.allow_reuse_address = True
            
            self.proxy_server = CustomHTTPServer((ip, port), ProxyRequestHandler, parent=self)
            self.update_status(f"代理服务器运行在 {ip}:{port}")
            
            # 使用serve_forever替代handle_request
            self.proxy_server.serve_forever()
            
        except Exception as e:
            self.update_status(f"代理服务器错误: {str(e)}")
        finally:
            if self.proxy_server:
                try:
                    self.proxy_server.shutdown()
                    self.proxy_server.server_close()
                except:
                    pass

    def update_packet_list(self, packet):
        """更新数据包列表"""
        self.packet_tree.insert("", "end", values=(
            packet['time'],
            packet['method'],
            packet['url'],
            "已捕获"
        ))

    def show_packet_detail(self, event):
        """显示选中数据包的详细信息"""
        selected_items = self.packet_tree.selection()
        if not selected_items:
            return
            
        item = selected_items[0]
        packet_index = self.packet_tree.index(item)
        if packet_index < len(self.captured_packets):
            packet = self.captured_packets[packet_index]
            self.packet_detail.delete(1.0, tk.END)
            self.packet_detail.insert(tk.END, packet.get('raw', ''))

    def start_injection_test(self):
        """开始注入测试"""
        if not self.captured_packets:
            messagebox.showwarning("警告", "没有可测试的数据包")
            return

        self.test_button.config(state="disabled")
        threading.Thread(target=self._run_injection_test, daemon=True).start()

    def _run_injection_test(self):
        """运行注入测试"""
        try:
            for packet in self.captured_packets:
                # 保存HTTP请求到临时文件
                with open("temp_request.txt", "w") as f:
                    f.write(packet['raw'])

                # 执行sqlmap测试
                try:
                    result = subprocess.run(
                        ['sqlmap', '-r', 'temp_request.txt', '--batch'],
                        capture_output=True,
                        text=True
                    )

                    # 解析结果
                    if "Parameter: " in result.stdout:
                        # 提取注入参数和类型
                        param_match = re.search(r"Parameter: ([^\s]+)", result.stdout)
                        type_match = re.search(r"Type: ([^\n]+)", result.stdout)
                        payload_match = re.search(r"Payload: ([^\n]+)", result.stdout)

                        param = param_match.group(1) if param_match else "未知"
                        inj_type = type_match.group(1) if type_match else "未知"
                        payload = payload_match.group(1) if payload_match else "未知"

                        # 更新结果表格
                        self.result_tree.insert("", "end", values=(
                            packet['url'],
                            param,
                            inj_type,
                            payload
                        ))

                        # 更新状态
                        self.update_status(f"发现注入点: {packet['url']}")

                except Exception as e:
                    self.update_status(f"测试失败: {str(e)}")

                # 更新进度
                self.update()

            # 清理临时文件
            if os.path.exists("temp_request.txt"):
                os.remove("temp_request.txt")

            self.update_status("注入测试完成")

        except Exception as e:
            messagebox.showerror("错误", f"注入测试失败: {str(e)}")
        finally:
            self.test_button.config(state="normal")

    def show_packet_context_menu(self, event):
        """显示右键菜单"""
        # 检查是否选中了某一行
        selected_item = self.packet_tree.identify_row(event.y)
        if selected_item:
            # 创建右键菜单
            menu = tk.Menu(self, tearoff=0)
            menu.add_command(label="删除选中数据包", command=self.delete_selected_packet)
            menu.post(event.x_root, event.y_root)

    def delete_selected_packet(self):
        """删除选中的数据包"""
        selected_items = self.packet_tree.selection()
        for item in selected_items:
            # 获取选中项的索引
            packet_index = self.packet_tree.index(item)
            if packet_index < len(self.captured_packets):
                del self.captured_packets[packet_index]
            self.packet_tree.delete(item)
        self.update_status("已删除选中数据包")

    def show_tree_context_menu(self, event):
        """显示树形视图右键菜单"""
        item = self.tree.identify_row(event.y)
        if item:
            menu = tk.Menu(self, tearoff=0)
            menu.add_command(label="删除", command=lambda: self.delete_tree_item(item))
            menu.post(event.x_root, event.y_root)

    def delete_tree_item(self, item):
        """删除树形视图中的选中项"""
        self.tree.delete(item)
        self.update_status("已删除选中项")

    def show_http_detail(self, event):
        """显示HTTP数据包详情"""
        selected = self.tree.selection()
        if selected:
            item = self.tree.item(selected[0])
            if 'values' in item and len(item['values']) > 0:
                self.http_preview.delete(1.0, tk.END)
                self.http_preview.insert(tk.END, item['values'][0])
                self.update_status("已更新HTTP数据包预览")


# 导入必要的模块
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from datetime import datetime
import threading
import requests

class ProxyRequestHandler(BaseHTTPRequestHandler):
    """处理代理请求的Handler类"""
    
    def __init__(self, request, client_address, server):
        self.parent = server.parent
        super().__init__(request, client_address, server)
    
    def do_GET(self):
        """处理GET请求"""
        try:
            # 1. 捕获完整的请求信息
            request_info = f"{self.command} {self.path} HTTP/1.1\n"
            request_info += "\n".join(f"{k}: {v}" for k, v in self.headers.items())
            
            # 2. 转发请求并获取响应
            response = self.forward_request()
            
            # 3. 发送响应给客户端
            self.send_response(response.status_code)
            for header, value in response.headers.items():
                self.send_header(header, value)
            self.end_headers()
            self.wfile.write(response.content)
            
            # 4. 构造完整的数据包记录
            packet = {
                'time': datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                'method': self.command,
                'url': self.path,
                'headers': dict(self.headers),
                'raw': request_info + "\n\n" + (response.text if hasattr(response, 'text') else "")
            }
            
            # 5. 在主线程中安全更新UI
            def update_ui():
                try:
                    if hasattr(self.parent, 'tree') and self.parent.tree.winfo_exists():
                        self.parent.tree.insert("", "end", values=(
                            request_info,
                            "No",  # Injection状态
                            "",    # Payload
                            ""     # InjectionType
                        ))
                        self.parent.captured_packets.append(packet)
                        self.parent.update_status(f"已捕获 {self.command} 请求: {self.path}")
                        print(f"DEBUG: 成功更新UI - {self.path}")  # 调试输出
                except Exception as e:
                    print(f"UI更新错误: {str(e)}")
            
            if hasattr(self.parent, 'after'):
                self.parent.after(0, update_ui)
            else:
                print("ERROR: parent对象没有after方法")
            
        except Exception as e:
            self.send_error(500, str(e))
    
    def do_POST(self):
        """处理POST请求"""
        try:
            # 1. 读取POST数据
            content_length = int(self.headers.get('Content-Length', 0))
            post_data = self.rfile.read(content_length)
            post_body = post_data.decode('utf-8', errors='ignore')
            print(f"DEBUG: 收到POST请求, 长度={content_length}")  # 调试输出
            
            # 2. 捕获完整的请求信息
            request_info = f"{self.command} {self.path} HTTP/1.1\n"
            request_info += "\n".join(f"{k}: {v}" for k, v in self.headers.items())
            request_info += f"\nContent-Length: {content_length}\n\n{post_body}"
            
            # 3. 转发请求并获取响应
            response = self.forward_request(post_data)
            print(f"DEBUG: 转发POST请求完成, 状态码={response.status_code}")  # 调试输出
            
            # 4. 发送响应给客户端
            self.send_response(response.status_code)
            for header, value in response.headers.items():
                self.send_header(header, value)
            self.end_headers()
            self.wfile.write(response.content)
            
            # 5. 构造完整的数据包记录
            packet = {
                'time': datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                'method': self.command,
                'url': self.path,
                'headers': dict(self.headers),
                'body': post_body,
                'raw': request_info,
                'response': response.text if hasattr(response, 'text') else ""
            }
            print(f"DEBUG: 构造数据包完成 - {packet['method']} {packet['url']}")  # 调试输出
            
            # 6. 在主线程中安全更新UI
            def update_ui():
                try:
                    if hasattr(self.parent, 'tree') and self.parent.tree.winfo_exists():
                        self.parent.tree.insert("", "end", values=(
                            f"POST {self.path}",
                            "No",  # Injection状态
                            "",    # Payload
                            ""     # InjectionType
                        ))
                        self.parent.captured_packets.append(packet)
                        self.parent.update_status(f"已捕获 POST 请求: {self.path}")
                        print(f"DEBUG: 成功更新UI - POST {self.path}")  # 调试输出
                except Exception as e:
                    print(f"UI更新错误(POST): {str(e)}")
            
            if hasattr(self.parent, 'after'):
                self.parent.after(0, update_ui)
                print("DEBUG: 已调度UI更新")  # 调试输出
            else:
                print("ERROR: parent对象没有after方法")
            
        except Exception as e:
            self.send_error(500, str(e))
    
    def forward_request(self, post_data=None):
        """转发请求到目标服务器"""
        try:
            # 解析请求URL
            url = self.path
            if not url.startswith(('http://', 'https://')):
                url = f"http://{url}"
            
            # 准备请求头
            headers = dict(self.headers)
            headers.pop('Proxy-Connection', None)
            headers.pop('Host', None)
            
            # 设置超时和重试
            session = requests.Session()
            adapter = requests.adapters.HTTPAdapter(
                max_retries=3,
                pool_connections=10,
                pool_maxsize=100
            )
            session.mount('http://', adapter)
            session.mount('https://', adapter)
            
            # 转发请求
            if self.command == 'GET':
                response = session.get(
                    url,
                    headers=headers,
                    verify=False,
                    timeout=10
                )
            elif self.command == 'POST':
                response = session.post(
                    url,
                    headers=headers,
                    data=post_data,
                    verify=False,
                    timeout=10
                )
            else:
                raise ValueError(f"Unsupported method: {self.command}")
                
            return response
            
        except requests.exceptions.RequestException as e:
            # 返回友好的错误响应
            error_html = f"""
            <html>
                <head><title>Proxy Error</title></head>
                <body>
                    <h1>Proxy Forwarding Error</h1>
                    <p>{str(e)}</p>
                    <p>Please check the target server availability.</p>
                </body>
            </html>
            """
            from io import StringIO
            response = requests.models.Response()
            response.status_code = 502  # Bad Gateway
            response.raw = StringIO(error_html)
            response.headers['Content-Type'] = 'text/html'
            return response


class CustomHTTPServer(ThreadingHTTPServer):
    """自定义HTTP服务器，支持传递parent引用"""
    
    def __init__(self, server_address, RequestHandlerClass, parent):
        self.parent = parent
        super().__init__(server_address, RequestHandlerClass)


if __name__ == "__main__":
    app = SQLMapGUI()
    app.mainloop()