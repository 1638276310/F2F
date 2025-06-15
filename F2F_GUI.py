import os
import threading
import tkinter as tk
from tkinter import ttk, filedialog, messagebox
from deepseek_f2b import file_to_encoded, encoded_to_file
import datetime

class DeepseekGUI(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("DeepSeek F2B 文件编码/解码工具")
        self.geometry("750x600")
        self._create_widgets()
        self._load_defaults()
        # 拖拽功能
        # self._enable_drag_and_drop()

    def _create_widgets(self):
        self.mode = tk.StringVar(value="encode")
        self.file_path = tk.StringVar()
        self.output_path = tk.StringVar()
        self.password = tk.StringVar()
        self.encoding = tk.StringVar(value="base64")
        self.compression = tk.StringVar(value="none")
        self.volume_size = tk.IntVar(value=0)
        self.safe_mode = tk.BooleanVar(value=False)

        frm_file = ttk.LabelFrame(self, text="文件设置")
        frm_file.pack(fill="x", padx=10, pady=5)
        ttk.Label(frm_file, text="选择文件:").grid(row=0, column=0, padx=5, pady=5)
        self.entry_input = ttk.Entry(frm_file, textvariable=self.file_path, width=60)
        self.entry_input.grid(row=0, column=1, padx=5)
        ttk.Button(frm_file, text="浏览", command=self.select_file).grid(row=0, column=2, padx=5)

        ttk.Label(frm_file, text="输出文件:").grid(row=1, column=0, padx=5, pady=5)
        self.entry_output = ttk.Entry(frm_file, textvariable=self.output_path, width=60)
        self.entry_output.grid(row=1, column=1, padx=5)
        ttk.Button(frm_file, text="选择路径", command=self.select_output).grid(row=1, column=2, padx=5)

        frm_mode = ttk.LabelFrame(self, text="模式选择")
        frm_mode.pack(fill="x", padx=10, pady=5)
        ttk.Radiobutton(frm_mode, text="编码", variable=self.mode, value="encode").pack(side="left", padx=20)
        ttk.Radiobutton(frm_mode, text="解码", variable=self.mode, value="decode").pack(side="left")

        frm_params = ttk.LabelFrame(self, text="参数配置")
        frm_params.pack(fill="x", padx=10, pady=5)

        ttk.Label(frm_params, text="编码格式:").grid(row=0, column=0, padx=5, pady=5, sticky="e")
        encoding_options = ["base64", "base32", "base16", "base85", "hex", "urlsafe"]
        ttk.Combobox(frm_params, textvariable=self.encoding, values=encoding_options).grid(row=0, column=1, padx=5, sticky="w")

        ttk.Label(frm_params, text="压缩算法:").grid(row=1, column=0, padx=5, pady=5, sticky="e")
        compress_options = ["none", "zlib", "gzip", "lzma", "bz2"]
        ttk.Combobox(frm_params, textvariable=self.compression, values=compress_options).grid(row=1, column=1, padx=5, sticky="w")

        ttk.Label(frm_params, text="分卷大小(MB):").grid(row=2, column=0, padx=5, pady=5, sticky="e")
        ttk.Entry(frm_params, textvariable=self.volume_size).grid(row=2, column=1, padx=5, sticky="w")

        ttk.Checkbutton(frm_params, text="内存安全模式", variable=self.safe_mode).grid(row=3, column=1, sticky="w")

        ttk.Label(frm_params, text="密码(可选):").grid(row=4, column=0, padx=5, pady=5, sticky="e")
        ttk.Entry(frm_params, textvariable=self.password, show="*").grid(row=4, column=1, padx=5, sticky="w")

        frm_action = ttk.Frame(self)
        frm_action.pack(fill="x", pady=10)
        ttk.Button(frm_action, text="开始执行", command=self.run_task).pack(side="left", padx=10)
        ttk.Button(frm_action, text="保存默认参数", command=self._save_defaults).pack(side="left", padx=10)
        ttk.Button(frm_action, text="清空日志", command=self._clear_log).pack(side="left", padx=10)
        ttk.Button(frm_action, text="导出日志", command=self._export_log).pack(side="left", padx=10)
        ttk.Button(frm_action, text="打开目录", command=self._open_output_dir).pack(side="left", padx=10)

        self.progress_var = tk.DoubleVar()
        self.progress = ttk.Progressbar(self, variable=self.progress_var, maximum=100)
        self.progress.pack(fill="x", padx=10, pady=5)

        self.log_text = tk.Text(self, height=10, bg="#111", fg="#0f0")
        self.log_text.pack(fill="both", expand=True, padx=10, pady=5)

    def select_file(self):
        path = filedialog.askopenfilename()
        if path:
            self.file_path.set(path)

    def select_output(self):
        path = filedialog.asksaveasfilename()
        if path:
            self.output_path.set(path)

    def run_task(self):
        if not self.file_path.get():
            messagebox.showerror("错误", "请选择文件")
            return

        self.log_text.delete(1.0, tk.END)
        self.progress_var.set(0)
        threading.Thread(target=self._execute, daemon=True).start()

    def _log(self, msg):
        timestamp = datetime.datetime.now().strftime("[%H:%M:%S] ")
        self.log_text.insert(tk.END, timestamp + msg + "\n")
        self.log_text.see(tk.END)

    def _execute(self):
        try:
            if self.mode.get() == "encode":
                self._log("[编码开始]")
                import time
                start_time = time.time()
                files = file_to_encoded(
                    input_file=self.file_path.get(),
                    output_file=self.output_path.get() or None,
                    encoding=self.encoding.get(),
                    compression=self.compression.get(),
                    password=self.password.get() or None,
                    max_volume_size=self.volume_size.get(),
                    safe_mode=self.safe_mode.get(),
                    progress=False
                )
                elapsed = time.time() - start_time
                input_size = os.path.getsize(self.file_path.get())
                encoded_size = sum(os.path.getsize(f) for f in files)
                ratio = encoded_size / input_size if input_size > 0 else 0

                self._log("生成文件: " + ", ".join(files))
                self._log(f"原始大小: {self._format_size(input_size)}")
                self._log(f"编码后大小: {self._format_size(encoded_size)}")
                self._log(f"压缩率: {ratio:.2%}")
                self._log(f"耗时: {elapsed:.1f} 秒")
                self._log("[编码完成]")
                
            else:
                self._log("[解码开始]")
                encoded_to_file(
                    input_data=self.file_path.get(),
                    output_file=self.output_path.get() or None,
                    password=self.password.get() or None,
                    safe_mode=self.safe_mode.get(),
                    progress=False
                )
                self._log("[解码完成]")

            self.progress_var.set(100)
            messagebox.showinfo("完成", "任务执行完毕！")
        except Exception as e:
            self._log("错误: " + str(e))
            messagebox.showerror("执行失败", str(e))

    # 清晰命名的版本
    def _format_size(self, size):
        UNITS = ['B', 'KB', 'MB', 'GB', 'TB']  # 常量命名
        for unit in UNITS:  # 一目了然
            if size < 1024:
                return f"{size:.2f} {unit}"
            size /= 1024
        return f"{size:.2f} PB"


    def _save_defaults(self):
        import json
        defaults = {
            "encoding": self.encoding.get(),
            "compression": self.compression.get(),
            "volume_size": self.volume_size.get(),
            "safe_mode": self.safe_mode.get(),
        }
        with open("deepseek_config.json", "w", encoding="utf-8") as f:
            json.dump(defaults, f)
        self._log("默认参数已保存")

    def _load_defaults(self):
        import json
        try:
            if os.path.exists("deepseek_config.json"):
                with open("deepseek_config.json", "r", encoding="utf-8") as f:
                    defaults = json.load(f)
                    self.encoding.set(defaults.get("encoding", "base64"))
                    self.compression.set(defaults.get("compression", "none"))
                    self.volume_size.set(defaults.get("volume_size", 0))
                    self.safe_mode.set(defaults.get("safe_mode", False))
        except Exception as e:
            self._log("读取默认参数失败: " + str(e))

    # def _enable_drag_and_drop(self):
    #     def drop(event):
    #         self.file_path.set(event.data.strip("{}"))
    #     try:
    #         import tkinterdnd2 as tkdnd
    #         self.tk.call('package', 'require', 'tkdnd')
    #         self.drop_target_register(tkdnd.DND_FILES)
    #         self.dnd_bind('<<Drop>>', drop)
    #     except Exception as e:
    #         self._log("拖拽功能初始化失败: " + str(e))

    def _clear_log(self):
        self.log_text.delete(1.0, tk.END)

    def _export_log(self):
        try:
            log_content = self.log_text.get(1.0, tk.END)
            path = filedialog.asksaveasfilename(defaultextension=".txt", filetypes=[("文本文件", "*.txt")])
            if path:
                with open(path, "w", encoding="utf-8") as f:
                    f.write(log_content)
                self._log("日志已导出到: " + path)
        except Exception as e:
            self._log("导出日志失败: " + str(e))

    def _open_output_dir(self):
        path = self.output_path.get()
        if path:
            folder = os.path.dirname(path)
            if os.path.exists(folder):
                os.startfile(folder)

if __name__ == '__main__':
    app = DeepseekGUI()
    app.mainloop()