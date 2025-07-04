# SQLMAP-GUI-Pro
SQLMAP-GUI-Pro
注意：本工具只支持Linux环境下正常使用
![image](https://github.com/user-attachments/assets/a64b8c1f-330b-4ffd-bc1e-22261e779727)

1 GUI 图形化实现调用 sqlmap 以及参数配置
    项目用 Tkinter 做了一个直观的图形界面，用 ttk.Entry 和 ttk.Combobox 来输入和选择参数，把 sqlmap 的命令行操作简化成按钮和输入框，用户可以在界面上配置 sqlmap 的参数，还能实时看到检测结果，使得用户无需依赖复杂的命令行操作。通过 subprocess.run 来动态调用 sqlmap，把用户输入的参数传给命令行工具，通过直观的图形界面即可简便地配置和调用sqlmap 进行 SQL 注入检测，显著降低了使用门槛并提升了用户体验。

2 HTTP 数据包批量导入，助力实现批量检测 SQL 注入漏洞
    使用pandas读取Excel文件，或逐行读取文本文件，支持从.xlsx或.txt文件中批量导入 HTTP 数据包，也可以通过代理监听的形式捕获数据包，将数据插入到Treeview控件中，便于用户快速加载测试目标，实现对多个URL或HTTP数据包的高效自动化SQL注入测试，大幅提高了测试效率。

3 数据库结构图形化展示
    整 体 设 计 多 个 方 法 的 组 合 ， 如 scan_output_directory 、 build_database_tree 和load_table_data 等 ，实现了从对 sqlmap 输出目录的扫描解析到构建树型视图，展示 IP 地址、数据库、表和字段信息并加载并显示表数据，提升了数据分析的便捷性和直观性。

![image](https://github.com/user-attachments/assets/55a44086-abf0-4565-a02c-633fb81cd71b)
![image](https://github.com/user-attachments/assets/6cd9bedf-93c3-467d-a280-0254e8af756b)
![image](https://github.com/user-attachments/assets/fa1b4ac7-ef32-4596-915e-3876a88b0213)



本项目的工具通过调用 sqlmap 实现 SQL 注入，因此本工具支持与 sqlmap 相同的SQL 注入类型。
![image](https://github.com/user-attachments/assets/231f8609-71af-4d5e-b243-c4942672407a)


在本项目中，采用了一系列关键技术来实现 SQL 注入测试工具的功能。这些技术点不仅支持了工具的核心功能，还提升了用户体验和操作的灵活性。

![image](https://github.com/user-attachments/assets/d4dd9bce-e040-4aac-bd94-7dec4f0080c5)



